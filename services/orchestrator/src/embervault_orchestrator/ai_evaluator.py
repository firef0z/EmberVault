"""AI-driven decision making for error evaluation and retry/fail resolution."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from sqlalchemy.orm import Session

from embervault_common.ai.anonymizer import DataAnonymizer
from embervault_common.ai.client import AIClient
from embervault_common.ai.prompts import get_default_error_system_prompt
from embervault_common.observability import get_logger
from embervault_db.models.auth import AuditLog
from embervault_db.models.execution import JobRun, Task, TaskAssignment
from embervault_db.repositories.execution_repository import ExecutionRepository
from embervault_db.settings_store import SettingsStore

logger = get_logger("embervault_orchestrator.ai_evaluator")


@dataclass
class AIErrorDecision:
    """Decision evaluated by the AI model for a failed task."""

    decision: str  # "retry", "fail", or "ignore"
    reason: str
    confidence: float
    suggested_backoff_seconds: int | None
    system_prompt: str
    user_prompt: str
    raw_response: str
    interpretation: str
    action_taken: str


class AIErrorEvaluator:
    """Evaluates task failures using OpenAI-compatible or Ollama LLM to decide retry vs fail."""

    def __init__(self, settings_store: SettingsStore) -> None:
        self.settings_store = settings_store

    def is_enabled(self) -> bool:
        """Check if AI integration and error handling sub-option are both enabled."""
        ai_enabled = bool(self.settings_store.get_setting("ai_enabled"))
        error_handling = bool(self.settings_store.get_setting("ai_error_handling_enabled"))
        endpoint = str(self.settings_store.get_setting("ai_endpoint_url") or "").strip()
        model = str(self.settings_store.get_setting("ai_model") or "").strip()
        return ai_enabled and error_handling and bool(endpoint) and bool(model)

    def is_uncensored(self) -> bool:
        """Check if sensitive data censoring is disabled."""
        return bool(self.settings_store.get_setting("ai_error_handling_uncensored"))

    def get_ai_language(self) -> tuple[str, str]:
        """Resolve configured AI language code and display name (default: English)."""
        import os

        raw = (
            str(
                self.settings_store.get_setting("ai_language")
                or os.environ.get("AI_LANGUAGE")
                or os.environ.get("EMBERVAULT_AI_LANGUAGE")
                or "en"
            )
            .strip()
            .lower()
        )

        lang_map = {
            "en": "English",
            "it": "Italian",
            "de": "German",
            "es": "Spanish",
            "fr": "French",
            "zh": "Chinese",
            "ja": "Japanese",
            "ko": "Korean",
            "ar": "Arabic",
        }
        if raw in lang_map:
            return raw, lang_map[raw]
        for code, name in lang_map.items():
            if raw.startswith(code) or raw == name.lower():
                return code, name
        return "en", "English"

    def _get_ai_client(self) -> AIClient:
        endpoint_url = str(
            self.settings_store.get_setting("ai_endpoint_url") or "http://localhost:11434"
        ).strip()
        model = str(self.settings_store.get_setting("ai_model") or "llama3.2").strip()
        provider_type = str(
            self.settings_store.get_setting("ai_provider_type") or "openai_compatible"
        ).strip()
        api_key = self.settings_store.get_setting("ai_api_key")
        timeout_s = int(self.settings_store.get_setting("ai_timeout_seconds") or 15)

        return AIClient(
            endpoint_url=endpoint_url,
            model=model,
            provider_type=provider_type,
            api_key=api_key,
            timeout_seconds=timeout_s,
        )

    def evaluate_task_failure(
        self,
        session: Session,
        task: Task,
        assignment: TaskAssignment,
        exit_code: int | None = None,
        error_class: str | None = None,
        error_code: str | None = None,
        recent_log_lines: list[str] | None = None,
    ) -> AIErrorDecision | None:
        """Evaluate a task failure using AI and record full prompt/response/action logs.

        Returns:
            AIErrorDecision if evaluated, or None if AI is disabled or evaluation errored.
        """
        if not self.is_enabled():
            return None

        uncensored = self.is_uncensored()
        anonymizer = DataAnonymizer() if not uncensored else None

        # Build context
        run: JobRun = task.run
        job = run.job

        job_name = job.name if job else run.job_snapshot.get("name", "Unknown Job")
        job_op = job.operation if job else run.job_snapshot.get("operation", "sync")
        src_backend = (
            job.source_remote.backend_type
            if (job and job.source_remote)
            else run.job_snapshot.get("source_backend", "local")
        )
        dst_backend = (
            job.destination_remote.backend_type
            if (job and job.destination_remote)
            else run.job_snapshot.get("destination_backend", "local")
        )
        src_path = job.source_path if job else run.job_snapshot.get("source_path", "")
        dst_path = job.destination_path if job else run.job_snapshot.get("destination_path", "")

        subpath = task.spec.get("source_subpath", "") if task.spec else ""
        task_scope = task.scope or "unknown"
        attempt_count = task.attempt_count or 1
        max_attempts = task.max_attempts or 3

        error_details = {
            "exit_code": exit_code,
            "error_class": error_class,
            "error_code": error_code,
            "attempts_so_far": attempt_count,
            "max_attempts": max_attempts,
            "recent_logs": recent_log_lines[-20:] if recent_log_lines else [],
        }

        # Apply anonymization if not uncensored
        if anonymizer is not None:
            job_name = anonymizer.anonymize_text(job_name)
            src_path = anonymizer.anonymize_text(src_path)
            dst_path = anonymizer.anonymize_text(dst_path)
            subpath = anonymizer.anonymize_text(subpath)
            error_details = anonymizer.anonymize_data(error_details)

        lang_code, lang_name = self.get_ai_language()
        custom_system_prompt = str(
            self.settings_store.get_setting("ai_system_prompt") or ""
        ).strip()
        base_prompt = (
            custom_system_prompt if custom_system_prompt else get_default_error_system_prompt()
        )

        # Enforce AI_LANGUAGE instruction dynamically at runtime
        system_prompt = (
            f"{base_prompt.strip()}\n\n"
            f"MANDATORY LANGUAGE REQUIREMENT:\n"
            f"You MUST formulate your entire response and the 'reason' field strictly in {lang_name}."
        )

        # Build user prompt according to AI_LANGUAGE
        if lang_code == "it":
            user_prompt = (
                f"Dettagli Job:\n"
                f"- Nome: {job_name}\n"
                f"- Operazione: {job_op}\n"
                f"- Sorgente ({src_backend}): {src_path}\n"
                f"- Destinazione ({dst_backend}): {dst_path}\n\n"
                f"Dettagli Task:\n"
                f"- ID Task: {task.id}\n"
                f"- Ambito: {task_scope}\n"
                f"- Sottopercorso: {subpath or 'radice'}\n"
                f"- Tentativo: {attempt_count} di {max_attempts}\n\n"
                f"Dettagli Errore:\n"
                f"- Codice Uscita: {error_details['exit_code']}\n"
                f"- Classe Errore: {error_details['error_class']}\n"
                f"- Codice Errore: {error_details['error_code']}\n"
                f"- Log di Errore:\n"
                + "\n".join(f"  {line}" for line in error_details["recent_logs"])
            )
        elif lang_code == "de":
            user_prompt = (
                f"Job-Details:\n"
                f"- Name: {job_name}\n"
                f"- Operation: {job_op}\n"
                f"- Quelle ({src_backend}): {src_path}\n"
                f"- Ziel ({dst_backend}): {dst_path}\n\n"
                f"Task-Details:\n"
                f"- Task-ID: {task.id}\n"
                f"- Umfang: {task_scope}\n"
                f"- Unterpfad: {subpath or 'root'}\n"
                f"- Versuch: {attempt_count} von {max_attempts}\n\n"
                f"Fehlerdetails:\n"
                f"- Exit-Code: {error_details['exit_code']}\n"
                f"- Fehlerklasse: {error_details['error_class']}\n"
                f"- Fehlercode: {error_details['error_code']}\n"
                f"- Fehlerprotokolle:\n"
                + "\n".join(f"  {line}" for line in error_details["recent_logs"])
            )
        elif lang_code == "es":
            user_prompt = (
                f"Detalles del Job:\n"
                f"- Nombre: {job_name}\n"
                f"- Operación: {job_op}\n"
                f"- Origen ({src_backend}): {src_path}\n"
                f"- Destino ({dst_backend}): {dst_path}\n\n"
                f"Detalles de la Tarea:\n"
                f"- ID de Tarea: {task.id}\n"
                f"- Ámbito: {task_scope}\n"
                f"- Subruta: {subpath or 'raíz'}\n"
                f"- Intento: {attempt_count} de {max_attempts}\n\n"
                f"Detalles del Error:\n"
                f"- Código de Salida: {error_details['exit_code']}\n"
                f"- Clase de Error: {error_details['error_class']}\n"
                f"- Código de Error: {error_details['error_code']}\n"
                f"- Registros de Error:\n"
                + "\n".join(f"  {line}" for line in error_details["recent_logs"])
            )
        elif lang_code == "fr":
            user_prompt = (
                f"Détails du Job:\n"
                f"- Nom: {job_name}\n"
                f"- Opération: {job_op}\n"
                f"- Source ({src_backend}): {src_path}\n"
                f"- Destination ({dst_backend}): {dst_path}\n\n"
                f"Détails de la Tâche:\n"
                f"- ID de Tâche: {task.id}\n"
                f"- Portée: {task_scope}\n"
                f"- Sous-chemin: {subpath or 'racine'}\n"
                f"- Tentative: {attempt_count} sur {max_attempts}\n\n"
                f"Détails de l'Erreur:\n"
                f"- Code de Sortie: {error_details['exit_code']}\n"
                f"- Classe d'Erreur: {error_details['error_class']}\n"
                f"- Code d'Erreur: {error_details['error_code']}\n"
                f"- Journaux d'Erreur:\n"
                + "\n".join(f"  {line}" for line in error_details["recent_logs"])
            )
        else:
            # Default English
            user_prompt = (
                f"Job Details:\n"
                f"- Name: {job_name}\n"
                f"- Operation: {job_op}\n"
                f"- Source ({src_backend}): {src_path}\n"
                f"- Destination ({dst_backend}): {dst_path}\n\n"
                f"Task Details:\n"
                f"- Task ID: {task.id}\n"
                f"- Scope: {task_scope}\n"
                f"- Subpath: {subpath or 'root'}\n"
                f"- Attempt: {attempt_count} of {max_attempts}\n\n"
                f"Error Details:\n"
                f"- Exit Code: {error_details['exit_code']}\n"
                f"- Error Class: {error_details['error_class']}\n"
                f"- Error Code: {error_details['error_code']}\n"
                f"- Error Logs:\n" + "\n".join(f"  {line}" for line in error_details["recent_logs"])
            )

        raw_response = ""
        decision_val = "fail"
        reason_val = (
            "No valid response obtained from AI"
            if lang_code != "it"
            else "Impossibile ottenere risposta valida dall'IA"
        )
        confidence_val = 0.5
        suggested_backoff = None

        try:
            client = self._get_ai_client()
            ai_resp = client.chat_completion(system_prompt=system_prompt, user_prompt=user_prompt)
            raw_response = ai_resp.raw_content

            # Parse JSON from response
            cleaned_json = raw_response.strip()
            if "```" in cleaned_json:
                match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned_json, re.DOTALL)
                if match:
                    cleaned_json = match.group(1)

            parsed = json.loads(cleaned_json)
            raw_decision = str(parsed.get("decision", "")).strip().lower()
            if raw_decision in ("retry", "riprova", "reintentar", "wiederholen", "réessayer"):
                decision_val = "retry"
            elif raw_decision in ("ignore", "ignora", "ignorer", "ignoriere", "ignorar"):
                decision_val = "ignore"
            else:
                decision_val = "fail"

            fallback_reason_msg = (
                "No reason specified" if lang_code != "it" else "Nessun motivo specificato"
            )
            reason_val = str(parsed.get("reason", fallback_reason_msg)).strip()
            confidence_val = float(parsed.get("confidence", 0.8))
            if parsed.get("suggested_backoff_seconds") is not None:
                suggested_backoff = int(parsed["suggested_backoff_seconds"])

            if lang_code == "it":
                if decision_val == "retry":
                    dec_desc = "TEMPORANEO (retry consigliato con backoff)"
                elif decision_val == "ignore":
                    dec_desc = "FILE PROBLEMATICO (ignore consigliato per ripetere la sincronizzazione escludendo il file)"
                else:
                    dec_desc = "IRREVERSIBILE GENERALIZZATO (fallimento permanente)"
                interpretation = (
                    f"L'IA ha classificato l'errore come {dec_desc}. "
                    f"Confidenza: {confidence_val:.0%}. Motivo: {reason_val}"
                )
            else:
                if decision_val == "retry":
                    dec_desc = "TEMPORARY (retry recommended with backoff)"
                elif decision_val == "ignore":
                    dec_desc = "PROBLEMATIC FILE (ignore recommended to resync skipping the file)"
                else:
                    dec_desc = "GENERALIZED IRREVERSIBLE (permanent failure)"
                interpretation = (
                    f"The AI classified the error as {dec_desc}. "
                    f"Confidence: {confidence_val:.0%}. Reason: {reason_val}"
                )

        except Exception as exc:
            logger.warning(
                "ai_evaluation_failed",
                task_id=str(task.id),
                error=str(exc),
            )
            raw_response = (
                f"Error querying AI endpoint: {exc}"
                if lang_code != "it"
                else f"Errore durante l'interrogazione dell'IA: {exc}"
            )
            # Fallback safe: maintain standard logic (retry if attempts remain and not permanent)
            if attempt_count < max_attempts and error_class != "permanent":
                decision_val = "retry"
                reason_val = (
                    f"Safety fallback (AI unreachable: {exc}): retry permitted."
                    if lang_code != "it"
                    else f"Fallback di sicurezza (IA non raggiungibile: {exc}): riprova consentita."
                )
            else:
                decision_val = "fail"
                reason_val = (
                    f"Safety fallback (AI unreachable: {exc}): attempts exhausted."
                    if lang_code != "it"
                    else f"Fallback di sicurezza (IA non raggiungibile: {exc}): tentativi esauriti."
                )

            if lang_code == "it":
                interpretation = f"Interrogazione IA fallita ({exc}). Applicato fallback standard: {decision_val.upper()}."
            else:
                interpretation = f"AI query failed ({exc}). Applied standard safety fallback: {decision_val.upper()}."

        # Determine action taken according to AI_LANGUAGE
        if lang_code == "it":
            if decision_val == "retry":
                if attempt_count < max_attempts:
                    backoff_info = (
                        f" (backoff suggerito: {suggested_backoff}s)" if suggested_backoff else ""
                    )
                    action_taken = (
                        f"Pianificato nuovo tentativo di esecuzione del task{backoff_info}."
                    )
                else:
                    action_taken = "L'IA ha suggerito retry, ma i tentativi massimi sono esauriti: il task viene marcato come FALLITO."
                    decision_val = "fail"
            elif decision_val == "ignore":
                if attempt_count < max_attempts:
                    backoff_info = f" (backoff: {suggested_backoff}s)" if suggested_backoff else ""
                    action_taken = f"Pianificata riesecuzione della sincronizzazione ignorando il file problematico{backoff_info}."
                else:
                    action_taken = "L'IA ha suggerito ignore, ma i tentativi massimi sono esauriti: il task viene marcato come FALLITO."
                    decision_val = "fail"
            else:
                action_taken = "Il task viene segnato immediatamente come FALLITO permanente (non recuperabile)."
        else:
            if decision_val == "retry":
                if attempt_count < max_attempts:
                    backoff_info = (
                        f" (suggested backoff: {suggested_backoff}s)" if suggested_backoff else ""
                    )
                    action_taken = f"Scheduled new execution attempt for the task{backoff_info}."
                else:
                    action_taken = "The AI suggested retry, but maximum attempts are exhausted: task is marked as FAILED."
                    decision_val = "fail"
            elif decision_val == "ignore":
                if attempt_count < max_attempts:
                    backoff_info = f" (backoff: {suggested_backoff}s)" if suggested_backoff else ""
                    action_taken = f"Scheduled re-execution of synchronization ignoring the problematic file{backoff_info}."
                else:
                    action_taken = "The AI suggested ignore, but maximum attempts are exhausted: task is marked as FAILED."
                    decision_val = "fail"
            else:
                action_taken = "The task is marked immediately as permanent FAILED (unrecoverable)."

        decision_obj = AIErrorDecision(
            decision=decision_val,
            reason=reason_val,
            confidence=confidence_val,
            suggested_backoff_seconds=suggested_backoff,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            raw_response=raw_response,
            interpretation=interpretation,
            action_taken=action_taken,
        )

        # MANDATORY LOGGING (4 points):
        # 1. Che cosa gli è stato inviato (system + user prompt)
        # 2. Che cosa ha risposto (raw_response)
        # 3. Come embervault ha interpretato la risposta (interpretation)
        # 4. Che azione è stata intrapresa (action_taken)

        # A) Structured python logging
        logger.info(
            "ai_task_error_evaluation",
            task_id=str(task.id),
            assignment_id=str(assignment.id),
            decision=decision_val,
            confidence=confidence_val,
            uncensored=uncensored,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            raw_response=raw_response,
            interpretation=interpretation,
            action_taken=action_taken,
        )

        # B) TaskLog entries in database
        try:
            mode_desc = "dati in chiaro" if uncensored else "dati censurati"
            ExecutionRepository.record_task_log(
                session=session,
                assignment_id=assignment.id,
                task_id=task.id,
                run_id=run.id,
                message=f"[AI-DECISION-MAKING] Interrogazione IA per valutazione errore ({mode_desc})",
                stream="stderr",
                level="info",
            )
            ExecutionRepository.record_task_log(
                session=session,
                assignment_id=assignment.id,
                task_id=task.id,
                run_id=run.id,
                message=f"[AI-SYSTEM-PROMPT]\n{system_prompt}",
                stream="stderr",
                level="info",
            )
            ExecutionRepository.record_task_log(
                session=session,
                assignment_id=assignment.id,
                task_id=task.id,
                run_id=run.id,
                message=f"[AI-USER-PROMPT]\n{user_prompt}",
                stream="stderr",
                level="info",
            )
            ExecutionRepository.record_task_log(
                session=session,
                assignment_id=assignment.id,
                task_id=task.id,
                run_id=run.id,
                message=f"[AI-RAW-RESPONSE]\n{raw_response}",
                stream="stderr",
                level="info",
            )
            ExecutionRepository.record_task_log(
                session=session,
                assignment_id=assignment.id,
                task_id=task.id,
                run_id=run.id,
                message=f"[AI-INTERPRETATION] {interpretation}",
                stream="stderr",
                level="info",
            )
            ExecutionRepository.record_task_log(
                session=session,
                assignment_id=assignment.id,
                task_id=task.id,
                run_id=run.id,
                message=f"[AI-ACTION] {action_taken}",
                stream="stderr",
                level="info",
            )
        except Exception as log_exc:
            logger.warning("failed_to_record_ai_task_logs", error=str(log_exc))

        # C) AuditLog entry in database
        try:
            session.add(
                AuditLog(
                    action="ai.error_decision",
                    actor_user_id=run.requested_by,
                    entity_type="task",
                    entity_id=str(task.id),
                    details={
                        "run_id": str(run.id),
                        "assignment_id": str(assignment.id),
                        "decision": decision_val,
                        "confidence": confidence_val,
                        "uncensored": uncensored,
                        "system_prompt": system_prompt,
                        "user_prompt": user_prompt,
                        "raw_response": raw_response,
                        "interpretation": interpretation,
                        "action_taken": action_taken,
                    },
                )
            )
        except Exception as audit_exc:
            logger.warning("failed_to_record_ai_audit_log", error=str(audit_exc))

        return decision_obj
