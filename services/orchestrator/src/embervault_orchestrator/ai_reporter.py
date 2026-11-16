"""AI-driven report analysis and summarization for notification reporting."""

from __future__ import annotations

import re
import uuid
from typing import Any

from sqlalchemy.orm import Session

from embervault_common.ai.client import AIClient
from embervault_common.ai.prompts import get_default_reporting_system_prompt
from embervault_common.observability import get_logger
from embervault_db.models.auth import AuditLog
from embervault_db.settings_store import SettingsStore

logger = get_logger("embervault_orchestrator.ai_reporter")


class AIReporter:
    """Generates AI-driven summaries, problem detection, and actionable solutions for notifications."""

    def __init__(self, settings_store: SettingsStore) -> None:
        self.settings_store = settings_store

    def is_enabled(self) -> bool:
        """Check if AI integration and reporting analysis option are both enabled."""
        ai_enabled = bool(self.settings_store.get_setting("ai_enabled"))
        reporting_enabled = bool(self.settings_store.get_setting("ai_reporting_analysis_enabled"))
        endpoint = str(self.settings_store.get_setting("ai_endpoint_url") or "").strip()
        model = str(self.settings_store.get_setting("ai_model") or "").strip()
        return ai_enabled and reporting_enabled and bool(endpoint) and bool(model)

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

    def generate_report_analysis(
        self,
        session: Session,
        event_type: str,
        context: dict[str, Any],
        entity_id: str | None = None,
        actor_user_id: uuid.UUID | None = None,
    ) -> str | None:
        """Query AI for an executive summary, problem diagnosis, and actionable solutions.

        Args:
            session: Active database session.
            event_type: The notification event type (e.g. job_run_completed, proxy_offline).
            context: Metadata dictionary for the notification event.
            entity_id: Optional ID of the run or proxy being reported.
            actor_user_id: Optional user ID for the audit trail.

        Returns:
            AI-generated summary and recommendations, or None if disabled or failed.
        """
        if not self.is_enabled():
            return None

        lang_code, lang_name = self.get_ai_language()
        custom_system_prompt = str(
            self.settings_store.get_setting("ai_reporting_system_prompt") or ""
        ).strip()

        if custom_system_prompt:
            max_chars = 900
            max_tokens = 350
            base_prompt = custom_system_prompt
        elif event_type == "proxy_offline":
            max_chars = 500
            max_tokens = 220
            base_prompt = (
                "You are a system diagnostic assistant for EmberVault.\n"
                "Analyze the offline event of the specified proxy node and generate an essential, focused diagnosis.\n"
                "MANDATORY RULES:\n"
                "1. Maximum conciseness: response MUST NOT exceed 450 characters.\n"
                "2. Do NOT use pleasantries or preambles. Get straight to the point.\n"
                "3. Do NOT assume or mention synchronized files, data volume, jobs, or load balancing: this event strictly concerns network connectivity and proxy health.\n"
                "4. Structure response in 3 brief bullet points:\n"
                "• Cause: reason for non-response and consecutive failed checks.\n"
                "• Impact: operational consequences for tasks/jobs assigned to this proxy.\n"
                "• Actions: 2-3 immediate practical checks (host/port reachability, proxy daemon, TLS certificate, or firewall)."
            )
        elif event_type in ("job_run_completed", "job_run_completion"):
            max_chars = 900
            max_tokens = 350
            base_prompt = get_default_reporting_system_prompt()
        elif event_type == "hook_failed":
            max_chars = 500
            max_tokens = 220
            base_prompt = (
                "You are a diagnostic assistant for EmberVault.\n"
                "Analyze the bash hook script failure and provide an essential diagnosis.\n"
                "MANDATORY RULES:\n"
                "1. Maximum conciseness: under 450 characters. No pleasantries.\n"
                "2. Structure in 3 points: Error, Impact, Actions."
            )
        else:
            max_chars = 500
            max_tokens = 220
            base_prompt = (
                "You are a diagnostic assistant for EmberVault.\n"
                "Provide an essential summary and actionable recommendations regarding the indicated event.\n"
                "RULES: Max 450 characters, no pleasantries, only concrete facts and actions."
            )

        # Enforce AI_LANGUAGE instruction dynamically at runtime
        system_prompt = (
            f"{base_prompt.strip()}\n\n"
            f"MANDATORY LANGUAGE REQUIREMENT:\n"
            f"You MUST formulate your entire response strictly in {lang_name}."
        )

        if lang_code == "it":
            user_prompt_lines = [f"Tipo Evento: {event_type}"]
        else:
            user_prompt_lines = [f"Event Type: {event_type}"]

        tasks_detail = context.get("tasks_detail")

        for k, v in context.items():
            if k in ("ai_analysis", "tasks_detail"):
                continue
            if v is not None and str(v).strip() != "":
                user_prompt_lines.append(f"- {k}: {v}")

        if tasks_detail and isinstance(tasks_detail, list):
            tasks_hdr = (
                "\nDettaglio Esecuzione Singoli Task:"
                if lang_code == "it"
                else "\nSingle Task Execution Details:"
            )
            user_prompt_lines.append(tasks_hdr)
            for t in tasks_detail:
                seq = t.get("seq", 0)
                kind = t.get("kind", "transfer")
                scope = t.get("scope", "")
                subpath = t.get("subpath")
                status = t.get("status", "unknown")
                dur_s = t.get("duration_s", 0.0)
                dur_ms = t.get("duration_ms", 0)
                files = t.get("files_transferred", 0)
                bytes_cnt = t.get("bytes_transferred", 0)
                proxy = t.get("proxy") or "locale/default"
                attempts = t.get("attempt_count", 1)
                max_attempts = t.get("max_attempts", 3)
                err = t.get("last_error_code")
                err_class = t.get("last_error_class")
                error_logs = t.get("error_logs") or []
                ai_eval = t.get("ai_evaluation")

                scope_info = f"scope={scope}"
                if subpath:
                    scope_info += f", percorso='{subpath}'"

                if bytes_cnt >= 1024 * 1024 * 1024:
                    vol_str = f"{bytes_cnt / (1024**3):.2f} GB ({bytes_cnt} byte)"
                elif bytes_cnt >= 1024 * 1024:
                    vol_str = f"{bytes_cnt / (1024**2):.2f} MB ({bytes_cnt} byte)"
                elif bytes_cnt >= 1024:
                    vol_str = f"{bytes_cnt / 1024:.2f} KB ({bytes_cnt} byte)"
                else:
                    vol_str = f"{bytes_cnt} byte"

                line = (
                    f"  * Task #{seq} ({kind}, {scope_info}): "
                    f"esito={status}, durata={dur_s}s ({dur_ms}ms), "
                    f"file sincronizzati={files}, volume={vol_str}, "
                    f"proxy={proxy}, tentativi={attempts}/{max_attempts}"
                )
                if err or err_class:
                    line += f", errore={err or err_class}"
                user_prompt_lines.append(line)

                if ai_eval and isinstance(ai_eval, dict):
                    eval_dec = ai_eval.get("decision", "n/d")
                    eval_reason = ai_eval.get("reason") or ai_eval.get("interpretation")
                    if eval_reason:
                        user_prompt_lines.append(
                            f"    -> Valutazione IA Decision Making: decisione={eval_dec}, motivazione: {eval_reason}"
                        )

                if error_logs:
                    user_prompt_lines.append("    -> Ultime righe log d'errore:")
                    for eline in error_logs[-5:]:
                        user_prompt_lines.append(f"       {eline}")

        user_prompt = "\n".join(user_prompt_lines)

        is_error = False
        try:
            client = self._get_ai_client()
            ai_resp = client.chat_completion(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=0.2,
                max_tokens=max_tokens,
            )
            raw_response = ai_resp.raw_content.strip()

            # Rimozione di preamboli o formule di cortesia conversazionali
            raw_response = re.sub(
                r"^(certamente[.,!\s]*|di seguito[^\n]*\n+|ecco l['’]analisi[^\n]*\n+|certamente,\s*)",
                "",
                raw_response,
                flags=re.IGNORECASE,
            ).strip()

            # Troncamento programmatico per garantire che non ecceda max_chars
            if len(raw_response) > max_chars:
                truncated = raw_response[:max_chars]
                last_dot = max(truncated.rfind(". "), truncated.rfind(".\n"))
                if last_dot > max_chars // 2:
                    raw_response = truncated[: last_dot + 1].strip()
                else:
                    raw_response = truncated.rsplit(" ", 1)[0].rstrip(".,;:-") + "..."

            interpretation = "Sintesi e analisi diagnostica generata con successo dall'IA."
            action_taken = (
                "Analisi e raccomandazioni IA incorporate nel corpo del report di notifica."
            )

        except Exception as exc:
            is_error = True
            logger.warning(
                "ai_report_analysis_failed",
                event_type=event_type,
                entity_id=entity_id,
                error=str(exc),
            )
            raw_response = f"Errore durante l'interrogazione dell'IA: {exc}"
            interpretation = f"Interrogazione IA per reportistica fallita ({exc}). Notifica inviata senza analisi IA."
            action_taken = "Notifica inviata con il template standard senza sezione IA."

        # MANDATORY LOGGING (4 points):
        # 1. Che cosa gli è stato inviato (system + user prompt)
        # 2. Che cosa ha risposto (raw_response)
        # 3. Come embervault ha interpretato la risposta (interpretation)
        # 4. Che azione è stata intrapresa (action_taken)

        # Structured python log
        logger.info(
            "ai_report_analysis_generated" if not is_error else "ai_report_analysis_failed_log",
            event_type=event_type,
            entity_id=entity_id,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            raw_response=raw_response,
            interpretation=interpretation,
            action_taken=action_taken,
        )

        # AuditLog entry in database
        try:
            session.add(
                AuditLog(
                    action="ai.report_analysis",
                    actor_user_id=actor_user_id,
                    entity_type="notification_report",
                    entity_id=entity_id or event_type,
                    details={
                        "status": "error" if is_error else "success",
                        "event_type": event_type,
                        "point_1_prompt": {
                            "system_prompt": system_prompt,
                            "user_prompt": user_prompt,
                        },
                        "point_2_raw_response": raw_response,
                        "point_3_interpretation": interpretation,
                        "point_4_action_taken": action_taken,
                    },
                )
            )
        except Exception as audit_exc:
            logger.warning("failed_to_record_ai_report_audit_log", error=str(audit_exc))

        if is_error:
            return None
        return raw_response
