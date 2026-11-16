"""Notification message formatting for Email and Telegram in Plain Text, HTML, and Markdown."""

from __future__ import annotations

import html
import re
from typing import Any

import apprise

from embervault_common.notifications.contracts import NotificationEventType, TelegramFormat


def format_bytes(num_bytes: int) -> str:
    """Format bytes into human-readable units."""
    if num_bytes < 1024:
        return f"{num_bytes} B"
    for unit in ["KB", "MB", "GB", "TB"]:
        num_bytes_float = num_bytes / 1024.0
        if num_bytes_float < 1024.0:
            return f"{num_bytes_float:.1f} {unit}"
        num_bytes = int(num_bytes_float)
    return f"{num_bytes_float:.1f} PB"


def format_duration(seconds: float | int | None) -> str:
    """Format duration in seconds into a human-readable string."""
    if seconds is None or seconds < 0:
        return "N/D"
    sec_int = int(seconds)
    if sec_int < 60:
        return f"{sec_int}s"
    minutes = sec_int // 60
    remaining_secs = sec_int % 60
    if minutes < 60:
        return f"{minutes}m {remaining_secs:02d}s"
    hours = minutes // 60
    remaining_mins = minutes % 60
    return f"{hours}h {remaining_mins:02d}m {remaining_secs:02d}s"


def escape_telegram_markdown(text: str) -> str:
    """Escape Telegram Markdown special characters in plain user strings."""
    # Characters reserved in Telegram Markdown: _ * [ ] ( ) ~ ` > # + - = | { } . !
    escape_chars = r"_*[]()~`>#+-=|{}.!"
    return re.sub(f"([{re.escape(escape_chars)}])", r"\\\1", str(text))


def escape_telegram_html(text: str) -> str:
    """Escape HTML special characters for safe inclusion in Telegram HTML messages."""
    return html.escape(str(text), quote=True)


class NotificationFormatter:
    """Builds formatted notification titles and message bodies tailored to the target channel format."""

    @classmethod
    def format(
        cls,
        event_type: NotificationEventType | str,
        context: dict[str, Any],
        telegram_format: TelegramFormat | str = TelegramFormat.HTML,
    ) -> tuple[str, str, apprise.NotifyFormat]:
        """Format a notification into (title, body, notify_format).

        Args:
            event_type: The notification event (job_run_completed, proxy_offline, test).
            context: Dictionary containing dynamic event metadata.
            telegram_format: Telegram formatting mode ('text', 'html', 'markdown').

        Returns:
            A tuple of (title, body, apprise_notify_format).
        """
        fmt = (
            TelegramFormat(telegram_format) if isinstance(telegram_format, str) else telegram_format
        )
        ev = NotificationEventType(event_type) if isinstance(event_type, str) else event_type

        if ev == NotificationEventType.JOB_RUN_COMPLETED:
            return cls._format_job_run_completed(context, fmt)
        elif ev == NotificationEventType.JOB_POLICY_EXECUTED:
            return cls._format_job_policy_executed(context, fmt)
        elif ev == NotificationEventType.PROXY_OFFLINE:
            return cls._format_proxy_offline(context, fmt)
        elif ev == NotificationEventType.PROXY_CERT_EXPIRING:
            return cls._format_proxy_cert_expiring(context, fmt)
        elif ev == NotificationEventType.PROXY_UNTRUSTED:
            return cls._format_proxy_untrusted(context, fmt)
        elif ev == NotificationEventType.HOOK_FAILED:
            return cls._format_hook_failed(context, fmt)
        elif ev == NotificationEventType.RCLONE_UPDATE_AVAILABLE:
            return cls._format_rclone_update_available(context, fmt)
        return cls._format_test_notification(context, fmt)

    @classmethod
    def _format_job_run_completed(
        cls, context: dict[str, Any], fmt: TelegramFormat
    ) -> tuple[str, str, apprise.NotifyFormat]:
        job_name = context.get("job_name", "Job")
        status = context.get("status", "unknown").lower()
        run_id = str(context.get("run_id", ""))
        files_transferred = context.get("files_transferred", 0)
        bytes_transferred = context.get("bytes_transferred", 0)
        duration_s = context.get("duration_s")
        tasks_succeeded = context.get("tasks_succeeded", 0)
        tasks_failed = context.get("tasks_failed", 0)
        error_msg = context.get("error_message")
        tasks_detail = context.get("tasks_detail") or []

        # If run-level error_message is missing or generic, build diagnostic summary from failed tasks
        if not error_msg and tasks_failed > 0 and tasks_detail:
            failed_summaries: list[str] = []
            for t in tasks_detail:
                if t.get("status") in ("failed", "partially_failed") or t.get("last_error_code"):
                    seq = t.get("seq", 0)
                    scope = t.get("subpath") or t.get("scope") or "root"
                    err = (
                        t.get("last_error_code")
                        or t.get("last_error_class")
                        or "Errore sconosciuto"
                    )
                    err_logs = t.get("error_logs") or []
                    log_detail = f"\n   Log: {err_logs[-1]}" if err_logs else ""
                    ai_eval = t.get("ai_evaluation")
                    ai_detail = (
                        f"\n   AI: {ai_eval.get('reason') or ai_eval.get('interpretation')}"
                        if ai_eval
                        else ""
                    )
                    failed_summaries.append(f"Task #{seq} ({scope}): {err}{log_detail}{ai_detail}")
            if failed_summaries:
                error_msg = "\n".join(failed_summaries)

        status_meta = {
            "succeeded": ("Completato", "✅ Successo", "✅"),
            "failed": ("Fallito", "❌ Fallito", "❌"),
            "partially_failed": ("Parzialmente Fallito", "⚠️ Parzialmente Fallito", "⚠️"),
            "cancelled": ("Annullato", "⏹️ Annullato", "⏹️"),
        }.get(status, (status.capitalize(), status.capitalize(), "ℹ️"))

        status_label, status_badge, status_icon = status_meta
        title = f"[EmberVault] {status_icon} Job '{job_name}' {status_label}"
        bytes_str = format_bytes(bytes_transferred)
        dur_str = format_duration(duration_s)

        if fmt == TelegramFormat.HTML:
            safe_name = escape_telegram_html(job_name)
            body = (
                f"<b>Job:</b> {safe_name}<br/>"
                f"<b>Stato:</b> {status_badge}<br/>"
                f"<b>File trasferiti:</b> {files_transferred}<br/>"
                f"<b>Volume:</b> {bytes_str}<br/>"
                f"<b>Durata:</b> {dur_str}<br/>"
                f"<b>Task riusciti:</b> {tasks_succeeded} | <b>Falliti:</b> {tasks_failed}<br/>"
                f"<b>Run ID:</b> <code>{run_id}</code>"
            )
            if error_msg:
                safe_err = escape_telegram_html(error_msg[:1000])
                body += f"<br/><br/><b>Dettaglio Errore:</b><br/><pre>{safe_err}</pre>"
            ai_analysis = context.get("ai_analysis")
            if ai_analysis:
                safe_ai = escape_telegram_html(ai_analysis)
                body += f"<br/><br/><b>🤖 Analisi & Raccomandazioni IA:</b><br/>{safe_ai}"
            return title, body, apprise.NotifyFormat.HTML

        elif fmt == TelegramFormat.MARKDOWN:
            esc_name = escape_telegram_markdown(job_name)
            esc_run_id = escape_telegram_markdown(run_id)
            body = (
                f"*Job:* {esc_name}\n"
                f"*Stato:* {status_badge}\n"
                f"*File trasferiti:* {files_transferred}\n"
                f"*Volume:* {bytes_str}\n"
                f"*Durata:* {dur_str}\n"
                f"*Task riusciti:* {tasks_succeeded} \\| *Falliti:* {tasks_failed}\n"
                f"*Run ID:* `{esc_run_id}`"
            )
            if error_msg:
                esc_err = error_msg.replace("`", r"\`")[:1000]
                body += f"\n\n*Dettaglio Errore:*\n```{esc_err}```"
            ai_analysis = context.get("ai_analysis")
            if ai_analysis:
                esc_ai = ai_analysis.replace("`", r"\`")
                body += f"\n\n*🤖 Analisi & Raccomandazioni IA:*\n{esc_ai}"
            return title, body, apprise.NotifyFormat.MARKDOWN

        else:  # TelegramFormat.TEXT
            body = (
                f"Job: {job_name}\n"
                f"Stato: {status_label}\n"
                f"File trasferiti: {files_transferred}\n"
                f"Volume: {bytes_str}\n"
                f"Durata: {dur_str}\n"
                f"Task riusciti: {tasks_succeeded} | Falliti: {tasks_failed}\n"
                f"Run ID: {run_id}"
            )
            if error_msg:
                body += f"\n\nDettaglio Errore:\n{error_msg[:1000]}"
            ai_analysis = context.get("ai_analysis")
            if ai_analysis:
                body += f"\n\n[Analisi & Raccomandazioni IA]\n{ai_analysis}"
            return title, body, apprise.NotifyFormat.TEXT

    @classmethod
    def _format_proxy_offline(
        cls, context: dict[str, Any], fmt: TelegramFormat
    ) -> tuple[str, str, apprise.NotifyFormat]:
        proxy_name = context.get("proxy_name", "Proxy")
        host = context.get("host", "unknown")
        port = context.get("port", 8443)
        failures = context.get("consecutive_failures", 0)
        reason = context.get("reason", "Heartbeat timeout")
        last_seen = context.get("last_seen_at", "N/D")
        is_incompatible = bool(context.get("is_incompatible", False))
        detected_version = context.get("detected_version")
        min_version = context.get("min_version")

        if is_incompatible:
            title = f"[EmberVault] ⚠️ Allerta: Proxy '{proxy_name}' Versione Incompatibile"
            status_label = "⚠️ Versione Incompatibile (Offline)"
            status_text = "Versione Incompatibile (Offline)"
        else:
            title = f"[EmberVault] 🔴 Allerta: Proxy '{proxy_name}' Offline"
            status_label = "🔴 Offline"
            status_text = "Offline"

        ai_analysis = context.get("ai_analysis")
        if fmt == TelegramFormat.HTML:
            safe_name = escape_telegram_html(proxy_name)
            safe_host = escape_telegram_html(f"{host}:{port}")
            safe_reason = escape_telegram_html(reason)
            version_line = ""
            if detected_version and min_version:
                version_line = f"<b>Versione container:</b> <code>v{escape_telegram_html(str(detected_version))}</code> (richiesta &gt;= <code>v{escape_telegram_html(str(min_version))}</code>)<br/>"
            body = (
                f"<b>Proxy:</b> {safe_name}<br/>"
                f"<b>Stato:</b> {status_label}<br/>"
                f"<b>Endpoint:</b> <code>{safe_host}</code><br/>"
                f"{version_line}"
                f"<b>Sondaggi falliti:</b> {failures}<br/>"
                f"<b>Ultimo contatto:</b> {last_seen}<br/>"
                f"<b>Motivo:</b> <pre>{safe_reason}</pre>"
            )
            if ai_analysis:
                safe_ai = escape_telegram_html(ai_analysis)
                body += f"<br/><br/><b>🤖 Analisi & Raccomandazioni IA:</b><br/>{safe_ai}"
            return title, body, apprise.NotifyFormat.HTML

        elif fmt == TelegramFormat.MARKDOWN:
            esc_name = escape_telegram_markdown(proxy_name)
            esc_host = escape_telegram_markdown(f"{host}:{port}")
            version_line = ""
            if detected_version and min_version:
                version_line = f"*Versione container:* `v{escape_telegram_markdown(str(detected_version))}` \\(richiesta >= `v{escape_telegram_markdown(str(min_version))}`\\)\n"
            body = (
                f"*Proxy:* {esc_name}\n"
                f"*Stato:* {status_label}\n"
                f"*Endpoint:* `{esc_host}`\n"
                f"{version_line}"
                f"*Sondaggi falliti:* {failures}\n"
                f"*Ultimo contatto:* {last_seen}\n"
                f"*Motivo:*\n```{reason}```"
            )
            if ai_analysis:
                esc_ai = ai_analysis.replace("`", r"\`")
                body += f"\n\n*🤖 Analisi & Raccomandazioni IA:*\n{esc_ai}"
            return title, body, apprise.NotifyFormat.MARKDOWN

        else:  # TelegramFormat.TEXT
            version_line = ""
            if detected_version and min_version:
                version_line = (
                    f"Versione container: v{detected_version} (richiesta >= v{min_version})\n"
                )
            body = (
                f"Proxy: {proxy_name}\n"
                f"Stato: {status_text}\n"
                f"Endpoint: {host}:{port}\n"
                f"{version_line}"
                f"Sondaggi falliti: {failures}\n"
                f"Ultimo contatto: {last_seen}\n"
                f"Motivo: {reason}"
            )
            if ai_analysis:
                body += f"\n\n[Analisi & Raccomandazioni IA]\n{ai_analysis}"
            return title, body, apprise.NotifyFormat.TEXT

    @classmethod
    def _format_proxy_cert_expiring(
        cls, context: dict[str, Any], fmt: TelegramFormat
    ) -> tuple[str, str, apprise.NotifyFormat]:
        proxy_name = context.get("proxy_name", "Proxy")
        host = context.get("host", "unknown")
        port = context.get("port", 8443)
        days_remaining = context.get("days_remaining", 0)
        cert_expires_at = context.get("cert_expires_at", "N/D")

        title = f"[EmberVault] ⚠️ Certificato TLS Proxy in Scadenza: '{proxy_name}'"
        status_label = f"⚠️ In Scadenza ({days_remaining} giorni rimasti)"

        if fmt == TelegramFormat.HTML:
            safe_name = escape_telegram_html(proxy_name)
            safe_host = escape_telegram_html(f"{host}:{port}")
            body = (
                f"<b>Proxy:</b> {safe_name}<br/>"
                f"<b>Stato Certificato:</b> {status_label}<br/>"
                f"<b>Endpoint:</b> <code>{safe_host}</code><br/>"
                f"<b>Data Scadenza (UTC):</b> <code>{escape_telegram_html(str(cert_expires_at))}</code><br/>"
                f"<b>Giorni rimanenti:</b> <b>{days_remaining}</b><br/><br/>"
                f"<i>È possibile rinnovare anticipatamente il certificato direttamente dalla console web nella lista dei Proxy.</i>"
            )
            return title, body, apprise.NotifyFormat.HTML

        elif fmt == TelegramFormat.MARKDOWN:
            esc_name = escape_telegram_markdown(proxy_name)
            esc_host = escape_telegram_markdown(f"{host}:{port}")
            body = (
                f"*Proxy:* {esc_name}\n"
                f"*Stato Certificato:* {status_label}\n"
                f"*Endpoint:* `{esc_host}`\n"
                f"*Data Scadenza (UTC):* `{cert_expires_at}`\n"
                f"*Giorni rimanenti:* *{days_remaining}*\n\n"
                f"_È possibile rinnovare anticipatamente il certificato direttamente dalla console web nella lista dei Proxy._"
            )
            return title, body, apprise.NotifyFormat.MARKDOWN

        else:  # TelegramFormat.TEXT
            body = (
                f"Proxy: {proxy_name}\n"
                f"Stato Certificato: In Scadenza ({days_remaining} giorni rimasti)\n"
                f"Endpoint: {host}:{port}\n"
                f"Data Scadenza (UTC): {cert_expires_at}\n"
                f"Giorni rimanenti: {days_remaining}\n\n"
                f"È possibile rinnovare anticipatamente il certificato direttamente dalla console web nella lista dei Proxy."
            )
            return title, body, apprise.NotifyFormat.TEXT

    @classmethod
    def _format_proxy_untrusted(
        cls, context: dict[str, Any], fmt: TelegramFormat
    ) -> tuple[str, str, apprise.NotifyFormat]:
        proxy_name = context.get("proxy_name", "Proxy")
        host = context.get("host", "unknown")
        port = context.get("port", 8443)
        reason = context.get("reason", "TLS fingerprint mismatch")

        title = f"[EmberVault] 🔴 Allerta Sicurezza: Proxy Non Affidabile '{proxy_name}'"
        status_label = "🔴 Untrusted (Fingerprint Mismatch)"

        if fmt == TelegramFormat.HTML:
            safe_name = escape_telegram_html(proxy_name)
            safe_host = escape_telegram_html(f"{host}:{port}")
            safe_reason = escape_telegram_html(reason)
            body = (
                f"<b>Proxy:</b> {safe_name}<br/>"
                f"<b>Stato:</b> {status_label}<br/>"
                f"<b>Endpoint:</b> <code>{safe_host}</code><br/>"
                f"<b>Dettaglio Errore:</b> <pre>{safe_reason}</pre><br/>"
                f"<b>Azione Richiesta:</b> Il certificato TLS del nodo è variato. Ristabilire la fiducia confermando il nuovo fingerprint nella console web."
            )
            return title, body, apprise.NotifyFormat.HTML

        elif fmt == TelegramFormat.MARKDOWN:
            esc_name = escape_telegram_markdown(proxy_name)
            esc_host = escape_telegram_markdown(f"{host}:{port}")
            body = (
                f"*Proxy:* {esc_name}\n"
                f"*Stato:* {status_label}\n"
                f"*Endpoint:* `{esc_host}`\n"
                f"*Dettaglio Errore:*\n```{reason}```\n\n"
                f"*Azione Richiesta:* Il certificato TLS del nodo è variato. Ristabilire la fiducia confermando il nuovo fingerprint nella console web."
            )
            return title, body, apprise.NotifyFormat.MARKDOWN

        else:  # TelegramFormat.TEXT
            body = (
                f"Proxy: {proxy_name}\n"
                f"Stato: Untrusted (Fingerprint Mismatch)\n"
                f"Endpoint: {host}:{port}\n"
                f"Dettaglio Errore: {reason}\n\n"
                f"Azione Richiesta: Il certificato TLS del nodo è variato. Ristabilire la fiducia confermando il nuovo fingerprint nella console web."
            )
            return title, body, apprise.NotifyFormat.TEXT

    @classmethod
    def _format_test_notification(
        cls, context: dict[str, Any], fmt: TelegramFormat
    ) -> tuple[str, str, apprise.NotifyFormat]:
        channel_name = context.get("channel_name", "Test Channel")
        title = "[EmberVault] 🔔 Test Connessione Notifiche"

        if fmt == TelegramFormat.HTML:
            safe_name = escape_telegram_html(channel_name)
            body = (
                f"<b>Test Notifica Riuscito!</b><br/>"
                f"Il canale <code>{safe_name}</code> è configurato correttamente.<br/>"
                f"EmberVault invierà qui le notifiche sui job e sullo stato dell'infrastruttura."
            )
            return title, body, apprise.NotifyFormat.HTML

        elif fmt == TelegramFormat.MARKDOWN:
            esc_name = escape_telegram_markdown(channel_name)
            body = (
                f"*Test Notifica Riuscito!*\n"
                f"Il canale `{esc_name}` è configurato correttamente\\.\n"
                f"EmberVault invierà qui le notifiche sui job e sullo stato dell'infrastruttura\\."
            )
            return title, body, apprise.NotifyFormat.MARKDOWN

        else:  # TelegramFormat.TEXT
            body = (
                f"Test Notifica Riuscito!\n"
                f"Il canale '{channel_name}' è configurato correttamente.\n"
                f"EmberVault invierà qui le notifiche sui job e sullo stato dell'infrastruttura."
            )
            return title, body, apprise.NotifyFormat.TEXT

    @classmethod
    def _format_hook_failed(
        cls, context: dict[str, Any], fmt: TelegramFormat
    ) -> tuple[str, str, apprise.NotifyFormat]:
        job_name = context.get("job_name", "Job")
        run_id = str(context.get("run_id", ""))
        hook_type = context.get("hook_type", "pre_run")
        status = str(context.get("status", "failed"))
        exit_code = context.get("exit_code")
        duration_ms = context.get("duration_ms")
        output = context.get("output")

        hook_label = "Script Pre-Run" if hook_type == "pre_run" else "Script Post-Run"
        title = f"[EmberVault] ⚠️ Fallimento {hook_label} - Job '{job_name}'"
        dur_str = f"{duration_ms:.1f} ms" if duration_ms is not None else "N/D"
        exit_str = str(exit_code) if exit_code is not None else "N/D"

        if fmt == TelegramFormat.HTML:
            safe_name = escape_telegram_html(job_name)
            safe_hook = escape_telegram_html(hook_label)
            safe_status = escape_telegram_html(status)
            body = (
                f"<b>Job:</b> {safe_name}<br/>"
                f"<b>Evento:</b> ⚠️ Fallimento {safe_hook}<br/>"
                f"<b>Stato:</b> {safe_status}<br/>"
                f"<b>Codice di uscita:</b> <code>{exit_str}</code><br/>"
                f"<b>Durata:</b> {dur_str}<br/>"
                f"<b>Run ID:</b> <code>{run_id}</code>"
            )
            if output:
                safe_out = escape_telegram_html(output[:1000])
                body += f"<br/><br/><b>Output / Errore:</b><br/><pre>{safe_out}</pre>"
            return title, body, apprise.NotifyFormat.HTML

        elif fmt == TelegramFormat.MARKDOWN:
            esc_name = escape_telegram_markdown(job_name)
            esc_hook = escape_telegram_markdown(hook_label)
            esc_status = escape_telegram_markdown(status)
            esc_run_id = escape_telegram_markdown(run_id)
            esc_exit = escape_telegram_markdown(exit_str)
            esc_dur = escape_telegram_markdown(dur_str)
            body = (
                f"*Job:* {esc_name}\n"
                f"*Evento:* ⚠️ Fallimento {esc_hook}\n"
                f"*Stato:* {esc_status}\n"
                f"*Codice di uscita:* `{esc_exit}`\n"
                f"*Durata:* {esc_dur}\n"
                f"*Run ID:* `{esc_run_id}`"
            )
            if output:
                esc_out = output.replace("`", r"\`")[:1000]
                body += f"\n\n*Output / Errore:*\n```{esc_out}```"
            return title, body, apprise.NotifyFormat.MARKDOWN

        else:  # TelegramFormat.TEXT
            body = (
                f"Job: {job_name}\n"
                f"Evento: Fallimento {hook_label}\n"
                f"Stato: {status}\n"
                f"Codice di uscita: {exit_str}\n"
                f"Durata: {dur_str}\n"
                f"Run ID: {run_id}"
            )
            if output:
                body += f"\n\nOutput / Errore:\n{output[:1000]}"
            return title, body, apprise.NotifyFormat.TEXT

    @classmethod
    def _format_rclone_update_available(
        cls, context: dict[str, Any], fmt: TelegramFormat
    ) -> tuple[str, str, apprise.NotifyFormat]:
        proxies = context.get("proxies") or []
        if isinstance(proxies, str):
            proxies_str = proxies
        else:
            proxies_str = ", ".join(str(p) for p in proxies)
        latest_version = str(context.get("latest_version") or "").lstrip("vV")
        ver_display = f"v{latest_version}" if latest_version else "più recente"

        title = "[EmberVault] Aggiornamenti RClone disponibili"

        if fmt == TelegramFormat.HTML:
            esc_proxies = escape_telegram_html(proxies_str)
            esc_ver = escape_telegram_html(ver_display)
            body = (
                f"<b>Aggiornamenti di RClone disponibili sui seguenti proxy:</b>\n"
                f"{esc_proxies}\n\n"
                f"Nuova versione disponibile: <code>{esc_ver}</code>"
            )
            return title, body, apprise.NotifyFormat.HTML

        elif fmt == TelegramFormat.MARKDOWN:
            esc_proxies = escape_telegram_markdown(proxies_str)
            body = (
                f"*Aggiornamenti di RClone disponibili sui seguenti proxy:*\n"
                f"{esc_proxies}\n\n"
                f"Nuova versione disponibile: `{ver_display}`"
            )
            return title, body, apprise.NotifyFormat.MARKDOWN

        else:  # TelegramFormat.TEXT
            body = (
                f"Aggiornamenti di RClone disponibili sui seguenti proxy: {proxies_str}\n"
                f"Nuova versione disponibile: {ver_display}"
            )
            return title, body, apprise.NotifyFormat.TEXT

    @classmethod
    def _format_job_policy_executed(
        cls, context: dict[str, Any], fmt: TelegramFormat
    ) -> tuple[str, str, apprise.NotifyFormat]:
        job_name = context.get("job_name", "Job")
        policy_type = context.get("policy_type", "policy")
        policy_label = context.get("policy_label") or policy_type
        policy_value = str(context.get("policy_value", "")).upper()
        message = context.get("message", "")
        run_id = context.get("run_id")

        title = f"[EmberVault] 🛡️ Policy '{policy_label}' eseguita per il Job '{job_name}'"

        if fmt == TelegramFormat.HTML:
            safe_name = escape_telegram_html(job_name)
            safe_policy = escape_telegram_html(policy_label)
            safe_val = escape_telegram_html(policy_value)
            safe_msg = escape_telegram_html(message)
            run_line = (
                f"<b>Run ID:</b> <code>{escape_telegram_html(str(run_id))}</code><br/>"
                if run_id
                else ""
            )
            body = (
                f"<b>Job:</b> {safe_name}<br/>"
                f"<b>Policy:</b> {safe_policy}<br/>"
                f"<b>Azione configurata:</b> <code>{safe_val}</code><br/>"
                f"{run_line}"
                f"<br/><b>Dettaglio:</b><br/>{safe_msg}"
            )
            return title, body, apprise.NotifyFormat.HTML

        elif fmt == TelegramFormat.MARKDOWN:
            esc_name = escape_telegram_markdown(job_name)
            esc_policy = escape_telegram_markdown(policy_label)
            esc_val = escape_telegram_markdown(policy_value)
            esc_msg = message.replace("`", r"\`")
            run_line = (
                f"*Run ID:* `{escape_telegram_markdown(str(run_id))}`\n" if run_id else ""
            )
            body = (
                f"*Job:* {esc_name}\n"
                f"*Policy:* {esc_policy}\n"
                f"*Azione configurata:* `{esc_val}`\n"
                f"{run_line}\n"
                f"*Dettaglio:*\n{esc_msg}"
            )
            return title, body, apprise.NotifyFormat.MARKDOWN

        else:  # TelegramFormat.TEXT
            run_line = f"Run ID: {run_id}\n" if run_id else ""
            body = (
                f"Job: {job_name}\n"
                f"Policy: {policy_label}\n"
                f"Azione configurata: {policy_value}\n"
                f"{run_line}\n"
                f"Dettaglio:\n{message}"
            )
            return title, body, apprise.NotifyFormat.TEXT

    @classmethod
    def _format_generic(
        cls, event_type: str, context: dict[str, Any], fmt: TelegramFormat
    ) -> tuple[str, str, apprise.NotifyFormat]:
        title = f"[EmberVault] Evento: {event_type}"
        lines = [f"{k}: {v}" for k, v in context.items()]
        body = "\n".join(lines)
        if fmt == TelegramFormat.HTML:
            return title, f"<pre>{escape_telegram_html(body)}</pre>", apprise.NotifyFormat.HTML
        elif fmt == TelegramFormat.MARKDOWN:
            return title, f"```{body}```", apprise.NotifyFormat.MARKDOWN
        return title, body, apprise.NotifyFormat.TEXT


def split_notification_body(
    body: str,
    max_chunk_size: int = 4000,
    body_format: apprise.NotifyFormat | str = apprise.NotifyFormat.HTML,
) -> list[str]:
    """Split a formatted notification body into chunks not exceeding max_chunk_size.

    Preserves balanced HTML tags and Markdown code fences across splits.
    """
    if not body:
        return [""]
    if max_chunk_size <= 0 or len(body) <= max_chunk_size:
        return [body]

    fmt_str = str(body_format).lower()
    is_html = "html" in fmt_str
    is_markdown = "markdown" in fmt_str

    tag_pattern = re.compile(r"<\s*(/?)\s*([a-zA-Z0-9]+)(?:\s+[^>]*)?>")
    void_tags = {"br", "hr", "img", "input", "meta", "link"}

    html_separators = ["<br/><br/>", "<br/>", "\n\n", "\n", ". ", " "]
    plain_separators = ["\n\n", "\n", ". ", " "]
    separators = html_separators if is_html else plain_separators

    chunks: list[str] = []
    remaining = body
    active_html_tags: list[str] = []

    while remaining:
        if len(remaining) <= max_chunk_size:
            chunks.append(remaining)
            break

        search_window = remaining[:max_chunk_size]
        split_pos = -1

        for sep in separators:
            pos = search_window.rfind(sep)
            if pos > max_chunk_size // 4:
                split_pos = pos + len(sep)
                break

        if split_pos == -1:
            split_pos = max_chunk_size

        chunk = remaining[:split_pos].rstrip()
        remaining = remaining[split_pos:].lstrip()

        if is_html:
            current_tags = list(active_html_tags)
            for match in tag_pattern.finditer(chunk):
                is_close, tag_name = match.group(1), match.group(2).lower()
                if tag_name in void_tags:
                    continue
                if is_close:
                    if tag_name in current_tags:
                        for idx in range(len(current_tags) - 1, -1, -1):
                            if current_tags[idx] == tag_name:
                                current_tags.pop(idx)
                                break
                else:
                    current_tags.append(tag_name)

            if current_tags:
                close_suffix = "".join(f"</{t}>" for t in reversed(current_tags))
                chunk += close_suffix

            chunks.append(chunk)

            if current_tags and remaining:
                open_prefix = "".join(f"<{t}>" for t in current_tags)
                remaining = open_prefix + remaining
                active_html_tags = current_tags
            else:
                active_html_tags = []

        elif is_markdown:
            fence_count = chunk.count("```")
            if fence_count % 2 == 1:
                chunk += "\n```"
                if remaining:
                    remaining = "```\n" + remaining
            chunks.append(chunk)

        else:
            chunks.append(chunk)

    return chunks
