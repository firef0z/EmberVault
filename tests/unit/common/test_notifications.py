"""Unit tests for notification URL builders, masking, formatters, and AppriseNotifier."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from embervault_common.notifications.apprise_notifier import (
    AppriseNotifier,
    build_email_url,
    build_telegram_url,
    mask_apprise_url,
    validate_apprise_url,
)
from embervault_common.notifications.contracts import (
    NotificationEventType,
    TelegramFormat,
)
from embervault_common.notifications.formatter import (
    NotificationFormatter,
    format_bytes,
    format_duration,
)


class TestAppriseUrlValidationAndMasking:
    def test_validate_valid_urls(self) -> None:
        valid_urls = [
            "tgram://123456789:AAHq_Abc123def456ghi789jkl/987654321",
            "mailto://user:pass@smtp.example.com:587",
            "mailtos://user:pass@smtp.example.com:465",
            "discord://123456789012345678/abcdefghijklmnopqrstuvwxyz_0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        ]
        for url in valid_urls:
            is_valid, err = validate_apprise_url(url)
            assert is_valid is True, f"Expected {url} to be valid, got err: {err}"
            assert err is None

    def test_validate_empty_or_whitespace_url(self) -> None:
        is_valid, err = validate_apprise_url("")
        assert is_valid is False
        assert err is not None
        assert "non può essere vuoto" in err

        is_valid, err = validate_apprise_url("   ")
        assert is_valid is False
        assert err is not None

    def test_validate_unsupported_or_invalid_scheme(self) -> None:
        is_valid, err = validate_apprise_url("notarealscheme://something")
        assert is_valid is False
        assert err is not None
        assert "non supportati" in err

    def test_mask_telegram_url(self) -> None:
        raw = "tgram://123456789:ABC_SECRET_TOKEN/987654321"
        masked = mask_apprise_url(raw)
        assert "ABC_SECRET_TOKEN" not in masked
        assert "••••••••" in masked
        assert "987654321" in masked

    def test_mask_email_url(self) -> None:
        raw = "mailto://backup_user:SuperSecretPassword123@smtp.example.com:587"
        masked = mask_apprise_url(raw)
        assert "SuperSecretPassword123" not in masked
        assert "backup_user:••••••••@smtp.example.com:587" in masked

    def test_mask_generic_url_with_credentials(self) -> None:
        raw = "https://admin:mysecrettoken@webhook.internal/notify"
        masked = mask_apprise_url(raw)
        assert "mysecrettoken" not in masked
        assert "••••••••" in masked


class TestUrlBuilders:
    def test_build_telegram_url(self) -> None:
        url = build_telegram_url(
            bot_token="123456789:ABCdef",
            chat_id="-100123456789",
            format_mode="html",
        )
        assert url == "tgram://123456789:ABCdef/-100123456789/?format=html"

        # Stripping leading @ or formatting
        url_text = build_telegram_url(
            bot_token="bot123456:secret",
            chat_id="@my_channel",
            format_mode="text",
        )
        assert url_text == "tgram://bot123456:secret/@my_channel/?format=text"

    def test_build_email_url(self) -> None:
        # Standard STARTTLS SMTP
        url = build_email_url(
            host="smtp.gmail.com",
            port=587,
            user="alerts@example.com",
            password="app-password",
            from_addr="alerts@example.com",
            to_addrs="admin@example.com,ops@example.com",
            secure=False,
        )
        assert url.startswith("mailto://alerts%40example.com:app-password@smtp.gmail.com:587")
        assert "from=alerts%40example.com" in url
        assert "to=admin%40example.com%2Cops%40example.com" in url

        # Direct SSL/TLS SMTP (mailtos)
        url_ssl = build_email_url(
            host="smtp.example.com",
            port=465,
            secure=True,
        )
        assert url_ssl.startswith("mailtos://smtp.example.com:465")


class TestNotificationFormatter:
    def test_format_bytes_and_duration_helpers(self) -> None:
        assert format_bytes(500) == "500 B"
        assert format_bytes(1024) == "1.0 KB"
        assert format_bytes(1024 * 1024 * 5) == "5.0 MB"
        assert format_bytes(1024 * 1024 * 1024 * 2) == "2.0 GB"

        assert format_duration(None) == "N/D"
        assert format_duration(45) == "45s"
        assert format_duration(125) == "2m 05s"
        assert format_duration(3665) == "1h 01m 05s"

    def test_job_completed_plain_text(self) -> None:
        context = {
            "job_name": "Daily Backup",
            "status": "succeeded",
            "run_id": "c1f7b9c2-28df-419b-b2ad-2ffc4155a001",
            "files_transferred": 142,
            "bytes_transferred": 10485760,
            "duration_s": 72,
            "tasks_succeeded": 3,
            "tasks_failed": 0,
        }
        title, body, fmt = NotificationFormatter.format(
            NotificationEventType.JOB_RUN_COMPLETED,
            context,
            TelegramFormat.TEXT,
        )
        assert "Daily Backup" in title
        assert "Completato" in title
        assert "Job: Daily Backup" in body
        assert "Stato: Completato" in body
        assert "File trasferiti: 142" in body
        assert "10.0 MB" in body
        assert "1m 12s" in body
        assert "<b>" not in body
        assert "*" not in body

    def test_job_completed_telegram_html(self) -> None:
        context = {
            "job_name": "Backup <Prod> & Dev",
            "status": "failed",
            "run_id": "abc-123",
            "files_transferred": 5,
            "bytes_transferred": 2048,
            "duration_s": 10,
            "tasks_succeeded": 1,
            "tasks_failed": 1,
            "error_message": "Connection timed out with proxy <edge-1>",
        }
        title, body, fmt = NotificationFormatter.format(
            NotificationEventType.JOB_RUN_COMPLETED,
            context,
            TelegramFormat.HTML,
        )
        assert "Fallito" in title
        # HTML tags present
        assert "<b>Job:</b>" in body
        # Sensitive chars escaped
        assert "&lt;Prod&gt; &amp; Dev" in body
        assert "<pre>Connection timed out with proxy &lt;edge-1&gt;</pre>" in body

    def test_job_completed_telegram_markdown(self) -> None:
        context = {
            "job_name": "Prod_Backup (Hourly)",
            "status": "succeeded",
            "run_id": "abc-123",
            "files_transferred": 10,
            "bytes_transferred": 1024,
            "duration_s": 5,
            "tasks_succeeded": 1,
            "tasks_failed": 0,
        }
        title, body, fmt = NotificationFormatter.format(
            NotificationEventType.JOB_RUN_COMPLETED,
            context,
            TelegramFormat.MARKDOWN,
        )
        assert "*Job:*" in body
        # Markdown special chars like _ and () should be escaped
        assert "Prod\\_Backup" in body

    def test_proxy_offline_formatting(self) -> None:
        context = {
            "proxy_name": "proxy-milan-01",
            "proxy_id": "proxy-uuid",
            "last_seen": "2026-10-21 09:30:00 UTC",
            "host": "192.168.1.100",
            "port": 50051,
            "consecutive_failures": 3,
            "reason": "Connection refused",
        }
        title, body, fmt = NotificationFormatter.format(
            NotificationEventType.PROXY_OFFLINE,
            context,
            TelegramFormat.HTML,
        )
        assert "proxy-milan-01" in title
        assert "Offline" in title
        assert "<b>Proxy:</b> proxy-milan-01" in body
        assert "192.168.1.100:50051" in body

    def test_test_notification_formatting(self) -> None:
        context = {
            "channel_name": "Telegram Admin",
            "test_user": "administrator",
            "timestamp": "2026-10-21 10:00:00 UTC",
        }
        title, body, fmt = NotificationFormatter.format(
            NotificationEventType.TEST,
            context,
            TelegramFormat.TEXT,
        )
        assert "Test Connessione Notifiche" in title

    def test_hook_failed_formatting(self) -> None:
        context = {
            "job_name": "Backup-Daily",
            "run_id": "d093b451-9f93-4e4b-9759-4b6e51111111",
            "hook_type": "pre_run",
            "status": "failed",
            "exit_code": 1,
            "duration_ms": 125.4,
            "output": "Failed to reach hook runner sidecar at http://runner:8080",
        }
        # HTML
        title, body, fmt = NotificationFormatter.format(
            NotificationEventType.HOOK_FAILED,
            context,
            TelegramFormat.HTML,
        )
        assert "Script Pre-Run" in title
        assert "Backup-Daily" in title
        assert "<b>Job:</b> Backup-Daily" in body
        assert "⚠️ Fallimento Script Pre-Run" in body
        assert "125.4 ms" in body
        assert "Failed to reach hook runner" in body

        # Text
        context["hook_type"] = "post_run"
        t_title, t_body, t_fmt = NotificationFormatter.format(
            NotificationEventType.HOOK_FAILED,
            context,
            TelegramFormat.TEXT,
        )
        assert "Script Post-Run" in t_title
        assert "Evento: Fallimento Script Post-Run" in t_body
        assert "Codice di uscita: 1" in t_body

    def test_test_notification_telegram_markdown(self) -> None:
        context = {
            "channel_name": "My_Telegram_Alerts",
        }
        title, body, fmt = NotificationFormatter.format(
            NotificationEventType.TEST,
            context,
            TelegramFormat.MARKDOWN,
        )
        assert "*Test Notifica Riuscito!*" in body
        assert "My\\_Telegram\\_Alerts" in body


class TestAppriseNotifier:
    @patch("embervault_common.notifications.apprise_notifier.apprise.Apprise")
    def test_send_success(self, mock_apprise_cls: MagicMock) -> None:
        mock_instance = MagicMock()
        mock_instance.add.return_value = True
        mock_instance.notify.return_value = True
        mock_apprise_cls.return_value = mock_instance

        notifier = AppriseNotifier()
        result = notifier.send(
            url="tgram://123:abc/456",
            title="Test Title",
            body="Test Body",
        )
        assert result is True
        mock_instance.add.assert_called_once_with("tgram://123:abc/456")
        mock_instance.notify.assert_called_once()

    @patch("embervault_common.notifications.apprise_notifier.apprise.Apprise")
    def test_send_delivery_failed(self, mock_apprise_cls: MagicMock) -> None:
        mock_instance = MagicMock()
        mock_instance.add.return_value = True
        mock_instance.notify.return_value = False
        mock_apprise_cls.return_value = mock_instance

        notifier = AppriseNotifier()
        result = notifier.send(
            url="mailto://user:pass@smtp.example.com",
            title="Fail",
            body="Fail",
        )
        assert result is False

    def test_send_invalid_url_handles_gracefully(self) -> None:
        notifier = AppriseNotifier()
        result = notifier.send(
            url="invalid-not-a-url",
            title="Test",
            body="Test",
        )
        assert result is False

    @patch("embervault_common.notifications.apprise_notifier.apprise.Apprise")
    def test_send_splits_long_body_into_multiple_notifications(
        self, mock_apprise_cls: MagicMock
    ) -> None:
        mock_instance = MagicMock()
        mock_instance.add.return_value = True
        mock_instance.notify.return_value = True
        mock_apprise_cls.return_value = mock_instance

        notifier = AppriseNotifier()
        # Message of 1000 characters with custom max_chunk_size of 400
        long_body = "Primo blocco di testo importante.<br/><br/>" * 25
        result = notifier.send(
            url="tgram://123:abc/456",
            title="Allerta Proxy",
            body=long_body,
            max_chunk_size=400,
        )
        assert result is True
        assert mock_instance.notify.call_count > 1

        # Check titles contain chunk indicators [1/N], [2/N], etc.
        calls = mock_instance.notify.call_args_list
        assert "[1/" in calls[0].kwargs["title"]
        assert f"[{len(calls)}/" in calls[-1].kwargs["title"]
        for c in calls:
            assert len(c.kwargs["body"]) <= 450  # respects max chunk size including tag closing


class TestNotificationSplitting:
    def test_split_short_message_returns_single_chunk(self) -> None:
        from embervault_common.notifications.formatter import split_notification_body

        body = "Breve messaggio di notifica."
        chunks = split_notification_body(body, max_chunk_size=400)
        assert chunks == [body]

    def test_split_html_preserves_tag_balance(self) -> None:
        from embervault_common.notifications.formatter import split_notification_body

        # Body with <pre> that exceeds 300 chars
        long_code = "line_of_error_log_data_value = 1234567890;\n" * 15
        body = f"<b>Intestazione Errore</b><br/><pre>{long_code}</pre>"
        chunks = split_notification_body(body, max_chunk_size=300)

        assert len(chunks) >= 2
        # First chunk opens <pre> and must properly close it
        assert chunks[0].endswith("</pre>")
        # Second chunk must re-open <pre>
        assert chunks[1].startswith("<pre>")

    def test_split_markdown_preserves_code_fences(self) -> None:
        import apprise
        from embervault_common.notifications.formatter import split_notification_body

        long_code = "log_entry_detail_output_data\n" * 20
        body = f"*Job Fallito*\n```\n{long_code}```"
        chunks = split_notification_body(
            body, max_chunk_size=200, body_format=apprise.NotifyFormat.MARKDOWN
        )

        assert len(chunks) >= 2
        # First chunk must close the code block
        assert chunks[0].endswith("```")
        # Second chunk must reopen the code block
        assert chunks[1].startswith("```")
