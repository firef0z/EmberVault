"""Apprise notifier wrapper, URL builder, masking, and delivery helpers."""

from __future__ import annotations

import re
import time
import urllib.parse

import apprise

from embervault_common.notifications.formatter import split_notification_body
from embervault_common.observability import get_logger

logger = get_logger("embervault_common.notifications.apprise_notifier")


def validate_apprise_url(url: str) -> tuple[bool, str | None]:
    """Validate whether an Apprise URL schema is recognized and syntactically valid.

    Args:
        url: The Apprise notification service URL.

    Returns:
        (True, None) if valid, or (False, error_reason) if invalid.
    """
    clean_url = url.strip()
    if not clean_url:
        return False, "L'URL di notifica non può essere vuoto."

    ap = apprise.Apprise()
    try:
        success = ap.add(clean_url)
        if not success or len(list(ap)) == 0:
            return (
                False,
                "Schema o parametri URL non supportati da Apprise (es. 'tgram://', 'mailto://', 'discord://').",
            )
        return True, None
    except Exception as exc:
        return False, f"Errore durante la validazione dell'URL: {exc}"


def build_telegram_url(bot_token: str, chat_id: str, format_mode: str = "html") -> str:
    """Build a canonical Apprise Telegram URL.

    Args:
        bot_token: Telegram bot token (e.g. '123456789:ABC-DEF1234ghIkl-zyx57W2v1u123ew11').
        chat_id: Telegram Chat ID, Channel name (e.g. '@mychannel'), or Group ID (e.g. '-100123456').
        format_mode: Syntax mode ('text', 'html', 'markdown').

    Returns:
        Canonical Apprise Telegram URL.
    """
    clean_token = bot_token.strip()
    clean_chat = chat_id.strip()
    clean_format = format_mode.strip().lower()
    if clean_format not in ("text", "html", "markdown"):
        clean_format = "html"

    # In Apprise tgram://, leading slash for chat_id is standard
    if not clean_chat.startswith("/"):
        clean_chat = f"/{clean_chat}"
    if not clean_chat.endswith("/"):
        clean_chat = f"{clean_chat}/"

    return f"tgram://{clean_token}{clean_chat}?format={clean_format}"


def build_email_url(
    host: str,
    port: int,
    user: str | None = None,
    password: str | None = None,
    from_addr: str | None = None,
    to_addrs: list[str] | str | None = None,
    secure: bool = False,
) -> str:
    """Build a canonical Apprise Email URL (mailto:// or mailtos://).

    Args:
        host: SMTP server hostname or IP.
        port: SMTP server port (e.g. 587, 465, 25).
        user: SMTP username.
        password: SMTP password.
        from_addr: Sender email address.
        to_addrs: Recipient email address(es).
        secure: If True, uses mailtos:// (SMTPS / SSL); otherwise mailto://.

    Returns:
        Canonical Apprise Email URL.
    """
    scheme = "mailtos" if secure else "mailto"
    clean_host = host.strip()
    auth_part = ""
    if user:
        clean_user = urllib.parse.quote(user.strip(), safe="")
        if password:
            clean_pass = urllib.parse.quote(password, safe="")
            auth_part = f"{clean_user}:{clean_pass}@"
        else:
            auth_part = f"{clean_user}@"

    netloc = f"{auth_part}{clean_host}:{port}"
    params: dict[str, str] = {}
    if from_addr:
        params["from"] = from_addr.strip()
    if to_addrs:
        if isinstance(to_addrs, list):
            params["to"] = ",".join(t.strip() for t in to_addrs if t.strip())
        else:
            params["to"] = to_addrs.strip()

    query_str = urllib.parse.urlencode(params) if params else ""
    return f"{scheme}://{netloc}" + (f"?{query_str}" if query_str else "")


def mask_apprise_url(url: str) -> str:
    """Mask credentials and sensitive tokens from an Apprise URL for safe display and logging.

    Args:
        url: Raw Apprise URL.

    Returns:
        Redacted URL with passwords and tokens replaced by '••••••••'.
    """
    clean_url = url.strip()
    if not clean_url:
        return ""

    # 1. Telegram URLs: tgram://123456789:ABCdefGHI.../chat_id/...
    # Mask the token secret part after the bot ID prefix:
    if clean_url.startswith("tgram://"):
        return re.sub(
            r"^(tgram://[^:/]+):[^/@]+(/.*)$",
            r"\1:••••••••\2",
            clean_url,
        )

    # 2. Standard URI credentials: scheme://user:password@host...
    masked = re.sub(
        r"(://[^:/@\s]+):([^/@\s]+)@",
        r"\1:••••••••@",
        clean_url,
    )
    return masked


class AppriseNotifier:
    """Delivers notifications across configured Apprise endpoints with automatic chunking."""

    # Default maximum message lengths before splitting per service
    SERVICE_MAX_CHUNK_SIZES = {
        "tgram": 4000,
        "telegram": 4000,
        "discord": 1900,
        "slack": 3900,
    }
    DEFAULT_MAX_CHUNK_SIZE = 4000

    def __init__(self, request_timeout_s: float = 10.0) -> None:
        self.request_timeout_s = request_timeout_s

    def get_max_chunk_size_for_url(self, url: str) -> int:
        """Determine safe maximum chunk size for an Apprise URL."""
        scheme = url.split("://", 1)[0].lower() if "://" in url else ""
        return self.SERVICE_MAX_CHUNK_SIZES.get(scheme, self.DEFAULT_MAX_CHUNK_SIZE)

    def send(
        self,
        url: str,
        title: str,
        body: str,
        body_format: apprise.NotifyFormat = apprise.NotifyFormat.HTML,
        max_chunk_size: int | None = None,
    ) -> bool:
        """Send a notification to a single Apprise URL, automatically splitting into parts if needed.

        Args:
            url: Target Apprise service URL.
            title: Notification title.
            body: Notification body.
            body_format: Format mode (HTML, Markdown, or Text).
            max_chunk_size: Optional maximum character length per chunk (defaults to service limit, e.g. 4000 for Telegram).

        Returns:
            True if delivered successfully, False otherwise.
        """
        limit = (
            max_chunk_size if max_chunk_size is not None else self.get_max_chunk_size_for_url(url)
        )
        chunks = split_notification_body(body, max_chunk_size=limit, body_format=body_format)
        if not chunks:
            chunks = [body]

        total_chunks = len(chunks)
        ap = apprise.Apprise()
        try:
            added = ap.add(url)
            if not added:
                logger.warning("apprise_add_target_failed", masked_url=mask_apprise_url(url))
                return False

            all_success = True
            for idx, chunk in enumerate(chunks, 1):
                chunk_title = f"{title} [{idx}/{total_chunks}]" if total_chunks > 1 else title
                result = ap.notify(
                    title=chunk_title,
                    body=chunk,
                    body_format=body_format,
                )
                if result:
                    logger.info(
                        "notification_delivered_success",
                        masked_url=mask_apprise_url(url),
                        part=f"{idx}/{total_chunks}" if total_chunks > 1 else "1/1",
                    )
                else:
                    logger.warning(
                        "notification_delivery_returned_false",
                        masked_url=mask_apprise_url(url),
                        part=f"{idx}/{total_chunks}" if total_chunks > 1 else "1/1",
                    )
                    all_success = False

                if total_chunks > 1 and idx < total_chunks:
                    time.sleep(0.05)

            return all_success
        except Exception as exc:
            logger.error(
                "notification_delivery_exception",
                masked_url=mask_apprise_url(url),
                error=str(exc),
            )
            return False
