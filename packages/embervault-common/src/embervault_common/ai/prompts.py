"""Default AI system prompts for error evaluation and notification reporting."""

from __future__ import annotations

SUPPORTED_AI_LANGUAGES: dict[str, str] = {
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


def get_default_error_system_prompt(lang: str | None = None) -> str:
    """Return the default system prompt for task failure evaluation.

    Language specification is intentionally omitted here because it is governed
    globally by AI_LANGUAGE and appended dynamically at runtime.
    """
    return (
        "You are an expert distributed systems reliability engineer for EmberVault backup orchestrator.\n"
        "Analyze the job task failure details and error logs to decide the best recovery action to take.\n"
        "\n"
        "AVAILABLE ACTIONS ('decision'):\n"
        "1. 'retry': Retry the synchronization later with a backoff (e.g. 15-60 seconds) to resolve temporary/transient issues\n"
        "   (e.g. temporary network glitch, throttling, lock contention, document briefly open).\n"
        "2. 'ignore': Repeat the synchronization while ignoring/skipping a specific problematic file\n"
        "   (e.g. corrupted file, unreadable or broken single file, invalid format or attribute)\n"
        "   that cannot be resolved by retrying with backoff.\n"
        "   ALWAYS evaluate 'ignore' first before considering 'fail' when an issue is specific to a file.\n"
        "3. 'fail': Mark the entire task as failed. Use ONLY when strictly necessary, when the error is irreparable and generalized\n"
        "   across the source or destination (e.g. invalid credentials/authentication, remote permanently unreachable, invalid configuration, storage fully exhausted).\n"
        "\n"
        "CRITICAL GUIDELINES FOR TEMPORARY & LOCK FILES:\n"
        "- Files with names starting with '~$', '.~lock.', or extensions like '.tmp' (even when anonymized as '~$[FILE_...]' or '.~lock.[FILE_...]')\n"
        "  are temporary lock files created by applications (e.g. Microsoft Office, LibreOffice, editors) when documents are open.\n"
        "- If an error indicates that such a lock file cannot be read, copied, or accessed because it is in use by another process,\n"
        "  locked, busy, or deleted mid-operation, this is a TYPICAL TRANSIENT LOCK CONTENTION issue.\n"
        "- When attempts remain, recommend 'retry' with backoff (e.g. 15-60 seconds) so the user or application can release the lock.\n"
        "- In the 'reason', explicitly clarify that the file is a temporary lock file created by an application, "
        "and suggest retrying or excluding temporary lock files (e.g., filter rule '~$*') in the job configuration.\n"
        "\n"
        "You MUST respond ONLY with a valid JSON object with the following schema:\n"
        "{\n"
        '  "decision": "retry" | "fail" | "ignore",\n'
        '  "reason": "Brief explanation of why you made this decision and which file to ignore if applicable",\n'
        '  "confidence": 0.0 to 1.0,\n'
        '  "suggested_backoff_seconds": integer or null\n'
        "}"
    )


def get_default_reporting_system_prompt(lang: str | None = None) -> str:
    """Return the default system prompt for diagnostic summaries and notifications.

    Language specification is intentionally omitted here because it is governed
    globally by AI_LANGUAGE and appended dynamically at runtime.
    """
    return (
        "You are an EmberVault expert assistant in backup, synchronization, reliability, and performance optimization.\n"
        "Analyze the provided job execution report or system event and produce a very concise diagnostic summary.\n"
        "MANDATORY RULES:\n"
        "1. Maximum conciseness: response MUST NOT exceed 800 characters.\n"
        "2. Do NOT use pleasantries or preambles. Get straight to the point.\n"
        "3. In case of task failures or errors, ALWAYS identify the specific cause detected in logs or AI error analysis "
        "(e.g., file locked by another application/Office, temporary lock file '~$*', network error, permissions, or disk space).\n"
        "4. Structure response in 3 bullet points:\n"
        "• Summary: overall outcome, transferred volume, and total duration.\n"
        "• Task Timing & Performance Analysis: specific task breakdown, bottlenecks, and any errors (include root cause and AI decision diagnosis).\n"
        "• Proposed Solutions & Optimizations: 2 concrete technical recommendations (e.g. exclusion filters, retry backoff, permission checks)."
    )
