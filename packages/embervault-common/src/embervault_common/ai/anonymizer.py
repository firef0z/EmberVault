"""Data anonymizer for AI decision-making.

Censors sensitive data like IP addresses, hostnames, file and folder names,
and credentials while preserving consistent pseudonymous identifiers across
occurrences so that AI models can correlate entities across logs.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any


class DataAnonymizer:
    """Anonymizes sensitive details in logs and prompts with deterministic placeholders."""

    # Common extensions to identify filenames
    COMMON_EXTENSIONS = (
        r"txt|log|json|xml|yaml|yml|pdf|docx?|xlsx?|pptx?|csv|zip|tar|gz|bz2|xz|7z|"
        r"bak|evb|sql|db|sqlite[0-9]?|bin|iso|img|mp4|mkv|avi|mov|mp3|wav|jpg|jpeg|"
        r"png|gif|webp|svg|tmp|conf|cfg|ini|env|sh|py|js|ts|html|css"
    )

    def __init__(self) -> None:
        self._ip_map: dict[str, str] = {}
        self._host_map: dict[str, str] = {}
        self._dir_map: dict[str, str] = {}
        self._file_map: dict[str, str] = {}
        self._secret_counter = 0

    @property
    def ip_mappings(self) -> dict[str, str]:
        """Mapping from original IP to anonymized token."""
        return dict(self._ip_map)

    @property
    def host_mappings(self) -> dict[str, str]:
        """Mapping from original hostname to anonymized token."""
        return dict(self._host_map)

    @property
    def dir_mappings(self) -> dict[str, str]:
        """Mapping from original folder name to anonymized token."""
        return dict(self._dir_map)

    @property
    def file_mappings(self) -> dict[str, str]:
        """Mapping from original filename to anonymized token."""
        return dict(self._file_map)

    def reset(self) -> None:
        """Clear all mappings."""
        self._ip_map.clear()
        self._host_map.clear()
        self._dir_map.clear()
        self._file_map.clear()
        self._secret_counter = 0

    def get_ip_token(self, ip_str: str) -> str:
        """Get or assign an anonymized token for an IP address."""
        if ip_str not in self._ip_map:
            self._ip_map[ip_str] = f"[IP_{len(self._ip_map) + 1}]"
        return self._ip_map[ip_str]

    def get_host_token(self, host_str: str) -> str:
        """Get or assign an anonymized token for a hostname."""
        host_lower = host_str.lower()
        if host_lower not in self._host_map:
            self._host_map[host_lower] = f"[HOST_{len(self._host_map) + 1}]"
        return self._host_map[host_lower]

    def get_dir_token(self, dir_name: str) -> str:
        """Get or assign an anonymized token for a directory name."""
        clean = dir_name.strip("/\\ ")
        if not clean:
            return dir_name
        if clean not in self._dir_map:
            self._dir_map[clean] = f"[DIR_{len(self._dir_map) + 1}]"
        return self._dir_map[clean]

    def get_file_token(self, file_name: str) -> str:
        """Get or assign an anonymized token for a filename, preserving lock prefixes."""
        clean = file_name.strip("/\\ ")
        if not clean:
            return file_name
        if clean not in self._file_map:
            ext = ""
            if "." in clean:
                ext = "." + clean.rsplit(".", 1)[1]

            prefix = ""
            if clean.startswith("~$"):
                prefix = "~$"
            elif clean.startswith(".~lock."):
                prefix = ".~lock."

            self._file_map[clean] = f"{prefix}[FILE_{len(self._file_map) + 1}{ext}]"
        return self._file_map[clean]

    def anonymize_text(self, text: str) -> str:
        """Anonymize sensitive values in arbitrary text while preserving consistency."""
        if not text:
            return text

        result = text

        # 1. Redact explicit credentials and secrets
        result = self._redact_secrets(result)

        # 2. Extract and replace file paths (Windows, Unix, UNC, Rclone remote)
        result = self._anonymize_paths(result)

        # 3. Anonymize standalone filenames with known extensions
        result = self._anonymize_standalone_files(result)

        # 4. Anonymize already recognized directory names that appear standalone
        result = self._anonymize_known_dirs(result)

        # 5. Anonymize IP addresses (IPv4 and IPv6)
        result = self._anonymize_ips(result)

        # 6. Anonymize Hostnames and URLs
        result = self._anonymize_hosts(result)

        return result

    def anonymize_data(self, data: Any) -> Any:
        """Recursively anonymize strings in dicts, lists, or primitive values."""
        if isinstance(data, str):
            return self.anonymize_text(data)
        if isinstance(data, dict):
            return {self.anonymize_text(str(k)): self.anonymize_data(v) for k, v in data.items()}
        if isinstance(data, list):
            return [self.anonymize_data(item) for item in data]
        if isinstance(data, tuple):
            return tuple(self.anonymize_data(item) for item in data)
        return data

    def _redact_secrets(self, text: str) -> str:
        """Redact tokens, passwords, and sensitive keys."""
        patterns = [
            (r"(?i)(--password(?:-file)?\s+)[^\s]+", r"\1[SECRET_REDACTED]"),
            (r"(?i)(--token\s+)[^\s]+", r"\1[SECRET_REDACTED]"),
            (r"(?i)(password\s*[:=]\s*)[^\s,;\"']+", r"\1[SECRET_REDACTED]"),
            (r"(?i)(token\s*[:=]\s*)[^\s,;\"']+", r"\1[SECRET_REDACTED]"),
            (r"(?i)(api[_-]?key\s*[:=]\s*)[^\s,;\"']+", r"\1[SECRET_REDACTED]"),
            (r"(?i)(secret[_-]?key\s*[:=]\s*)[^\s,;\"']+", r"\1[SECRET_REDACTED]"),
            (r"(?i)(Bearer\s+)[A-Za-z0-9_\-\.]{10,}", r"\1[SECRET_REDACTED]"),
            (r"(?i)(Authorization:\s*Basic\s+)[A-Za-z0-9+/=]+", r"\1[SECRET_REDACTED]"),
        ]
        res = text
        for pat, repl in patterns:
            res = re.sub(pat, repl, res)
        return res

    def _anonymize_paths(self, text: str) -> str:
        """Identify and replace filesystem and remote paths."""
        # Windows full path: C:\path\to\file.ext, C:\path\to\dir\ or \\?\C:\...
        win_path_regex = re.compile(
            r"((?:\\\\\?\\)?[a-zA-Z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*(?:[^\\/:*?\"<>|\r\n]+)?)"
        )

        def replace_win_path(m: re.Match[str]) -> str:
            full = m.group(1)
            prefix = ""
            clean_path = full
            if clean_path.startswith("\\\\?\\"):
                prefix = "\\\\?\\"
                clean_path = clean_path[4:]

            parts = [p for p in clean_path.split("\\") if p]
            if not parts:
                return full
            drive = parts[0]
            segments = parts[1:]
            if not segments:
                return full

            anonymized_segments = []
            for i, seg in enumerate(segments):
                # Is it the last segment and has an extension or likely a file?
                is_last = i == len(segments) - 1
                if is_last and ("." in seg or not clean_path.endswith("\\")):
                    anonymized_segments.append(self.get_file_token(seg))
                else:
                    anonymized_segments.append(self.get_dir_token(seg))

            res = prefix + drive + "\\" + "\\".join(anonymized_segments)
            if clean_path.endswith("\\"):
                res += "\\"
            return res

        text = win_path_regex.sub(replace_win_path, text)

        # Unix absolute path: /var/log/app/file.log
        unix_path_regex = re.compile(
            r"(?<![a-zA-Z0-9_])(/(?:[a-zA-Z0-9_\-\. ]+/)+[a-zA-Z0-9_\-\. ]*)"
        )

        def replace_unix_path(m: re.Match[str]) -> str:
            full = m.group(1)
            parts = [p for p in full.split("/") if p]
            if not parts:
                return full

            anonymized_segments = []
            for i, seg in enumerate(parts):
                is_last = i == len(parts) - 1
                if is_last and ("." in seg or not full.endswith("/")):
                    anonymized_segments.append(self.get_file_token(seg))
                else:
                    anonymized_segments.append(self.get_dir_token(seg))

            res = "/" + "/".join(anonymized_segments)
            if full.endswith("/"):
                res += "/"
            return res

        text = unix_path_regex.sub(replace_unix_path, text)

        # Rclone remote path: remote_name:path/to/file or remote_name:bucket
        # Ensure remote is not preceded by file extensions/words and path does not start with spaces
        rclone_path_regex = re.compile(
            r"(?<![a-zA-Z0-9_\-\.])\b([a-zA-Z][a-zA-Z0-9_\-]*):((?:[a-zA-Z0-9_\-\. ]+/)+[a-zA-Z0-9_\-\. ]*|[a-zA-Z0-9_\-\.]+)"
        )

        def replace_rclone_path(m: re.Match[str]) -> str:
            remote = m.group(1)
            path_part = m.group(2)
            remote_token = self.get_host_token(remote)
            parts = [p for p in path_part.split("/") if p]
            anonymized_segments = []
            for i, seg in enumerate(parts):
                is_last = i == len(parts) - 1
                if is_last and "." in seg:
                    anonymized_segments.append(self.get_file_token(seg))
                else:
                    anonymized_segments.append(self.get_dir_token(seg))
            return f"{remote_token}:{'/'.join(anonymized_segments)}"

        text = rclone_path_regex.sub(replace_rclone_path, text)
        return text

    def _anonymize_standalone_files(self, text: str) -> str:
        """Find standalone filenames like 'invoice.pdf' or '~$Document.xlsx'."""
        # 1. Substitute already identified filenames first to guarantee consistency
        for orig_file, token in sorted(
            self._file_map.items(), key=lambda x: len(x[0]), reverse=True
        ):
            if len(orig_file) >= 3:
                text = text.replace(orig_file, token)

        # 2. Temporary lock files (Office ~$ or LibreOffice .~lock.) which may contain spaces
        lock_pattern = re.compile(
            rf'(?<![a-zA-Z0-9_/\\\[])((?:~\$|\.~lock\.)[^\\/:*?"<>|\r\n\t]+?\.(?:{self.COMMON_EXTENSIONS}))(?![a-zA-Z0-9_\]])',
            re.IGNORECASE,
        )

        def repl_lock(m: re.Match[str]) -> str:
            fname = m.group(1)
            if fname.startswith(("FILE_", "DIR_", "IP_", "HOST_")) or "[FILE_" in fname:
                return m.group(0)
            return self.get_file_token(fname)

        text = lock_pattern.sub(repl_lock, text)

        # 3. Quoted filenames: 'some file.ext' or "some file.ext"
        quoted_pattern = re.compile(
            rf'["\']([^"\'\r\n]+\.(?:{self.COMMON_EXTENSIONS}))["\']',
            re.IGNORECASE,
        )

        def repl_quoted(m: re.Match[str]) -> str:
            fname = m.group(1)
            if fname.startswith(("FILE_", "DIR_", "IP_", "HOST_")) or "[FILE_" in fname:
                return m.group(0)
            quote = m.group(0)[0]
            return f"{quote}{self.get_file_token(fname)}{quote}"

        text = quoted_pattern.sub(repl_quoted, text)

        # 4. Standard filenames without spaces:
        pattern = re.compile(
            rf"(?<![a-zA-Z0-9_/\\\[])([a-zA-Z0-9_\-]+\.(?:{self.COMMON_EXTENSIONS}))(?![a-zA-Z0-9_\]])",
            re.IGNORECASE,
        )

        def repl(m: re.Match[str]) -> str:
            fname = m.group(1)
            if fname.startswith(("FILE_", "DIR_", "IP_", "HOST_")) or "[FILE_" in fname:
                return m.group(0)
            return self.get_file_token(fname)

        text = pattern.sub(repl, text)
        return text

    def _anonymize_known_dirs(self, text: str) -> str:
        """Replace standalone occurrences of directory names that have already been identified."""
        for orig_dir, token in sorted(self._dir_map.items(), key=lambda x: len(x[0]), reverse=True):
            if len(orig_dir) < 3:
                continue
            pattern = re.compile(rf"\b{re.escape(orig_dir)}\b")
            text = pattern.sub(token, text)
        return text

    def _anonymize_ips(self, text: str) -> str:
        """Find and replace valid IPv4 and IPv6 addresses."""
        # IPv4
        ipv4_pattern = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

        def repl_ipv4(m: re.Match[str]) -> str:
            val = m.group(1)
            try:
                ip = ipaddress.IPv4Address(val)
                # Ignore loopback 127.0.0.1 or 0.0.0.0 if not strictly necessary,
                # but to be completely safe and consistent with censoring, replace all non-standard or valid IPs:
                return self.get_ip_token(str(ip))
            except ValueError:
                return val

        text = ipv4_pattern.sub(repl_ipv4, text)

        # IPv6
        ipv6_pattern = re.compile(
            r"\b([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7}|[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){1,6}:|:(?::[0-9a-fA-F]{1,4}){1,7})\b"
        )

        def repl_ipv6(m: re.Match[str]) -> str:
            val = m.group(1)
            try:
                ip = ipaddress.IPv6Address(val)
                return self.get_ip_token(str(ip))
            except ValueError:
                return val

        text = ipv6_pattern.sub(repl_ipv6, text)
        return text

    def _anonymize_hosts(self, text: str) -> str:
        """Find and replace hostnames, FQDNs, and URLs."""
        # URLs: http(s)://domain.com[:port]/path
        url_pattern = re.compile(r"(https?://)([^/:\s\"']+)(?::\d+)?")

        def repl_url(m: re.Match[str]) -> str:
            proto = m.group(1)
            host = m.group(2)
            # Check if host is already an IP token
            if host.startswith("[IP_"):
                return f"{proto}{host}"
            # Check if host is raw IP
            try:
                ipaddress.ip_address(host)
                token = self.get_ip_token(host)
                return f"{proto}{token}"
            except ValueError:
                token = self.get_host_token(host)
                return f"{proto}{token}"

        text = url_pattern.sub(repl_url, text)

        # FQDNs: server.corp.internal, s3.eu-west-1.amazonaws.com, etc.
        fqdn_pattern = re.compile(
            r"\b([a-zA-Z0-9_\-]+\.(?:lan|local|internal|corp|home|org|net|com|it|io|cloud|amazonaws\.com|azure\.com))\b",
            re.IGNORECASE,
        )

        def repl_fqdn(m: re.Match[str]) -> str:
            raw = m.group(1)
            return self.get_host_token(raw)

        text = fqdn_pattern.sub(repl_fqdn, text)
        return text
