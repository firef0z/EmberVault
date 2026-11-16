"""Unit tests for DataAnonymizer in embervault_common.ai.anonymizer."""

from embervault_common.ai.anonymizer import DataAnonymizer


def test_ip_anonymization_consistency() -> None:
    anonymizer = DataAnonymizer()
    text = "Connection from 192.168.1.50 failed. Retrying 192.168.1.50 port 443. Another server 10.0.0.1 replied."
    res = anonymizer.anonymize_text(text)

    assert "192.168.1.50" not in res
    assert "10.0.0.1" not in res
    assert "[IP_1]" in res
    assert "[IP_2]" in res

    # Check consistency: 192.168.1.50 should appear twice with [IP_1]
    assert res.count("[IP_1]") == 2
    assert res.count("[IP_2]") == 1


def test_file_and_directory_anonymization_consistency() -> None:
    anonymizer = DataAnonymizer()
    text = (
        "Failed reading /mnt/storage/finance/reports_2026.pdf: permission denied.\n"
        "Second attempt on reports_2026.pdf also failed in finance folder."
    )
    res = anonymizer.anonymize_text(text)

    assert "reports_2026.pdf" not in res
    assert "finance" not in res
    # Find the token for reports_2026.pdf
    pdf_token = anonymizer.file_mappings.get("reports_2026.pdf")
    assert pdf_token is not None
    assert pdf_token.endswith(".pdf]")
    # Verify that the same token appears for both occurrences
    assert res.count(pdf_token) == 2

    # Check directory token consistency
    dir_token = anonymizer.dir_mappings.get("finance")
    assert dir_token is not None
    assert res.count(dir_token) == 2


def test_windows_path_anonymization() -> None:
    anonymizer = DataAnonymizer()
    text = r"Error opening file C:\Backups\CriticalData\database.sqlite3: disk is full."
    res = anonymizer.anonymize_text(text)

    assert "CriticalData" not in res
    assert "database.sqlite3" not in res
    token = anonymizer.file_mappings.get("database.sqlite3")
    assert token is not None
    assert token in res


def test_secrets_redaction() -> None:
    anonymizer = DataAnonymizer()
    text = (
        "Command: rclone copy --password secret_password_123 --token my_super_token remote:bucket"
    )
    res = anonymizer.anonymize_text(text)

    assert "secret_password_123" not in res
    assert "my_super_token" not in res
    assert "[SECRET_REDACTED]" in res


def test_anonymize_data_dict_and_list() -> None:
    anonymizer = DataAnonymizer()
    data = {
        "host": "192.168.1.100",
        "error_file": "/var/data/error.log",
        "nested": [
            "192.168.1.100",
            "file error.log occurred again",
        ],
    }
    anonymized = anonymizer.anonymize_data(data)

    assert anonymized["host"] == "[IP_1]"
    assert "192.168.1.100" not in str(anonymized)
    assert "error.log" not in str(anonymized)
    assert "[IP_1]" in anonymized["nested"]


def test_temporary_lock_file_anonymization() -> None:
    anonymizer = DataAnonymizer()
    text = (
        "2026/10/26 10:00:12 ERROR : ~$Nuovo Foglio di lavoro di Microsoft Excel.xlsx: "
        r"Failed to copy: open \\?\C:\Users\user\Documents\~$Nuovo Foglio di lavoro di Microsoft Excel.xlsx: "
        "The process cannot access the file because it is being used by another process."
    )
    res = anonymizer.anonymize_text(text)

    # Must preserve the lock prefix "~$"
    assert "~$[FILE_1.xlsx]" in res
    assert "Nuovo Foglio di lavoro di Microsoft Excel" not in res
    # Must not mangle the timestamp into a remote host
    assert "10:00:12" in res
    # Occurrences should match consistently across standalone and full Windows path
    assert res.count("~$[FILE_1.xlsx]") == 2
