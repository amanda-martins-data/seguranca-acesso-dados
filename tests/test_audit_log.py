"""
Testes de audit_log.py - 100% offline.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from access_control import Dataset, can_read
from audit_log import AuditLog

PUBLIC = Dataset("air_quality_bronze", "public")
PERSONAL = Dataset("dim_usuario", "personal", pii_fields=["nome"])


def test_audit_log_starts_empty():
    log = AuditLog()

    assert log.entries == []
    assert log.denial_rate() == 0.0


def test_record_appends_decision():
    log = AuditLog()
    decision = can_read("data_owner", PUBLIC)

    log.record(decision)

    assert len(log.entries) == 1
    assert log.entries[0] is decision


def test_denied_attempts_filters_correctly():
    log = AuditLog()
    log.record(can_read("data_owner", PERSONAL))  # granted
    log.record(can_read("public", PERSONAL))  # denied
    log.record(can_read("data_consumer", PERSONAL))  # denied

    denied = log.denied_attempts()

    assert len(denied) == 2
    assert all(not d.granted for d in denied)


def test_attempts_for_dataset_filters_by_name():
    log = AuditLog()
    log.record(can_read("data_owner", PUBLIC))
    log.record(can_read("data_owner", PERSONAL))

    attempts = log.attempts_for_dataset("dim_usuario")

    assert len(attempts) == 1
    assert attempts[0].dataset_name == "dim_usuario"


def test_attempts_by_role_filters_correctly():
    log = AuditLog()
    log.record(can_read("auditor", PUBLIC))
    log.record(can_read("public", PUBLIC))
    log.record(can_read("auditor", PERSONAL))

    auditor_attempts = log.attempts_by_role("auditor")

    assert len(auditor_attempts) == 2
    assert all(a.role == "auditor" for a in auditor_attempts)


def test_denial_rate_computes_correct_proportion():
    log = AuditLog()
    log.record(can_read("data_owner", PERSONAL))  # granted
    log.record(can_read("public", PERSONAL))  # denied
    log.record(can_read("data_consumer", PERSONAL))  # denied
    log.record(can_read("data_steward", PERSONAL))  # denied

    assert log.denial_rate() == 0.75


def test_log_is_append_only_in_practice():
    """Nao ha metodo de remocao ou edicao exposto - a unica forma de
    adicionar uma entrada e via record(), e a lista cresce
    monotonicamente."""
    log = AuditLog()
    log.record(can_read("data_owner", PUBLIC))
    log.record(can_read("data_owner", PUBLIC))

    assert len(log.entries) == 2
    assert not hasattr(log, "delete")
    assert not hasattr(log, "clear_entries")
