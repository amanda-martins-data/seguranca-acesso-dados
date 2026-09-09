"""
Testes de access_control.py - 100% offline, sem dependencia de
infraestrutura real. Usa os mesmos datasets (nomes e niveis de
sensibilidade) catalogados no Projeto 08, para que a politica testada
aqui seja a mesma que se aplicaria aos dados reais do portfolio.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from access_control import Dataset, ROLES, can_read, can_write, mask_row

# Datasets espelhando o catalogo real do Projeto 08
PUBLIC_DATASET = Dataset("air_quality_bronze", "public")
INTERNAL_DATASET = Dataset("data_quality_report", "internal")
CONFIDENTIAL_DATASET = Dataset("contrato_comercial", "confidential")  # hipotetico, nao existe no Projeto 08
PERSONAL_DATASET = Dataset("dim_usuario", "personal", pii_fields=["nome", "email", "cargo"])


def test_public_dataset_readable_by_everyone():
    for role in ROLES:
        decision = can_read(role, PUBLIC_DATASET)
        assert decision.granted is True


def test_personal_dataset_only_readable_by_owner_and_auditor():
    granted_roles = {can_read(role, PERSONAL_DATASET).role for role in ROLES if can_read(role, PERSONAL_DATASET).granted}

    assert granted_roles == {"data_owner", "auditor"}


def test_public_role_cannot_read_internal_dataset():
    """'internal' significa 'interno a organizacao, nao publico' -
    o papel 'public' (qualquer parte externa sem papel atribuido) e
    o unico que nao deveria ver dados internal; data_consumer, sendo
    um papel interno, pode."""
    decision = can_read("public", INTERNAL_DATASET)

    assert decision.granted is False


def test_data_consumer_can_read_internal_dataset():
    """Data Consumer e um papel interno a organizacao (ex.: alguem
    consumindo um dashboard) - diferente de 'public', que representa
    uma parte externa sem nenhum papel. Por isso Data Consumer tem
    acesso a dados 'internal', mas nao a 'confidential' ou 'personal'."""
    decision = can_read("data_consumer", INTERNAL_DATASET)

    assert decision.granted is True


def test_data_consumer_cannot_read_confidential_dataset():
    decision = can_read("data_consumer", CONFIDENTIAL_DATASET)

    assert decision.granted is False


def test_sensitivity_hierarchy_is_strictly_decreasing():
    """Cada nivel de sensibilidade deve ter um conjunto de papeis com
    acesso que e subconjunto do nivel anterior - public tem mais
    acesso que internal, que tem mais que confidential, que tem mais
    que personal. Se essa hierarquia for violada, a politica esta
    inconsistente."""
    from access_control import READ_ACCESS_BY_SENSITIVITY

    public_roles = READ_ACCESS_BY_SENSITIVITY["public"]
    internal_roles = READ_ACCESS_BY_SENSITIVITY["internal"]
    confidential_roles = READ_ACCESS_BY_SENSITIVITY["confidential"]
    personal_roles = READ_ACCESS_BY_SENSITIVITY["personal"]

    assert internal_roles.issubset(public_roles)
    assert confidential_roles.issubset(internal_roles)
    assert personal_roles.issubset(confidential_roles)


def test_invalid_sensitivity_raises():
    import pytest

    with pytest.raises(ValueError):
        Dataset("x", "top-secret")


def test_unknown_role_is_always_denied():
    decision = can_read("intruder", PUBLIC_DATASET)

    assert decision.granted is False
    assert "desconhecido" in decision.reason


def test_only_owner_and_steward_can_write():
    for role in ROLES:
        decision = can_write(role, PUBLIC_DATASET)
        expected = role in ("data_owner", "data_steward")

        assert decision.granted is expected


def test_write_permission_does_not_depend_on_sensitivity():
    """Diferente da leitura, a permissao de escrita e a mesma
    independente do dataset ser public ou personal - Data Owner
    sempre pode escrever, em qualquer dataset."""
    decision_public = can_write("data_owner", PUBLIC_DATASET)
    decision_personal = can_write("data_owner", PERSONAL_DATASET)

    assert decision_public.granted == decision_personal.granted is True


def test_mask_row_redacts_pii_fields_for_unprivileged_role():
    row = {"nome": "Joao Silva", "email": "joao@example.com", "municipio_id": "SP"}

    masked = mask_row(row, PERSONAL_DATASET, role="auditor")

    assert masked["nome"] == "***REDACTED***"
    assert masked["email"] == "***REDACTED***"
    assert masked["municipio_id"] == "SP"  # campo nao-PII permanece intacto


def test_mask_row_does_not_redact_for_data_owner():
    row = {"nome": "Joao Silva", "email": "joao@example.com"}

    unmasked = mask_row(row, PERSONAL_DATASET, role="data_owner")

    assert unmasked["nome"] == "Joao Silva"
    assert unmasked["email"] == "joao@example.com"


def test_mask_row_is_noop_for_dataset_without_pii():
    row = {"cidade": "Sao Paulo", "valor": 42}

    result = mask_row(row, PUBLIC_DATASET, role="public")

    assert result == row


def test_pii_masking_is_a_second_layer_beyond_read_access():
    """O achado central deste modulo: auditor PASSA no controle de
    leitura para um dataset personal (pode ver que o dataset existe
    e tem acesso de leitura concedido), mas AINDA ASSIM tem os
    campos PII mascarados - duas camadas de defesa independentes,
    nao uma unica decisao binaria de tudo-ou-nada."""
    read_decision = can_read("auditor", PERSONAL_DATASET)
    row = {"nome": "Joao Silva", "email": "joao@example.com"}
    masked = mask_row(row, PERSONAL_DATASET, role="auditor")

    assert read_decision.granted is True  # passa na primeira camada
    assert masked["nome"] == "***REDACTED***"  # mas e barrado na segunda


def test_mask_row_never_mutates_original_row():
    row = {"nome": "Joao Silva", "email": "joao@example.com"}

    mask_row(row, PERSONAL_DATASET, role="auditor")

    assert row["nome"] == "Joao Silva"  # o dict original nao foi alterado
