"""
access_control.py
-------------------
Motor de decisao de controle de acesso (RBAC) para os datasets
catalogados no Projeto 08 (governanca-catalogo-dados). A politica de
acesso e derivada diretamente do campo `sensitivity` de cada dataset
e dos papeis definidos no framework de governanca daquele projeto -
nao e uma lista de regras arbitraria criada do zero, e a traducao
executavel de uma decisao que ja foi tomada em prosa.

Papeis (identicos aos do Projeto 08):
- data_owner: responsavel final pelo dataset
- data_steward: garante qualidade e documentacao
- data_consumer: consome o dataset, sem permissao de escrita
- auditor: papel adicional deste projeto - acesso de leitura amplo
  para fins de auditoria/compliance, sem permissao de escrita
- public: qualquer parte externa sem papel atribuido
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

ROLES = ["data_owner", "data_steward", "data_consumer", "auditor", "public"]

VALID_SENSITIVITY = ["public", "internal", "confidential", "personal"]

# Quais papeis podem LER um dataset, por nivel de sensibilidade -
# quanto mais sensivel o dado, menor o conjunto de papeis com acesso.
# Isto e uma hierarquia estrita: cada nivel e um subconjunto do
# anterior (ver test_sensitivity_hierarchy_is_strictly_decreasing).
READ_ACCESS_BY_SENSITIVITY: dict[str, set[str]] = {
    "public": {"data_owner", "data_steward", "data_consumer", "auditor", "public"},
    "internal": {"data_owner", "data_steward", "data_consumer", "auditor"},
    "confidential": {"data_owner", "data_steward", "auditor"},
    "personal": {"data_owner", "auditor"},  # LGPD: acesso minimo necessario
}

# Quem pode escrever, independente do dataset - reflete a matriz RACI
# do Projeto 08: Data Owner e Data Steward sao Responsaveis por
# mudancas; Data Consumer e Auditor nunca escrevem.
WRITE_ACCESS_BY_ROLE: dict[str, bool] = {
    "data_owner": True,
    "data_steward": True,
    "data_consumer": False,
    "auditor": False,
    "public": False,
}

MASK_PLACEHOLDER = "***REDACTED***"

# Papeis que podem ver campos PII sem mascaramento - deliberadamente
# um conjunto menor que READ_ACCESS_BY_SENSITIVITY["personal"], para
# que o teste de defesa em profundidade (test_pii_masking_is_a_second_layer)
# tenha algo real para verificar.
PII_UNMASKED_ROLES = {"data_owner"}


@dataclass
class Dataset:
    name: str
    sensitivity: str
    pii_fields: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.sensitivity not in VALID_SENSITIVITY:
            raise ValueError(f"sensitivity invalida: {self.sensitivity!r}")


@dataclass
class AccessDecision:
    role: str
    dataset_name: str
    action: str  # "read" ou "write"
    granted: bool
    reason: str
    timestamp: str


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def can_read(role: str, dataset: Dataset) -> AccessDecision:
    """Decide se `role` pode ler `dataset`, baseado no nivel de
    sensibilidade do dataset. Retorna a decisao junto com o motivo -
    nunca so um booleano solto, para que toda decisao seja
    auditavel (ver audit_log.py)."""
    if role not in ROLES:
        return AccessDecision(role, dataset.name, "read", False, f"papel desconhecido: {role!r}", _now_iso())

    allowed_roles = READ_ACCESS_BY_SENSITIVITY[dataset.sensitivity]
    granted = role in allowed_roles
    reason = (
        f"papel '{role}' {'esta' if granted else 'nao esta'} na lista de leitura "
        f"para sensibilidade '{dataset.sensitivity}'"
    )
    return AccessDecision(role, dataset.name, "read", granted, reason, _now_iso())


def can_write(role: str, dataset: Dataset) -> AccessDecision:
    """Decide se `role` pode escrever em `dataset`. Diferente da
    leitura, a permissao de escrita nao depende da sensibilidade do
    dataset - depende so do papel (Data Owner e Data Steward sempre
    podem escrever, independente de quao sensivel o dado e, porque
    sao eles os responsaveis por manter o dataset atualizado)."""
    if role not in ROLES:
        return AccessDecision(role, dataset.name, "write", False, f"papel desconhecido: {role!r}", _now_iso())

    granted = WRITE_ACCESS_BY_ROLE[role]
    reason = f"papel '{role}' {'tem' if granted else 'nao tem'} permissao de escrita"
    return AccessDecision(role, dataset.name, "write", granted, reason, _now_iso())


def mask_row(row: dict, dataset: Dataset, role: str) -> dict:
    """Aplica mascaramento de campos PII em uma linha de dado, como
    segunda camada de defesa alem do controle de leitura por
    sensibilidade - mesmo um papel que passou em `can_read` para um
    dataset `personal` (ex.: auditor) pode nao ter direito de ver o
    valor real de cada campo PII individual, dependendo da politica.

    Isto reflete o principio de defesa em profundidade descrito no
    Projeto 09 (isolamento multi-tenant): nunca uma unica camada de
    controle sozinha."""
    if not dataset.pii_fields or role in PII_UNMASKED_ROLES:
        return dict(row)

    masked = dict(row)
    for field_name in dataset.pii_fields:
        if field_name in masked:
            masked[field_name] = MASK_PLACEHOLDER
    return masked
