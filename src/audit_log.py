"""
audit_log.py
-------------
Trilha de auditoria para decisoes de controle de acesso. Toda
chamada a `can_read`/`can_write` em access_control.py produz uma
AccessDecision - este modulo registra essas decisoes em uma lista
append-only, e oferece consultas sobre o historico (ex.: "quais
tentativas de acesso foram negadas para o dataset X").

Em uma implantacao real, este log seria persistido (ex.: gravado no
S3 como parte da camada Bronze de auditoria, seguindo o mesmo
principio de imutabilidade do ADR 0002 do repositorio de
arquitetura) - aqui, para fins de teste e demonstracao, fica em
memoria.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from access_control import AccessDecision


@dataclass
class AuditLog:
    entries: list[AccessDecision] = field(default_factory=list)

    def record(self, decision: AccessDecision) -> None:
        """Adiciona uma decisao ao log - append-only, nunca remove
        ou altera uma entrada ja registrada."""
        self.entries.append(decision)

    def denied_attempts(self) -> list[AccessDecision]:
        """Retorna todas as tentativas de acesso negadas - a
        consulta mais importante de um log de auditoria de
        seguranca, tipicamente a primeira coisa que se olha ao
        investigar um incidente."""
        return [e for e in self.entries if not e.granted]

    def attempts_for_dataset(self, dataset_name: str) -> list[AccessDecision]:
        return [e for e in self.entries if e.dataset_name == dataset_name]

    def attempts_by_role(self, role: str) -> list[AccessDecision]:
        return [e for e in self.entries if e.role == role]

    def denial_rate(self) -> float:
        """Proporcao de tentativas negadas sobre o total - uma
        metrica simples que, se subir de forma anormal, pode
        indicar uma tentativa de acesso indevido em andamento (ou,
        mais comumente na pratica, uma credencial mal configurada)."""
        if not self.entries:
            return 0.0
        return len(self.denied_attempts()) / len(self.entries)
