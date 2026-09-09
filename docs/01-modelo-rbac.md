# 01. Modelo de Controle de Acesso (RBAC)

## Origem: nao e uma politica nova, e uma traducao executavel

O [Projeto 08](https://github.com/amanda-martins-data/governanca-catalogo-dados)
definiu papeis (Data Owner, Data Steward, Data Consumer) e um campo
`sensitivity` (public/internal/confidential/personal) para cada
dataset do catalogo - mas tudo em prosa e YAML descritivo, sem
nenhuma decisao de acesso sendo de fato **aplicada**. Este projeto
pega exatamente essas definicoes e as transforma em uma funcao que
retorna uma decisao (`can_read`, `can_write`), testavel e auditavel.

Um papel novo foi adicionado em relacao ao Projeto 08: **auditor**,
com acesso de leitura amplo (incluindo dados `personal`) mas nunca
escrita - o papel que investiga incidentes ou faz compliance, sem
poder alterar nada.

## A hierarquia de sensibilidade

Cada nivel de sensibilidade define um subconjunto estritamente
menor de papeis com acesso de leitura - verificado por
`test_sensitivity_hierarchy_is_strictly_decreasing`:

| Sensibilidade | Papeis com leitura |
|---|---|
| `public` | data_owner, data_steward, data_consumer, auditor, **public** |
| `internal` | data_owner, data_steward, data_consumer, auditor |
| `confidential` | data_owner, data_steward, auditor |
| `personal` | data_owner, auditor |

**Distincao importante**: `public` (o papel) e `internal` (a
sensibilidade) nao sao a mesma coisa. `internal` significa "interno
a organizacao, nao publico" - um Data Consumer, sendo um papel
interno (ex.: alguem consumindo um dashboard dentro da empresa), tem
acesso a dados `internal`. Ja o papel `public` representa uma parte
totalmente externa, sem nenhuma credencial - esse e o unico papel
que fica de fora a partir do nivel `internal`.

## Escrita: nao depende de sensibilidade, depende so do papel

Diferente da leitura, a permissao de escrita e binaria por papel,
independente de quao sensivel o dataset e:

- `data_owner` e `data_steward`: sempre podem escrever (refletindo a
  matriz RACI do Projeto 08, onde ambos sao "Responsaveis" por
  mudancas de dataset).
- `data_consumer`, `auditor`, `public`: nunca escrevem, em nenhum
  dataset.

Isso e verificado por `test_write_permission_does_not_depend_on_sensitivity` -
`data_owner` tem a mesma permissao de escrita em um dataset `public`
e em um `personal`.

## Papel invalido: negado por padrao

Qualquer papel fora da lista `ROLES` (ex.: um typo de credencial, ou
uma tentativa de acesso com um papel que nunca foi cadastrado) e
automaticamente negado, com o motivo registrado como "papel
desconhecido" - nunca falha aberto (fail-open), sempre fechado
(fail-closed).

## Uso

```python
from access_control import Dataset, can_read, can_write

gold = Dataset("air_quality_daily_gold", sensitivity="public")
decision = can_read("data_consumer", gold)
print(decision.granted, decision.reason)
```
