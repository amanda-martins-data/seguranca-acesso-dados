# Arquitetura de Seguranca e Acesso a Dados

Motor de controle de acesso (RBAC) real e testado, aplicado aos
papeis e niveis de sensibilidade ja definidos no
[Projeto 08](https://github.com/amanda-martins-data/governanca-catalogo-dados)
- alem de mascaramento de PII como segunda camada de defesa e uma
trilha de auditoria append-only. Documenta tambem as lacunas de
criptografia de infraestrutura ainda nao aplicadas no
[Projeto 04](https://github.com/amanda-martins-data/iac-pipeline-cloud-qualidade-ar).

Projeto 11 de uma serie documentando minha transicao de Analista de
Dados para Arquitetura de Dados - veja o [perfil
completo](https://github.com/amanda-martins-data).

## Por que este projeto

Governanca (Projeto 08) definiu papeis e classificacao de dados em
prosa e YAML - mas nunca aplicou nenhuma decisao de acesso de fato.
Este projeto fecha essa lacuna: traduz aquelas definicoes em uma
funcao testavel que decide, para cada combinacao de papel e dataset,
se o acesso e concedido - e por que.

## O achado central

Controle de acesso por dataset e mascaramento de campo sao **duas
camadas independentes**, nao uma unica decisao binaria. O papel
`auditor` passa no controle de leitura para um dataset `personal`
(pode confirmar que o registro existe), mas tem os campos PII
mascarados mesmo assim - so `data_owner` ve o valor real. Verificado
por `test_pii_masking_is_a_second_layer_beyond_read_access`. Detalhes
completos em
[docs/02-mascaramento-e-defesa-em-profundidade.md](docs/02-mascaramento-e-defesa-em-profundidade.md).

## Estrutura

```
.
├── docs/
│   ├── 01-modelo-rbac.md                          # hierarquia de papeis e sensibilidade
│   ├── 02-mascaramento-e-defesa-em-profundidade.md # PII, criptografia (lacunas registradas)
│   └── 03-auditoria-e-logging.md                  # o que o AuditLog responde
├── src/
│   ├── access_control.py                          # motor de decisao RBAC
│   └── audit_log.py                                # trilha de auditoria append-only
└── tests/
    ├── test_access_control.py
    └── test_audit_log.py
```

## Como rodar

```bash
pip install -r requirements.txt

# rodar os 22 testes
python -m pytest tests/ -v

# testar uma decisao especifica
python -c "
from src.access_control import Dataset, can_read
d = Dataset('dim_usuario', sensitivity='personal', pii_fields=['nome'])
print(can_read('auditor', d))
"
```

## Validacao

**22/22 testes passando**, incluindo:
- Hierarquia de sensibilidade estritamente decrescente (public >
  internal > confidential > personal em conjunto de papeis com
  acesso).
- Papel desconhecido sempre negado (fail-closed, nao fail-open).
- Permissao de escrita independente de sensibilidade (so depende do
  papel).
- Mascaramento de PII como camada independente do controle de
  leitura.
- Log de auditoria append-only, com calculo de taxa de negacao
  verificado.

Durante a construcao, um teste pegou uma suposicao errada minha:
assumi que o papel `data_consumer` nao deveria ler datasets
`internal`, mas a semantica correta (revisada e documentada em
[docs/01-modelo-rbac.md](docs/01-modelo-rbac.md)) e que `internal`
significa "interno a organizacao", e Data Consumer e um papel
interno - o teste, nao o codigo, estava errado, e foi corrigido.

## Lacunas registradas, nao escondidas

Criptografia em repouso e em transito no Terraform do Projeto 04
ainda nao estao configuradas - documentado explicitamente em
[docs/02-mascaramento-e-defesa-em-profundidade.md](docs/02-mascaramento-e-defesa-em-profundidade.md),
como proximo passo concreto, nao como lacuna escondida.
