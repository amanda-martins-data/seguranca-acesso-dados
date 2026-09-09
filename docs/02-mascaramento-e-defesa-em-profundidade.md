# 02. Mascaramento de PII e Defesa em Profundidade

## O achado central deste projeto

Controle de acesso por dataset (documento 01) responde "quem pode
ver este dataset existe e ler dele". Mas isso nao e a mesma pergunta
que "quem pode ver o valor real de cada campo sensivel dentro dele".
Este projeto implementa as duas perguntas como **duas camadas
independentes** - exatamente o mesmo principio de defesa em
profundidade ja aplicado ao isolamento multi-tenant do
[Projeto 09](https://github.com/amanda-martins-data/blueprint-arquitetura-corporativa/blob/main/04-modelo-fisico.md#decisao-nova-isolamento-fisico-de-dados-entre-municipios).

`test_pii_masking_is_a_second_layer_beyond_read_access` demonstra
isso de forma concreta: o papel `auditor` **passa** no controle de
leitura para um dataset `personal` (`can_read` retorna `granted=True`),
mas os campos declarados em `pii_fields` (ex.: `nome`, `email`) sao
mascarados mesmo assim - o auditor sabe que o registro existe e pode
inspecionar campos nao-PII, mas nao ve o dado pessoal em si, a menos
que tenha o papel `data_owner`.

## Por que isso importa na pratica

Um sistema real de auditoria frequentemente precisa confirmar "este
registro existe e tem estas caracteristicas" sem precisar expor o
dado pessoal - por exemplo, confirmar que um Operador Municipal
(cenario do [Projeto 09](https://github.com/amanda-martins-data/blueprint-arquitetura-corporativa))
tem uma linha em `dim_usuario` associada a um municipio_id correto,
sem que o processo de auditoria precise ver o nome e e-mail da
pessoa. Uma unica camada de controle (so `can_read`, tudo-ou-nada)
nao consegue expressar essa diferenca - e por isso o mascaramento
existe como uma segunda camada, nao como parte da mesma decisao.

## Como o mascaramento funciona

```python
from access_control import Dataset, mask_row

usuario = Dataset(
    "dim_usuario",
    sensitivity="personal",
    pii_fields=["nome", "email", "cargo"],
)

row = {"nome": "Joao Silva", "email": "joao@example.com", "municipio_id": "SP"}

mask_row(row, usuario, role="auditor")
# {"nome": "***REDACTED***", "email": "***REDACTED***", "municipio_id": "SP"}

mask_row(row, usuario, role="data_owner")
# {"nome": "Joao Silva", "email": "joao@example.com", "municipio_id": "SP"}
```

Campos que nao estao em `pii_fields` (ex.: `municipio_id`) nunca sao
mascarados, independente do papel - o mascaramento e cirurgico, por
campo, nao um bloqueio do registro inteiro.

## Garantia de imutabilidade

`test_mask_row_never_mutates_original_row` garante que `mask_row`
nunca altera o dicionario original passado como argumento - sempre
retorna uma copia. Isso evita uma classe inteira de bug sutil: um
mascaramento aplicado para exibicao que acidentalmente corrompe o
dado em memoria antes de outra parte do sistema (ex.: o proprio
pipeline de escrita) precisar do valor real.

## Criptografia em transito e em repouso (nao implementado em codigo)

Mascaramento de PII na camada de aplicacao nao substitui
criptografia de infraestrutura - sao controles complementares:

- **Em repouso**: os buckets S3 (Bronze/Silver do
  [Projeto 04](https://github.com/amanda-martins-data/iac-pipeline-cloud-qualidade-ar))
  deveriam ter `server_side_encryption_configuration` habilitado
  (SSE-S3 ou SSE-KMS); o RDS Postgres deveria ter
  `storage_encrypted = true`. Nenhuma dessas configuracoes esta
  presente no Terraform atual do Projeto 04 - e uma lacuna real,
  registrada aqui explicitamente, nao escondida.
- **Em transito**: conexoes ao RDS deveriam forcar TLS
  (`rds.force_ssl = 1` via parameter group); chamadas a API HTTP de
  ingestao (documento 05 do Blueprint) deveriam ser exclusivamente
  HTTPS.

Estas mudancas nao foram implementadas neste projeto porque exigiriam
alterar e reaplicar o Terraform do Projeto 04 contra uma conta AWS
real - ficam registradas aqui como o proximo passo concreto, não
como um "seria bom ter" vago.
