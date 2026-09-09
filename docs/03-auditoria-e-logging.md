# 03. Auditoria e Logging

## Toda decisao e um objeto, nunca um booleano solto

`can_read` e `can_write` (documento 01) nunca retornam apenas
`True`/`False` - retornam um `AccessDecision`, com o papel, o
dataset, a acao, o resultado, o motivo em texto e um timestamp. Essa
escolha de design existe unicamente para tornar o log de auditoria
possivel: um booleano solto nao carrega informacao suficiente para
reconstruir "quem tentou o que, quando, e por que foi negado".

## O que o `AuditLog` responde

`audit_log.py` implementa um log append-only (`record()` e a unica
forma de adicionar uma entrada - nao ha metodo de remocao ou edicao,
verificado por `test_log_is_append_only_in_practice`) com quatro
consultas:

- **`denied_attempts()`**: todas as tentativas negadas - a primeira
  consulta que se faz ao investigar um incidente de seguranca.
- **`attempts_for_dataset(nome)`**: historico de acesso de um
  dataset especifico.
- **`attempts_by_role(papel)`**: historico de um papel especifico -
  util para auditar o comportamento de uma credencial suspeita.
- **`denial_rate()`**: proporcao de tentativas negadas sobre o
  total.

## Por que `denial_rate()` importa

Uma taxa de negacao anormalmente alta e, na pratica, quase sempre um
sintoma de configuracao errada (uma credencial com o papel errado,
um servico apontando para o dataset errado) e nao de um ataque -
mas em ambos os casos, e um sinal que vale a pena monitorar. O
teste `test_denial_rate_computes_correct_proportion` confirma que o
calculo (negados / total) esta correto com um exemplo simples: 3 de
4 tentativas negadas resulta em `0.75`.

## Onde isso se conectaria a infraestrutura real

Em uma implantacao real, cada chamada a `can_read`/`can_write` no
pipeline do [Projeto 04](https://github.com/amanda-martins-data/iac-pipeline-cloud-qualidade-ar)
registraria a decisao no `AuditLog`, e o log seria persistido de
forma imutavel - o candidato natural e o mesmo padrao de Bronze
imutavel particionada por data do
[ADR 0002](https://github.com/amanda-martins-data/adr-arquitetura-dados/blob/main/decisions/0002-particionamento-bronze-ingestion-vs-silver-measured.md),
aplicado a logs de acesso em vez de leituras de sensor. Isso nao foi
implementado neste projeto (ficaria em memoria, como esta agora) -
e um proximo passo natural, nao uma limitacao escondida.

## Retencao de log de auditoria

Diferente dos dados de negocio, logs de auditoria de acesso a dados
pessoais tem exigencia de retencao propria sob a LGPD - tipicamente
mais longa que a retencao do proprio dado, ja que o log precisa
sobreviver o suficiente para investigar um incidente que so foi
percebido meses depois. Isso nao foi modelado em codigo neste
projeto (seria um campo `retention_days` proprio no `AuditLog`,
seguindo o mesmo padrao do catalogo do
[Projeto 08](https://github.com/amanda-martins-data/governanca-catalogo-dados)),
mas fica registrado como decisao pendente, nao ignorada.
