# Prowler na AWS com Python e profiles

Executa todos os checks AWS disponíveis no Prowler instalado, uma conta/profile por vez. Usa seus profiles existentes, mostra a conta via boto3/STS e salva relatórios HTML, CSV e JSON-OCSF em pastas separadas.

O script chama a CLI oficial com o mesmo Python do ambiente virtual. Não usa filtros de checks, serviços, severidades, compliance ou regiões e inclui `--scan-unused-services`, para avaliar também serviços/recursos sem uso. Não ativa remediação automática ou envio de relatórios para integrações.

## 1. Pré-requisitos

- Python **3.10 a 3.13** (sugestão: 3.12).
- Profiles AWS já configurados na máquina.
- Acesso de rede às APIs AWS. AWS CLI v2 é necessária se você usa `aws sso login`.

Na identidade final de cada profile (usuário ou role assumida), confira as permissões indicadas pelo Prowler:

- `arn:aws:iam::aws:policy/SecurityAudit`
- `arn:aws:iam::aws:policy/job-function/ViewOnlyAccess`
- A política complementar oficial [prowler-additions-policy.json da versão utilizada](https://github.com/prowler-cloud/prowler/blob/5.46.0/permissions/prowler-additions-policy.json).

Se faltarem permissões, peça o ajuste ao responsável pelo IAM. A chamada STS valida a identidade; ela não comprova permissão para todos os checks. SCPs, permission boundaries e restrições de região também podem limitar a coleta.

## 2. Instalar

Abra o terminal na pasta que contém este README e o script.

**Windows / PowerShell** — os comandos usam diretamente o Python do venv, sem precisar ativá-lo:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m prowler -v
```

Se já tem Python 3.10, 3.11 ou 3.13, ajuste `-3.12` para a versão instalada. O boto3 do seu ambiente atual não precisa ser alterado: o venv instala as dependências compatíveis com o Prowler.

**Linux / macOS**:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m prowler -v
```

Nos exemplos abaixo, `python` significa o Python do venv. No PowerShell, substitua `python` por `.\.venv\Scripts\python.exe`.

## 3. Conferir os profiles

```bash
python scan_aws.py --list-profiles
```

Se o profile usa SSO/IAM Identity Center, renove o login antes da varredura:

```bash
aws sso login --profile producao
```

Repita para as sessões necessárias. Os profiles vêm dos arquivos padrão `~/.aws/config` e `~/.aws/credentials` (no Windows, em `%USERPROFILE%\.aws`). Configurações `AWS_CONFIG_FILE` e `AWS_SHARED_CREDENTIALS_FILE` também são respeitadas pelo SDK. Profiles com roles seguem a configuração existente, incluindo `source_profile`.

## 4. Executar a varredura

Troque os nomes pelos seus profiles reais.

**Uma conta:**

```bash
python scan_aws.py --profiles producao
```

**Várias contas:**

```bash
python scan_aws.py --profiles producao homologacao desenvolvimento
```

**Todos os profiles locais, incluindo `default` se existir:**

```bash
python scan_aws.py --all-profiles
```

**Ver os comandos antes, sem chamadas AWS:**

```bash
python scan_aws.py --all-profiles --dry-run
```

Para mudar a pasta de saída:

```bash
python scan_aws.py --profiles producao --output-dir meus-relatorios
```

Cada profile representa uma execução. Profiles diferentes para a mesma conta repetem a varredura; profiles de origem usados apenas para assumir roles também entram em `--all-profiles`. Use `--profiles` para escolher só as contas desejadas. O script não descobre automaticamente contas do AWS Organizations.

## 5. Ler os resultados

Os relatórios ficam em `reports/<data-hora-UTC>/<numero>_<profile>/`. Abra o arquivo **HTML** no navegador; use CSV para análise tabular e JSON-OCSF para automação. Relatórios de compliance gerados pelo Prowler ficam na subpasta `compliance/`.

O arquivo `reports/<data-hora-UTC>/resumo.json` registra profile, conta identificada, pasta, status e código retornado pelo Prowler. Uma falha em um profile não impede a tentativa nos seguintes.

| Código do script | Significado |
| --- | --- |
| `0` | Prowler terminou sem sinalizar achados FAIL, ou comando de listagem/simulação concluído. |
| `3` | Prowler terminou e sinalizou achados FAIL; consulte os relatórios. |
| `1` | Houve erro operacional em pelo menos um profile; revise a saída do terminal e o resumo. |
| `2` | Argumento inválido, profile ausente ou dependência faltando. |
| `130` | Interrompido com Ctrl+C. |

**Cobertura:** “todos” significa todos os checks AWS incluídos na versão instalada, dentro das regiões suportadas/acessíveis da partição da conta. Não é garantia de verificar toda possível condição de segurança da AWS. Ausência de recursos, serviços indisponíveis, credenciais expiradas e permissões insuficientes podem deixar checks sem resultados. Mesmo com código `0` ou `3`, revise erros/`AccessDenied` no terminal e resultados manuais. Não considere ausência de achados como evidência de cobertura completa.

Se houver `PROWLER_AWS_DISALLOWED_REGIONS` ou configurações externas de exclusão no ambiente, elas podem reduzir a cobertura. Para GovCloud/China, configure no profile uma região da partição correspondente.

## Problemas comuns

- **Token expirado / SSO:** refaça `aws sso login --profile NOME` ou renove as credenciais temporárias e execute novamente. Faça o mesmo se expirarem durante a coleta.
- **AccessDenied:** confira as políticas da identidade final, SCPs e boundaries; depois repita a varredura.
- **Prowler não encontrado:** instale `requirements.txt` usando o mesmo Python que executa o script.
- **Throttling ou demora:** a coleta completa faz muitas chamadas; aguarde a execução sequencial e consulte os erros no terminal. Não há tempo fixo de conclusão.

## Referências

- [Instalação oficial](https://docs.prowler.com/getting-started/installation/prowler-cli)
- [Uso da CLI e listagem de checks](https://docs.prowler.com/getting-started/basic-usage/prowler-cli) — consulte o catálogo instalado com `python -m prowler aws --list-checks`.
- [Permissões AWS](https://docs.prowler.com/user-guide/providers/aws/authentication)
- [Serviços sem uso](https://docs.prowler.com/user-guide/cli/tutorials/scan-unused-services)
- [Regiões e partições](https://docs.prowler.com/user-guide/providers/aws/regions-and-partitions)
- [Relatórios](https://docs.prowler.com/user-guide/cli/tutorials/reporting)

Validação da entrega: script verificado localmente com simulações de STS e da execução do Prowler. Não foi executada uma varredura real nas suas contas AWS.
