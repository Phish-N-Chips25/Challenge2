# PLNTDIA - Opções CLI

## Uso Básico

```bash
python main.py [opções]
```

## Opções Disponíveis

### Fonte de CVEs

| Opção | Descrição | Default |
|-------|-----------|---------|
| `-c, --cves N` | Número de CVEs sintéticos a gerar | 50 |
| `--dataset PATH` | Usar CVEs reais do dataset (ex: `dataset/merged_cve_data.csv`) | - |

> **Nota:** As opções `-c` e `--dataset` são mutuamente exclusivas.

### Filtros de Data (requer `--dataset`)

| Opção | Descrição | Default |
|-------|-----------|---------|
| `--days N` | CVEs dos últimos N dias | 30 |
| `--period PERÍODO` | Período temporal em linguagem natural (ver exemplos abaixo) | - |
| `--month MM` | CVEs de um mês específico (ex: `12` ou `2025-01`) | - |
| `--year YYYY` | Ano para o filtro de mês | ano atual |
| `--min-severity LEVEL` | Severidade mínima: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | LOW |

#### Formatos Aceites para `--period`

| Período | Dias |
|---------|------|
| `1 semana` / `1 week` | 7 |
| `2 semanas` / `2 weeks` | 14 |
| `1 mês` / `1 mes` / `1 month` | 30 |
| `3 meses` / `3 months` | 90 |
| `1 ano` / `1 year` | 365 |
| `15 dias` / `15 days` | 15 |

### Tracking de Patches

| Opção | Descrição | Default |
|-------|-----------|---------|
| `--track-patches` | Registar patches agendados no histórico | desativado |
| `--patch-history PATH` | Ficheiro de histórico de patches | `data/applied_patches.csv` |
| `--skip-applied` | Ignorar CVEs já aplicados aos servidores | desativado |
| `--patch-report PATH` | Gerar relatório de patches aplicados | - |

### Disponibilidade da Equipa

| Opção | Descrição | Default |
|-------|-----------|---------|
| `--vacations PATH` | Ficheiro CSV de férias/ausências | `csv/team_vacations.csv` |
| `--ignore-vacations` | Ignorar férias/ausências no planeamento | desativado |
| `--start-date YYYY-MM-DD` | Data de início do planeamento | hoje |
| `--show-availability` | Mostrar resumo de disponibilidade da equipa | desativado |

### Dependências de Pipeline (DEV → TEST → PROD)

| Opção | Descrição | Default |
|-------|-----------|---------|
| `--enforce-dependencies` | Bloquear patches em PROD se não foram testados em TEST | desativado |
| `--show-pipeline` | Mostrar estado do pipeline de deployment | desativado |

### Configuração Geral

| Opção | Descrição | Default |
|-------|-----------|---------|
| `--csv-path PATH` | Caminho para a pasta CSV com dados da infraestrutura | `./csv` |
| `--seed N` | Seed para reprodutibilidade | 42 |
| `-o, --output FILE` | Ficheiro de output do relatório | `relatorio_analise.txt` |
| `-v, --verbose` | Modo verbose com mais detalhes | desativado |
| `--save-scenario FILE` | Salvar cenário gerado em ficheiro JSON | - |
| `--max-display N` | Máximo de tarefas a mostrar no relatório | 20 |

---

## Exemplos de Uso

### 1. Execução Básica (CVEs Sintéticos)

```bash
# Gerar 50 CVEs sintéticos (default)
python main.py

# Gerar 100 CVEs sintéticos
python main.py -c 100

# Com modo verbose
python main.py -c 100 -v
```

### 2. Usar Dataset Real de CVEs

```bash
# CVEs dos últimos 30 dias (default)
python main.py --dataset dataset/merged_cve_data.csv

# CVEs dos últimos 60 dias
python main.py --dataset dataset/merged_cve_data.csv --days 60

# Usando período em linguagem natural
python main.py --dataset dataset/merged_cve_data.csv --period "1 semana"
python main.py --dataset dataset/merged_cve_data.csv --period "2 semanas"
python main.py --dataset dataset/merged_cve_data.csv --period "1 mês"
python main.py --dataset dataset/merged_cve_data.csv --period "3 meses"

# CVEs de Janeiro 2025
python main.py --dataset dataset/merged_cve_data.csv --month 2025-01

# CVEs de Dezembro do ano atual
python main.py --dataset dataset/merged_cve_data.csv --month 12
```

### 3. Filtrar por Severidade

```bash
# Apenas CVEs HIGH e CRITICAL
python main.py --dataset dataset/merged_cve_data.csv --min-severity HIGH

# Apenas CVEs CRITICAL
python main.py --dataset dataset/merged_cve_data.csv --min-severity CRITICAL
```

### 4. Tracking de Patches

```bash
# Registar patches agendados no histórico
python main.py --dataset dataset/merged_cve_data.csv --track-patches

# Ignorar CVEs já aplicados (útil para re-execuções)
python main.py --dataset dataset/merged_cve_data.csv --skip-applied

# Combinar: registar novos e ignorar já aplicados
python main.py --dataset dataset/merged_cve_data.csv --track-patches --skip-applied

# Gerar relatório de patches aplicados
python main.py --patch-report relatorio_patches.txt
```

### 5. Disponibilidade da Equipa e Férias

```bash
# Usar ficheiro de férias personalizado
python main.py --dataset dataset/merged_cve_data.csv --vacations csv/team_vacations.csv

# Ignorar férias no planeamento (agendar mesmo com pessoal em férias)
python main.py --dataset dataset/merged_cve_data.csv --ignore-vacations

# Mostrar resumo de disponibilidade da equipa
python main.py --dataset dataset/merged_cve_data.csv --show-availability

# Definir data de início do planeamento
python main.py --dataset dataset/merged_cve_data.csv --start-date 2025-01-06

# Combinar: verificar disponibilidade antes de planear
python main.py --dataset dataset/merged_cve_data.csv --show-availability --start-date 2025-01-06 -v
```

### 6. Dependências de Pipeline (DEV → TEST → PROD)

```bash
# Bloquear patches em PROD se não foram testados em TEST
python main.py --dataset dataset/merged_cve_data.csv --enforce-dependencies

# Mostrar estado do pipeline de deployment
python main.py --dataset dataset/merged_cve_data.csv --show-pipeline

# Combinar: pipeline com dependências forçadas
python main.py --dataset dataset/merged_cve_data.csv --enforce-dependencies --show-pipeline -v
```

### 7. Customizar Output

```bash
# Definir ficheiro de output
python main.py -o meu_relatorio.txt

# Mostrar mais tarefas no relatório
python main.py --max-display 50

# Salvar cenário para análise posterior
python main.py --save-scenario cenario.json
```

### 8. Comandos Combinados (Uso Real)

```bash
# Análise completa: CVEs HIGH dos últimos 60 dias, tracking ativo
python main.py \
  --dataset dataset/merged_cve_data.csv \
  --days 60 \
  --min-severity HIGH \
  --track-patches \
  --skip-applied \
  -o relatorio_semanal.txt \
  -v

# Planeamento mensal de patches críticos
python main.py \
  --dataset dataset/merged_cve_data.csv \
  --month 2025-01 \
  --min-severity CRITICAL \
  --track-patches \
  --patch-report patches_janeiro.txt \
  -o plano_janeiro.txt

# Planeamento com verificação de férias e dependências
python main.py \
  --dataset dataset/merged_cve_data.csv \
  --days 30 \
  --min-severity HIGH \
  --show-availability \
  --enforce-dependencies \
  --show-pipeline \
  --start-date 2025-01-13 \
  -o plano_completo.txt \
  -v

# Planeamento para próxima semana, ignorando férias
python main.py \
  --dataset dataset/merged_cve_data.csv \
  --period "1 semana" \
  --min-severity MEDIUM \
  --ignore-vacations \
  --track-patches \
  -o plano_urgente.txt
```

---

## Ficheiros de Dados

### Entrada (pasta `csv/`)
| Ficheiro | Descrição |
|----------|-----------|
| `servers.csv` | Lista de servidores (DEV, TEST, PROD) |
| `server_applications.csv` | Software instalado em cada servidor |
| `server_windows.csv` | Janelas de manutenção por servidor |
| `team.csv` | Equipa técnica (nome, nível, skills, horários) |
| `team_vacations.csv` | Férias e ausências da equipa |
| `holidays.csv` | Feriados nacionais/empresa |

### Dataset de CVEs
| Ficheiro | Descrição |
|----------|-----------|
| `dataset/merged_cve_data.csv` | CVEs reais (~206,794 registos) |

### Saída
| Ficheiro | Descrição |
|----------|-----------|
| `relatorio_analise.txt` | Relatório de planeamento (default) |
| `data/applied_patches.csv` | Histórico de patches aplicados |
| `plntdia.log` | Log detalhado de execução |

---

## Resumo de Todas as Opções

```bash
python main.py --help
```

```
usage: main.py [-h] [-c CVES | --dataset PATH] [--days N] [--period PERÍODO]
               [--month MM] [--year YYYY] [--min-severity {LOW,MEDIUM,HIGH,CRITICAL}]
               [--track-patches] [--patch-history PATH] [--skip-applied]
               [--patch-report PATH] [--vacations PATH] [--ignore-vacations]
               [--start-date YYYY-MM-DD] [--show-availability]
               [--enforce-dependencies] [--show-pipeline] [--csv-path PATH]
               [--seed N] [-o FILE] [-v] [--save-scenario FILE] [--max-display N]

PLNTDIA - Sistema de Planeamento de Patches

Fonte de CVEs:
  -c, --cves N            Número de CVEs sintéticos a gerar (default: 50)
  --dataset PATH          Usar CVEs reais do dataset

Filtros de Data (requer --dataset):
  --days N                CVEs dos últimos N dias (default: 30)
  --period PERÍODO        Período temporal: "1 semana", "2 meses", etc.
  --month MM              CVEs de um mês específico (ex: 12 ou 2025-01)
  --year YYYY             Ano para o filtro de mês
  --min-severity LEVEL    Severidade mínima: LOW, MEDIUM, HIGH, CRITICAL

Tracking de Patches:
  --track-patches         Registar patches agendados no histórico
  --patch-history PATH    Ficheiro de histórico de patches
  --skip-applied          Ignorar CVEs já aplicados aos servidores
  --patch-report PATH     Gerar relatório de patches aplicados

Disponibilidade da Equipa:
  --vacations PATH        Ficheiro CSV de férias/ausências
  --ignore-vacations      Ignorar férias/ausências no planeamento
  --start-date YYYY-MM-DD Data de início do planeamento (default: hoje)
  --show-availability     Mostrar resumo de disponibilidade da equipa

Dependências de Pipeline:
  --enforce-dependencies  Bloquear patches em PROD se não testados em TEST
  --show-pipeline         Mostrar estado do pipeline de deployment

Configuração Geral:
  --csv-path PATH         Caminho para a pasta CSV (default: ./csv)
  --seed N                Seed para reprodutibilidade (default: 42)
  -o, --output FILE       Ficheiro de output (default: relatorio_analise.txt)
  -v, --verbose           Modo verbose com mais detalhes
  --save-scenario FILE    Salvar cenário gerado em ficheiro JSON
  --max-display N         Máximo de tarefas a mostrar (default: 20)
```

---

## Estatísticas do Dataset

| Métrica | Valor |
|---------|-------|
| Total de CVEs | ~206,794 |
| CVEs últimos 60 dias | ~6,936 |
| CVEs HIGH/CRITICAL (infra) | ~11 |
| Software suportado | SQL Server, Exchange, Active Directory, IIS, SharePoint, etc. |
| Servidores na infra | 60 (20 DEV + 20 TEST + 20 PROD) |
| Técnicos na equipa | 10 (4 Senior, 4 Mid, 2 Junior) |
