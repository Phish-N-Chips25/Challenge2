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

### 5. Customizar Output

```bash
# Definir ficheiro de output
python main.py -o meu_relatorio.txt

# Mostrar mais tarefas no relatório
python main.py --max-display 50

# Salvar cenário para análise posterior
python main.py --save-scenario cenario.json
```

### 6. Comandos Combinados (Uso Real)

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
```

---

## Ficheiros de Dados

### Entrada (pasta `csv/`)
- `servers.csv` - Lista de servidores
- `server_applications.csv` - Software instalado
- `server_windows.csv` - Janelas de manutenção
- `team.csv` - Equipa técnica

### Dataset de CVEs
- `dataset/merged_cve_data.csv` - CVEs reais (206,794 registos)

### Saída
- `relatorio_analise.txt` - Relatório de planeamento (default)
- `data/applied_patches.csv` - Histórico de patches
- `plntdia.log` - Log detalhado de execução

---

## Estatísticas do Dataset

| Métrica | Valor |
|---------|-------|
| Total de CVEs | 206,794 |
| CVEs últimos 60 dias | ~6,936 |
| CVEs HIGH/CRITICAL (infra) | ~11 |
| Software suportado | SQL Server, Exchange, Active Directory, IIS, SharePoint |
