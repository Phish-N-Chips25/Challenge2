import pandas as pd
import random

# 1. Carregar os dados
cves_df = pd.read_csv('cves_windows_ready_for_loader.csv')


# 2. Função para pontuar a compatibilidade das CVEs
# Prioridade: Windows (2), Software Comum de Servidor (1), Outros (0), Incompatível (-1)
def score_compatibility(software_name):
    software_name = str(software_name).lower()

    # Prioridade Máxima: Windows e Microsoft
    if 'microsoft' in software_name or 'windows' in software_name:
        return 2

    # Prioridade Média: Software comum em servidores (Enterprise/Web/DB)
    common_apps = ['adobe', 'google', 'apache', 'vmware', 'sap', 'solarwinds',
                   'zoho', 'ivanti', 'oracle', 'ibm', 'citrix', 'symantec',
                   'gitlab', 'jenkins', 'mysql', 'sql', 'postgresql', 'nginx']
    if any(app in software_name for app in common_apps):
        return 1

    # Excluir explicitamente incompatíveis (Mobile, Hardware doméstico, etc.)
    exclusions = ['firmware', 'router', 'android', 'ios', 'iphone', 'camera',
                  'dlink', 'tenda', 'netgear', 'tp-link']
    if any(ex in software_name for ex in exclusions):
        return -1

    return 0


# 3. Aplicar filtro e seleção
cves_df['compatibility_score'] = cves_df['software'].apply(score_compatibility)

# Filtra incompatíveis e ordena por pontuação
compatible_cves = cves_df[cves_df['compatibility_score'] >= 0].copy()
compatible_cves = compatible_cves.sort_values(by='compatibility_score', ascending=False)

# Seleciona as top 20 CVEs
selected_cves = compatible_cves.head(20).reset_index(drop=True)

# 4. Gerar a lista de servidores e aplicações
output_rows = []

# Loop para criar 100 conjuntos de servidores (001 a 100)
for i in range(1, 101):
    # Escolhe aleatoriamente entre 1 e 3 CVEs para aplicar a este conjunto de servidores
    num_cves_for_server = random.randint(1, 7)

    # Seleciona as CVEs aleatoriamente da nossa pool de 20
    server_cves = selected_cves.sample(n=num_cves_for_server)

    # Define os IDs dos servidores
    srv_dev = f"Srv_DEV_{i:03d}"
    srv_uat = f"Srv_UAT_{i:03d}"
    srv_prod = f"Srv_PROD_{i:03d}"

    for _, cve_row in server_cves.iterrows():
        # Extrai dados da CVE
        cve_data = [
            cve_row['id'],
            cve_row['severity'],
            cve_row['epss'],
            cve_row['software'],
            cve_row['version']
        ]

        # Adiciona a entrada para os 3 ambientes (DEV, UAT, PROD) com a mesma CVE
        output_rows.append([srv_dev] + cve_data)
        output_rows.append([srv_uat] + cve_data)
        output_rows.append([srv_prod] + cve_data)

# 5. Criar DataFrame e Salvar
columns = ['server_id', 'cve_id', 'severity', 'epss', 'software', 'version']
result_df = pd.DataFrame(output_rows, columns=columns)

# Salvar para CSV
result_df.to_csv('generated_server_cves.csv', index=False)
print("Ficheiro 'generated_server_cves.csv' gerado com sucesso.")