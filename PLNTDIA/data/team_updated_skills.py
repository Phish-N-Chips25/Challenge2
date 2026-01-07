import pandas as pd
import random

# 1. Carregar os ficheiros
team_df = pd.read_csv('team.csv')
cves_df = pd.read_csv('generated_server_cves.csv')

# 2. Obter a lista única de softwares usados nos servidores
unique_softwares = cves_df['software'].unique().tolist()
print(f"Softwares únicos encontrados: {len(unique_softwares)}")

# 3. Preparar a atribuição de skills
techs = team_df.index.tolist()
num_techs = len(techs)

# Lista auxiliar para garantir que todos os softwares são atribuídos pelo menos uma vez
# Copiamos a lista e baralhamo-la para distribuir aleatoriamente pelos primeiros techs
unassigned_softwares = unique_softwares.copy()
random.shuffle(unassigned_softwares)

new_skills_list = []

for i in range(num_techs):
    # Determina número de skills para este funcionário (2 a 4)
    num_skills = random.randint(2, 4)

    current_tech_skills = []

    # Prioridade 1: Atribuir softwares que ainda não foram dados a ninguém
    while len(current_tech_skills) < num_skills and unassigned_softwares:
        skill = unassigned_softwares.pop()
        current_tech_skills.append(skill)

    # Prioridade 2: Preencher o resto das vagas com softwares aleatórios já existentes
    while len(current_tech_skills) < num_skills:
        # Escolhe um software da lista completa, garantindo que não repete o que já tem
        available_choices = [s for s in unique_softwares if s not in current_tech_skills]
        if not available_choices:
            break
        skill = random.choice(available_choices)
        current_tech_skills.append(skill)

    # Juntar com ';' (formato padrão do ficheiro)
    new_skills_list.append(";".join(current_tech_skills))

# Verificação de segurança: Se por acaso algum software ficou de fora (caso haja mais softwares que slots de skills na equipa toda, o que é improvável aqui)
if unassigned_softwares:
    print(f"Atenção: {len(unassigned_softwares)} softwares forçados nos primeiros funcionários.")
    for idx, soft in enumerate(unassigned_softwares):
        tech_idx = idx % num_techs
        current = new_skills_list[tech_idx].split(';')
        if soft not in current:
            current.append(soft)
            new_skills_list[tech_idx] = ";".join(current)

# 4. Atualizar o DataFrame
team_df['skills'] = new_skills_list

# 5. Guardar o ficheiro
output_filename = 'team_updated_skills.csv'
team_df.to_csv(output_filename, index=False)

print("Ficheiro 'team_updated_skills.csv' gerado com sucesso.")
print(team_df[['tech_name', 'skills']].head())