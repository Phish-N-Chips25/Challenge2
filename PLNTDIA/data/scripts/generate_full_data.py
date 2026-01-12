import csv
import random

# --- CONFIGURAÇÕES ---
NUM_CHAINS = 100  # 100 Cadeias = 300 Servidores
NUM_TECHS = 50    # Equipa robusta

def generate_servers(filename="data/servers.csv"):
    print(f"-> A gerar {NUM_CHAINS * 3} servidores em '{filename}'...")
    header = ["id", "os_name", "os_version", "rto_hours"]
    
    # Pesos para RTO
    rto_uat_opts = [12, 3]
    rto_uat_weights = [0.90, 0.10]
    rto_prod_opts = [7, 3, 2]
    rto_prod_weights = [0.70, 0.20, 0.10]

    with open(filename, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(header)

        for i in range(1, NUM_CHAINS + 1):
            str_id = f"{i:03d}"
            # DEV
            writer.writerow([f"Srv_DEV_{str_id}", "Windows", "Server 2022", "48"])
            # UAT
            rto_u = random.choices(rto_uat_opts, weights=rto_uat_weights)[0]
            writer.writerow([f"Srv_UAT_{str_id}", "Windows", "Server 2022", str(rto_u)])
            # PROD
            rto_p = random.choices(rto_prod_opts, weights=rto_prod_weights)[0]
            writer.writerow([f"Srv_PROD_{str_id}", "Windows", "Server 2022", str(rto_p)])
            
    print("✅ servers.csv gerado.")

def generate_team(filename="data/team.csv"):
    print(f"-> A gerar {NUM_TECHS} técnicos em '{filename}'...")
    header = ["tech_id", "tech_name", "level", "skills", "work_start_h", "lunch_start_h", "lunch_end_h", "work_end_h", "on_call", "work_days"]
    
    first_names = ["Ana", "João", "Maria", "Pedro", "Inês", "Ricardo", "Sofia", "Miguel", "Carla", "Tiago", "Rui", "Joana", "André", "Beatriz", "Hugo", "Diana", "Bruno", "Cátia", "Diogo", "Elsa"]
    last_names = ["Silva", "Pereira", "Costa", "Santos", "Rodrigues", "Fernandes", "Almeida", "Teixeira", "Nunes", "Lopes", "Martins", "Gomes", "Ferreira", "Sousa", "Oliveira", "Ribeiro", "Pinto", "Carvalho", "Dias", "Moreira"]
    all_skills = ["Patch Management", "Security Hardening", "Active Directory", "Exchange", "SQL Server", "SharePoint", "IIS", "Windows Server", "Backup & Recovery", "Nginx", "Linux Administration", "Firewall Mgmt"]

    with open(filename, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(header)

        for i in range(1, NUM_TECHS + 1):
            t_id = f"Tech_{i:02d}"
            name = f"{random.choice(first_names)} {random.choice(last_names)}"
            level = random.choices(["Senior", "Mid", "Junior"], weights=[0.3, 0.4, 0.3])[0]
            k = 5 if level == "Senior" else (4 if level == "Mid" else 3)
            my_skills = ";".join(random.sample(all_skills, k=k))
            
            # Tipos de Horário
            schedule_type = random.choices([1, 2, 3, 4], weights=[0.50, 0.20, 0.15, 0.15])[0]
            if schedule_type == 1: start_h, days = 9.0, "0;1;2;3;4"
            elif schedule_type == 2: start_h, days = 7.0, "0;1;2;3;4"
            elif schedule_type == 3: start_h, days = 14.0, "0;1;2;3;4"
            else: start_h, days = 10.0, "4;5;6;0;1"
            
            lunch_start = start_h + 4.0
            lunch_end = lunch_start + 1.0
            end_h = start_h + 9.0
            
            is_on_call = 0
            if level == "Senior": is_on_call = 1 if random.random() < 0.8 else 0
            elif level == "Mid": is_on_call = 1 if random.random() < 0.4 else 0
            
            writer.writerow([t_id, name, level, my_skills, start_h, lunch_start, lunch_end, end_h, is_on_call, days])

    print("✅ team.csv gerado.")

def generate_applications(filename="data/server_applications.csv"):
    """
    Distribui os softwares uniformemente pelas 100 cadeias.
    """
    print(f"-> A gerar aplicações para {NUM_CHAINS} cadeias em '{filename}'...")
    header = ["server_id", "software_id", "version", "criticality"]
    
    with open(filename, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(header)

        for i in range(1, NUM_CHAINS + 1):
            str_id = f"{i:03d}"
            servers = [f"Srv_DEV_{str_id}", f"Srv_UAT_{str_id}", f"Srv_PROD_{str_id}"]
            
            # Lógica de distribuição baseada no ID (Ciclo de 5 grupos)
            # 01-20: SQL, 21-40: AD, 41-60: Exchange, 61-80: IIS+SharePoint, 81-100: Nginx
            
            if 1 <= i <= 20:
                app, ver, crit = "SQL Server", "2019", "10.0"
                for srv in servers: writer.writerow([srv, app, ver, crit])
            
            elif 21 <= i <= 40:
                app, ver, crit = "Active Directory", "2016+", "10.0"
                for srv in servers: writer.writerow([srv, app, ver, crit])
                
            elif 41 <= i <= 60:
                app, ver, crit = "Exchange", "2016", "9.0"
                for srv in servers: writer.writerow([srv, app, ver, crit])
            
            elif 61 <= i <= 80:
                # Este grupo tem DUAS apps por servidor
                for srv in servers:
                    writer.writerow([srv, "IIS", "10.0", "6.0"])
                    writer.writerow([srv, "SharePoint", "Subscription", "7.0"])
            
            else: # 81-100
                app, ver, crit = "Nginx", "1.18", "8.0"
                for srv in servers: writer.writerow([srv, app, ver, crit])

    print("✅ server_applications.csv gerado.")

def generate_windows(filename="data/server_windows.csv"):
    """
    Aplica as regras de janela de manutenção a TODOS os servidores.
    """
    print(f"-> A gerar janelas de manutenção em '{filename}'...")
    header = ["server_id", "day", "start_h", "end_h"]
    
    with open(filename, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(header)

        for i in range(1, NUM_CHAINS + 1):
            str_id = f"{i:03d}"
            
            # --- DEV (Sábado e Domingo, Dia Todo) ---
            dev_srv = f"Srv_DEV_{str_id}"
            writer.writerow([dev_srv, "5", "0", "24"]) # Sábado
            writer.writerow([dev_srv, "6", "0", "24"]) # Domingo
            
            # --- UAT (Sábado e Domingo, Dia Todo) ---
            uat_srv = f"Srv_UAT_{str_id}"
            writer.writerow([uat_srv, "5", "0", "24"])
            writer.writerow([uat_srv, "6", "0", "24"])
            
            # --- PROD (Terça a Sexta, 01h-05h) ---
            prod_srv = f"Srv_PROD_{str_id}"
            writer.writerow([prod_srv, "1", "1", "5"]) # Terça
            writer.writerow([prod_srv, "2", "1", "5"]) # Quarta
            writer.writerow([prod_srv, "3", "1", "5"]) # Quinta
            writer.writerow([prod_srv, "4", "1", "5"]) # Sexta

    print("✅ server_windows.csv gerado.")

if __name__ == "__main__":
    generate_servers()
    generate_team()
    generate_applications()
    generate_windows()
    print("\n🚀 INFRAESTRUTURA COMPLETA GERADA COM SUCESSO!")