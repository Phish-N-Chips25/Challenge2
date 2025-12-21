import pandas as pd
import os

# Garantir que a pasta data existe
if not os.path.exists('data'):
    os.makedirs('data')

software_distribution = [
    ("SQL Server", "2019", 10.0), # Correntes 001-007
    ("Active Directory", "2016+", 10.0), # Correntes 008-014
    ("Exchange", "2016", 9.0), # Correntes 015-021
    ("IIS", "10.0", 6.0), # Correntes 022-028
    ("Nginx", "1.18", 8.0) # Correntes 029-033
]

servers_data, apps_data, windows_data = [], [], []

for i in range(1, 34):
    chain_num = f"{i:03d}"
    
    # Atribuição de Software
    if i <= 7: sw = [software_distribution[0]]
    elif i <= 14: sw = [software_distribution[1]]
    elif i <= 21: sw = [software_distribution[2]]
    elif i <= 28: sw = [software_distribution[3], ("SharePoint", "Subscription", 7.0)]
    else: sw = [software_distribution[4]]

    envs = [
        ("DEV", 48, "Windows", "Server 2022"),
        ("UAT", 12, "Windows", "Server 2022"),
        ("PROD", 7, "Windows", "Server 2022")
    ]
    
    for env_name, rto, os_name, os_ver in envs:
        srv_id = f"Srv_{env_name}_{chain_num}"
        servers_data.append({"id": srv_id, "os_name": os_name, "os_version": os_ver, "rto_hours": rto})
        
        for s_name, s_ver, s_crit in sw:
            apps_data.append({"server_id": srv_id, "software_id": s_name, "version": s_ver, "criticality": s_crit})
            
        if env_name == "PROD":
            for day in range(1, 5): # 2ª a 5ª
                windows_data.append({"server_id": srv_id, "day": day, "start_h": 1, "end_h": 5})
        else:
            for day in [5, 6]: # Sáb e Dom
                windows_data.append({"server_id": srv_id, "day": day, "start_h": 0, "end_h": 24})

pd.DataFrame(servers_data).to_csv("data/servers.csv", index=False)
pd.DataFrame(apps_data).to_csv("data/server_applications.csv", index=False)
pd.DataFrame(windows_data).to_csv("data/server_windows.csv", index=False)

print("✅ Ficheiros data/servers.csv, data/server_applications.csv e data/server_windows.csv criados!")