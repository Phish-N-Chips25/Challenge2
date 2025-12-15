# Ficheiro: src/config.py

# --- Configurações da Simulação ---
HORIZON_HOURS = 168
TOTAL_STAFF = 0  # Ignorado (usamos lista de operators)

# --- Pesos do Algoritmo Genético (MODO DE APRENDIZAGEM) ---

# Recompensa MASSIVA por resolver patches (para garantir score > 0)
WEIGHT_RISK = 5000.0     

# Penalidades LEVES (para ele não ir logo para zero)
PENALTY_WINDOW = 100.0   # Se falhar a janela, perde pouco (mas perde)
PENALTY_STAFF = 100.0    # Se falhar staff, perde pouco

# Penalidades GRAVES (estas mantemos altas porque são impossíveis físicos)
PENALTY_RTO = 10000.0