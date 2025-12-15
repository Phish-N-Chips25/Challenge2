# Ficheiro: main.py
from src.utils import generate_random_infrastructure
from src.optimizer import run_genetic_algorithm, DAYS_MAP, get_day_and_hour

def main():
    print("\n=== SISTEMA INTELIGENTE DE PATCHING (ESCALA LARGA) ===\n")

    # 1. Gerar Infraestrutura Randomizada
    # 15 Servidores, 40 Patches, 6 Técnicos
    print("-> A gerar cenário aleatório...")
    servers, patches, operators = generate_random_infrastructure(
        n_servers=15, 
        n_patches=40, 
        n_ops=6
    )
    
    print(f"-> Cenário Criado:")
    print(f"   - Servidores: {len(servers)}")
    print(f"   - Patches: {len(patches)}")
    print(f"   - Técnicos: {len(operators)}")

    # 2. Executar Otimização
    print("\n-> A iniciar otimização genética...")
    best_schedule = run_genetic_algorithm(servers, patches, operators)

    # 3. Análise e Relatório do Plano
    print("\n=== RELATÓRIO DE EXECUÇÃO ===")
    
    count_scheduled = 0
    count_adiados = 0
    total_risk_mitigated = 0.0
    violations_count = 0
    
    # Preparar lista para ordenação cronológica
    plan_details = []
    for i, start_time in enumerate(best_schedule):
        plan_details.append((start_time, patches[i]))
    
    plan_details.sort(key=lambda x: x[0])

    print("\n--- Detalhe das Ações (Amostra Cronológica) ---")
    
    shown_count = 0
    MAX_SHOW = 15 # Mostrar apenas os primeiros 15 para não encher o terminal

    for start_time, patch in plan_details:
        # Se foi ADIADO (-1)
        if start_time == -1:
            count_adiados += 1
            # Se for crítico e foi adiado, mostramos aviso
            if patch.severity == "Critical" and shown_count < MAX_SHOW:
                print(f"⚠️  [ADIADO] {patch.id} ({patch.severity}) - Falta de Janela/Staff")
                shown_count += 1
            continue

        # Se foi AGENDADO
        count_scheduled += 1
        total_risk_mitigated += patch.risk_score
        
        # --- VERIFICAÇÃO DE VALIDADE (A "Prova Real") ---
        # Vamos verificar se o horário escolhido bate certo com a janela do servidor
        server = next(s for s in servers if s.id == patch.server_id)
        current_day, current_h = get_day_and_hour(start_time)
        
        valid_window = False
        for w_day, w_start, w_end in server.maintenance_windows:
            if w_day == current_day:
                p_end = current_h + patch.estimated_time
                if current_h >= w_start and p_end <= w_end:
                    valid_window = True
                    break
        
        # Formatação para o print
        day_name = DAYS_MAP[current_day]
        end_abs = start_time + patch.estimated_time
        _, end_hour = get_day_and_hour(end_abs)
        _, start_hour_display = get_day_and_hour(start_time) # Apenas hora do dia
        
        icon = "✅"
        status_text = ""
        
        if not valid_window:
            icon = "❌"
            status_text = " [VIOLAÇÃO JANELA]"
            violations_count += 1

        if shown_count < MAX_SHOW:
            print(f"{icon} [{day_name} {start_hour_display:02d}h-{end_hour:02d}h] {patch.id} ({patch.severity}) -> {server.id}{status_text}")
            shown_count += 1

    if shown_count >= MAX_SHOW:
        print(f"... (e mais {len(patches) - shown_count} ações)")

    print(f"\n--- Estatísticas Finais ---")
    print(f"Patches Agendados: {count_scheduled}")
    print(f"Patches Adiados:   {count_adiados}")
    print(f"Violações de Janela: {violations_count}")
    print(f"Risco Total Mitigado: {total_risk_mitigated:.2f}")
    
    if violations_count > 0:
        print("\n💡 DICA: Se há violações, tenta aumentar os PESOS das penalidades no config.py")
    elif count_scheduled == 0:
        print("\n⚠️ AVISO: Nada agendado. Verifica se as penalidades não estão altas demais!")

    print("\n=====================================")

if __name__ == "__main__":
    main()