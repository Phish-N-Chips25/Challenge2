# Restrições para Planeamento

## Servidor

- [x] ID
- [x] Sistema operativo
- [x] Criticalidade
- [x] Períodos de downtime Disponíveis 
- [x] Custo de downtime
- [x] RTO/RPO

## Patches (derivados dos CVES)

- [x] ID
- [x] Severity
- [x] epss_score (target variable do modelo ml)
- [x] Tempo estimado para patch
- [x] Sistema operativo afetado
- [x] Operadores requeridos

## Operários

- [x] ID
- [x] Skills
- [x] Horário de trabalho com devidas restrições (não pode trabalhar mais que 8h por dia)

## Funcionamento do Sistema

O modelo ml vai nos dar um epss score (probabilidade de uma cve ser exploited nos próximos 30 dias). Com esse eps score e junto com outras características e restrições do sistema vamos tentar escalonar a melhor solução possível para aliciamento de parches. 

Por exemplo:
- Se o epss score for abaixo de x não precisamos de nos preocupar / não é uma ação urgente
- Se for entre x e x vamos ter de dar alguma prioridade e arranjar uma maneira de tratar do problema
- Se for acima de x vamos ter de arranjar uma solução o mais rápido possível

Isto não se baseara apenas o epsscore, mas também noutras restrições, por exemplo a criminalidade que a cve tem no sistema
