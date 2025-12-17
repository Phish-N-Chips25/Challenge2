# Restrições para Planeamento

## Servidor

- [x] ID
- [x] Sistema operativo
- [x] versão Sistema Operativo
- [x] Períodos de downtime Disponíveis 
- [x] RTO

## Software
- [x] ID
- [x] Versão Software
- [x] Criticalidade do software


## Patches (derivados dos CVES)

- [x] ID
- [x] Severity
- [x] epss_score (target variable do modelo ml)
- [x] estimated fix time
- [x] Software afetado
- [x] Operadores requeridos

## Operários

- [x] ID
- [x] Horário de trabalho com devidas restrições (não pode trabalhar mais que 8h por dia)

## Funcionamento do Sistema

O modelo ml vai nos dar um epss score (probabilidade de uma cve ser exploited nos próximos 30 dias). Com esse eps score que representa a probabilidade de a CVE ser explorada nos proximos 30 dias.

A infraestrutura vai ter servidores, os servidores ao ter softwares.
O que é afetado são os softwares, ou seja a cve no dataset vai estar associada a um versão, o cve afeta uma versão de software.
Ou seja o modelo diz que CVE x tem alto risco, nos percorrermos a infraestrutura e procuramos as versoes de software associados a essa cve.

A CvE tem a sua severidade e o software tem a sua criticalidade para o servidor em especifico.
Para aplicar o patch podem ser requeridos um ou mais operarios, associados a um servidor.
O servidor tera um rto.

Tudo isto são restricoes que tem de ser implementadas.

Dependendo do EPSS score as prioridades tambem podem variar. Por exemplo, se ha uma cve que tem risco medio(defincao de medio, baixo e alto ainda por definir) de ser explorado e outro tem risco alto, teremos de aplicar e priorzar primeiro a aplicacao de um mais alto.

Tal como uma cve com grande criticalidade num servidor e media severidade talvez tenha de ser priorizada em relação a uma cve com media criticalidade e media severidade (definicoes de combinacoes entre estas duas fatures ainda tem de ser definidas tambem)

Um operario tera o seu horario de trabalho, tal como um servidor tera o seu horario disponivel para downtime. Um operador nao pode trabalhar mais que 8 horas por dia, mas podemos por exemplo, imaginando que podemos aplicar o patch e nao temos ninguem para o fazer chamar um trabalhador que ou nao trabalhou nesse dia ou ainda nao atingiu as 8 horas.

O objetivo é maximizar o aproveitamento.


O output esperado seria algo do genero de sequencias:

Patch para CVE x com risco x e severidade x, aplicada ao servidor x no software x com criticalidade x. A aplicação foi realizada em x durante x tempo pelos operarios x.



Severidade,Duração Estimada (h),Justificação
Critical,4h,"Requer backup, coordenação de equipa e testes extensos."
High,2h,Requer validação e aplicação cuidadosa.
Medium,1h,Patch padrão de rotina.
Low,1h,Atualização simples de configuração ou biblioteca.