/**
 * PLNTDIA - Sistema de Planeamento de Patches
 * Frontend Application
 */

// Estado global da aplicação
let appState = {
    currentTab: 'dashboard',
    cves: [],
    servers: [],
    workers: [],
    holidays: [],
    selectedPatches: new Map(), // server_id -> [cve_ids]
    selectedCVEsForPlan: new Set(), // CVE IDs selecionadas na página de CVEs
    planData: null,
    currentMonth: new Date(),
    requiredPatches: [],
    cvesBySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
};

// API Base URL
const API_BASE = '';

/**
 * Fetch helper com tratamento de erros detalhado
 */
async function fetchAPI(endpoint, options = {}) {
    try {
        const response = await fetch(`${API_BASE}${endpoint}`, {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        });
        
        if (!response.ok) {
            let errorMessage = `Erro ${response.status}`;
            try {
                const errorData = await response.json();
                errorMessage = errorData.error || errorData.message || errorMessage;
            } catch (e) {
                // Se não conseguir parsear JSON, usar mensagem padrão
                errorMessage = getHttpErrorMessage(response.status);
            }
            throw new Error(errorMessage);
        }
        
        return await response.json();
    } catch (error) {
        console.error(`API Error (${endpoint}):`, error);
        
        // Detectar tipo de erro e mostrar mensagem apropriada
        if (error.name === 'TypeError' && error.message.includes('fetch')) {
            showNotification('❌ Servidor não está acessível. Verifique se o servidor está a correr.', 'error');
        } else if (error.message.includes('NetworkError') || error.message.includes('Failed to fetch')) {
            showNotification('🌐 Erro de rede. Verifique a sua ligação à internet.', 'error');
        } else {
            showNotification(`❌ ${error.message}`, 'error');
        }
        throw error;
    }
}

/**
 * Obter mensagem de erro HTTP legível
 */
function getHttpErrorMessage(status) {
    const messages = {
        400: 'Pedido inválido. Verifique os dados enviados.',
        401: 'Não autorizado. Faça login novamente.',
        403: 'Acesso negado. Sem permissões suficientes.',
        404: 'Recurso não encontrado.',
        408: 'Tempo de espera excedido. Tente novamente.',
        422: 'Dados inválidos. Verifique os campos preenchidos.',
        429: 'Demasiados pedidos. Aguarde um momento.',
        500: 'Erro interno do servidor. Tente mais tarde.',
        502: 'Gateway inválido. Servidor temporariamente indisponível.',
        503: 'Serviço indisponível. Tente mais tarde.',
        504: 'Tempo de gateway excedido. Tente novamente.'
    };
    return messages[status] || `Erro do servidor (${status})`;
}

/**
 * Mostrar notificação com ícones e duração ajustável
 */
function showNotification(message, type = 'info', duration = null) {
    const container = document.getElementById('notification-container') || createNotificationContainer();
    
    // Definir ícone e duração baseado no tipo
    const config = {
        success: { icon: '✅', duration: 4000 },
        error: { icon: '❌', duration: 8000 },
        warning: { icon: '⚠️', duration: 6000 },
        info: { icon: 'ℹ️', duration: 5000 }
    };
    
    const { icon, duration: defaultDuration } = config[type] || config.info;
    const finalDuration = duration || defaultDuration;
    
    // Verificar se já existe uma notificação igual (evitar duplicados)
    const existingNotifications = container.querySelectorAll('.notification');
    for (const existing of existingNotifications) {
        if (existing.textContent.includes(message.replace(/^[\p{Emoji}\s]+/u, ''))) {
            return; // Não mostrar duplicado
        }
    }
    
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    
    // Adicionar ícone apenas se a mensagem não começar com emoji
    const hasEmoji = /^[\p{Emoji}]/u.test(message);
    const displayMessage = hasEmoji ? message : `${icon} ${message}`;
    
    notification.innerHTML = `
        <div class="notification-content">
            <span class="notification-message">${displayMessage}</span>
            <span class="notification-time">${new Date().toLocaleTimeString('pt-PT', { hour: '2-digit', minute: '2-digit' })}</span>
        </div>
        <button class="notification-close" onclick="this.parentElement.remove()" title="Fechar">×</button>
    `;
    
    container.appendChild(notification);
    
    // Limitar número de notificações visíveis
    const maxNotifications = 5;
    while (container.children.length > maxNotifications) {
        container.firstChild.remove();
    }
    
    // Auto-remover após duração
    setTimeout(() => {
        notification.classList.add('fade-out');
        setTimeout(() => {
            if (notification.parentElement) {
                notification.remove();
            }
        }, 300);
    }, finalDuration);
}

function createNotificationContainer() {
    const container = document.createElement('div');
    container.id = 'notification-container';
    container.style.cssText = 'position: fixed; top: 20px; right: 20px; z-index: 1000;';
    document.body.appendChild(container);
    return container;
}

/**
 * Navegação por tabs
 */
function showTab(tabName) {
    // Atualizar estado
    appState.currentTab = tabName;
    
    // Atualizar navegação
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.toggle('active', link.dataset.tab === tabName);
    });
    
    // Atualizar conteúdo
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.toggle('active', content.id === `${tabName}-tab`);
    });
    
    // Carregar dados específicos da tab
    switch(tabName) {
        case 'dashboard':
            loadStats();
            break;
        case 'cves':
            loadCVEs();
            break;
        case 'servers':
            loadServers();
            break;
        case 'schedule':
            loadScheduleData();
            break;
        case 'calendar':
            renderMonthlyCalendar();
            break;
    }
}

/**
 * Carregar estatísticas do dashboard
 */
async function loadStats() {
    try {
        const [stats, holidays] = await Promise.all([
            fetchAPI('/api/stats'),
            fetchAPI('/api/holidays')
        ]);
        
        appState.holidays = holidays.holidays || [];
        
        // Atualizar cards
        document.getElementById('total-servers').textContent = stats.total_servers || 0;
        document.getElementById('total-cves').textContent = stats.total_cves || 0;
        document.getElementById('total-workers').textContent = stats.total_workers || 0;
        document.getElementById('total-holidays').textContent = appState.holidays.length || 0;
        
        // Atualizar barras de ambiente
        const total = stats.total_servers || 1;
        const serversByEnv = stats.servers_by_environment || {};
        
        ['dev', 'test', 'prod'].forEach(env => {
            const count = serversByEnv[env.toUpperCase()] || 0;
            const bar = document.getElementById(`${env}-bar`);
            const countEl = document.getElementById(`${env}-count`);
            if (bar) bar.style.width = `${(count / total) * 100}%`;
            if (countEl) countEl.textContent = count;
        });
        
        // Atualizar CVEs por severidade (API retorna Title Case: Critical, High, etc.)
        const severityData = stats.cves_by_severity || {};
        appState.cvesBySeverity = {
            CRITICAL: severityData.Critical || severityData.CRITICAL || 0,
            HIGH: severityData.High || severityData.HIGH || 0,
            MEDIUM: severityData.Medium || severityData.MEDIUM || 0,
            LOW: severityData.Low || severityData.LOW || 0
        };
        document.getElementById('critical-count').textContent = appState.cvesBySeverity.CRITICAL;
        document.getElementById('high-count').textContent = appState.cvesBySeverity.HIGH;
        document.getElementById('medium-count').textContent = appState.cvesBySeverity.MEDIUM;
        document.getElementById('low-count').textContent = appState.cvesBySeverity.LOW;
        
        // Carregar próximos feriados
        loadUpcomingHolidays();
        
    } catch (error) {
        console.error('Erro ao carregar estatísticas:', error);
        showNotification('Não foi possível carregar estatísticas do dashboard. Verifique a ligação ao servidor.', 'warning');
    }
}

/**
 * Carregar próximos feriados
 */
function loadUpcomingHolidays() {
    const container = document.getElementById('holidays-list');
    if (!container) return;
    
    const today = new Date();
    const upcoming = appState.holidays
        .filter(h => new Date(h.date) >= today)
        .sort((a, b) => new Date(a.date) - new Date(b.date))
        .slice(0, 5);
    
    if (upcoming.length === 0) {
        container.innerHTML = '<p class="no-data">Nenhum feriado próximo</p>';
        return;
    }
    
    container.innerHTML = upcoming.map(h => `
        <div class="holiday-item">
            <span class="holiday-date">${formatDate(h.date)}</span>
            <span class="holiday-name">${h.name}</span>
        </div>
    `).join('');
}

/**
 * Carregar lista de CVEs
 */
async function loadCVEs() {
    try {
        // Tentar carregar do banco de dados primeiro
        let data;
        try {
            data = await fetchAPI('/api/db/cves?per_page=200&sort_by=base_score&sort_order=DESC');
            if (data.cves && data.cves.length > 0) {
                // Converter formato do banco de dados para formato esperado
                appState.cves = data.cves.map(cve => ({
                    cve_id: cve.cve_id,
                    severity: cve.base_severity || 'MEDIUM',
                    cvss_score: cve.base_score || 0,
                    epss_score: cve.epss_score || 0,
                    priority: cve.base_score || 0,
                    affected_software: cve.impacted_products || 'Unknown',
                    vendor: cve.impacted_vendor || 'Unknown',
                    cwe: cve.cwe_number || '',
                    cwe_description: cve.cwe_description || '',
                    attack_vector: cve.attack_vector || 'NETWORK',
                    published_date: cve.published_date || '',
                    cisa_kev: cve.cisa_kev || false,
                    ssvc_decision: cve.ssvc_decision || ''
                }));
                appState.cveSource = 'database';
            }
        } catch (dbError) {
            console.log('Database not available, falling back to API:', dbError);
        }
        
        // Fallback para a API legacy se o banco não tiver dados
        if (!appState.cves || appState.cves.length === 0) {
            data = await fetchAPI('/api/cves?sort=priority&per_page=200');
            appState.cves = data.cves || [];
            appState.cveSource = 'api';
        }
        
        renderCVETable();
        
        // Mostrar fonte dos dados
        const sourceIndicator = document.getElementById('cve-source');
        if (sourceIndicator) {
            sourceIndicator.textContent = appState.cveSource === 'database' 
                ? '📊 Dados: SQLite Database' 
                : '🔄 Dados: API (gerados)';
        }
        
    } catch (error) {
        console.error('Erro ao carregar CVEs:', error);
    }
}

/**
 * Inicializar banco de dados com CVEs do dataset
 */
async function initDatabase(clearExisting = false) {
    try {
        showNotification('A inicializar banco de dados...', 'info');
        
        const result = await fetchAPI('/api/db/init', {
            method: 'POST',
            body: JSON.stringify({ clear_existing: clearExisting })
        });
        
        if (result.success) {
            showNotification(`${result.message}`, 'success');
            // Recarregar CVEs
            await loadCVEs();
            // Atualizar stats
            loadStats();
        } else {
            showNotification('Falha ao inicializar banco de dados. Verifique os ficheiros de dados.', 'error');
        }
    } catch (error) {
        console.error('Erro ao inicializar banco:', error);
        showNotification('Erro ao inicializar banco de dados: ' + (error.message || 'verifique se o servidor está a correr'), 'error');
    }
}

/**
 * Carregar estatísticas de CVEs do banco de dados
 */
async function loadDBStats() {
    try {
        const stats = await fetchAPI('/api/db/cves/stats');
        
        const container = document.getElementById('db-stats');
        if (container) {
            container.innerHTML = `
                <div class="db-stats-grid">
                    <div class="stat-item">
                        <span class="stat-value">${stats.total || 0}</span>
                        <span class="stat-label">Total CVEs</span>
                    </div>
                    <div class="stat-item critical">
                        <span class="stat-value">${stats.by_severity?.CRITICAL || 0}</span>
                        <span class="stat-label">Critical</span>
                    </div>
                    <div class="stat-item high">
                        <span class="stat-value">${stats.by_severity?.HIGH || 0}</span>
                        <span class="stat-label">High</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-value">${stats.cisa_kev_count || 0}</span>
                        <span class="stat-label">CISA KEV</span>
                    </div>
                    <div class="stat-item">
                        <span class="stat-value">${stats.avg_cvss_score || 0}</span>
                        <span class="stat-label">Média CVSS</span>
                    </div>
                </div>
            `;
        }
        return stats;
    } catch (error) {
        console.error('Erro ao carregar stats DB:', error);
        showNotification('Não foi possível carregar estatísticas da base de dados.', 'warning');
        return null;
    }
}

/**
 * Renderizar tabela de CVEs (suporta dados do DB e API)
 */
function renderCVETable() {
    const tbody = document.getElementById('cve-table-body');
    if (!tbody) return;
    
    // Aplicar filtros
    const filteredCVEs = filterCVEs(appState.cves);
    
    if (filteredCVEs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="10" class="no-data">Nenhuma CVE encontrada com os filtros aplicados</td></tr>';
        updateCVEFilterCount(0);
        return;
    }
    
    tbody.innerHTML = filteredCVEs.map(cve => {
        // Suportar ambos os formatos (DB e API)
        const cveId = cve.cve_id;
        const severity = cve.severity || cve.base_severity || 'MEDIUM';
        const cvssScore = cve.cvss_score || cve.base_score || 0;
        const epssScore = cve.epss_score || 0;
        const software = cve.affected_software || cve.software || cve.impacted_products || 'Unknown';
        const publishedDate = cve.published_date || '';
        const priority = cve.priority || cvssScore || 0;
        const duration = cve.patch_duration_hours || Math.ceil(cvssScore / 2) || 4;
        const isSelected = appState.selectedCVEsForPlan?.has(cveId) || false;
        
        // Formatar data de publicação
        let dateDisplay = '-';
        if (publishedDate) {
            try {
                const d = new Date(publishedDate);
                dateDisplay = d.toLocaleDateString('pt-PT', { year: 'numeric', month: 'short', day: 'numeric' });
            } catch (e) {
                dateDisplay = publishedDate.substring(0, 10);
            }
        }
        
        return `
            <tr data-severity="${severity}" data-software="${software}" data-cve="${cveId}" data-date="${publishedDate}" class="${isSelected ? 'selected' : ''}">
                <td><input type="checkbox" class="cve-checkbox" data-cve="${cveId}" ${isSelected ? 'checked' : ''}></td>
                <td>
                    <strong>${cveId}</strong>
                    ${cve.cisa_kev ? '<span class="kev-badge" title="CISA KEV">⚠️</span>' : ''}
                </td>
                <td><span class="severity-badge ${severity.toLowerCase()}">${severity}</span></td>
                <td><strong>${cvssScore?.toFixed(1) || '-'}</strong></td>
                <td>${epssScore ? (epssScore * 100).toFixed(2) + '%' : '-'}</td>
                <td class="vendor-cell" title="${software}">${software.substring(0, 25)}${software.length > 25 ? '...' : ''}</td>
                <td class="date-cell">${dateDisplay}</td>
                <td>${duration}h</td>
                <td><strong>${priority.toFixed ? priority.toFixed(1) : priority}</strong></td>
                <td>
                    <button class="btn btn-sm" onclick="showCVEDetails('${cveId}')" title="Ver detalhes">🔍</button>
                </td>
            </tr>
        `;
    }).join('');
    
    // Atualizar contadores
    updateCVEFilterCount(filteredCVEs.length);
    
    // Adicionar listeners aos checkboxes
    tbody.querySelectorAll('.cve-checkbox').forEach(cb => {
        cb.addEventListener('change', handleCVECheckboxChange);
    });
}

/**
 * Filtrar CVEs com base nos filtros ativos
 */
function filterCVEs(cves) {
    const severityFilter = document.getElementById('cve-severity-filter')?.value || '';
    const softwareFilter = document.getElementById('cve-software-filter')?.value?.toLowerCase() || '';
    const sortBy = document.getElementById('cve-sort')?.value || 'priority';
    const datePeriod = document.getElementById('cve-date-period')?.value || '';
    const dateFrom = document.getElementById('cve-date-from')?.value || '';
    const dateTo = document.getElementById('cve-date-to')?.value || '';
    
    let filtered = [...cves];
    
    // Filtro de severidade
    if (severityFilter) {
        filtered = filtered.filter(cve => {
            const sev = cve.severity || cve.base_severity || '';
            return sev.toUpperCase() === severityFilter.toUpperCase();
        });
    }
    
    // Filtro de software
    if (softwareFilter) {
        filtered = filtered.filter(cve => {
            const sw = cve.affected_software || cve.software || cve.impacted_products || '';
            const vendor = cve.vendor || cve.impacted_vendor || '';
            return sw.toLowerCase().includes(softwareFilter) || vendor.toLowerCase().includes(softwareFilter);
        });
    }
    
    // Filtro de data
    if (datePeriod && datePeriod !== 'custom') {
        const days = parseInt(datePeriod);
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - days);
        
        filtered = filtered.filter(cve => {
            const pubDate = cve.published_date;
            if (!pubDate) return false;
            return new Date(pubDate) >= cutoffDate;
        });
    } else if (datePeriod === 'custom' && (dateFrom || dateTo)) {
        const fromDate = dateFrom ? new Date(dateFrom) : null;
        const toDate = dateTo ? new Date(dateTo + 'T23:59:59') : null;
        
        filtered = filtered.filter(cve => {
            const pubDate = cve.published_date;
            if (!pubDate) return false;
            const d = new Date(pubDate);
            if (fromDate && d < fromDate) return false;
            if (toDate && d > toDate) return false;
            return true;
        });
    }
    
    // Ordenação
    filtered.sort((a, b) => {
        switch (sortBy) {
            case 'severity':
                const sevOrder = { 'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1 };
                return (sevOrder[(b.severity || b.base_severity || '').toUpperCase()] || 0) - 
                       (sevOrder[(a.severity || a.base_severity || '').toUpperCase()] || 0);
            case 'epss':
                return (b.epss_score || 0) - (a.epss_score || 0);
            case 'date':
                const dateA = a.published_date ? new Date(a.published_date) : new Date(0);
                const dateB = b.published_date ? new Date(b.published_date) : new Date(0);
                return dateB - dateA;
            case 'priority':
            default:
                return (b.priority || b.cvss_score || b.base_score || 0) - (a.priority || a.cvss_score || a.base_score || 0);
        }
    });
    
    return filtered;
}

/**
 * Atualizar contador de CVEs filtradas
 */
function updateCVEFilterCount(count) {
    const countEl = document.getElementById('cve-filter-count');
    if (countEl) {
        countEl.textContent = `${count} CVEs ${count === 1 ? 'encontrada' : 'encontradas'}`;
    }
}

/**
 * Handler para mudança de checkbox de CVE
 */
function handleCVECheckboxChange(event) {
    const checkbox = event.target;
    const cveId = checkbox.dataset.cve;
    const row = checkbox.closest('tr');
    
    if (!appState.selectedCVEsForPlan) {
        appState.selectedCVEsForPlan = new Set();
    }
    
    if (checkbox.checked) {
        appState.selectedCVEsForPlan.add(cveId);
        row?.classList.add('selected');
    } else {
        appState.selectedCVEsForPlan.delete(cveId);
        row?.classList.remove('selected');
    }
    
    updateSelectedCVECount();
}

/**
 * Atualizar contador de CVEs selecionadas para planeamento
 */
function updateSelectedCVECount() {
    const count = appState.selectedCVEsForPlan?.size || 0;
    const countEl = document.getElementById('selected-cve-count');
    const planBtn = document.getElementById('plan-selected-cves');
    
    if (countEl) {
        countEl.textContent = count;
    }
    
    if (planBtn) {
        planBtn.disabled = count === 0;
    }
    
    // Atualizar checkbox "selecionar todos"
    const selectAllCb = document.getElementById('select-all-cves');
    if (selectAllCb) {
        const allCheckboxes = document.querySelectorAll('#cve-table-body .cve-checkbox');
        const checkedCheckboxes = document.querySelectorAll('#cve-table-body .cve-checkbox:checked');
        selectAllCb.checked = allCheckboxes.length > 0 && allCheckboxes.length === checkedCheckboxes.length;
        selectAllCb.indeterminate = checkedCheckboxes.length > 0 && checkedCheckboxes.length < allCheckboxes.length;
    }
}

/**
 * Selecionar todas as CVEs filtradas
 */
function selectAllFilteredCVEs() {
    if (!appState.selectedCVEsForPlan) {
        appState.selectedCVEsForPlan = new Set();
    }
    
    const checkboxes = document.querySelectorAll('#cve-table-body .cve-checkbox');
    checkboxes.forEach(cb => {
        cb.checked = true;
        appState.selectedCVEsForPlan.add(cb.dataset.cve);
        cb.closest('tr')?.classList.add('selected');
    });
    
    updateSelectedCVECount();
    showNotification(`✅ ${checkboxes.length} CVEs selecionadas`, 'success');
}

/**
 * Abrir modal para criar planeamento com CVEs selecionadas
 */
async function openPlanFromCVEsModal() {
    if (!appState.selectedCVEsForPlan || appState.selectedCVEsForPlan.size === 0) {
        showNotification('⚠️ Selecione pelo menos uma CVE para o planeamento', 'warning');
        return;
    }
    
    const modal = document.getElementById('plan-servers-modal');
    const body = document.getElementById('plan-servers-body');
    
    // Mostrar loading
    body.innerHTML = '<div class="loading-spinner">A carregar servidores...</div>';
    modal.style.display = 'flex';
    
    try {
        // Carregar todos os servidores (sem paginação)
        const serversData = await fetchAPI('/api/servers?per_page=100');
        const servers = serversData.servers || [];
        
        // Obter CVEs selecionadas
        const selectedCVEIds = Array.from(appState.selectedCVEsForPlan);
        const selectedCVEs = appState.cves.filter(cve => selectedCVEIds.includes(cve.cve_id));
        
        // Calcular estatísticas
        const severityCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
        selectedCVEs.forEach(cve => {
            const sev = (cve.severity || cve.base_severity || 'MEDIUM').toUpperCase();
            severityCounts[sev] = (severityCounts[sev] || 0) + 1;
        });
        
        body.innerHTML = `
            <div class="plan-summary">
                <div class="plan-summary-item">
                    <span class="value">${selectedCVEIds.length}</span>
                    <span class="label">CVEs Selecionadas</span>
                </div>
                <div class="plan-summary-item">
                    <span class="value" style="color: var(--danger)">${severityCounts.CRITICAL}</span>
                    <span class="label">Critical</span>
                </div>
                <div class="plan-summary-item">
                    <span class="value" style="color: var(--warning)">${severityCounts.HIGH}</span>
                    <span class="label">High</span>
                </div>
                <div class="plan-summary-item">
                    <span class="value">${severityCounts.MEDIUM + severityCounts.LOW}</span>
                    <span class="label">Medium/Low</span>
                </div>
            </div>
            
            <h4>📋 Selecione os servidores para aplicar patches:</h4>
            <div class="filter-group" style="margin-bottom: var(--spacing-md);">
                <label><input type="checkbox" id="select-all-servers" checked> Selecionar todos os servidores</label>
            </div>
            
            <div class="servers-selection-grid">
                ${servers.map(server => `
                    <div class="server-selection-card selected" data-server="${server.id}">
                        <input type="checkbox" class="server-checkbox" data-server="${server.id}" checked>
                        <div class="server-selection-info">
                            <div class="server-name">${server.id}</div>
                            <div class="server-meta">
                                <span class="env-badge env-${server.environment?.toLowerCase()}">${server.environment}</span>
                                ${server.application_group || ''}
                            </div>
                            <div class="server-cves">${(server.installed_software || []).length} software instalado</div>
                        </div>
                    </div>
                `).join('')}
            </div>
            
            <div class="plan-options">
                <h4>⚙️ Opções do Planeamento</h4>
                <div class="plan-options-grid">
                    <div class="filter-group">
                        <label>Data de início:</label>
                        <input type="date" id="plan-start-date" value="${new Date().toISOString().split('T')[0]}">
                    </div>
                    <div class="filter-group">
                        <label>Prioridade ambiente:</label>
                        <select id="plan-env-priority">
                            <option value="DEV,TEST,PROD">DEV → TEST → PROD</option>
                            <option value="PROD,TEST,DEV">PROD → TEST → DEV</option>
                            <option value="">Sem prioridade</option>
                        </select>
                    </div>
                </div>
            </div>
        `;
        
        // Adicionar listeners
        document.getElementById('select-all-servers').addEventListener('change', (e) => {
            document.querySelectorAll('.server-checkbox').forEach(cb => {
                cb.checked = e.target.checked;
                cb.closest('.server-selection-card')?.classList.toggle('selected', e.target.checked);
            });
        });
        
        document.querySelectorAll('.server-selection-card').forEach(card => {
            card.addEventListener('click', (e) => {
                if (e.target.type !== 'checkbox') {
                    const cb = card.querySelector('.server-checkbox');
                    cb.checked = !cb.checked;
                    card.classList.toggle('selected', cb.checked);
                }
            });
        });
        
    } catch (error) {
        body.innerHTML = `<div class="error-message">Erro ao carregar servidores: ${error.message}</div>`;
    }
}

/**
 * Fechar modal de planeamento
 */
function closePlanServersModal() {
    const modal = document.getElementById('plan-servers-modal');
    if (modal) {
        modal.style.display = 'none';
    }
}

/**
 * Executar planeamento com CVEs e servidores selecionados
 */
async function executePlanFromCVEs() {
    const selectedServers = Array.from(document.querySelectorAll('.server-checkbox:checked')).map(cb => cb.dataset.server);
    const selectedCVEIds = Array.from(appState.selectedCVEsForPlan || []);
    const startDate = document.getElementById('plan-start-date')?.value || new Date().toISOString().split('T')[0];
    const envPriority = document.getElementById('plan-env-priority')?.value || '';
    
    if (selectedServers.length === 0) {
        showNotification('⚠️ Selecione pelo menos um servidor', 'warning');
        return;
    }
    
    if (selectedCVEIds.length === 0) {
        showNotification('⚠️ Nenhuma CVE selecionada', 'warning');
        return;
    }
    
    const confirmBtn = document.getElementById('confirm-plan-btn');
    if (confirmBtn) {
        confirmBtn.disabled = true;
        confirmBtn.innerHTML = '⏳ A gerar planeamento...';
    }
    
    try {
        // Construir patches manualmente
        const patches = [];
        const selectedCVEs = appState.cves.filter(cve => selectedCVEIds.includes(cve.cve_id));
        
        selectedServers.forEach(serverId => {
            selectedCVEs.forEach(cve => {
                patches.push({
                    server_id: serverId,
                    cve_id: cve.cve_id,
                    priority: cve.priority || cve.cvss_score || cve.base_score || 5,
                    duration_hours: cve.patch_duration_hours || Math.ceil((cve.cvss_score || cve.base_score || 5) / 2) || 4,
                    operators_required: cve.operators_required || (cve.severity?.toUpperCase() === 'CRITICAL' ? 2 : 1)
                });
            });
        });
        
        // Chamar API de planeamento
        const result = await fetchAPI('/api/plan', {
            method: 'POST',
            body: JSON.stringify({
                patches: patches,
                start_date: startDate,
                environment_priority: envPriority ? envPriority.split(',') : null
            })
        });
        
        if (result.schedule && result.schedule.length > 0) {
            appState.planData = result;
            closePlanServersModal();
            
            // Ir para a tab de planeamento
            showTab('schedule');
            
            // Atualizar visualização
            renderPlanResults(result);
            
            showNotification(`✅ Planeamento gerado: ${result.schedule.length} tarefas agendadas`, 'success');
        } else {
            showNotification('⚠️ Nenhuma tarefa foi agendada. Verifique os dados.', 'warning');
        }
        
    } catch (error) {
        console.error('Erro ao gerar planeamento:', error);
        showNotification(`❌ Erro ao gerar planeamento: ${error.message}`, 'error');
    } finally {
        if (confirmBtn) {
            confirmBtn.disabled = false;
            confirmBtn.innerHTML = '🚀 Gerar Planeamento';
        }
    }
}

/**
 * Mostrar detalhes completos de um CVE
 */
async function showCVEDetails(cveId) {
    try {
        // Tentar carregar do banco de dados primeiro
        let cve;
        try {
            cve = await fetchAPI(`/api/db/cves/${cveId}`);
        } catch (e) {
            // Fallback para dados em memória
            cve = appState.cves.find(c => c.cve_id === cveId);
        }
        
        if (!cve) {
            showNotification('CVE não encontrada', 'error');
            return;
        }
        
        const modal = document.getElementById('cve-details-modal') || createCVEDetailsModal();
        const modalBody = document.getElementById('cve-details-body');
        
        modalBody.innerHTML = `
            <div class="cve-detail-header">
                <h3>${cve.cve_id}</h3>
                <span class="severity-badge ${(cve.base_severity || cve.severity || 'medium').toLowerCase()}">${cve.base_severity || cve.severity}</span>
                ${cve.cisa_kev ? '<span class="kev-badge-large">⚠️ CISA KEV</span>' : ''}
            </div>
            
            <div class="cve-detail-grid">
                <div class="detail-section">
                    <h4>📊 Scores</h4>
                    <div class="scores-grid">
                        <div class="score-item">
                            <span class="score-label">CVSS Score</span>
                            <span class="score-value cvss">${cve.base_score?.toFixed(1) || '-'}</span>
                        </div>
                        <div class="score-item">
                            <span class="score-label">EPSS Score</span>
                            <span class="score-value">${cve.epss_score ? (cve.epss_score * 100).toFixed(3) + '%' : '-'}</span>
                        </div>
                        <div class="score-item">
                            <span class="score-label">Exploitability</span>
                            <span class="score-value">${cve.exploitability_score?.toFixed(1) || '-'}</span>
                        </div>
                        <div class="score-item">
                            <span class="score-label">Impact</span>
                            <span class="score-value">${cve.impact_score?.toFixed(1) || '-'}</span>
                        </div>
                    </div>
                </div>
                
                <div class="detail-section">
                    <h4>🎯 Attack Vector</h4>
                    <table class="detail-table">
                        <tr><td>Vector</td><td>${cve.attack_vector || '-'}</td></tr>
                        <tr><td>Complexity</td><td>${cve.attack_complexity || '-'}</td></tr>
                        <tr><td>Privileges Required</td><td>${cve.privileges_required || '-'}</td></tr>
                        <tr><td>User Interaction</td><td>${cve.user_interaction || '-'}</td></tr>
                        <tr><td>Scope</td><td>${cve.scope || '-'}</td></tr>
                    </table>
                </div>
                
                <div class="detail-section">
                    <h4>💥 Impact</h4>
                    <table class="detail-table">
                        <tr><td>Confidentiality</td><td>${cve.confidentiality_impact || '-'}</td></tr>
                        <tr><td>Integrity</td><td>${cve.integrity_impact || '-'}</td></tr>
                        <tr><td>Availability</td><td>${cve.availability_impact || '-'}</td></tr>
                    </table>
                </div>
                
                <div class="detail-section">
                    <h4>📋 SSVC</h4>
                    <table class="detail-table">
                        <tr><td>Decision</td><td><span class="ssvc-badge ssvc-${(cve.ssvc_decision || '').toLowerCase()}">${cve.ssvc_decision || '-'}</span></td></tr>
                        <tr><td>Exploitation</td><td>${cve.ssvc_exploitation || '-'}</td></tr>
                        <tr><td>Automatable</td><td>${cve.ssvc_automatable || '-'}</td></tr>
                        <tr><td>Technical Impact</td><td>${cve.ssvc_technical_impact || '-'}</td></tr>
                    </table>
                </div>
                
                <div class="detail-section full-width">
                    <h4>🏢 Affected Products</h4>
                    <p><strong>Vendor:</strong> ${cve.impacted_vendor || '-'}</p>
                    <p><strong>Products:</strong> ${cve.impacted_products || '-'}</p>
                    <p><strong>Versions:</strong> ${cve.vulnerable_versions || '-'}</p>
                </div>
                
                <div class="detail-section full-width">
                    <h4>🐛 CWE</h4>
                    <p><strong>${cve.cwe_number || '-'}</strong>: ${cve.cwe_description || '-'}</p>
                </div>
                
                <div class="detail-section full-width">
                    <h4>📅 Dates</h4>
                    <p><strong>Published:</strong> ${cve.published_date || '-'}</p>
                    <p><strong>Updated:</strong> ${cve.updated_date || '-'}</p>
                    ${cve.cisa_kev_date ? `<p><strong>CISA KEV Date:</strong> ${cve.cisa_kev_date}</p>` : ''}
                </div>
            </div>
        `;
        
        modal.classList.add('active');
        
    } catch (error) {
        console.error('Erro ao carregar detalhes CVE:', error);
        showNotification(`Não foi possível carregar detalhes do CVE. ${error.message || ''}`, 'error');
    }
}

/**
 * Criar modal de detalhes CVE se não existir
 */
function createCVEDetailsModal() {
    const modal = document.createElement('div');
    modal.id = 'cve-details-modal';
    modal.className = 'modal';
    modal.innerHTML = `
        <div class="modal-content modal-large">
            <div class="modal-header">
                <h3>Detalhes do CVE</h3>
                <button class="modal-close" onclick="closeCVEDetailsModal()">×</button>
            </div>
            <div id="cve-details-body" class="modal-body"></div>
            <div class="modal-footer">
                <button class="btn btn-primary" onclick="closeCVEDetailsModal()">Fechar</button>
            </div>
        </div>
    `;
    document.body.appendChild(modal);
    return modal;
}

/**
 * Fechar modal de detalhes CVE
 */
function closeCVEDetailsModal() {
    const modal = document.getElementById('cve-details-modal');
    if (modal) modal.classList.remove('active');
}

/**
 * Mostrar servidores afetados por uma CVE
 */
async function showCVEServers(cveId) {
    try {
        const data = await fetchAPI(`/api/cves/${cveId}/affected-servers`);
        const cve = appState.cves.find(c => c.cve_id === cveId || c.id === cveId);
        
        const modal = document.getElementById('cve-servers-modal');
        const modalTitle = document.getElementById('modal-cve-title');
        const modalBody = document.getElementById('modal-cve-body');
        
        if (!modal || !modalBody) return;
        
        modalTitle.textContent = `${cveId} - Servidores Afetados`;
        
        // Verificar se há servidores afectados
        if (!data.servers || data.servers.length === 0) {
            modalBody.innerHTML = `
                <div class="no-servers-message">
                    <p>⚠️ Nenhum servidor afectado encontrado para esta CVE.</p>
                    <p class="info-text">
                        ${data.source === 'database' ? 
                            `<small>Vendor: ${data.vendor || 'N/A'} | Product: ${data.product || 'N/A'}</small>` : 
                            ''}
                    </p>
                    <p class="info-text">
                        <small>Isto pode acontecer se o software afectado não está instalado em nenhum servidor da infraestrutura.</small>
                    </p>
                </div>
            `;
            modal.classList.add('active');
            return;
        }
        
        // Agrupar por ambiente
        const byEnv = { DEV: [], TEST: [], PROD: [] };
        data.servers.forEach(s => {
            const env = s.environment || 'DEV';
            if (byEnv[env]) byEnv[env].push(s);
        });
        
        // Obter info do CVE (suporta ambos formatos)
        const severity = cve?.severity || cve?.base_severity || 'N/A';
        const software = cve?.software || cve?.product || cve?.vendor || data.product || 'N/A';
        const duration = cve?.patch_duration_hours || cve?.duration_hours || 4;
        
        modalBody.innerHTML = `
            <div class="cve-modal-info">
                <span class="severity-badge ${severity.toLowerCase()}">${severity}</span>
                <span><strong>Software:</strong> ${software}</span>
                <span><strong>Duração Est.:</strong> ${duration}h</span>
            </div>
            <p class="servers-count">${data.count} servidor(es) afectado(s)</p>
            <div class="servers-by-env">
                ${Object.entries(byEnv).map(([env, servers]) => servers.length > 0 ? `
                    <div class="env-group">
                        <h4 class="env-${env.toLowerCase()}">${env} (${servers.length})</h4>
                        <div class="server-checkboxes">
                            ${servers.map(s => `
                                <label class="server-checkbox-label">
                                    <input type="checkbox" class="server-select" 
                                           data-server="${s.server_id}" data-cve="${cveId}"
                                           ${isServerSelectedForCVE(s.server_id, cveId) ? 'checked' : ''}>
                                    <span class="server-name">${s.server_id}</span>
                                    <span class="server-app">${s.application_group || ''}</span>
                                </label>
                            `).join('')}
                        </div>
                    </div>
                ` : '').join('')}
            </div>
        `;
        
        modal.classList.add('active');
        
        // Setup confirmar seleção
        const confirmBtn = document.getElementById('confirm-server-selection');
        if (confirmBtn) {
            confirmBtn.onclick = () => saveServerSelections(cveId);
        }
        
    } catch (error) {
        console.error('Erro ao carregar servidores:', error);
        showNotification('Não foi possível carregar servidores afectados para esta CVE.', 'error');
    }
}

/**
 * Verificar se servidor está selecionado para uma CVE
 */
function isServerSelectedForCVE(serverId, cveId) {
    const patches = appState.selectedPatches.get(serverId) || [];
    return patches.includes(cveId);
}

/**
 * Guardar seleções de servidores para uma CVE
 */
function saveServerSelections(cveId) {
    const checkboxes = document.querySelectorAll('.server-select');
    
    checkboxes.forEach(cb => {
        const serverId = cb.dataset.server;
        
        if (!appState.selectedPatches.has(serverId)) {
            appState.selectedPatches.set(serverId, []);
        }
        
        const patches = appState.selectedPatches.get(serverId);
        const index = patches.indexOf(cveId);
        
        if (cb.checked && index === -1) {
            patches.push(cveId);
        } else if (!cb.checked && index !== -1) {
            patches.splice(index, 1);
        }
    });
    
    document.getElementById('cve-servers-modal').classList.remove('active');
    showNotification('Seleções guardadas com sucesso', 'success');
}

/**
 * Carregar lista de servidores
 */
async function loadServers() {
    try {
        // Pedir todos os servidores (per_page=100 para garantir que todos são retornados)
        const data = await fetchAPI('/api/servers?per_page=100');
        appState.servers = data.servers || [];
        renderServersGrid();
        populateAppFilter();
    } catch (error) {
        console.error('Erro ao carregar servidores:', error);
        showNotification('Não foi possível carregar a lista de servidores.', 'warning');
    }
}

/**
 * Renderizar grid de servidores
 */
function renderServersGrid() {
    const container = document.getElementById('servers-grid');
    if (!container) return;
    
    // Agrupar por ambiente
    const byEnv = { DEV: [], TEST: [], PROD: [] };
    appState.servers.forEach(server => {
        if (byEnv[server.environment]) {
            byEnv[server.environment].push(server);
        }
    });
    
    container.innerHTML = Object.entries(byEnv).map(([env, servers]) => `
        <div class="env-section">
            <h3 class="env-header env-${env.toLowerCase()}">${env} (${servers.length} servidores)</h3>
            <div class="servers-list">
                ${servers.map(server => `
                    <div class="server-card" data-environment="${server.environment}" data-app="${server.application_group}">
                        <div class="server-header">
                            <span class="server-name">${server.server_id}</span>
                            <span class="env-badge env-${server.environment.toLowerCase()}">${server.environment}</span>
                        </div>
                        <div class="server-body">
                            <p><strong>Aplicação:</strong> ${server.application_group}</p>
                            <p><strong>RTO:</strong> ${server.rto_hours}h</p>
                            <p><strong>Software:</strong> ${(server.software || []).slice(0, 3).join(', ')}${server.software?.length > 3 ? '...' : ''}</p>
                        </div>
                        <div class="server-footer">
                            <button class="btn btn-sm" onclick="showServerDetails('${server.server_id}')">Detalhes</button>
                        </div>
                    </div>
                `).join('')}
            </div>
        </div>
    `).join('');
}

/**
 * Popular filtro de aplicações
 */
function populateAppFilter() {
    const filter = document.getElementById('server-app-filter');
    if (!filter) return;
    
    const apps = [...new Set(appState.servers.map(s => s.application_group))].sort();
    
    filter.innerHTML = '<option value="">Todas</option>' + 
        apps.map(app => `<option value="${app}">${app}</option>`).join('');
}

/**
 * Mostrar detalhes de um servidor
 */
function showServerDetails(serverId) {
    const server = appState.servers.find(s => s.server_id === serverId);
    if (!server) return;
    
    const modal = document.getElementById('server-modal');
    const title = document.getElementById('modal-server-title');
    const body = document.getElementById('modal-server-body');
    
    if (!modal || !body) return;
    
    title.textContent = server.server_id;
    
    body.innerHTML = `
        <div class="server-details">
            <div class="detail-row">
                <span class="label">Ambiente:</span>
                <span class="value env-badge env-${server.environment.toLowerCase()}">${server.environment}</span>
            </div>
            <div class="detail-row">
                <span class="label">Aplicação:</span>
                <span class="value">${server.application_group}</span>
            </div>
            <div class="detail-row">
                <span class="label">RTO:</span>
                <span class="value">${server.rto_hours} horas</span>
            </div>
            <div class="detail-row">
                <span class="label">Janela de Manutenção:</span>
                <span class="value">${server.maintenance_window || 'Não definida'}</span>
            </div>
            <div class="detail-section">
                <h4>Software Instalado:</h4>
                <div class="software-list">
                    ${(server.software || []).map(sw => `<span class="software-tag">${sw}</span>`).join('')}
                </div>
            </div>
        </div>
    `;
    
    modal.classList.add('active');
}

/**
 * Carregar dados para o planeamento (tab schedule)
 */
async function loadScheduleData() {
    await Promise.all([
        loadCVEs(),
        loadServers()
    ]);
    renderScheduleView();
}

/**
 * Auto-detetar patches necessários
 */
async function loadRequiredPatches() {
    try {
        showNotification('A detetar todos os patches necessários...', 'info');
        // Load all CVEs for complete patch detection (max_cves=0 means unlimited)
        const data = await fetchAPI('/api/patches/required?max_cves=0');
        appState.requiredPatches = data.servers || [];
        
        // Atualizar seleções automaticamente
        appState.selectedPatches.clear();
        appState.requiredPatches.forEach(serverData => {
            const patches = serverData.patches.map(p => p.cve_id);
            if (patches.length > 0) {
                appState.selectedPatches.set(serverData.server_id, patches);
            }
        });
        
        updateSelectedCount();
        renderRequiredPatchesView();
        showNotification(`Detetados ${data.total_patches} patches em ${appState.requiredPatches.length} servidores`, 'success');
    } catch (error) {
        console.error('Erro ao detetar patches:', error);
        showNotification('Erro ao identificar patches necessários. Verifique se existem CVEs e servidores carregados.', 'error');
    }
}

/**
 * Renderizar vista de patches detetados
 */
function renderRequiredPatchesView() {
    const container = document.getElementById('required-patches-list');
    if (!container) return;
    
    if (appState.requiredPatches.length === 0) {
        container.innerHTML = '<p class="no-data">Nenhum patch necessário detetado</p>';
        return;
    }
    
    // Agrupar por ambiente
    const byEnv = { DEV: [], TEST: [], PROD: [] };
    appState.requiredPatches.forEach(server => {
        if (byEnv[server.environment]) {
            byEnv[server.environment].push(server);
        }
    });
    
    container.innerHTML = Object.entries(byEnv).map(([env, servers]) => {
        if (servers.length === 0) return '';
        return `
            <div class="env-section">
                <h4 class="env-header env-${env.toLowerCase()}">${env} (${servers.length} servidores)</h4>
                <div class="required-patches-grid">
                    ${servers.map(server => `
                        <div class="server-patch-card">
                            <div class="server-patch-header">
                                <span class="server-name">${server.server_id}</span>
                                <span class="env-badge env-${server.environment.toLowerCase()}">${server.environment}</span>
                            </div>
                            <div class="server-patch-body">
                                <p><strong>Grupo:</strong> ${server.application_group}</p>
                                <p><strong>Patches necessários:</strong> ${server.patches.length}</p>
                                <div class="patches-list">
                                    ${server.patches.map(patch => `
                                        <div class="patch-item">
                                            <label>
                                                <input type="checkbox" 
                                                       class="auto-patch-checkbox"
                                                       data-server="${server.server_id}"
                                                       data-cve="${patch.cve_id}"
                                                       checked>
                                                <span class="patch-cve">${patch.cve_id}</span>
                                                <span class="severity-badge severity-${patch.severity.toLowerCase()}">${patch.severity}</span>
                                                <span class="patch-duration">${patch.duration_hours}h</span>
                                            </label>
                                        </div>
                                    `).join('')}
                                </div>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }).join('');
    
    // Adicionar event listeners para checkboxes
    document.querySelectorAll('.auto-patch-checkbox').forEach(cb => {
        cb.addEventListener('change', (e) => {
            const serverId = e.target.dataset.server;
            const cveId = e.target.dataset.cve;
            
            if (!appState.selectedPatches.has(serverId)) {
                appState.selectedPatches.set(serverId, []);
            }
            
            const patches = appState.selectedPatches.get(serverId);
            const index = patches.indexOf(cveId);
            
            if (e.target.checked && index === -1) {
                patches.push(cveId);
            } else if (!e.target.checked && index !== -1) {
                patches.splice(index, 1);
            }
            
            updateSelectedCount();
        });
    });
}

/**
 * Renderizar vista de planeamento
 */
function renderScheduleView() {
    const container = document.getElementById('schedule-summary');
    if (!container) return;
    
    let totalPatches = 0;
    let serverCount = 0;
    
    appState.selectedPatches.forEach((patches, serverId) => {
        if (patches.length > 0) {
            totalPatches += patches.length;
            serverCount++;
        }
    });
    
    container.innerHTML = `
        <div class="schedule-stats">
            <div class="stat-card">
                <span class="stat-value">${serverCount}</span>
                <span class="stat-label">Servidores</span>
            </div>
            <div class="stat-card">
                <span class="stat-value">${totalPatches}</span>
                <span class="stat-label">Patches</span>
            </div>
        </div>
    `;
}

/**
 * Gerar plano de patches com algoritmo genético
 */
async function generatePlan() {
    // Construir lista de tasks a partir das seleções
    const tasks = [];
    
    appState.selectedPatches.forEach((cveIds, serverId) => {
        cveIds.forEach(cveId => {
            const cve = appState.cves.find(c => c.cve_id === cveId);
            const server = appState.servers.find(s => s.server_id === serverId);
            
            if (cve && server) {
                tasks.push({
                    server_id: serverId,
                    cve_id: cveId,
                    duration_hours: cve.patch_duration_hours,
                    priority: cve.priority || getSeverityPriority(cve.severity)
                });
            }
        });
    });
    
    if (tasks.length === 0) {
        showNotification('Selecione pelo menos um patch para planear', 'warning');
        return;
    }
    
    try {
        showNotification('A gerar plano com algoritmo genético...', 'info');
        
        const result = await fetchAPI('/api/plan', {
            method: 'POST',
            body: JSON.stringify({ tasks })
        });
        
        // Normalizar formato dos dados (API retorna schedule, não tasks)
        const schedule = result?.schedule || result?.tasks || [];
        appState.planData = {
            ...result,
            tasks: schedule.map(t => ({
                ...t,
                start_time: t.date || t.start_time  // Garantir que start_time existe
            }))
        };
        
        const tasksCount = schedule.length;
        showNotification(`Plano gerado: ${tasksCount} tarefas agendadas`, 'success');
        
        // Mostrar resultados e ir para o calendário
        renderPlanResults(result);
        showTab('calendar');
        
    } catch (error) {
        console.error('Erro ao gerar plano:', error);
        showNotification('Falha ao gerar planeamento. ' + (error.message || 'Tente novamente.'), 'error');
    }
}

/**
 * Obter prioridade baseada na severidade
 */
function getSeverityPriority(severity) {
    const priorities = { 'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 3, 'LOW': 4 };
    return priorities[severity] || 3;
}

/**
 * Atualizar contagem de patches selecionados
 */
function updateSelectedCount() {
    let total = 0;
    appState.selectedPatches.forEach(patches => {
        total += patches.length;
    });
    console.log(`Total patches selecionados: ${total}`);
}

/**
 * Renderizar calendário mensal (estilo planning de turnos)
 */
function renderMonthlyCalendar() {
    const container = document.getElementById('calendar-body');
    if (!container) return;
    
    const year = appState.currentMonth.getFullYear();
    const month = appState.currentMonth.getMonth();
    
    // Atualizar título do mês
    const monthTitle = document.getElementById('calendar-month-title');
    if (monthTitle) {
        monthTitle.textContent = new Date(year, month).toLocaleDateString('pt-PT', { 
            month: 'long', 
            year: 'numeric' 
        });
    }
    
    // Obter dias do mês
    const firstDay = new Date(year, month, 1);
    const lastDay = new Date(year, month + 1, 0);
    const daysInMonth = lastDay.getDate();
    
    // Ajustar para começar na Segunda (0=Seg, 6=Dom)
    let startDayOfWeek = firstDay.getDay() - 1;
    if (startDayOfWeek < 0) startDayOfWeek = 6; // Domingo passa a ser 6
    
    // Criar células do calendário
    let currentDay = 1;
    const today = new Date();
    let calendarHTML = '';
    
    // Calcular número de semanas necessárias
    const weeksNeeded = Math.ceil((startDayOfWeek + daysInMonth) / 7);
    
    for (let week = 0; week < weeksNeeded; week++) {
        calendarHTML += '<tr>';
        
        for (let dayOfWeek = 0; dayOfWeek < 7; dayOfWeek++) {
            const cellIndex = week * 7 + dayOfWeek;
            
            if (cellIndex < startDayOfWeek || currentDay > daysInMonth) {
                // Célula vazia
                calendarHTML += '<td class="empty-cell"></td>';
            } else {
                const cellDate = new Date(year, month, currentDay);
                const isToday = cellDate.toDateString() === today.toDateString();
                const isWeekend = dayOfWeek >= 5; // Sáb e Dom
                const isHoliday = isHolidayDate(cellDate);
                const tasks = getTasksForDate(cellDate);
                
                let cellClasses = ['calendar-cell'];
                if (isToday) cellClasses.push('today');
                if (isWeekend) cellClasses.push('weekend');
                if (isHoliday) cellClasses.push('holiday');
                if (tasks.length > 0) cellClasses.push('has-tasks');
                
                calendarHTML += `
                    <td class="${cellClasses.join(' ')}" data-date="${formatDateISO(cellDate)}" onclick="showDayDetails('${formatDateISO(cellDate)}')">
                        <div class="cell-header">
                            <span class="day-number">${currentDay}</span>
                            ${isHoliday ? `<span class="holiday-badge" title="${getHolidayName(cellDate)}">🎉</span>` : ''}
                        </div>
                        <div class="cell-tasks">
                            ${renderCellTasks(tasks)}
                        </div>
                    </td>
                `;
                currentDay++;
            }
        }
        
        calendarHTML += '</tr>';
    }
    
    container.innerHTML = calendarHTML;
}

/**
 * Renderizar tarefas dentro de uma célula do calendário
 */
function renderCellTasks(tasks) {
    if (tasks.length === 0) return '';
    
    return tasks.slice(0, 3).map(task => {
        const env = (task.environment || 'DEV').toLowerCase();
        
        // Suportar diferentes formatos de hora
        let timeStr;
        if (task.hour_start !== undefined) {
            // Formato da API: hour_start é um número (0-23)
            timeStr = `${String(task.hour_start).padStart(2, '0')}:00`;
        } else if (task.start_time) {
            // Formato antigo: start_time é timestamp
            const startTime = new Date(task.start_time);
            timeStr = startTime.toLocaleTimeString('pt-PT', { hour: '2-digit', minute: '2-digit' });
        } else {
            timeStr = '--:--';
        }
        
        const severity = (task.severity || 'Medium').toLowerCase();
        const serverId = task.server_id || 'Unknown';
        const cveId = task.cve_id || 'N/A';
        
        return `
            <div class="task-block ${severity}" title="${serverId} - ${cveId} (${timeStr})">
                <span class="task-time">${timeStr}</span>
                <span class="task-server">${serverId}</span>
                <span class="task-env env-${env}">${env.toUpperCase()}</span>
            </div>
        `;
    }).join('') + (tasks.length > 3 ? `<div class="more-tasks">+${tasks.length - 3} mais</div>` : '');
}

/**
 * Obter tarefas para uma data específica
 */
function getTasksForDate(date) {
    if (!appState.planData || !appState.planData.tasks) return [];
    
    const dateStr = formatDateISO(date);
    
    return appState.planData.tasks.filter(task => {
        // Suportar diferentes formatos de data
        const taskDateValue = task.date || task.start_time || task.scheduled_date;
        if (!taskDateValue) return false;
        
        // Se já é uma string ISO (YYYY-MM-DD)
        if (typeof taskDateValue === 'string' && taskDateValue.length >= 10) {
            return taskDateValue.substring(0, 10) === dateStr;
        }
        
        // Se é timestamp ou Date
        const taskDate = new Date(taskDateValue);
        return formatDateISO(taskDate) === dateStr;
    });
}

/**
 * Verificar se uma data é feriado
 */
function isHolidayDate(date) {
    const dateStr = formatDateISO(date);
    return appState.holidays.some(h => h.date === dateStr);
}

/**
 * Obter nome do feriado
 */
function getHolidayName(date) {
    const dateStr = formatDateISO(date);
    const holiday = appState.holidays.find(h => h.date === dateStr);
    return holiday ? holiday.name : '';
}

/**
 * Mostrar detalhes de um dia específico
 */
function showDayDetails(dateStr) {
    const tasks = getTasksForDate(new Date(dateStr));
    const holiday = appState.holidays.find(h => h.date === dateStr);
    
    const panel = document.getElementById('day-detail-panel');
    const title = document.getElementById('day-detail-title');
    const content = document.getElementById('day-detail-content');
    
    if (!panel || !content) return;
    
    title.textContent = `Detalhes: ${formatDate(dateStr)}`;
    
    let html = '';
    
    if (holiday) {
        html += `<div class="holiday-notice">🎉 Feriado: ${holiday.name}</div>`;
    }
    
    if (tasks.length === 0) {
        html += '<p class="no-tasks">Nenhuma tarefa agendada para este dia.</p>';
    } else {
        html += `<div class="day-tasks-list">`;
        tasks.forEach(task => {
            // Suportar diferentes formatos de hora
            let timeStartStr, timeEndStr;
            if (task.hour_start !== undefined) {
                timeStartStr = `${String(task.hour_start).padStart(2, '0')}:00`;
                timeEndStr = `${String(task.hour_end || task.hour_start + (task.duration || 1)).padStart(2, '0')}:00`;
            } else if (task.start_time) {
                const startTime = new Date(task.start_time);
                const endTime = task.end_time ? new Date(task.end_time) : new Date(startTime.getTime() + 3600000);
                timeStartStr = startTime.toLocaleTimeString('pt-PT', {hour: '2-digit', minute: '2-digit'});
                timeEndStr = endTime.toLocaleTimeString('pt-PT', {hour: '2-digit', minute: '2-digit'});
            } else {
                timeStartStr = '--:--';
                timeEndStr = '--:--';
            }
            
            const env = (task.environment || 'DEV').toLowerCase();
            const severity = (task.severity || 'Medium').toLowerCase();
            const duration = task.duration || task.duration_hours || 1;
            const workers = task.workers || [];
            
            html += `
                <div class="day-task-item ${env} ${severity}">
                    <div class="task-header">
                        <span class="task-time">${timeStartStr} - ${timeEndStr}</span>
                        <span class="task-env env-${env}">${(task.environment || 'DEV').toUpperCase()}</span>
                        <span class="severity-badge severity-${severity}">${task.severity || 'Medium'}</span>
                    </div>
                    <div class="task-info">
                        <div><strong>Servidor:</strong> ${task.server_id || 'N/A'}</div>
                        <div><strong>CVE:</strong> ${task.cve_id || 'N/A'}</div>
                        <div><strong>Software:</strong> ${task.software_id || 'N/A'} ${task.software_version || ''}</div>
                        <div><strong>Duração:</strong> ${duration}h</div>
                        <div><strong>Prioridade:</strong> ${task.priority || 'N/A'}</div>
                    </div>
                    <div class="task-team">
                        <strong>Equipa:</strong>
                        ${workers.length > 0 ? workers.map(w => `<span class="worker-tag">${w}</span>`).join('') : '<span class="no-workers">Não atribuída</span>'}
                    </div>
                </div>
            `;
        });
        html += '</div>';
    }
    
    content.innerHTML = html;
    panel.style.display = 'block';
}

/**
 * Mostrar detalhes de uma tarefa
 */
function showTaskDetails(taskId) {
    const task = appState.planData?.tasks?.find(t => t.task_id === taskId);
    if (!task) return;
    
    const modal = document.getElementById('server-modal');
    const modalTitle = document.getElementById('modal-server-title');
    const modalBody = document.getElementById('modal-server-body');
    
    if (!modal || !modalBody) return;
    
    const startTime = new Date(task.start_time);
    const endTime = new Date(task.end_time);
    
    modalTitle.textContent = `Tarefa: ${task.server_id}`;
    
    modalBody.innerHTML = `
        <div class="task-details">
            <div class="detail-row">
                <span class="detail-label">Servidor:</span>
                <span class="detail-value">${task.server_id}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Ambiente:</span>
                <span class="detail-value env-badge env-${task.environment?.toLowerCase()}">${task.environment}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">CVE:</span>
                <span class="detail-value">${task.cve_id}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Início:</span>
                <span class="detail-value">${formatDateTime(startTime)}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Fim:</span>
                <span class="detail-value">${formatDateTime(endTime)}</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Duração:</span>
                <span class="detail-value">${task.duration_hours}h</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Equipa:</span>
                <span class="detail-value">
                    ${(task.workers || []).map(w => `<span class="worker-tag">${w}</span>`).join('')}
                </span>
            </div>
        </div>
    `;
    
    modal.classList.add('active');
}

/**
 * Navegar para mês anterior
 */
function previousMonth() {
    appState.currentMonth.setMonth(appState.currentMonth.getMonth() - 1);
    renderMonthlyCalendar();
}

/**
 * Navegar para próximo mês
 */
function nextMonth() {
    appState.currentMonth.setMonth(appState.currentMonth.getMonth() + 1);
    renderMonthlyCalendar();
}

/**
 * Ir para o mês atual
 */
function goToCurrentMonth() {
    appState.currentMonth = new Date();
    renderMonthlyCalendar();
}

/**
 * Formatar data para exibição
 */
function formatDate(dateStr) {
    const date = new Date(dateStr);
    return date.toLocaleDateString('pt-PT', { 
        day: '2-digit', 
        month: 'short', 
        year: 'numeric' 
    });
}

/**
 * Formatar data ISO (YYYY-MM-DD)
 */
function formatDateISO(date) {
    return date.toISOString().split('T')[0];
}

/**
 * Formatar data e hora
 */
function formatDateTime(date) {
    return date.toLocaleString('pt-PT', {
        day: '2-digit',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

/**
 * Filtrar CVEs por severidade
 */
function filterCVEsBySeverity(severity) {
    const container = document.getElementById('cve-list');
    const cards = container.querySelectorAll('.cve-card');
    
    cards.forEach(card => {
        if (severity === 'all') {
            card.style.display = 'block';
        } else {
            const badge = card.querySelector('.severity-badge');
            card.style.display = badge.textContent === severity ? 'block' : 'none';
        }
    });
}

/**
 * Pesquisar CVEs
 */
function searchCVEs(query) {
    const container = document.getElementById('cve-list');
    const cards = container.querySelectorAll('.cve-card');
    const searchTerm = query.toLowerCase();
    
    cards.forEach(card => {
        const text = card.textContent.toLowerCase();
        card.style.display = text.includes(searchTerm) ? 'block' : 'none';
    });
}

/**
 * Inicialização da aplicação
 */
document.addEventListener('DOMContentLoaded', () => {
    // Setup navegação por tabs
    document.querySelectorAll('.nav-item').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const tab = link.dataset.tab;
            
            // Atualizar navegação ativa
            document.querySelectorAll('.nav-item').forEach(l => l.classList.remove('active'));
            link.classList.add('active');
            
            // Mostrar conteúdo da tab
            document.querySelectorAll('.tab-content').forEach(content => {
                content.classList.remove('active');
            });
            document.getElementById(tab)?.classList.add('active');
            
            // Carregar dados da tab
            appState.currentTab = tab;
            switch(tab) {
                case 'dashboard': loadStats(); break;
                case 'cves': loadCVEs(); break;
                case 'servers': loadServers(); break;
                case 'schedule': loadScheduleTab(); break;
                case 'calendar': renderMonthlyCalendar(); break;
            }
        });
    });
    
    // Setup navegação do calendário
    document.getElementById('prev-month')?.addEventListener('click', previousMonth);
    document.getElementById('next-month')?.addEventListener('click', nextMonth);
    
    // Setup fechar painel de detalhes do dia
    document.getElementById('close-day-detail')?.addEventListener('click', () => {
        document.getElementById('day-detail-panel').style.display = 'none';
    });
    
    // Setup botão de auto-geração de plano
    document.getElementById('auto-generate-plan')?.addEventListener('click', autoGeneratePlan);
    
    // Setup filtros de CVE
    document.getElementById('cve-severity-filter')?.addEventListener('change', renderCVETable);
    document.getElementById('cve-software-filter')?.addEventListener('input', renderCVETable);
    document.getElementById('cve-sort')?.addEventListener('change', renderCVETable);
    document.getElementById('refresh-cves')?.addEventListener('click', loadCVEs);
    
    // Setup filtros de data de CVE
    const cveDatePeriod = document.getElementById('cve-date-period');
    const cveCustomDateRange = document.getElementById('cve-custom-date-range');
    if (cveDatePeriod) {
        cveDatePeriod.addEventListener('change', (e) => {
            if (cveCustomDateRange) {
                cveCustomDateRange.style.display = e.target.value === 'custom' ? 'flex' : 'none';
            }
            renderCVETable();
        });
    }
    document.getElementById('cve-date-from')?.addEventListener('change', renderCVETable);
    document.getElementById('cve-date-to')?.addEventListener('change', renderCVETable);
    
    // Setup select all CVEs checkbox
    document.getElementById('select-all-cves')?.addEventListener('change', (e) => {
        if (!appState.selectedCVEsForPlan) {
            appState.selectedCVEsForPlan = new Set();
        }
        document.querySelectorAll('#cve-table-body .cve-checkbox').forEach(cb => {
            cb.checked = e.target.checked;
            if (e.target.checked) {
                appState.selectedCVEsForPlan.add(cb.dataset.cve);
                cb.closest('tr')?.classList.add('selected');
            } else {
                appState.selectedCVEsForPlan.delete(cb.dataset.cve);
                cb.closest('tr')?.classList.remove('selected');
            }
        });
        updateSelectedCVECount();
    });
    
    // Setup botão selecionar filtradas
    document.getElementById('select-filtered-cves')?.addEventListener('click', selectAllFilteredCVEs);
    
    // Setup botão de planeamento a partir de CVEs
    document.getElementById('plan-selected-cves')?.addEventListener('click', openPlanFromCVEsModal);
    
    // Setup filtros de servidor
    document.getElementById('server-env-filter')?.addEventListener('change', filterServers);
    document.getElementById('server-app-filter')?.addEventListener('change', filterServers);
    document.getElementById('refresh-servers')?.addEventListener('click', loadServers);
    
    // Setup filtro do calendário
    document.getElementById('calendar-env-filter')?.addEventListener('change', renderMonthlyCalendar);
    
    // Setup exportar calendário
    document.getElementById('export-calendar')?.addEventListener('click', exportCalendar);
    
    // Setup modal close
    document.querySelectorAll('.modal-close').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.modal').forEach(m => m.classList.remove('active'));
        });
    });
    
    // Definir data de início padrão
    const startDateInput = document.getElementById('plan-start-date');
    if (startDateInput) {
        startDateInput.value = formatDateISO(new Date());
    }
    
    // Setup CVE period selector
    const cvePeriodSelect = document.getElementById('plan-cve-period');
    const customDateRange = document.getElementById('custom-date-range');
    if (cvePeriodSelect && customDateRange) {
        cvePeriodSelect.addEventListener('change', (e) => {
            if (e.target.value === 'custom') {
                customDateRange.style.display = 'flex';
                // Definir datas padrão para custom (último mês)
                const today = new Date();
                const monthAgo = new Date();
                monthAgo.setDate(today.getDate() - 30);
                document.getElementById('plan-cve-from-date').value = formatDateISO(monthAgo);
                document.getElementById('plan-cve-to-date').value = formatDateISO(today);
            } else {
                customDateRange.style.display = 'none';
            }
            // Update period indicator
            updatePeriodIndicator();
        });
        
        // Also update indicator when custom dates change
        document.getElementById('plan-cve-from-date')?.addEventListener('change', updatePeriodIndicator);
        document.getElementById('plan-cve-to-date')?.addEventListener('change', updatePeriodIndicator);
    }
    
    // Carregar dados iniciais
    loadStats();
    loadCVEs();
    loadServers();
    
    console.log('PLNTDIA Frontend initialized');
});

/**
 * Carregar tab de schedule com patches identificados
 */
async function loadScheduleTab() {
    try {
        // Load all CVEs for proper planning (max_cves=0 means unlimited)
        showNotification('A carregar todos os CVEs para planeamento...', 'info');
        const data = await fetchAPI('/api/patches/required?max_cves=0');
        appState.requiredPatches = data.servers || [];
        renderAutoPatchesSummary();
        updatePeriodIndicator();  // Update period indicator after loading
        showNotification(`${data.total_patches} patches identificados em ${data.total_servers} servidores`, 'success');
    } catch (error) {
        console.error('Erro ao carregar patches:', error);
        showNotification('Não foi possível carregar patches necessários. Clique em "Identificar Patches" primeiro.', 'warning');
    }
}

/**
 * Contar patches no período seleccionado
 */
function countPatchesInPeriod(periodDays) {
    if (!appState.requiredPatches || appState.requiredPatches.length === 0) {
        return { total: 0, inPeriod: 0 };
    }
    
    let total = 0;
    let inPeriod = 0;
    const now = new Date();
    let dateFrom = null;
    
    if (periodDays !== 'all' && periodDays !== 'custom') {
        dateFrom = new Date();
        dateFrom.setDate(now.getDate() - parseInt(periodDays));
    }
    
    appState.requiredPatches.forEach(server => {
        if (server.patches && Array.isArray(server.patches)) {
            server.patches.forEach(patch => {
                total++;
                if (!dateFrom) {
                    inPeriod++;
                } else {
                    const patchDate = patch.published_date ? new Date(patch.published_date) : null;
                    if (patchDate && patchDate >= dateFrom && patchDate <= now) {
                        inPeriod++;
                    }
                }
            });
        }
    });
    
    return { total, inPeriod };
}

/**
 * Actualizar indicador de período
 */
function updatePeriodIndicator() {
    const periodSelect = document.getElementById('plan-cve-period');
    const indicator = document.getElementById('period-patch-count');
    
    if (!periodSelect || !indicator) return;
    
    const period = periodSelect.value;
    
    if (period === 'all') {
        const counts = countPatchesInPeriod(period);
        indicator.textContent = `${counts.total} patches`;
        indicator.className = 'period-indicator';
    } else if (period === 'custom') {
        // Para custom, recalcular com as datas específicas
        const fromInput = document.getElementById('plan-cve-from-date')?.value;
        const toInput = document.getElementById('plan-cve-to-date')?.value;
        
        if (fromInput && toInput) {
            const counts = countPatchesInCustomPeriod(new Date(fromInput), new Date(toInput));
            indicator.textContent = `${counts.inPeriod}/${counts.total} patches`;
            indicator.className = 'period-indicator' + (counts.inPeriod === 0 ? ' empty' : '');
        } else {
            indicator.textContent = 'Seleccione datas';
            indicator.className = 'period-indicator';
        }
    } else {
        const counts = countPatchesInPeriod(period);
        indicator.textContent = `${counts.inPeriod}/${counts.total} patches`;
        indicator.className = 'period-indicator' + (counts.inPeriod === 0 ? ' empty' : '');
    }
}

/**
 * Contar patches num período custom
 */
function countPatchesInCustomPeriod(dateFrom, dateTo) {
    if (!appState.requiredPatches || appState.requiredPatches.length === 0) {
        return { total: 0, inPeriod: 0 };
    }
    
    let total = 0;
    let inPeriod = 0;
    
    appState.requiredPatches.forEach(server => {
        if (server.patches && Array.isArray(server.patches)) {
            server.patches.forEach(patch => {
                total++;
                const patchDate = patch.published_date ? new Date(patch.published_date) : null;
                if (patchDate && patchDate >= dateFrom && patchDate <= dateTo) {
                    inPeriod++;
                }
            });
        }
    });
    
    return { total, inPeriod };
}
/**
 * Renderizar resumo de patches identificados
 */
function renderAutoPatchesSummary() {
    const summary = document.getElementById('auto-patches-summary');
    const container = document.getElementById('patches-list-container');
    
    if (!summary || !container) return;
    
    // Calcular totais
    let totalPatches = 0;
    let criticalCount = 0;
    const byEnv = { DEV: 0, TEST: 0, PROD: 0 };
    
    appState.requiredPatches.forEach(server => {
        totalPatches += server.patches.length;
        byEnv[server.environment] = (byEnv[server.environment] || 0) + server.patches.length;
        server.patches.forEach(p => {
            if (p.severity === 'CRITICAL') criticalCount++;
        });
    });
    
    summary.innerHTML = `
        <div class="summary-stats">
            <div class="summary-stat">
                <span class="stat-value">${appState.requiredPatches.length}</span>
                <span class="stat-label">Servidores Afetados</span>
            </div>
            <div class="summary-stat">
                <span class="stat-value">${totalPatches}</span>
                <span class="stat-label">Patches a Aplicar</span>
            </div>
            <div class="summary-stat critical">
                <span class="stat-value">${criticalCount}</span>
                <span class="stat-label">Critical</span>
            </div>
        </div>
        <div class="env-breakdown">
            <span class="env-badge env-dev">DEV: ${byEnv.DEV}</span>
            <span class="env-badge env-test">TEST: ${byEnv.TEST}</span>
            <span class="env-badge env-prod">PROD: ${byEnv.PROD}</span>
        </div>
    `;
    
    // Renderizar lista de patches por servidor
    container.innerHTML = appState.requiredPatches.slice(0, 10).map(server => `
        <div class="patch-server-card">
            <div class="server-header">
                <span class="server-name">${server.server_id}</span>
                <span class="env-badge env-${server.environment.toLowerCase()}">${server.environment}</span>
            </div>
            <div class="patches-list">
                ${server.patches.map(p => `
                    <span class="patch-tag ${p.severity.toLowerCase()}" title="${p.software}">${p.cve_id}</span>
                `).join('')}
            </div>
        </div>
    `).join('') + (appState.requiredPatches.length > 10 ? `<p class="more-info">... e mais ${appState.requiredPatches.length - 10} servidores</p>` : '');
}

/**
 * Auto-gerar plano com patches identificados
 */
async function autoGeneratePlan() {
    // Verificar se há patches identificados
    if (!appState.requiredPatches || appState.requiredPatches.length === 0) {
        showNotification('Nenhum patch identificado. Clique em "Identificar Patches" primeiro.', 'warning');
        return;
    }
    
    // Obter período de CVEs seleccionado
    const cvePeriod = document.getElementById('plan-cve-period')?.value || 'all';
    let dateFrom = null;
    let dateTo = new Date();
    
    if (cvePeriod === 'custom') {
        const fromInput = document.getElementById('plan-cve-from-date')?.value;
        const toInput = document.getElementById('plan-cve-to-date')?.value;
        if (fromInput) dateFrom = new Date(fromInput);
        if (toInput) dateTo = new Date(toInput);
    } else if (cvePeriod !== 'all') {
        const days = parseInt(cvePeriod);
        dateFrom = new Date();
        dateFrom.setDate(dateFrom.getDate() - days);
    }
    
    // Construir tarefas a partir dos patches identificados
    const tasks = [];
    let filteredByPeriodCount = 0;
    
    appState.requiredPatches.forEach(server => {
        if (server.patches && Array.isArray(server.patches)) {
            server.patches.forEach(patch => {
                // Filtrar por período se especificado
                if (dateFrom) {
                    const patchDate = patch.published_date ? new Date(patch.published_date) : null;
                    if (patchDate && (patchDate < dateFrom || patchDate > dateTo)) {
                        filteredByPeriodCount++;
                        return; // Skip this patch
                    }
                }
                
                tasks.push({
                    server_id: server.server_id,
                    cve_id: patch.cve_id,
                    duration_hours: patch.duration_hours || 4,
                    priority: getSeverityPriority(patch.severity)
                });
            });
        }
    });
    
    if (tasks.length === 0) {
        if (filteredByPeriodCount > 0) {
            showNotification(`Nenhum patch no período seleccionado (${filteredByPeriodCount} filtrados)`, 'warning');
        } else {
            showNotification('Nenhum patch identificado para planear', 'warning');
        }
        return;
    }
    
    // Log de filtro de período
    if (filteredByPeriodCount > 0) {
        console.log(`Período CVE: ${filteredByPeriodCount} patches filtrados, ${tasks.length} incluídos`);
    }
    
    // Filtrar por severidade mínima
    const minSeverity = document.getElementById('plan-min-severity')?.value || 'Low';
    const severityOrder = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    const minIndex = severityOrder.indexOf(minSeverity.toUpperCase());
    
    const filteredTasks = tasks.filter(t => {
        const patch = appState.requiredPatches
            .flatMap(s => s.patches)
            .find(p => p.cve_id === t.cve_id);
        const taskIndex = severityOrder.indexOf(patch?.severity || 'LOW');
        return taskIndex <= minIndex;
    });
    
    if (filteredTasks.length === 0) {
        showNotification('Nenhum patch com a severidade selecionada', 'warning');
        return;
    }
    
    try {
        showNotification(`A gerar plano para ${filteredTasks.length} patches...`, 'info');
        
        // Ler configurações do formulário
        const startDate = document.getElementById('plan-start-date')?.value || null;
        const planningDays = parseInt(document.getElementById('plan-days')?.value) || 30;
        const generations = parseInt(document.getElementById('plan-generations')?.value) || 100;
        
        // Construir objecto de configuração
        const config = {
            planning_days: planningDays,
            generations: generations
        };
        
        // Adicionar data de início se especificada
        if (startDate) {
            config.start_date = startDate;
        }
        
        console.log('Configuração do planeamento:', { tasks: filteredTasks.length, config });
        
        const result = await fetchAPI('/api/plan', {
            method: 'POST',
            body: JSON.stringify({ 
                tasks: filteredTasks,
                config: config
            })
        });
        
        appState.planData = result;
        
        // Mostrar resultados
        const tasksCount = result?.tasks?.length || result?.scheduled_tasks?.length || 0;
        renderPlanResults(result);
        showNotification(`Plano gerado: ${tasksCount} tarefas agendadas`, 'success');
        
    } catch (error) {
        console.error('Erro ao gerar plano:', error);
        
        // Fornecer mensagem mais específica baseada no erro
        let errorMsg = 'Erro ao gerar plano automático';
        if (error.message) {
            if (error.message.includes('No valid tasks')) {
                errorMsg = 'Não há tarefas válidas para agendar. Verifique se os CVEs correspondem ao software instalado nos servidores.';
            } else if (error.message.includes('timeout') || error.message.includes('Timeout')) {
                errorMsg = 'O planeamento demorou demasiado tempo. Tente reduzir o número de dias ou patches.';
            } else {
                errorMsg = `Erro no planeamento: ${error.message}`;
            }
        }
        showNotification(errorMsg, 'error');
    }
}

/**
 * Renderizar resultados do planeamento com relatório detalhado do GA
 */
function renderPlanResults(result) {
    const container = document.getElementById('plan-results');
    if (!container) return;
    
    // Suportar diferentes formatos de resposta da API
    const schedule = result?.schedule || result?.tasks || result?.scheduled_tasks || [];
    const gaReport = result?.ga_report || {};
    const metrics = result?.metrics || {};
    
    if (schedule.length === 0) {
        container.innerHTML = '<p class="no-results">Nenhuma tarefa foi agendada.</p>';
        return;
    }
    
    // Agrupar por dia
    const byDay = {};
    schedule.forEach(task => {
        const taskDate = task.date || task.start_time || task.scheduled_date;
        const day = taskDate ? (typeof taskDate === 'string' && taskDate.length === 10 ? taskDate : formatDateISO(new Date(taskDate))) : 'Sem data';
        if (!byDay[day]) byDay[day] = [];
        byDay[day].push(task);
    });
    
    // Guardar schedule no estado para o calendário
    appState.planData = { 
        ...result, 
        tasks: schedule.map(t => ({
            ...t,
            start_time: t.start_time || t.date
        }))
    };
    
    container.innerHTML = `
        <!-- Resumo Rápido -->
        <div class="results-summary">
            <div class="summary-stats">
                <div class="stat-box">
                    <span class="stat-number">${schedule.length}</span>
                    <span class="stat-label">Tarefas Agendadas</span>
                </div>
                <div class="stat-box">
                    <span class="stat-number">${metrics.total_tasks || schedule.length}</span>
                    <span class="stat-label">Total de Tarefas</span>
                </div>
                <div class="stat-box success">
                    <span class="stat-number">${metrics.success_rate || 100}%</span>
                    <span class="stat-label">Taxa de Sucesso</span>
                </div>
                <div class="stat-box">
                    <span class="stat-number">${Object.keys(byDay).length}</span>
                    <span class="stat-label">Dias de Trabalho</span>
                </div>
            </div>
            <div class="summary-actions">
                <button class="btn btn-primary" onclick="showTab('calendar')">📅 Ver no Calendário</button>
                <button class="btn btn-secondary" onclick="showGAReport()">📊 Ver Relatório Detalhado</button>
                <button class="btn btn-secondary" onclick="exportCalendar()">📥 Exportar CSV</button>
            </div>
        </div>
        
        <!-- Distribuição por Severidade e Ambiente -->
        <div class="distribution-charts">
            <div class="chart-container">
                <h4>Por Severidade</h4>
                <div class="bar-chart">
                    ${renderDistributionBars(metrics.by_severity || {}, ['Critical', 'High', 'Medium', 'Low'])}
                </div>
            </div>
            <div class="chart-container">
                <h4>Por Ambiente</h4>
                <div class="bar-chart">
                    ${renderDistributionBars(metrics.by_environment || {}, ['DEV', 'TEST', 'PROD'])}
                </div>
            </div>
        </div>
        
        <!-- Timeline dos próximos dias -->
        <div class="results-timeline">
            <h4>📅 Próximas Tarefas</h4>
            ${Object.entries(byDay).sort((a, b) => a[0].localeCompare(b[0])).slice(0, 7).map(([day, dayTasks]) => `
                <div class="timeline-day">
                    <div class="timeline-date">${formatDate(day)}</div>
                    <div class="timeline-tasks">
                        ${dayTasks.map(t => `
                            <div class="timeline-task env-${(t.environment || 'DEV').toLowerCase()}">
                                <span class="task-time">${t.start_hour || '--'}:00</span>
                                <span class="task-server">${t.server_id}</span>
                                <span class="task-cve severity-${(t.severity || 'medium').toLowerCase()}">${t.cve_id}</span>
                                <span class="task-duration">${t.duration || t.duration_hours || '-'}h</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `).join('')}
            ${Object.keys(byDay).length > 7 ? `<p class="more-days">... e mais ${Object.keys(byDay).length - 7} dias</p>` : ''}
        </div>
        
        <!-- Detalhes GA (colapsável) -->
        <div id="ga-report-detail" class="ga-report-panel" style="display: none;">
            ${renderGAReportDetail(gaReport)}
        </div>
    `;
}

/**
 * Renderizar barras de distribuição
 */
function renderDistributionBars(data, keys) {
    const total = Object.values(data).reduce((a, b) => a + b, 0) || 1;
    
    return keys.map(key => {
        const count = data[key] || 0;
        const percentage = Math.round((count / total) * 100);
        const colorClass = key.toLowerCase().replace('_', '-');
        
        return `
            <div class="distribution-row">
                <span class="dist-label">${key}</span>
                <div class="dist-bar-container">
                    <div class="dist-bar ${colorClass}" style="width: ${percentage}%"></div>
                </div>
                <span class="dist-value">${count} (${percentage}%)</span>
            </div>
        `;
    }).join('');
}

/**
 * Renderizar detalhes do relatório GA
 */
function renderGAReportDetail(gaReport) {
    if (!gaReport || Object.keys(gaReport).length === 0) {
        return '<p>Dados do algoritmo genético não disponíveis.</p>';
    }
    
    const config = gaReport.config || {};
    const evolution = gaReport.evolution || {};
    const results = gaReport.results || {};
    const analysis = gaReport.analysis || {};
    
    return `
        <h4>📊 Relatório do Algoritmo Genético</h4>
        
        <div class="ga-report-grid">
            <!-- Configuração -->
            <div class="ga-section">
                <h5>⚙️ Configuração</h5>
                <table class="ga-config-table">
                    <tr><td>População</td><td>${config.population_size || '-'}</td></tr>
                    <tr><td>Gerações</td><td>${config.generations || '-'}</td></tr>
                    <tr><td>Taxa de Crossover</td><td>${((config.crossover_rate || 0) * 100).toFixed(0)}%</td></tr>
                    <tr><td>Taxa de Mutação</td><td>${((config.mutation_rate || 0) * 100).toFixed(0)}%</td></tr>
                    <tr><td>Elite Size</td><td>${config.elite_size || '-'}</td></tr>
                    <tr><td>Tournament Size</td><td>${config.tournament_size || '-'}</td></tr>
                    <tr><td>Semanas de Planeamento</td><td>${config.planning_weeks || '-'}</td></tr>
                </table>
            </div>
            
            <!-- Evolução -->
            <div class="ga-section">
                <h5>📈 Evolução</h5>
                <table class="ga-config-table">
                    <tr><td>Fitness Inicial</td><td>${(evolution.initial_fitness || 0).toFixed(2)}</td></tr>
                    <tr><td>Fitness Final</td><td>${(evolution.final_fitness || 0).toFixed(2)}</td></tr>
                    <tr><td>Melhoria</td><td class="improvement">+${(evolution.improvement || 0).toFixed(2)}%</td></tr>
                    <tr><td>Geração do Melhor</td><td>${evolution.generations_to_best || '-'}</td></tr>
                </table>
                <div class="fitness-chart">
                    ${renderFitnessChart(evolution.best_fitness_history || [], evolution.avg_fitness_history || [])}
                </div>
            </div>
            
            <!-- Resultados -->
            <div class="ga-section">
                <h5>✅ Resultados</h5>
                <table class="ga-config-table">
                    <tr><td>Tarefas Totais</td><td>${results.total_tasks || '-'}</td></tr>
                    <tr><td>Tarefas Agendadas</td><td class="success">${results.scheduled_tasks || '-'}</td></tr>
                    <tr><td>Tarefas Falhadas</td><td class="error">${results.failed_tasks || 0}</td></tr>
                    <tr><td>Taxa de Sucesso</td><td class="success">${(results.success_rate || 0).toFixed(1)}%</td></tr>
                    <tr><td>Horas Totais</td><td>${results.total_hours_scheduled || '-'}h</td></tr>
                </table>
            </div>
            
            <!-- Análise -->
            <div class="ga-section">
                <h5>🔍 Análise</h5>
                <table class="ga-config-table">
                    <tr><td>CVEs Críticos Agendados</td><td class="critical">${analysis.critical_scheduled || 0}</td></tr>
                    <tr><td>CVEs High Agendados</td><td class="high">${analysis.high_scheduled || 0}</td></tr>
                    <tr><td>Workers Utilizados</td><td>${analysis.workers_utilized || 0} / ${analysis.total_workers_available || 0}</td></tr>
                    <tr><td>Taxa de Utilização Workers</td><td>${(analysis.worker_utilization_rate || 0).toFixed(1)}%</td></tr>
                </table>
            </div>
        </div>
        
        <!-- Distribuição por Worker -->
        ${results.by_worker && Object.keys(results.by_worker).length > 0 ? `
            <div class="ga-section full-width">
                <h5>👥 Distribuição por Worker</h5>
                <div class="worker-distribution">
                    ${Object.entries(results.by_worker).map(([worker, count]) => `
                        <div class="worker-stat">
                            <span class="worker-name">${worker}</span>
                            <span class="worker-count">${count} tarefas</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        ` : ''}
        
        <!-- Tempo de Execução -->
        <div class="ga-footer">
            <span>Tempo de Execução: ${gaReport.execution_time_ms || 0}ms</span>
            ${gaReport.report_id ? `<span>Report ID: #${gaReport.report_id}</span>` : ''}
        </div>
    `;
}

/**
 * Renderizar gráfico de fitness (simplificado com CSS)
 */
function renderFitnessChart(bestHistory, avgHistory) {
    if (!bestHistory || bestHistory.length === 0) {
        return '<p class="no-chart">Dados de evolução não disponíveis</p>';
    }
    
    const maxFitness = Math.max(...bestHistory, ...avgHistory) || 1;
    const step = Math.max(1, Math.floor(bestHistory.length / 20)); // Mostrar até 20 pontos
    
    const points = [];
    for (let i = 0; i < bestHistory.length; i += step) {
        points.push({
            gen: i,
            best: bestHistory[i],
            avg: avgHistory[i] || 0
        });
    }
    // Garantir que o último ponto está incluído
    if (points[points.length - 1].gen !== bestHistory.length - 1) {
        points.push({
            gen: bestHistory.length - 1,
            best: bestHistory[bestHistory.length - 1],
            avg: avgHistory[avgHistory.length - 1] || 0
        });
    }
    
    return `
        <div class="mini-chart">
            <div class="chart-bars">
                ${points.map((p, i) => `
                    <div class="chart-bar-group" title="Gen ${p.gen}: Best=${p.best.toFixed(1)}, Avg=${p.avg.toFixed(1)}">
                        <div class="chart-bar best" style="height: ${(p.best / maxFitness * 100)}%"></div>
                        <div class="chart-bar avg" style="height: ${(p.avg / maxFitness * 100)}%"></div>
                    </div>
                `).join('')}
            </div>
            <div class="chart-legend">
                <span class="legend-item"><span class="legend-color best"></span> Best Fitness</span>
                <span class="legend-item"><span class="legend-color avg"></span> Avg Fitness</span>
            </div>
        </div>
    `;
}

/**
 * Mostrar/ocultar relatório GA detalhado
 */
function showGAReport() {
    const panel = document.getElementById('ga-report-detail');
    if (panel) {
        panel.style.display = panel.style.display === 'none' ? 'block' : 'none';
    }
}

/**
 * Filtrar tabela de CVEs
 */
function filterCVETable() {
    const severityFilter = document.getElementById('cve-severity-filter')?.value || '';
    const softwareFilter = (document.getElementById('cve-software-filter')?.value || '').toLowerCase();
    
    const rows = document.querySelectorAll('#cve-table-body tr');
    rows.forEach(row => {
        const severity = row.dataset.severity || '';
        const software = (row.dataset.software || '').toLowerCase();
        
        const matchesSeverity = !severityFilter || severity === severityFilter;
        const matchesSoftware = !softwareFilter || software.includes(softwareFilter);
        
        row.style.display = matchesSeverity && matchesSoftware ? '' : 'none';
    });
}

/**
 * Filtrar lista de servidores
 */
function filterServers() {
    const envFilter = document.getElementById('server-env-filter')?.value || '';
    const appFilter = document.getElementById('server-app-filter')?.value || '';
    
    const cards = document.querySelectorAll('.server-card');
    cards.forEach(card => {
        const env = card.dataset.environment || '';
        const app = card.dataset.app || '';
        
        const matchesEnv = !envFilter || env === envFilter;
        const matchesApp = !appFilter || app === appFilter;
        
        card.style.display = matchesEnv && matchesApp ? '' : 'none';
    });
}

/**
 * Exportar calendário
 */
function exportCalendar() {
    if (!appState.planData?.tasks?.length) {
        showNotification('Nenhum plano para exportar', 'warning');
        return;
    }
    
    // Criar CSV
    let csv = 'Data,Hora Início,Hora Fim,Servidor,Ambiente,CVE,Duração,Equipa\n';
    
    appState.planData.tasks.forEach(task => {
        const start = new Date(task.start_time);
        const end = new Date(task.end_time);
        csv += `${formatDateISO(start)},${start.toLocaleTimeString('pt-PT')},${end.toLocaleTimeString('pt-PT')},${task.server_id},${task.environment},${task.cve_id},${task.duration_hours}h,"${(task.workers || []).join(', ')}"\n`;
    });
    
    // Download
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `planeamento_${formatDateISO(new Date())}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    
    showNotification('Calendário exportado com sucesso', 'success');
}

/**
 * Mostrar uma tab específica
 */
function showTab(tabName) {
    const link = document.querySelector(`.nav-item[data-tab="${tabName}"]`);
    if (link) link.click();
}
