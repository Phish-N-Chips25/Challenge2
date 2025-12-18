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
    planData: null,
    currentMonth: new Date(),
    requiredPatches: [],
    cvesBySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
};

// API Base URL
const API_BASE = '';

/**
 * Fetch helper com tratamento de erros
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
            const error = await response.json();
            throw new Error(error.error || 'Erro na API');
        }
        
        return await response.json();
    } catch (error) {
        console.error(`API Error (${endpoint}):`, error);
        showNotification(error.message, 'error');
        throw error;
    }
}

/**
 * Mostrar notificação
 */
function showNotification(message, type = 'info') {
    const container = document.getElementById('notification-container') || createNotificationContainer();
    
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <span>${message}</span>
        <button onclick="this.parentElement.remove()">×</button>
    `;
    
    container.appendChild(notification);
    
    setTimeout(() => {
        notification.classList.add('fade-out');
        setTimeout(() => notification.remove(), 300);
    }, 5000);
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
        
        // Atualizar CVEs por severidade
        appState.cvesBySeverity = stats.cves_by_severity || { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
        document.getElementById('critical-count').textContent = appState.cvesBySeverity.CRITICAL || 0;
        document.getElementById('high-count').textContent = appState.cvesBySeverity.HIGH || 0;
        document.getElementById('medium-count').textContent = appState.cvesBySeverity.MEDIUM || 0;
        document.getElementById('low-count').textContent = appState.cvesBySeverity.LOW || 0;
        
        // Carregar próximos feriados
        loadUpcomingHolidays();
        
    } catch (error) {
        console.error('Erro ao carregar estatísticas:', error);
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
            data = await fetchAPI('/api/cves?sort=priority');
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
            showNotification('Erro ao inicializar banco de dados', 'error');
        }
    } catch (error) {
        console.error('Erro ao inicializar banco:', error);
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
        return null;
    }
}

/**
 * Renderizar tabela de CVEs (suporta dados do DB e API)
 */
function renderCVETable() {
    const tbody = document.getElementById('cve-table-body');
    if (!tbody) return;
    
    if (appState.cves.length === 0) {
        tbody.innerHTML = '<tr><td colspan="11" class="no-data">Nenhuma CVE encontrada</td></tr>';
        return;
    }
    
    tbody.innerHTML = appState.cves.map(cve => {
        // Suportar ambos os formatos (DB e API)
        const cveId = cve.cve_id;
        const severity = cve.severity || cve.base_severity || 'MEDIUM';
        const cvssScore = cve.cvss_score || cve.base_score || 0;
        const epssScore = cve.epss_score || 0;
        const software = cve.affected_software || cve.software || cve.impacted_products || 'Unknown';
        const vendor = cve.vendor || cve.impacted_vendor || '-';
        const attackVector = cve.attack_vector || 'NETWORK';
        const cwe = cve.cwe || cve.cwe_number || '';
        const cisaKev = cve.cisa_kev;
        const ssvcDecision = cve.ssvc_decision || '';
        const duration = cve.patch_duration_hours || Math.ceil(cvssScore / 2) || 4;
        
        return `
            <tr data-severity="${severity}" data-software="${software}" data-vendor="${vendor}">
                <td><input type="checkbox" class="cve-checkbox" data-cve="${cveId}"></td>
                <td>
                    <strong>${cveId}</strong>
                    ${cisaKev ? '<span class="kev-badge" title="CISA KEV">⚠️</span>' : ''}
                </td>
                <td><span class="severity-badge ${severity.toLowerCase()}">${severity}</span></td>
                <td><strong>${cvssScore?.toFixed(1) || '-'}</strong></td>
                <td>${epssScore ? (epssScore * 100).toFixed(2) + '%' : '-'}</td>
                <td class="vendor-cell" title="${software}">${vendor}</td>
                <td><span class="attack-vector av-${attackVector.toLowerCase()}">${attackVector.substring(0, 3)}</span></td>
                <td>${cwe || '-'}</td>
                <td>${ssvcDecision ? `<span class="ssvc-badge ssvc-${ssvcDecision.toLowerCase()}">${ssvcDecision}</span>` : '-'}</td>
                <td>${duration}h</td>
                <td>
                    <button class="btn btn-sm" onclick="showCVEDetails('${cveId}')" title="Ver detalhes">🔍</button>
                    <button class="btn btn-sm" onclick="showCVEServers('${cveId}')" title="Selecionar servidores">🖥️</button>
                </td>
            </tr>
        `;
    }).join('');
    
    // Atualizar contador
    const counter = document.getElementById('cve-count');
    if (counter) {
        counter.textContent = `${appState.cves.length} CVEs`;
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
        showNotification('Erro ao carregar detalhes', 'error');
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
        const cve = appState.cves.find(c => c.cve_id === cveId);
        
        const modal = document.getElementById('cve-servers-modal');
        const modalTitle = document.getElementById('modal-cve-title');
        const modalBody = document.getElementById('modal-cve-body');
        
        if (!modal || !modalBody) return;
        
        modalTitle.textContent = `${cveId} - Servidores Afetados`;
        
        // Agrupar por ambiente
        const byEnv = { DEV: [], TEST: [], PROD: [] };
        data.servers.forEach(s => {
            if (byEnv[s.environment]) byEnv[s.environment].push(s);
        });
        
        modalBody.innerHTML = `
            <div class="cve-modal-info">
                <span class="severity-badge ${cve.severity.toLowerCase()}">${cve.severity}</span>
                <span><strong>Software:</strong> ${cve.software}</span>
                <span><strong>Duração:</strong> ${cve.patch_duration_hours}h</span>
            </div>
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
                                    <span class="server-app">${s.application_group}</span>
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
        const data = await fetchAPI('/api/servers');
        appState.servers = data.servers || [];
        renderServersGrid();
        populateAppFilter();
    } catch (error) {
        console.error('Erro ao carregar servidores:', error);
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
        showNotification('A detetar patches necessários...', 'info');
        const data = await fetchAPI('/api/patches/required');
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
        showNotification(`Detetados patches para ${appState.requiredPatches.length} servidores`, 'success');
    } catch (error) {
        console.error('Erro ao detetar patches:', error);
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
    document.getElementById('cve-severity-filter')?.addEventListener('change', filterCVETable);
    document.getElementById('cve-software-filter')?.addEventListener('input', filterCVETable);
    document.getElementById('refresh-cves')?.addEventListener('click', loadCVEs);
    
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
    
    // Setup select all CVEs
    document.getElementById('select-all-cves')?.addEventListener('change', (e) => {
        document.querySelectorAll('.cve-checkbox').forEach(cb => {
            cb.checked = e.target.checked;
        });
    });
    
    // Definir data de início padrão
    const startDateInput = document.getElementById('plan-start-date');
    if (startDateInput) {
        startDateInput.value = formatDateISO(new Date());
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
        const data = await fetchAPI('/api/patches/required');
        appState.requiredPatches = data.servers || [];
        renderAutoPatchesSummary();
    } catch (error) {
        console.error('Erro ao carregar patches:', error);
    }
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
    
    // Construir tarefas a partir dos patches identificados
    const tasks = [];
    
    appState.requiredPatches.forEach(server => {
        if (server.patches && Array.isArray(server.patches)) {
            server.patches.forEach(patch => {
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
        showNotification('Nenhum patch identificado para planear', 'warning');
        return;
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
        
        const result = await fetchAPI('/api/plan', {
            method: 'POST',
            body: JSON.stringify({ tasks: filteredTasks })
        });
        
        appState.planData = result;
        
        // Mostrar resultados
        const tasksCount = result?.tasks?.length || result?.scheduled_tasks?.length || 0;
        renderPlanResults(result);
        showNotification(`Plano gerado: ${tasksCount} tarefas agendadas`, 'success');
        
    } catch (error) {
        console.error('Erro ao gerar plano:', error);
        showNotification('Erro ao gerar plano: ' + error.message, 'error');
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
