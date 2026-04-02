// ==========================================
// LLM Honeynet - Premium Frontend
// Modern JavaScript Application
// ==========================================

// ===== API Configuration =====
const API_BASE = window.location.origin + '/api';

// ===== State Management =====
let currentPage = 'dashboard';
let selectedHosts = new Set();
let pollIntervals = [];

// ===== Navigation =====
function initNavigation() {
    const navItems = document.querySelectorAll('.nav-item');

    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            const page = item.dataset.page;
            navigateTo(page);
        });
    });

    // Handle hash changes
    window.addEventListener('hashchange', () => {
        const hash = window.location.hash.slice(1);
        if (hash) {
            navigateTo(hash);
        }
    });

    // Check initial hash
    const initialHash = window.location.hash.slice(1);
    if (initialHash) {
        navigateTo(initialHash);
    }

    // Menu toggle for mobile
    const menuToggle = document.getElementById('menu-toggle');
    const sidebar = document.getElementById('sidebar');

    if (menuToggle && sidebar) {
        menuToggle.addEventListener('click', () => {
            sidebar.classList.toggle('open');
        });

        // Close sidebar when clicking outside on mobile
        document.addEventListener('click', (e) => {
            if (window.innerWidth <= 768) {
                if (!sidebar.contains(e.target) && !menuToggle.contains(e.target)) {
                    sidebar.classList.remove('open');
                }
            }
        });
    }

    // Initialize modern tabs
    initModernTabs();
}

function navigateTo(page) {
    // Update nav items
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
        if (item.dataset.page === page) {
            item.classList.add('active');
        }
    });

    // Update pages
    document.querySelectorAll('.page').forEach(p => {
        p.classList.remove('active');
    });

    const targetPage = document.getElementById(`page-${page}`);
    if (targetPage) {
        targetPage.classList.add('active');
        currentPage = page;

        // Update breadcrumb title
        const titles = {
            'dashboard': '仪表盘',
            'perception': '感知分析',
            'orchestration': '智能编排',
            'deception': '欺骗配置',
            'shadow': '影子数据'
        };

        const titleElement = document.getElementById('page-title');
        if (titleElement) {
            titleElement.textContent = titles[page] || 'Dashboard';
        }

        // Load page-specific data
        loadPageData(page);

        // Update hash
        window.location.hash = page;
    }

    // Close sidebar on mobile
    if (window.innerWidth <= 768) {
        const sidebar = document.getElementById('sidebar');
        if (sidebar) {
            sidebar.classList.remove('open');
        }
    }
}

function loadPageData(page) {
    switch (page) {
        case 'dashboard':
            loadDashboard();
            break;
        case 'perception':
            loadHosts();
            break;
        case 'orchestration':
            loadOrchestrationStatus();
            loadPreferences();
            initSliders();
            break;
        case 'deception':
            loadDeploymentHosts();
            loadConsistencyReport();
            break;
        case 'shadow':
            loadShadowData();
            break;
    }
}

function refreshCurrentPage() {
    loadPageData(currentPage);
    showToast('info', '刷新', '页面已刷新');
}

// ===== API Functions =====
async function apiCall(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json'
        }
    };

    try {
        const response = await fetch(url, { ...defaultOptions, ...options });
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || `HTTP ${response.status}`);
        }

        return data;
    } catch (error) {
        console.error('API Error:', error);
        throw error;
    }
}

// ===== Dashboard =====
async function loadDashboard() {
    try {
        const data = await apiCall('/dashboard/summary');

        // Update stats
        const statHosts = document.getElementById('stat-hosts');
        const statCompleted = document.getElementById('stat-completed');
        const statRunning = document.getElementById('stat-running');
        const statTotal = document.getElementById('stat-total');

        if (statHosts) statHosts.textContent = data.hosts?.count || '-';
        if (statCompleted) statCompleted.textContent = data.operations?.completed || '-';
        if (statRunning) statRunning.textContent = data.operations?.running || '-';
        if (statTotal) statTotal.textContent = data.operations?.total || '-';

        // Update pipeline status
        updatePipelineStatus('perception', data.hosts?.count > 0);
        updatePipelineStatus('orchestration', data.shadow_files?.['honey_agent.json']?.exists);
        updatePipelineStatus('deception', data.shadow_files?.['trap_agent.json']?.exists);

        // Load recent activity
        const ops = await apiCall('/operations?limit=5');
        displayRecentActivity(ops.operations);

        // Update system status
        updateSystemStatus(true);

    } catch (error) {
        console.error('Failed to load dashboard:', error);
        updateSystemStatus(false);
    }
}

function updatePipelineStatus(step, status) {
    const statusElement = document.getElementById(`pipeline-${step}`);
    if (!statusElement) return;

    statusElement.className = 'step-status';

    switch (status) {
        case 'running':
            statusElement.classList.add('running');
            break;
        case 'completed':
        case 'ready':
            statusElement.classList.add('active');
            break;
        case 'failed':
            statusElement.classList.add('error');
            break;
        case 'pending':
        default:
            // Default state
            break;
    }
}

function displayRecentActivity(operations) {
    const container = document.getElementById('recent-activity');

    if (!container) return;

    if (!operations || operations.length === 0) {
        container.innerHTML = `
            <div class="activity-item">
                <div class="activity-dot"></div>
                <div class="activity-content">
                    <div class="activity-time">系统消息</div>
                    <div class="activity-text">暂无操作记录</div>
                </div>
            </div>
        `;
        return;
    }

    container.innerHTML = operations.map(op => `
        <div class="activity-item">
            <div class="activity-dot" style="background: ${getStatusColor(op.status)}"></div>
            <div class="activity-content">
                <div class="activity-time">${formatTime(op.created_at)}</div>
                <div class="activity-text">${getOperationTypeName(op.type)} - ${getStatusText(op.status)}</div>
            </div>
        </div>
    `).join('');
}

function getStatusColor(status) {
    const colors = {
        'completed': 'var(--success)',
        'running': 'var(--warning)',
        'failed': 'var(--danger)',
        'pending': 'var(--text-muted)'
    };
    return colors[status] || 'var(--text-muted)';
}

function getOperationTypeName(type) {
    const names = {
        'perception': '感知分析',
        'honey_agent': 'Honey Agent',
        'trap_agent': 'Trap Agent',
        'deception': '欺骗配置'
    };
    return names[type] || type;
}

function getStatusText(status) {
    const texts = {
        'pending': '等待中',
        'running': '运行中',
        'completed': '已完成',
        'failed': '失败'
    };
    return texts[status] || status;
}

function formatTime(isoString) {
    if (!isoString) return '-';
    const date = new Date(isoString);
    const now = new Date();
    const diff = now - date;

    if (diff < 60000) return '刚刚';
    if (diff < 3600000) return `${Math.floor(diff / 60000)}分钟前`;
    if (diff < 86400000) return `${Math.floor(diff / 3600000)}小时前`;

    return date.toLocaleDateString('zh-CN');
}

function updateSystemStatus(online) {
    const statusText = document.getElementById('system-status-text');
    if (statusText) {
        statusText.textContent = online ? '正常' : '离线';
    }
}

// ===== Full Pipeline =====
async function runFullPipeline() {
    // Reset orchestration and deception steps to pending
    updatePipelineStatus('orchestration', 'pending');
    updatePipelineStatus('deception', 'pending');

    // Show loading overlay
    showLoadingOverlay('运行完整流程...');

    try {
        // Step 1: Orchestration (Honey Agent + Trap Agent)
        updatePipelineStatus('orchestration', 'running');
        updateLoadingMessage('正在生成诱饵和陷阱...');

        const honeyResult = await apiCall('/orchestrate/honey', {
            method: 'POST',
            body: JSON.stringify({ mode: 'initialization' })
        });

        await waitForOperation(honeyResult.operation_id, 'Honey Agent');

        const trapResult = await apiCall('/orchestrate/trap', {
            method: 'POST',
            body: JSON.stringify({ mode: 'all' })
        });

        await waitForOperation(trapResult.operation_id, 'Trap Agent');

        updatePipelineStatus('orchestration', 'completed');

        // Step 2: Deception
        updatePipelineStatus('deception', 'running');
        updateLoadingMessage('正在进行一致性审计和配置生成...');

        const deceptionResult = await apiCall('/deception/run', {
            method: 'POST',
            body: JSON.stringify({ mode: 'full' })
        });

        await waitForOperation(deceptionResult.operation_id, 'Deception');

        updatePipelineStatus('deception', 'completed');

        hideLoadingOverlay();
        showToast('success', '完整流程', '所有步骤已成功完成');
        loadDashboard();

    } catch (error) {
        // Mark current step as failed
        hideLoadingOverlay();
        showToast('error', '完整流程', `执行失败: ${error.message}`);

        // Check which step failed and mark it
        const orchestrationEl = document.getElementById('pipeline-orchestration');
        if (orchestrationEl && !orchestrationEl.classList.contains('active')) {
            updatePipelineStatus('orchestration', 'failed');
        }

        const deceptionEl = document.getElementById('pipeline-deception');
        if (deceptionEl && !deceptionEl.classList.contains('active')) {
            updatePipelineStatus('deception', 'failed');
        }
    }
}

// Update loading overlay message
function updateLoadingMessage(message) {
    const overlay = document.getElementById('loading-overlay');
    if (overlay) {
        const messageElement = overlay.querySelector('p');
        if (messageElement) {
            messageElement.textContent = message;
        }
    }
}

async function waitForOperation(operationId, stepName = '操作') {
    return new Promise((resolve, reject) => {
        const maxAttempts = 300;
        let attempts = 0;
        let lastUpdate = 0;

        const poll = async () => {
            try {
                const data = await apiCall(`/operations/${operationId}`);

                if (data.status === 'completed') {
                    updateLoadingMessage(`${stepName} 完成！`);
                    resolve(data);
                    return;
                }

                if (data.status === 'failed') {
                    updateLoadingMessage(`${stepName} 失败`);
                    reject(new Error(data.error || '操作失败'));
                    return;
                }

                // Update loading message every few seconds
                attempts++;
                if (attempts - lastUpdate >= 3) {
                    updateLoadingMessage(`正在执行 ${stepName}... (${attempts}s)`);
                    lastUpdate = attempts;
                }

                if (attempts < maxAttempts) {
                    setTimeout(poll, 1000);
                } else {
                    updateLoadingMessage(`${stepName} 超时`);
                    reject(new Error('操作超时'));
                }

            } catch (error) {
                updateLoadingMessage(`${stepName} 出错`);
                reject(error);
            }
        };

        poll();
    });
}

// ===== Perception =====
async function loadHosts() {
    const container = document.getElementById('perception-hosts');
    if (!container) return;

    container.innerHTML = `
        <div class="loading-spinner">
            <div class="spinner"></div>
        </div>
    `;

    try {
        const data = await apiCall('/perception/hosts');

        if (!data.hosts || data.hosts.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-server"></i>
                    <p>未找到主机</p>
                </div>
            `;
            return;
        }

        container.innerHTML = `<div class="hosts-grid">` + data.hosts.map(host => `
            <div class="host-item" data-host="${host.name}" onclick="toggleHostSelection('${host.name}')">
                <input type="checkbox" class="host-checkbox" ${selectedHosts.has(host.name) ? 'checked' : ''}>
                <div class="host-name">${host.name}</div>
                <div class="host-info">${host.log_files?.length || 0} 日志文件</div>
            </div>
        `).join('') + `</div>`;

    } catch (error) {
        container.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-exclamation-triangle"></i>
                <p>加载失败: ${error.message}</p>
            </div>
        `;
    }
}

function toggleHostSelection(hostName) {
    if (selectedHosts.has(hostName)) {
        selectedHosts.delete(hostName);
    } else {
        selectedHosts.add(hostName);
    }

    // Update checkbox
    const hostItem = document.querySelector(`.host-item[data-host="${hostName}"]`);
    if (hostItem) {
        const checkbox = hostItem.querySelector('.host-checkbox');
        if (checkbox) checkbox.checked = selectedHosts.has(hostName);
        hostItem.classList.toggle('selected', selectedHosts.has(hostName));
    }
}

async function runPerception() {
    const useOpenAI = document.getElementById('perception-openai')?.checked ?? false;
    const hosts = selectedHosts.size > 0 ? Array.from(selectedHosts) : null;

    const statusBadge = document.getElementById('perception-status');
    const resultsContainer = document.getElementById('perception-results');

    if (!statusBadge || !resultsContainer) return;

    try {
        statusBadge.querySelector('.status-text').textContent = '运行中';
        statusBadge.classList.add('running');

        const data = await apiCall('/perception/analyze', {
            method: 'POST',
            body: JSON.stringify({ hosts, use_openai: useOpenAI })
        });

        statusBadge.querySelector('.status-text').textContent = '处理中';
        statusBadge.classList.remove('running');
        statusBadge.classList.add('active');

        // Poll for results
        pollOperation(data.operation_id, (result) => {
            statusBadge.querySelector('.status-text').textContent = '完成';
            statusBadge.classList.remove('active');
            statusBadge.classList.add('active');
            displayPerceptionResults(result.result);
            showToast('success', '感知分析', '分析已完成');
        }, (error) => {
            statusBadge.querySelector('.status-text').textContent = '失败';
            statusBadge.classList.remove('active', 'running');
            statusBadge.classList.add('error');
            resultsContainer.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-exclamation-triangle"></i>
                    <p>分析失败: ${error}</p>
                </div>
            `;
            showToast('error', '感知分析', `分析失败: ${error}`);
        });

    } catch (error) {
        statusBadge.querySelector('.status-text').textContent = '失败';
        statusBadge.classList.remove('running', 'active');
        statusBadge.classList.add('error');
        showToast('error', '感知分析', `启动失败: ${error.message}`);
    }
}

function displayPerceptionResults(result) {
    const container = document.getElementById('perception-results');
    if (!container) return;

    if (!result || !result.analyses || result.analyses.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-search"></i>
                <p>无分析结果</p>
            </div>
        `;
        return;
    }

    let html = `<p class="text-muted" style="margin-bottom: 16px;">共分析 ${result.total_hosts} 个主机</p>`;

    if (result.openai_summary) {
        html += `
            <div class="operation-result show">
                <h4 style="margin-bottom: 8px;">AI 摘要</h4>
                <p style="font-size: 13px; color: var(--text-secondary);">${result.openai_summary}</p>
            </div>
        `;
    }

    result.analyses.forEach(analysis => {
        html += `
            <div class="operation-result show">
                <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
                    <span style="font-weight: 600;">🖥️ ${analysis.host}</span>
                    <span class="status-badge">${analysis.stage_label || 'Unknown'}</span>
                </div>
                <p class="text-muted">${analysis.event_count || 0} 个事件</p>
                ${analysis.events && analysis.events.length > 0 ? `
                    <div style="margin-top: 12px; display: flex; flex-direction: column; gap: 4px;">
                        ${analysis.events.slice(0, 5).map(e => `
                            <div style="padding: 8px; background: var(--bg-tertiary); border-radius: 4px; font-size: 12px;">
                                <span class="text-muted">${e.timestamp}</span>
                                <span style="margin-left: 8px;">${e.summary}</span>
                            </div>
                        `).join('')}
                    </div>
                ` : ''}
            </div>
        `;
    });

    container.innerHTML = html;
}

// ===== Orchestration =====
async function loadOrchestrationStatus() {
    try {
        const data = await apiCall('/orchestrate/status');

        const statusHoney = document.getElementById('status-honey');
        const statusTrap = document.getElementById('status-trap');
        const statusPrefs = document.getElementById('status-prefs');

        if (statusHoney && data.honey_agent?.exists) {
            statusHoney.textContent = `${data.honey_agent.hosts} 主机`;
            statusHoney.style.color = 'var(--success)';
        }

        if (statusTrap && data.trap_agent?.exists) {
            statusTrap.textContent = `${data.trap_agent.hosts} 主机, ${data.trap_agent.chains} 链`;
            statusTrap.style.color = 'var(--success)';
        }

        if (statusPrefs && data.attacker_preferences?.exists) {
            statusPrefs.textContent = `${data.attacker_preferences.count} 偏好`;
            statusPrefs.style.color = 'var(--success)';
        }

    } catch (error) {
        console.error('Failed to load orchestration status:', error);
    }
}

function initSliders() {
    // Honey Agent sliders
    const honeyTemp = document.getElementById('honey-temp');
    const honeyTempVal = document.getElementById('honey-temp-val');
    const honeyTopp = document.getElementById('honey-topp');
    const honeyToppVal = document.getElementById('honey-topp-val');

    if (honeyTemp && honeyTempVal) {
        honeyTemp.addEventListener('input', () => {
            honeyTempVal.textContent = honeyTemp.value;
        });
    }

    if (honeyTopp && honeyToppVal) {
        honeyTopp.addEventListener('input', () => {
            honeyToppVal.textContent = honeyTopp.value;
        });
    }

    // Trap Agent sliders
    const trapTemp = document.getElementById('trap-temp');
    const trapTempVal = document.getElementById('trap-temp-val');
    const trapTopp = document.getElementById('trap-topp');
    const trapToppVal = document.getElementById('trap-topp-val');

    if (trapTemp && trapTempVal) {
        trapTemp.addEventListener('input', () => {
            trapTempVal.textContent = trapTemp.value;
        });
    }

    if (trapTopp && trapToppVal) {
        trapTopp.addEventListener('input', () => {
            trapToppVal.textContent = trapTopp.value;
        });
    }
}

async function runHoneyAgent() {
    const resultDiv = document.getElementById('honey-result');
    const mode = document.getElementById('honey-mode')?.value || 'initialization';
    const model = document.getElementById('honey-model')?.value || 'gpt-4o-mini';
    const temp = parseFloat(document.getElementById('honey-temp')?.value || 0.1);
    const topP = parseFloat(document.getElementById('honey-topp')?.value || 0.9);

    if (!resultDiv) return;

    try {
        resultDiv.className = 'agent-result show';
        resultDiv.innerHTML = '<p>⏳ 正在运行 Honey Agent...</p>';

        const data = await apiCall('/orchestrate/honey', {
            method: 'POST',
            body: JSON.stringify({
                mode,
                openai_model: model,
                openai_temperature: temp,
                openai_top_p: topP
            })
        });

        pollOperation(data.operation_id, (result) => {
            const r = result.result;
            resultDiv.className = 'agent-result show success';
            resultDiv.innerHTML = `
                <p style="color: var(--success); font-weight: 600;">✅ 完成！生成 ${r.hosts_generated || 0} 个主机的诱饵配置</p>
                <p class="text-muted">模式: ${r.mode || mode}</p>
            `;
            loadOrchestrationStatus();
            showToast('success', 'Honey Agent', `已生成 ${r.hosts_generated || 0} 个主机的配置`);
        }, (error) => {
            resultDiv.className = 'agent-result show error';
            resultDiv.innerHTML = `<p style="color: var(--danger);">❌ 失败: ${error}</p>`;
            showToast('error', 'Honey Agent', `运行失败: ${error}`);
        });

    } catch (error) {
        resultDiv.className = 'agent-result show error';
        resultDiv.innerHTML = `<p style="color: var(--danger);">❌ 启动失败: ${error.message}</p>`;
    }
}

async function runTrapAgent() {
    const resultDiv = document.getElementById('trap-result');
    const mode = document.getElementById('trap-mode')?.value || 'all';
    const model = document.getElementById('trap-model')?.value || 'gpt-4o-mini';
    const temp = parseFloat(document.getElementById('trap-temp')?.value || 0.15);
    const topP = parseFloat(document.getElementById('trap-topp')?.value || 0.85);

    if (!resultDiv) return;

    try {
        resultDiv.className = 'agent-result show';
        resultDiv.innerHTML = '<p>⏳ 正在运行 Trap Agent...</p>';

        const data = await apiCall('/orchestrate/trap', {
            method: 'POST',
            body: JSON.stringify({
                mode,
                openai_model: model,
                openai_temperature: temp,
                openai_top_p: topP
            })
        });

        pollOperation(data.operation_id, (result) => {
            const r = result.result;
            resultDiv.className = 'agent-result show success';
            resultDiv.innerHTML = `
                <p style="color: var(--success); font-weight: 600;">✅ 完成！处理 ${r.hosts?.length || 0} 个主机</p>
                <p class="text-muted">模式: ${r.mode || mode}</p>
            `;
            loadOrchestrationStatus();
            showToast('success', 'Trap Agent', '陷阱链已生成');
        }, (error) => {
            resultDiv.className = 'agent-result show error';
            resultDiv.innerHTML = `<p style="color: var(--danger);">❌ 失败: ${error}</p>`;
            showToast('error', 'Trap Agent', `运行失败: ${error}`);
        });

    } catch (error) {
        resultDiv.className = 'agent-result show error';
        resultDiv.innerHTML = `<p style="color: var(--danger);">❌ 启动失败: ${error.message}</p>`;
    }
}

async function loadPreferences() {
    try {
        const data = await apiCall('/config/preferences');
        const textarea = document.getElementById('preferences-list');

        if (textarea && data.exists && data.preferences) {
            textarea.value = data.preferences.join('\n');
        }
    } catch (error) {
        console.error('Failed to load preferences:', error);
    }
}

async function savePreferences() {
    const textarea = document.getElementById('preferences-list');
    if (!textarea) return;

    const text = textarea.value;
    const preferences = text.split('\n').map(p => p.trim()).filter(p => p);

    try {
        await apiCall('/config/preferences', {
            method: 'POST',
            body: JSON.stringify({ preferences })
        });

        showToast('success', '偏好设置', `已保存 ${preferences.length} 条偏好`);
        loadOrchestrationStatus();
    } catch (error) {
        showToast('error', '偏好设置', `保存失败: ${error.message}`);
    }
}

// ===== Deception =====
async function loadDeploymentHosts() {
    const container = document.getElementById('deployment-hosts');
    if (!container) return;

    container.innerHTML = `
        <div class="loading-spinner">
            <div class="spinner"></div>
        </div>
    `;

    try {
        const data = await apiCall('/deployment/hosts');

        if (!data.hosts || data.hosts.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-server"></i>
                    <p>未找到部署主机</p>
                </div>
            `;
            return;
        }

        container.innerHTML = `<div class="deployment-grid">` + data.hosts.map(host => `
            <div class="deployment-item">
                <div class="deployment-name">${host.name}</div>
                <div class="deployment-info">
                    <span>${host.has_config ? '✓ 配置' : '✗ 配置'}</span>
                    <span>${host.has_logs ? '✓ 日志' : '✗ 日志'}</span>
                    ${host.configs ? `<span>${host.configs.length} 文件</span>` : ''}
                </div>
            </div>
        `).join('') + `</div>`;

    } catch (error) {
        container.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-exclamation-triangle"></i>
                <p>加载失败: ${error.message}</p>
            </div>
        `;
    }
}

async function loadConsistencyReport() {
    const container = document.getElementById('consistency-report');
    if (!container) return;

    try {
        const data = await apiCall('/deception/consistency');

        if (!data.exists) {
            container.innerHTML = `
                <div class="empty-state">
                    <i class="fas fa-clipboard"></i>
                    <p>暂无一致性报告</p>
                </div>
            `;
            return;
        }

        let html = `
            <p class="text-muted" style="margin-bottom: 12px;">生成时间: ${data.modified || '-'}</p>
        `;

        if (data.issues && data.issues.length > 0) {
            html += '<h4 style="margin-bottom: 8px;">发现问题:</h4><ul style="list-style: none; padding: 0;">';
            data.issues.forEach(issue => {
                html += `<li style="padding: 8px; background: var(--bg-tertiary); border-radius: 4px; margin-bottom: 4px; color: var(--danger);">${issue}</li>`;
            });
            html += '</ul>';
        } else {
            html += '<p style="color: var(--success);">✓ 未发现一致性问题</p>';
        }

        container.innerHTML = html;

    } catch (error) {
        container.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-exclamation-triangle"></i>
                <p>加载失败: ${error.message}</p>
            </div>
        `;
    }
}

async function runDeception(mode) {
    let resultDiv;

    if (mode === 'consistency') {
        resultDiv = document.getElementById('consistency-result');
    } else if (mode === 'generate-configs') {
        resultDiv = document.getElementById('config-result');
    } else {
        resultDiv = document.getElementById('deception-result');
    }

    if (!resultDiv) return;

    const hostsInput = document.getElementById('deception-hosts');
    const hosts = hostsInput?.value ? hostsInput.value.split(',').map(h => h.trim()) : null;

    try {
        resultDiv.className = 'operation-result show';
        resultDiv.innerHTML = '<p>⏳ 正在运行...</p>';

        const data = await apiCall('/deception/run', {
            method: 'POST',
            body: JSON.stringify({ mode, hosts })
        });

        pollOperation(data.operation_id, (result) => {
            const r = result.result;
            resultDiv.className = 'operation-result show';
            resultDiv.innerHTML = '<p style="color: var(--success); font-weight: 600;">✅ 完成</p>';

            if (mode === 'consistency') {
                loadConsistencyReport();
            } else if (mode === 'generate-configs') {
                const count = r.results?.host_configs?.generated || 0;
                resultDiv.innerHTML = `<p style="color: var(--success); font-weight: 600;">✅ 已生成 ${count} 个主机配置</p>`;
                loadDeploymentHosts();
            } else {
                loadConsistencyReport();
                loadDeploymentHosts();
            }

            showToast('success', '欺骗配置', '操作已完成');
        }, (error) => {
            resultDiv.className = 'operation-result show';
            resultDiv.innerHTML = `<p style="color: var(--danger);">❌ 失败: ${error}</p>`;
            showToast('error', '欺骗配置', `运行失败: ${error}`);
        });

    } catch (error) {
        resultDiv.className = 'operation-result show';
        resultDiv.innerHTML = `<p style="color: var(--danger);">❌ 启动失败: ${error.message}</p>`;
    }
}

// ===== Shadow Data =====
async function loadShadowData() {
    // Load file status
    try {
        const summary = await apiCall('/dashboard/summary');
        const container = document.getElementById('shadow-files-status');

        if (container) {
            container.innerHTML = Object.entries(summary.shadow_files || {}).map(([name, info]) => {
                const displayName = name.replace('.json', '').replace(/_/g, ' ');
                return `
                    <div class="file-status-item">
                        <div class="file-status-name">${displayName}</div>
                        <span class="file-status-indicator ${info.exists ? 'exists' : 'missing'}">
                            ${info.exists ? '✓ 存在' : '✗ 缺失'}
                        </span>
                        ${info.modified ? `<div class="history-time">${formatTime(info.modified)}</div>` : ''}
                    </div>
                `;
            }).join('');
        }

    } catch (error) {
        console.error('Failed to load shadow data:', error);
    }

    // Load detailed data
    try {
        const data = await apiCall('/shadow/data');

        // Render Honey Agent data
        renderHoneyAgentData(data.honey_agent || {});

        // Render Trap Agent data
        renderTrapAgentData(data.trap_agent || {});

        // Render Preferences data
        await renderPreferencesData();

        // Render Long Memory data
        renderLongMemoryData(data.long_memory || {});

    } catch (error) {
        console.error('Failed to load shadow data details:', error);
    }
}

// Render Honey Agent data
function renderHoneyAgentData(data) {
    const container = document.getElementById('honey-agent-data');

    if (!container) return;

    if (!data.hosts || data.hosts.length === 0) {
        container.innerHTML = '<p class="text-muted">暂无数据</p>';
        return;
    }

    let html = '<div class="data-cards">';

    data.hosts.forEach(host => {
        html += `
            <div class="data-card">
                <div class="data-card-header">
                    <h4 class="data-card-title">🖥️ ${host.name}</h4>
                </div>
                <div class="data-card-body">
                    <div class="data-section">
                        <h5 class="data-section-title">端口 (${host.ports?.length || 0})</h5>
                        <div class="port-list">
                            ${(host.ports || []).map(port => `
                                <div class="port-item">
                                    <span class="port-number">${port.port}</span>
                                    <span class="port-service">${port.service || 'unknown'}</span>
                                    ${port.protocol ? `<span class="port-protocol">${port.protocol}</span>` : ''}
                                </div>
                            `).join('')}
                        </div>
                    </div>
                    ${host.ports && host.ports.some(p => p.files && p.files.length > 0) ? `
                    <div class="data-section">
                        <h5 class="data-section-title">文件</h5>
                        <div class="file-list">
                            ${host.ports.flatMap(p => p.files || []).map(file => `
                                <div class="file-item">${file.path}</div>
                            `).join('')}
                        </div>
                    </div>
                    ` : ''}
                    ${host.ports && host.ports.some(p => p.vulnerabilities && p.vulnerabilities.length > 0) ? `
                    <div class="data-section">
                        <h5 class="data-section-title">漏洞</h5>
                        <div class="vuln-list">
                            ${host.ports.flatMap(p => p.vulnerabilities || []).map(vuln => `
                                <div class="vuln-item">
                                    <span class="vuln-type">${vuln.type}</span>
                                    ${vuln.target_file ? `<span class="vuln-target">${vuln.target_file}</span>` : ''}
                                    ${vuln.target_port ? `<span class="vuln-target">Port ${vuln.target_port}</span>` : ''}
                                </div>
                            `).join('')}
                        </div>
                    </div>
                    ` : ''}
                </div>
            </div>
        `;
    });

    html += '</div>';
    container.innerHTML = html;
}

// Render Trap Agent data
function renderTrapAgentData(data) {
    const container = document.getElementById('trap-agent-data');

    if (!container) return;

    const hasHosts = data.hosts && data.hosts.length > 0;
    const hasChains = data.chains && data.chains.length > 0;

    if (!hasHosts && !hasChains) {
        container.innerHTML = '<p class="text-muted">暂无数据</p>';
        return;
    }

    let html = '<div class="data-cards">';

    // Render host trap loops
    if (hasHosts) {
        data.hosts.forEach(host => {
            const hasLoops = host.host_loops && host.host_loops.length > 0;
            const hasPorts = host.ports && host.ports.length > 0;

            html += `
                <div class="data-card">
                    <div class="data-card-header">
                        <h4 class="data-card-title">🖥️ ${host.name}</h4>
                    </div>
                    <div class="data-card-body">
            `;

            // Show ports if available
            if (hasPorts) {
                html += `
                    <div class="data-section">
                        <h5 class="data-section-title">端口 (${host.ports.length})</h5>
                        <div class="port-list">
                            ${host.ports.map(port => `
                                <div class="port-item">
                                    <span class="port-number">${port.port}</span>
                                    <span class="port-service">${port.service || 'unknown'}</span>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `;
            }

            // Show trap loops
            if (hasLoops) {
                host.host_loops.forEach((loop, loopIdx) => {
                    html += `
                        <div class="data-section">
                            <h5 class="data-section-title">主机内陷阱环 ${loopIdx + 1}</h5>
                            <div class="trap-loop">
                                ${loop.map((file, idx) => `
                                    <div class="trap-step">
                                        <span class="trap-number">${idx + 1}</span>
                                        <span class="trap-file">${file}</span>
                                        ${idx < loop.length - 1 ? '<span class="trap-arrow">→</span>' : ''}
                                    </div>
                                `).join('')}
                            </div>
                        </div>
                    `;
                });
            }

            html += `
                    </div>
                </div>
            `;
        });
    }

    // Render inter-host chains
    if (hasChains) {
        data.chains.forEach(chain => {
            html += `
                <div class="data-card">
                    <div class="data-card-header">
                        <h4 class="data-card-title">🔗 跨主机陷阱链: ${chain.name}</h4>
                    </div>
                    <div class="data-card-body">
                        <div class="chain-steps">
                            ${chain.steps.map((step, idx) => `
                                <div class="chain-step">
                                    <div class="step-number">${idx + 1}</div>
                                    <div class="step-content">
                                        <div class="step-host">${step.host}</div>
                                        <div class="step-tier">${step.tier}</div>
                                    </div>
                                    ${idx < chain.steps.length - 1 ? '<div class="step-arrow">→</div>' : ''}
                                </div>
                            `).join('')}
                        </div>
                    </div>
                </div>
            `;
        });
    }

    html += '</div>';
    container.innerHTML = html;
}

// Render Attacker Preferences
async function renderPreferencesData() {
    const container = document.getElementById('preferences-data');

    if (!container) return;

    try {
        const data = await apiCall('/config/preferences');

        if (!data.exists || !data.preferences || data.preferences.length === 0) {
            container.innerHTML = '<p class="text-muted">暂无偏好设置</p>';
            return;
        }

        let html = '<div class="preferences-grid">';

        // Group preferences by category
        const categories = {
            'credential': { label: '🔑 凭证窃取', items: [] },
            'lateral': { label: '↔️ 横向移动', items: [] },
            'recon': { label: '🔍 侦察扫描', items: [] },
            'data': { label: '📊 数据窃取', items: [] },
            'other': { label: '📦 其他', items: [] }
        };

        data.preferences.forEach(pref => {
            const p = String(pref).toLowerCase();
            if (p.includes('credential') || p.includes('password') || p.includes('ssh') || p.includes('ftp') || p.includes('login')) {
                categories.credential.items.push(pref);
            } else if (p.includes('lateral') || p.includes('movement') || p.includes('pivot') || p.includes('jump')) {
                categories.lateral.items.push(pref);
            } else if (p.includes('scan') || p.includes('recon') || p.includes('enum') || p.includes('fuzz')) {
                categories.recon.items.push(pref);
            } else if (p.includes('exfil') || p.includes('data') || p.includes('download') || p.includes('steal')) {
                categories.data.items.push(pref);
            } else {
                categories.other.items.push(pref);
            }
        });

        Object.entries(categories).forEach(([key, cat]) => {
            if (cat.items.length > 0) {
                html += `
                    <div class="preference-category">
                        <h4 class="category-title">${cat.label}</h4>
                        <div class="preference-chips">
                            ${cat.items.map(item => `
                                <span class="preference-chip">${item}</span>
                            `).join('')}
                        </div>
                    </div>
                `;
            }
        });

        html += '</div>';

        // Add summary stats
        html += `
            <div class="preferences-summary">
                <div class="summary-stat">
                    <span class="stat-number">${data.preferences.length}</span>
                    <span class="stat-label">总偏好数</span>
                </div>
                <div class="summary-stat">
                    <span class="stat-number">${Object.values(categories).filter(c => c.items.length > 0).length}</span>
                    <span class="stat-label">分类数</span>
                </div>
            </div>
        `;

        container.innerHTML = html;

    } catch (error) {
        container.innerHTML = `<p style="color: var(--danger);">加载失败: ${error.message}</p>`;
    }
}

// Render Long Memory data
function renderLongMemoryData(data) {
    const container = document.getElementById('long-memory-data');

    if (!container) return;

    const hasPortFacts = data.ports && Object.keys(data.ports).length > 0;
    const hasPatterns = data.successful_patterns && data.successful_patterns.length > 0;
    const hasBehaviors = data.attacker_behaviors && data.attacker_behaviors.length > 0;
    const hasDecoys = data.effective_decoys && Object.keys(data.effective_decoys).length > 0;
    const hasHistory = data.config_history && data.config_history.length > 0;

    if (!hasPortFacts && !hasPatterns && !hasBehaviors && !hasDecoys && !hasHistory) {
        container.innerHTML = '<p class="text-muted">暂无长期记忆数据</p>';
        return;
    }

    let html = '<div class="long-memory-container">';

    // Summary section
    html += '<div class="memory-summary">';
    html += '<h3 class="summary-title">🧠 长期记忆概览</h3>';
    html += '<div class="summary-stats">';

    if (data.last_updated) {
        html += `
            <div class="summary-stat">
                <span class="stat-label">最后更新</span>
                <span class="stat-value">${formatTime(data.last_updated)}</span>
            </div>
        `;
    }

    if (data.ports) {
        html += `
            <div class="summary-stat">
                <span class="stat-label">端口知识</span>
                <span class="stat-value">${Object.keys(data.ports).length}</span>
            </div>
        `;
    }

    if (hasPatterns) {
        html += `
            <div class="summary-stat">
                <span class="stat-label">成功模式</span>
                <span class="stat-value">${data.successful_patterns.length}</span>
            </div>
        `;
    }

    if (hasBehaviors) {
        html += `
            <div class="summary-stat">
                <span class="stat-label">攻击行为</span>
                <span class="stat-value">${data.attacker_behaviors.length}</span>
            </div>
        `;
    }

    html += '</div></div>';

    // Port Facts section
    if (hasPortFacts) {
        html += '<div class="memory-section">';
        html += '<h3 class="section-title">🔌 端口知识库</h3>';
        html += '<div class="port-facts-grid">';

        Object.entries(data.ports).forEach(([portKey, facts]) => {
            const [port, protocol] = portKey.split('/');
            html += `
                <div class="port-fact-card">
                    <div class="port-fact-header">
                        <span class="port-fact-number">${port}</span>
                        <span class="port-fact-protocol">${protocol}</span>
                        <span class="port-fact-service">${facts.service || 'unknown'}</span>
                    </div>
                    ${facts.version ? `<div class="port-fact-version">${facts.version}</div>` : ''}
                    ${facts.banner ? `<div class="port-fact-banner">${facts.banner}</div>` : ''}
                    ${facts.notes && facts.notes.length > 0 ? `
                        <div class="port-fact-notes">
                            ${facts.notes.map(note => `<span class="note-tag">${note}</span>`).join('')}
                        </div>
                    ` : ''}
                    ${facts.effective_decoys && facts.effective_decoys.length > 0 ? `
                        <div class="port-fact-decoys">
                            <span class="decoy-label">有效诱饵:</span>
                            ${facts.effective_decoys.map(decoy => `<span class="decoy-tag">${decoy}</span>`).join('')}
                        </div>
                    ` : ''}
                </div>
            `;
        });

        html += '</div></div>';
    }

    // Successful Patterns section
    if (hasPatterns) {
        html += '<div class="memory-section">';
        html += '<h3 class="section-title">✅ 成功模式</h3>';
        html += '<div class="patterns-grid">';

        data.successful_patterns.forEach(pattern => {
            html += `
                <div class="pattern-card">
                    <div class="pattern-header">
                        <span class="pattern-name">${pattern.pattern || pattern.name || 'Unknown'}</span>
                        ${pattern.effectiveness ? `<span class="pattern-effectiveness">${pattern.effectiveness}</span>` : ''}
                    </div>
                    ${pattern.description ? `<div class="pattern-description">${pattern.description}</div>` : ''}
                    ${pattern.examples && pattern.examples.length > 0 ? `
                        <div class="pattern-examples">
                            ${pattern.examples.map(ex => `<code class="example-code">${ex}</code>`).join('')}
                        </div>
                    ` : ''}
                </div>
            `;
        });

        html += '</div></div>';
    }

    // Attacker Behaviors section
    if (hasBehaviors) {
        html += '<div class="memory-section">';
        html += '<h3 class="section-title">🎯 攻击者行为</h3>';
        html += '<div class="behaviors-grid">';

        data.attacker_behaviors.forEach(behavior => {
            html += `
                <div class="behavior-card">
                    <div class="behavior-header">
                        <span class="behavior-name">${behavior.behavior || 'Unknown'}</span>
                        ${behavior.frequency ? `<span class="behavior-frequency">${behavior.frequency}</span>` : ''}
                    </div>
                    ${behavior.description ? `<div class="behavior-description">${behavior.description}</div>` : ''}
                    ${behavior.common_credentials ? `
                        <div class="behavior-credentials">
                            <span class="behavior-label">常见凭证:</span>
                            <span class="behavior-value">${behavior.common_credentials.join(', ')}</span>
                        </div>
                    ` : ''}
                    ${behavior.common_paths ? `
                        <div class="behavior-paths">
                            <span class="behavior-label">常见路径:</span>
                            <span class="behavior-value">${behavior.common_paths.join(', ')}</span>
                        </div>
                    ` : ''}
                    ${behavior.indicators ? `
                        <div class="behavior-indicators">
                            <span class="behavior-label">指标:</span>
                            <span class="behavior-value">${behavior.indicators.join(', ')}</span>
                        </div>
                    ` : ''}
                </div>
            `;
        });

        html += '</div></div>';
    }

    // Effective Decoys section
    if (hasDecoys) {
        html += '<div class="memory-section">';
        html += '<h3 class="section-title">🎭 有效诱饵</h3>';
        html += '<div class="decoys-grid">';

        Object.entries(data.effective_decoys).forEach(([type, decoys]) => {
            html += `
                <div class="decoy-type-card">
                    <div class="decoy-type-header">
                        <span class="decoy-type-name">${type}</span>
                        <span class="decoy-count">${decoys.length}</span>
                    </div>
                    <div class="decoy-list">
                        ${decoys.slice(0, 5).map(decoy => `
                            <div class="decoy-item">
                                ${decoy.config ? `<span class="decoy-config">${decoy.config}</span>` : ''}
                                ${decoy.details ? `<span class="decoy-details">${decoy.details}</span>` : ''}
                            </div>
                        `).join('')}
                        ${decoys.length > 5 ? `<div class="decoy-more">...还有 ${decoys.length - 5} 个</div>` : ''}
                    </div>
                </div>
            `;
        });

        html += '</div></div>';
    }

    // Config History section
    if (hasHistory) {
        html += '<div class="memory-section">';
        html += '<h3 class="section-title">📜 配置历史 (最近10条)</h3>';
        html += '<div class="history-list">';

        data.config_history.slice(-10).reverse().forEach(entry => {
            html += `
                <div class="history-item">
                    <span class="history-time">${formatTime(entry.timestamp)}</span>
                    <span class="history-host">${entry.host}</span>
                    ${entry.summary ? `
                        <div class="history-summary">
                            ${entry.summary.services ? `服务: ${entry.summary.services.join(', ')}` : ''}
                            ${entry.summary.decoy_files ? `, 诱饵: ${entry.summary.decoy_files.length} 个` : ''}
                        </div>
                    ` : ''}
                </div>
            `;
        });

        html += '</div></div>';
    }

    html += '</div>';
    container.innerHTML = html;
}

// ===== Modern Tabs =====
function initModernTabs() {
    const tabBtns = document.querySelectorAll('.modern-tab');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const tabName = btn.dataset.tab;
            const container = btn.closest('.shadow-card-body');

            // Update buttons
            container.querySelectorAll('.modern-tab').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            // Update panes
            container.querySelectorAll('.modern-tab-pane').forEach(p => p.classList.remove('active'));
            const targetPane = container.querySelector(`#tab-${tabName}`);
            if (targetPane) {
                targetPane.classList.add('active');
            }
        });
    });
}

// ===== Polling =====
function pollOperation(opId, onSuccess, onError) {
    const maxAttempts = 300;
    let attempts = 0;

    const poll = async () => {
        try {
            const data = await apiCall(`/operations/${opId}`);

            if (data.status === 'completed') {
                onSuccess(data);
                return;
            }

            if (data.status === 'failed') {
                onError(data.error || '操作失败');
                return;
            }

            attempts++;
            if (attempts < maxAttempts) {
                setTimeout(poll, 1000);
            } else {
                onError('操作超时');
            }

        } catch (error) {
            onError(error.message);
        }
    };

    poll();
}

// ===== Toast Notifications =====
function showToast(type, title, message) {
    const container = document.getElementById('toast-container');

    if (!container) return;

    const icons = {
        success: 'fa-check-circle',
        error: 'fa-times-circle',
        info: 'fa-info-circle',
        warning: 'fa-exclamation-triangle'
    };

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <span class="toast-icon"><i class="fas ${icons[type] || icons.info}"></i></span>
        <div class="toast-content">
            <div class="toast-title">${title}</div>
            <div class="toast-message">${message}</div>
        </div>
        <button class="toast-close" onclick="this.parentElement.remove()"><i class="fas fa-times"></i></button>
    `;

    container.appendChild(toast);

    // Auto-remove after 5 seconds
    setTimeout(() => {
        toast.remove();
    }, 5000);
}

// ===== Loading Overlay =====
function showLoadingOverlay(message = '处理中...') {
    const overlay = document.getElementById('loading-overlay');
    if (overlay) {
        overlay.querySelector('p').textContent = message;
        overlay.classList.add('show');
    }
}

function hideLoadingOverlay() {
    const overlay = document.getElementById('loading-overlay');
    if (overlay) {
        overlay.classList.remove('show');
    }
}

// ===== Theme Toggle =====
function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-theme') || 'dark';
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';

    // Add rotation animation to button icon
    const buttonIcon = document.querySelector('[onclick="toggleTheme()"] i');
    if (buttonIcon) {
        buttonIcon.style.transform = 'rotate(360deg)';
    }

    // Apply theme change after a short delay for animation
    setTimeout(() => {
        html.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);

        // Update theme button icon
        updateThemeButton(newTheme);

        // Reset icon rotation
        if (buttonIcon) {
            buttonIcon.style.transform = '';
        }
    }, 150);

    // Show toast notification
    const themeName = newTheme === 'dark' ? '深色' : '浅色';
    showToast('info', '主题切换', `已切换到${themeName}主题`);
}

function updateThemeButton(theme) {
    const button = document.querySelector('[onclick="toggleTheme()"] i');
    if (button) {
        // Fade out, change icon, fade in
        button.style.opacity = '0';
        setTimeout(() => {
            button.className = theme === 'dark' ? 'fas fa-moon' : 'fas fa-sun';
            button.style.opacity = '1';
        }, 150);
    }
}

function initTheme() {
    const savedTheme = localStorage.getItem('theme') || 'dark';
    const html = document.documentElement;
    html.setAttribute('data-theme', savedTheme);

    // Set initial icon
    const button = document.querySelector('[onclick="toggleTheme()"] i');
    if (button) {
        button.className = savedTheme === 'dark' ? 'fas fa-moon' : 'fas fa-sun';
    }

    // Add transition style for theme icon
    if (button) {
        button.style.transition = 'transform 0.3s ease, opacity 0.15s ease';
    }
}

// ===== Auto-refresh =====
function startAutoRefresh() {
    // Refresh dashboard every 30 seconds
    setInterval(() => {
        if (currentPage === 'dashboard') {
            loadDashboard();
        }
    }, 30000);
}

// ===== Initialize =====
document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initNavigation();
    loadDashboard();
    startAutoRefresh();

    // Check initial connection
    apiCall('/health')
        .then(() => updateSystemStatus(true))
        .catch(() => updateSystemStatus(false));
});
