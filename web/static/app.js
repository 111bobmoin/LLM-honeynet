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

        // Update title
        const titles = {
            'dashboard': '概览',
            'perception': '感知',
            'orchestration': '编排',
            'deception': '欺骗',
            'operations': '操作记录',
            'shadow': '影子数据'
        };
        document.getElementById('page-title').textContent = titles[page] || 'Dashboard';

        // Load page-specific data
        loadPageData(page);

        // Update hash
        window.location.hash = page;
    }

    // Close sidebar on mobile
    if (window.innerWidth <= 768) {
        document.getElementById('sidebar').classList.remove('open');
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
            break;
        case 'deception':
            loadDeploymentHosts();
            loadConsistencyReport();
            break;
        case 'operations':
            loadOperations();
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
        document.getElementById('stat-hosts').textContent = data.hosts.count;
        document.getElementById('stat-completed').textContent = data.operations.completed;
        document.getElementById('stat-running').textContent = data.operations.running;
        document.getElementById('stat-failed').textContent = data.operations.failed;

        // Update phase status
        updatePhaseStatus('perception', data.hosts.count > 0);
        updatePhaseStatus('orchestration', data.shadow_files['honey_agent.json']?.exists);
        updatePhaseStatus('deception', data.shadow_files['trap_agent.json']?.exists);

        // Load recent operations
        const ops = await apiCall('/operations?limit=5');
        displayRecentOperations(ops.operations);

        // Update connection status
        updateConnectionStatus(true);

    } catch (error) {
        console.error('Failed to load dashboard:', error);
        updateConnectionStatus(false);
    }
}

function updatePhaseStatus(phase, isReady) {
    const indicator = document.getElementById(`phase-${phase}`);
    if (indicator) {
        indicator.className = 'phase-indicator';
        if (isReady) {
            indicator.classList.add('active');
            indicator.querySelector('.phase-text').textContent = '就绪';
        } else {
            indicator.querySelector('.phase-text').textContent = '待运行';
        }
    }
}

function displayRecentOperations(operations) {
    const container = document.getElementById('recent-operations');

    if (!operations || operations.length === 0) {
        container.innerHTML = '<p class="text-muted">暂无操作记录</p>';
        return;
    }

    container.innerHTML = operations.map(op => `
        <div class="operation-item">
            <span class="operation-type">${getOperationTypeName(op.type)}</span>
            <span class="operation-status ${op.status}">${getStatusText(op.status)}</span>
            <span class="operation-time">${formatTime(op.created_at)}</span>
        </div>
    `).join('');
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

function updateConnectionStatus(online) {
    const dot = document.getElementById('connection-status');
    const text = document.getElementById('connection-text');

    if (online) {
        dot.className = 'status-dot online';
        text.textContent = '已连接';
    } else {
        dot.className = 'status-dot offline';
        text.textContent = '连接失败';
    }
}

// ===== Perception =====
async function loadHosts() {
    const container = document.getElementById('perception-hosts');
    container.innerHTML = '<div class="loading">加载中...</div>';

    try {
        const data = await apiCall('/perception/hosts');

        if (!data.hosts || data.hosts.length === 0) {
            container.innerHTML = '<p class="text-muted">未找到主机</p>';
            return;
        }

        container.innerHTML = data.hosts.map(host => `
            <div class="host-item" data-host="${host.name}" onclick="toggleHostSelection('${host.name}')">
                <input type="checkbox" class="host-checkbox" ${selectedHosts.has(host.name) ? 'checked' : ''}>
                <div class="host-name">${host.name}</div>
                <div class="host-info">${host.log_files.length} 日志文件</div>
            </div>
        `).join('');

    } catch (error) {
        container.innerHTML = `<p class="text-danger">加载失败: ${error.message}</p>`;
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
    const checkbox = hostItem.querySelector('.host-checkbox');
    checkbox.checked = selectedHosts.has(hostName);

    // Update selected class
    hostItem.classList.toggle('selected', selectedHosts.has(hostName));
}

async function runPerception() {
    const useOpenAI = document.getElementById('perception-openai').checked;
    const hosts = selectedHosts.size > 0 ? Array.from(selectedHosts) : null;

    const statusBadge = document.getElementById('perception-status');
    const resultsContainer = document.getElementById('perception-results');

    try {
        statusBadge.textContent = '运行中...';
        statusBadge.className = 'badge badge-warning';

        const data = await apiCall('/perception/analyze', {
            method: 'POST',
            body: JSON.stringify({ hosts, use_openai: useOpenAI })
        });

        statusBadge.textContent = '处理中';
        statusBadge.className = 'badge badge-info';

        // Poll for results
        pollOperation(data.operation_id, (result) => {
            statusBadge.textContent = '完成';
            statusBadge.className = 'badge badge-success';
            displayPerceptionResults(result.result);
            showToast('success', '感知分析', '分析已完成');
        }, (error) => {
            statusBadge.textContent = '失败';
            statusBadge.className = 'badge badge-danger';
            resultsContainer.innerHTML = `<p class="text-danger">分析失败: ${error}</p>`;
            showToast('error', '感知分析', `分析失败: ${error}`);
        });

    } catch (error) {
        statusBadge.textContent = '失败';
        statusBadge.className = 'badge badge-danger';
        showToast('error', '感知分析', `启动失败: ${error.message}`);
    }
}

function displayPerceptionResults(result) {
    const container = document.getElementById('perception-results');

    if (!result || !result.analyses || result.analyses.length === 0) {
        container.innerHTML = '<p class="text-muted">无分析结果</p>';
        return;
    }

    let html = `<p class="text-muted">共分析 ${result.total_hosts} 个主机</p>`;

    if (result.openai_summary) {
        html += `
            <div class="analysis-result">
                <h4>🤖 AI 摘要</h4>
                <p>${result.openai_summary}</p>
            </div>
        `;
    }

    result.analyses.forEach(analysis => {
        html += `
            <div class="analysis-result">
                <div class="analysis-host">
                    <span>🖥️ ${analysis.host}</span>
                    <span class="analysis-stage ${analysis.stage_label}">${analysis.stage_label}</span>
                </div>
                <p class="text-muted">${analysis.event_count} 个事件</p>
                ${analysis.events && analysis.events.length > 0 ? `
                    <div class="analysis-events">
                        ${analysis.events.map(e => `
                            <div class="analysis-event">
                                <span class="text-muted">${e.timestamp}</span>
                                ${e.stage ? `<span class="badge badge-info">${e.stage}</span>` : ''}
                                <span>${e.summary}</span>
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

        const honeyEl = document.getElementById('orchestration-honey');
        const trapEl = document.getElementById('orchestration-trap');
        const prefsEl = document.getElementById('orchestration-prefs');

        if (data.honey_agent.exists) {
            honeyEl.textContent = `${data.honey_agent.hosts} 主机`;
            honeyEl.className = 'status-value ready';
        }

        if (data.trap_agent.exists) {
            trapEl.textContent = `${data.trap_agent.hosts} 主机, ${data.trap_agent.chains} 链`;
            trapEl.className = 'status-value ready';
        }

        if (data.attacker_preferences.exists) {
            prefsEl.textContent = `${data.attacker_preferences.count} 偏好`;
            prefsEl.className = 'status-value ready';
        }

    } catch (error) {
        console.error('Failed to load orchestration status:', error);
    }
}

async function runHoneyAgent() {
    const resultDiv = document.getElementById('honey-result');
    const mode = document.getElementById('honey-mode').value;
    const model = document.getElementById('honey-model').value;
    const temp = parseFloat(document.getElementById('honey-temp').value);
    const topP = parseFloat(document.getElementById('honey-topp').value);

    try {
        resultDiv.className = 'operation-result show';
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
            resultDiv.className = 'operation-result show success';
            resultDiv.innerHTML = `
                <p>✅ 完成！生成 ${r.hosts_generated} 个主机的诱饵配置</p>
                <p class="text-muted">模式: ${r.mode}</p>
            `;
            loadOrchestrationStatus();
            showToast('success', 'Honey Agent', `已生成 ${r.hosts_generated} 个主机的配置`);
        }, (error) => {
            resultDiv.className = 'operation-result show error';
            resultDiv.innerHTML = `<p>❌ 失败: ${error}</p>`;
            showToast('error', 'Honey Agent', `运行失败: ${error}`);
        });

    } catch (error) {
        resultDiv.className = 'operation-result show error';
        resultDiv.innerHTML = `<p>❌ 启动失败: ${error.message}</p>`;
    }
}

async function runTrapAgent() {
    const resultDiv = document.getElementById('trap-result');
    const mode = document.getElementById('trap-mode').value;
    const model = document.getElementById('trap-model').value;
    const temp = parseFloat(document.getElementById('trap-temp').value);
    const topP = parseFloat(document.getElementById('trap-topp').value);

    try {
        resultDiv.className = 'operation-result show';
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
            resultDiv.className = 'operation-result show success';
            resultDiv.innerHTML = `
                <p>✅ 完成！处理 ${r.hosts?.length || 0} 个主机</p>
                <p class="text-muted">模式: ${r.mode}</p>
            `;
            loadOrchestrationStatus();
            showToast('success', 'Trap Agent', '陷阱链已生成');
        }, (error) => {
            resultDiv.className = 'operation-result show error';
            resultDiv.innerHTML = `<p>❌ 失败: ${error}</p>`;
            showToast('error', 'Trap Agent', `运行失败: ${error}`);
        });

    } catch (error) {
        resultDiv.className = 'operation-result show error';
        resultDiv.innerHTML = `<p>❌ 启动失败: ${error.message}</p>`;
    }
}

async function loadPreferences() {
    try {
        const data = await apiCall('/config/preferences');

        if (data.exists && data.preferences) {
            document.getElementById('preferences-list').value = data.preferences.join('\n');
        }
    } catch (error) {
        console.error('Failed to load preferences:', error);
    }
}

async function savePreferences() {
    const text = document.getElementById('preferences-list').value;
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
    container.innerHTML = '<div class="loading">加载中...</div>';

    try {
        const data = await apiCall('/deployment/hosts');

        if (!data.hosts || data.hosts.length === 0) {
            container.innerHTML = '<p class="text-muted">未找到部署主机</p>';
            return;
        }

        container.innerHTML = data.hosts.map(host => `
            <div class="deployment-host">
                <div class="deployment-host-name">🖥️ ${host.name}</div>
                <div class="deployment-host-info">
                    <span>配置: ${host.has_config ? '✓' : '✗'}</span>
                    <span>日志: ${host.has_logs ? '✓' : '✗'}</span>
                    ${host.configs ? `<span>${host.configs.length} 文件</span>` : ''}
                </div>
            </div>
        `).join('');

    } catch (error) {
        container.innerHTML = `<p class="text-danger">加载失败: ${error.message}</p>`;
    }
}

async function loadConsistencyReport() {
    const container = document.getElementById('consistency-report');

    try {
        const data = await apiCall('/deception/consistency');

        if (!data.exists) {
            container.innerHTML = '<p class="text-muted">暂无一致性报告</p>';
            return;
        }

        let html = `
            <p class="text-muted">生成时间: ${data.modified || '-'}</p>
        `;

        if (data.issues && data.issues.length > 0) {
            html += '<h4>发现问题:</h4><ul>';
            data.issues.forEach(issue => {
                html += `<li class="text-danger">${issue}</li>`;
            });
            html += '</ul>';
        } else {
            html += '<p class="text-success">✓ 未发现一致性问题</p>';
        }

        container.innerHTML = html;

    } catch (error) {
        container.innerHTML = `<p class="text-danger">加载失败: ${error.message}</p>`;
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

    const hosts = document.getElementById('deception-hosts').value || null;

    try {
        resultDiv.className = 'operation-result show';
        resultDiv.innerHTML = '<p>⏳ 正在运行...</p>';

        const data = await apiCall('/deception/run', {
            method: 'POST',
            body: JSON.stringify({ mode, hosts })
        });

        pollOperation(data.operation_id, (result) => {
            const r = result.result;
            resultDiv.className = 'operation-result show success';

            if (mode === 'consistency') {
                resultDiv.innerHTML = '<p>✅ 一致性审计完成</p>';
                loadConsistencyReport();
            } else if (mode === 'generate-configs') {
                resultDiv.innerHTML = `<p>✅ 已生成 ${r.results?.host_configs?.generated || 0} 个主机配置</p>`;
                loadDeploymentHosts();
            } else {
                resultDiv.innerHTML = '<p>✅ 完整流程执行完成</p>';
                loadConsistencyReport();
                loadDeploymentHosts();
            }

            showToast('success', '欺骗配置', '操作已完成');
        }, (error) => {
            resultDiv.className = 'operation-result show error';
            resultDiv.innerHTML = `<p>❌ 失败: ${error}</p>`;
            showToast('error', '欺骗配置', `运行失败: ${error}`);
        });

    } catch (error) {
        resultDiv.className = 'operation-result show error';
        resultDiv.innerHTML = `<p>❌ 启动失败: ${error.message}</p>`;
    }
}

// ===== Operations =====
async function loadOperations() {
    const container = document.getElementById('operations-list');
    container.innerHTML = '<div class="loading">加载中...</div>';

    try {
        const data = await apiCall('/operations?limit=50');

        if (!data.operations || data.operations.length === 0) {
            container.innerHTML = '<p class="text-muted text-center" style="grid-column: 1/-1; padding: 24px;">暂无操作记录</p>';
            return;
        }

        container.innerHTML = data.operations.map(op => `
            <div class="table-row">
                <div class="table-cell">${getOperationTypeName(op.type)}</div>
                <div class="table-cell">
                    <span class="operation-status ${op.status}">${getStatusText(op.status)}</span>
                </div>
                <div class="table-cell">${formatTime(op.created_at)}</div>
                <div class="table-cell">
                    ${op.status === 'completed' ? `
                        <button class="btn btn-secondary btn-sm" onclick="showOperationDetail('${op.id}')">详情</button>
                    ` : ''}
                </div>
            </div>
        `).join('');

    } catch (error) {
        container.innerHTML = `<p class="text-danger text-center" style="grid-column: 1/-1; padding: 24px;">加载失败: ${error.message}</p>`;
    }
}

async function showOperationDetail(opId) {
    try {
        const data = await apiCall(`/operations/${opId}`);

        let content = `
            <h4>操作详情</h4>
            <p><strong>类型:</strong> ${getOperationTypeName(data.type)}</p>
            <p><strong>状态:</strong> ${getStatusText(data.status)}</p>
            <p><strong>创建时间:</strong> ${data.created_at}</p>
        `;

        if (data.params) {
            content += '<h5>参数:</h5><pre>' + JSON.stringify(data.params, null, 2) + '</pre>';
        }

        if (data.result) {
            content += '<h5>结果:</h5><pre>' + JSON.stringify(data.result, null, 2) + '</pre>';
        }

        if (data.error) {
            content += `<p class="text-danger"><strong>错误:</strong> ${data.error}</p>`;
        }

        // Show in modal or alert
        alert(content.replace(/<[^>]*>/g, '\n').replace(/\n+/g, '\n'));

    } catch (error) {
        showToast('error', '操作详情', `加载失败: ${error.message}`);
    }
}

// ===== Shadow Data =====
async function loadShadowData() {
    // Load file status
    try {
        const summary = await apiCall('/dashboard/summary');
        const container = document.getElementById('shadow-files-status');

        container.innerHTML = Object.entries(summary.shadow_files).map(([name, info]) => {
            const displayName = name.replace('.json', '').replace(/_/g, ' ');
            return `
                <div class="shadow-file-item">
                    <div class="shadow-file-name">${displayName}</div>
                    <span class="shadow-file-status ${info.exists ? 'exists' : 'missing'}">
                        ${info.exists ? '✓ 存在' : '✗ 缺失'}
                    </span>
                    ${info.modified ? `<div class="shadow-file-modified">${formatTime(info.modified)}</div>` : ''}
                </div>
            `;
        }).join('');

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

    // Initialize tabs
    initTabs();
}

// Render Honey Agent data with visual cards
function renderHoneyAgentData(data) {
    const container = document.getElementById('honey-agent-data');

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

// Render Trap Agent data with visual cards
function renderTrapAgentData(data) {
    const container = document.getElementById('trap-agent-data');

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
        container.innerHTML = `<p class="text-danger">加载失败: ${error.message}</p>`;
    }
}

// Render Long Memory data
function renderLongMemoryData(data) {
    const container = document.getElementById('long-memory-data');

    const portFacts = data.port_facts || {};
    const factCount = Object.keys(portFacts).length;

    if (factCount === 0) {
        container.innerHTML = '<p class="text-muted">暂无数据</p>';
        return;
    }

    let html = '<div class="data-cards">';

    // Group by service type
    const services = {};
    Object.entries(portFacts).forEach(([port, facts]) => {
        const service = facts.service || 'unknown';
        if (!services[service]) {
            services[service] = [];
        }
        services[service].push({ port, ...facts });
    });

    Object.entries(services).forEach(([service, ports]) => {
        html += `
            <div class="data-card">
                <div class="data-card-header">
                    <h4 class="data-card-title">🔌 ${service}</h4>
                </div>
                <div class="data-card-body">
                    <div class="port-facts-list">
                        ${ports.map(p => `
                            <div class="port-fact-item">
                                <span class="port-fact-port">Port ${p.port}</span>
                                <div class="port-fact-details">
                                    ${p.banner ? `<div class="port-fact-banner">${p.banner}</div>` : ''}
                                    ${p.default_software ? `<div class="port-fact-software">${p.default_software}</div>` : ''}
                                </div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            </div>
        `;
    });

    html += '</div>';
    container.innerHTML = html;
}

function initTabs() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabPanes = document.querySelectorAll('.tab-pane');

    tabBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const tabName = btn.dataset.tab;

            tabBtns.forEach(b => b.classList.remove('active'));
            tabPanes.forEach(p => p.classList.remove('active'));

            btn.classList.add('active');
            document.getElementById(`tab-${tabName}`).classList.add('active');
        });
    });
}

// ===== Polling =====
function pollOperation(opId, onSuccess, onError) {
    const maxAttempts = 300; // 5 minutes max
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

            // Still running, continue polling
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

    const icons = {
        success: '✅',
        error: '❌',
        info: 'ℹ️',
        warning: '⚠️'
    };

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <span class="toast-icon">${icons[type] || icons.info}</span>
        <div class="toast-content">
            <div class="toast-title">${title}</div>
            <div class="toast-message">${message}</div>
        </div>
        <button class="toast-close" onclick="this.parentElement.remove()">×</button>
    `;

    container.appendChild(toast);

    // Auto-remove after 5 seconds
    setTimeout(() => {
        toast.remove();
    }, 5000);
}

// ===== Auto-refresh =====
function startAutoRefresh() {
    // Refresh dashboard every 10 seconds
    setInterval(() => {
        if (currentPage === 'dashboard') {
            loadDashboard();
        }
    }, 10000);

    // Refresh running operations every 2 seconds
    setInterval(() => {
        if (currentPage === 'operations') {
            loadOperations();
        }
    }, 2000);
}

// ===== Initialize =====
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    loadDashboard();
    startAutoRefresh();

    // Check initial connection
    apiCall('/health')
        .then(() => updateConnectionStatus(true))
        .catch(() => updateConnectionStatus(false));
});
