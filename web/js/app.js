const app = {
    scanHistory: [],
    stats: {
        scansToday: 0,
        threatsDetected: 0
    }
};

document.addEventListener('DOMContentLoaded', async () => {
    console.log('[PROTEUS] Initializing...');
    
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const section = e.target.dataset.section;
            if (section) {
                console.log('[PROTEUS] Navigating to:', section);
                showSection(section);
            }
        });
    });
    
    await checkHealth();
    await loadStats();
    loadHistory();
    
    setTimeout(() => {
        if (typeof initCharts === 'function') {
            initCharts();
        }
    }, 100);
});

async function checkHealth() {
    try {
        const response = await fetch('/api/health');
        const data = await response.json();
        
        const mlStatus = document.getElementById('ml-status');
        const yaraStatus = document.getElementById('yara-status');
        
        if (data.ml_loaded) {
            mlStatus.classList.remove('bg-gray-500');
            mlStatus.classList.add('bg-green-500', 'pulse');
        }
        
        if (data.yara_loaded) {
            yaraStatus.classList.remove('bg-gray-500');
            yaraStatus.classList.add('bg-green-500', 'pulse');
        }
        
        console.log('[PROTEUS] Health check:', data);
    } catch (error) {
        console.error('[PROTEUS] Health check failed:', error);
        document.getElementById('status-indicator').innerHTML = `
            <div class="w-2 h-2 rounded-full bg-red-500"></div>
            <span class="text-xs text-slate-400">Offline</span>
        `;
    }
}

async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();
        
        if (data.yara_info && data.yara_info.rule_files) {
            document.getElementById('yara-rules').textContent = data.yara_info.rule_files;
        }
        
        console.log('[PROTEUS] Stats loaded:', data);
    } catch (error) {
        console.error('[PROTEUS] Failed to load stats:', error);
    }
}

function showSection(section) {
    console.log('[PROTEUS] Showing section:', section);
    
    document.querySelectorAll('.section').forEach(el => {
        el.classList.add('hidden');
    });
    
    const targetSection = document.getElementById(`${section}-section`);
    if (targetSection) {
        targetSection.classList.remove('hidden');
    } else {
        console.error('[PROTEUS] Section not found:', section);
    }
    
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.classList.remove('text-white');
        btn.classList.add('text-slate-300');
    });
    
    const activeBtn = document.querySelector(`[data-section="${section}"]`);
    if (activeBtn) {
        activeBtn.classList.remove('text-slate-300');
        activeBtn.classList.add('text-white');
    }
}

function loadHistory() {
    const stored = localStorage.getItem('proteus_history');
    if (stored) {
        app.scanHistory = JSON.parse(stored);
        renderHistory();
        updateDashboardStats();
    }
}

function saveHistory() {
    localStorage.setItem('proteus_history', JSON.stringify(app.scanHistory));
}

function addToHistory(result) {
    const historyItem = {
        id: Date.now(),
        timestamp: new Date().toISOString(),
        filename: result.filename,
        verdict: result.heuristic.verdict,
        score: result.heuristic.score,
        ml_prediction: result.ml?.prediction,
        yara_matches: result.yara?.match_count || 0
    };
    
    app.scanHistory.unshift(historyItem);
    
    if (app.scanHistory.length > 50) {
        app.scanHistory = app.scanHistory.slice(0, 50);
    }
    
    saveHistory();
    renderHistory();
    updateDashboardStats();
}

function renderHistory() {
    const historyList = document.getElementById('history-list');
    
    if (app.scanHistory.length === 0) {
        historyList.innerHTML = '<p class="text-center text-slate-400 py-8">No scans yet</p>';
        return;
    }
    
    historyList.innerHTML = app.scanHistory.map(item => `
        <div class="glass rounded-lg p-4 flex items-center justify-between">
            <div class="flex items-center space-x-4">
                <div class="text-2xl">
                    ${item.verdict === 'MALICIOUS' ? '⚠️' : '✅'}
                </div>
                <div>
                    <div class="font-semibold">${item.filename}</div>
                    <div class="text-sm text-slate-400">
                        ${new Date(item.timestamp).toLocaleString()}
                    </div>
                </div>
            </div>
            <div class="text-right">
                <div class="text-lg font-bold ${item.verdict === 'MALICIOUS' ? 'text-red-400' : 'text-green-400'}">
                    ${item.score.toFixed(1)}/100
                </div>
                <div class="text-xs text-slate-400">
                    ${item.yara_matches} YARA matches
                </div>
            </div>
        </div>
    `).join('');
}

function updateDashboardStats() {
    const today = new Date().toDateString();
    const todayScans = app.scanHistory.filter(item => 
        new Date(item.timestamp).toDateString() === today
    );
    
    document.getElementById('scans-today').textContent = todayScans.length;
    
    const threats = app.scanHistory.filter(item => item.verdict === 'MALICIOUS');
    document.getElementById('threats-detected').textContent = threats.length;
    
    app.stats.scansToday = todayScans.length;
    app.stats.threatsDetected = threats.length;
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function getVerdictColor(verdict) {
    return verdict === 'MALICIOUS' ? 'text-red-400' : 'text-green-400';
}

function getSeverityBadge(severity) {
    const colors = {
        'CRITICAL': 'bg-red-500',
        'HIGH': 'bg-orange-500',
        'MEDIUM': 'bg-yellow-500',
        'LOW': 'bg-blue-500'
    };
    
    return `<span class="px-2 py-1 text-xs rounded ${colors[severity] || 'bg-gray-500'}">${severity}</span>`;
}