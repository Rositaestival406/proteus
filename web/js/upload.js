let selectedFile = null;

document.addEventListener('DOMContentLoaded', () => {
    console.log('[PROTEUS] Upload module loaded');
    
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('fileInput');
    const scanBtn = document.getElementById('scan-btn');
    
    if (!dropzone || !fileInput || !scanBtn) {
        console.error('[PROTEUS] Required elements not found');
        return;
    }
    
    dropzone.addEventListener('click', () => {
        fileInput.click();
    });
    
    dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropzone.classList.add('dragover');
    });
    
    dropzone.addEventListener('dragleave', () => {
        dropzone.classList.remove('dragover');
    });
    
    dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('dragover');
        
        if (e.dataTransfer.files.length > 0) {
            handleFileSelect(e.dataTransfer.files[0]);
        }
    });
    
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileSelect(e.target.files[0]);
        }
    });
    
    scanBtn.addEventListener('click', () => {
        if (selectedFile) {
            console.log('[PROTEUS] Starting scan');
            startScan(selectedFile);
        }
    });
});

function handleFileSelect(file) {
    selectedFile = file;
    
    const maxSize = 100 * 1024 * 1024;
    if (file.size > maxSize) {
        showNotification('File too large (max 100MB)', 'error');
        return;
    }
    
    console.log('[PROTEUS] File selected:', file.name, formatBytes(file.size));
    
    const dropzone = document.getElementById('dropzone');
    dropzone.innerHTML = `
        <svg class="w-12 h-12 mx-auto mb-4 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/>
        </svg>
        <h3 class="text-xl font-semibold mb-2">${file.name}</h3>
        <p class="text-slate-400 mb-2">${formatBytes(file.size)}</p>
        <button onclick="resetUpload()" class="px-4 py-2 bg-slate-700 hover:bg-slate-600 rounded-lg transition text-sm">
            Change File
        </button>
    `;
    
    document.getElementById('scan-btn').disabled = false;
}

function resetUpload() {
    selectedFile = null;
    document.getElementById('scan-btn').disabled = true;
    location.reload();
}

async function startScan(file) {
    const progressSection = document.getElementById('progress-section');
    const resultsSection = document.getElementById('results-section');
    const scanBtn = document.getElementById('scan-btn');
    
    progressSection.classList.remove('hidden');
    resultsSection.classList.add('hidden');
    scanBtn.disabled = true;
    
    const options = {
        ml: document.getElementById('opt-ml').checked,
        yara: document.getElementById('opt-yara').checked,
        strings: document.getElementById('opt-strings').checked
    };
    
    console.log('[PROTEUS] Scan options:', options);
    
    try {
        const formData = new FormData();
        formData.append('file', file);
        formData.append('ml', options.ml.toString());
        formData.append('yara', options.yara.toString());
        formData.append('strings', options.strings.toString());
        
        updateProgress(10, 'Uploading...');
        
        const response = await fetch('/api/scan', {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        updateProgress(50, 'Analyzing...');
        
        const result = await response.json();
        
        updateProgress(100, 'Complete!');
        
        setTimeout(() => {
            displayResults(result);
            addToHistory(result);
            progressSection.classList.add('hidden');
            scanBtn.disabled = false;
        }, 500);
        
    } catch (error) {
        console.error('[PROTEUS] Error:', error);
        showNotification(`Scan failed: ${error.message}`, 'error');
        progressSection.classList.add('hidden');
        scanBtn.disabled = false;
    }
}

function updateProgress(percent, text) {
    document.getElementById('progress-bar').style.width = `${percent}%`;
    document.getElementById('progress-text').textContent = text;
}

function displayResults(result) {
    const resultsSection = document.getElementById('results-section');
    resultsSection.classList.remove('hidden');
    
    const verdict = result.heuristic.verdict;
    const score = result.heuristic.score;
    const color = verdict === 'MALICIOUS' ? 'text-red-400' : 'text-green-400';
    const icon = verdict === 'MALICIOUS' ? '⚠️' : '✅';
    
    let html = `
        <div class="glass rounded-xl p-8">
            <div class="flex items-center justify-between mb-6">
                <div class="flex items-center space-x-4">
                    <div class="text-4xl">${icon}</div>
                    <div>
                        <h3 class="text-2xl font-bold ${color}">${verdict}</h3>
                        <p class="text-slate-400">${result.filename}</p>
                    </div>
                </div>
                <div class="text-right">
                    <div class="text-3xl font-bold ${color}">${score.toFixed(1)}</div>
                    <div class="text-sm text-slate-400">Threat Score</div>
                </div>
            </div>
            
            <div class="grid grid-cols-3 gap-4 mb-6">
                <div class="glass rounded-lg p-4">
                    <div class="text-sm text-slate-400">Type</div>
                    <div class="font-semibold">${result.heuristic.type}</div>
                </div>
                <div class="glass rounded-lg p-4">
                    <div class="text-sm text-slate-400">Entropy</div>
                    <div class="font-semibold">${result.heuristic.entropy.toFixed(2)}</div>
                </div>
                <div class="glass rounded-lg p-4">
                    <div class="text-sm text-slate-400">Indicators</div>
                    <div class="font-semibold">${result.heuristic.indicators.length}</div>
                </div>
            </div>
    `;
    
    if (result.heuristic.indicators.length > 0) {
        html += '<div class="mb-6"><h4 class="font-semibold mb-2">Suspicious Indicators</h4><div class="space-y-2">';
        result.heuristic.indicators.forEach(ind => {
            html += `<div class="glass p-2 text-sm">${ind}</div>`;
        });
        html += '</div></div>';
    }
    
    if (result.ml && !result.ml.error) {
        const mlColor = result.ml.prediction === 'malicious' ? 'text-red-400' : 'text-green-400';
        html += `
            <div class="mb-6">
                <h4 class="font-semibold mb-2">ML Analysis</h4>
                <div class="glass p-4">
                    <div class="${mlColor} font-bold">${result.ml.prediction.toUpperCase()}</div>
                    <div class="text-sm">Confidence: ${(result.ml.confidence * 100).toFixed(1)}%</div>
                </div>
            </div>
        `;
    }
    
    if (result.yara && result.yara.match_count > 0) {
        html += `<div class="mb-6"><h4 class="font-semibold mb-2">YARA (${result.yara.match_count} matches)</h4>`;
        result.yara.matches.forEach(m => {
            html += `<div class="glass p-3 mb-2"><div class="text-red-400 font-semibold">${m.rule}</div>`;
            if (m.meta?.description) html += `<div class="text-sm text-slate-400">${m.meta.description}</div>`;
            html += '</div>';
        });
        html += '</div>';
    }
    
    html += '</div>';
    resultsSection.innerHTML = html;
}

function showNotification(msg, type) {
    const div = document.createElement('div');
    div.className = `fixed top-4 right-4 bg-${type === 'error' ? 'red' : 'green'}-500 text-white px-6 py-3 rounded-lg z-50`;
    div.textContent = msg;
    document.body.appendChild(div);
    setTimeout(() => div.remove(), 3000);
}