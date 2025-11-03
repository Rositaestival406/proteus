let detectionChart = null;
let threatChart = null;

function initCharts() {
    createDetectionChart();
    createThreatChart();
    
    setInterval(updateCharts, 5000);
}

function createDetectionChart() {
    const ctx = document.getElementById('detectionChart');
    if (!ctx) return;
    
    detectionChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
            datasets: [
                {
                    label: 'Clean',
                    data: [12, 19, 15, 25, 22, 18, 20],
                    borderColor: 'rgb(34, 197, 94)',
                    backgroundColor: 'rgba(34, 197, 94, 0.1)',
                    tension: 0.4,
                    fill: true
                },
                {
                    label: 'Malicious',
                    data: [5, 8, 6, 10, 9, 7, 8],
                    borderColor: 'rgb(239, 68, 68)',
                    backgroundColor: 'rgba(239, 68, 68, 0.1)',
                    tension: 0.4,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    labels: {
                        color: 'rgb(148, 163, 184)'
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: 'rgb(148, 163, 184)'
                    },
                    grid: {
                        color: 'rgba(148, 163, 184, 0.1)'
                    }
                },
                x: {
                    ticks: {
                        color: 'rgb(148, 163, 184)'
                    },
                    grid: {
                        color: 'rgba(148, 163, 184, 0.1)'
                    }
                }
            }
        }
    });
}

function createThreatChart() {
    const ctx = document.getElementById('threatChart');
    if (!ctx) return;
    
    threatChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Ransomware', 'Trojan', 'RAT', 'Stealer', 'Other'],
            datasets: [{
                data: [15, 25, 20, 18, 22],
                backgroundColor: [
                    'rgb(239, 68, 68)',
                    'rgb(249, 115, 22)',
                    'rgb(234, 179, 8)',
                    'rgb(168, 85, 247)',
                    'rgb(59, 130, 246)'
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: 'rgb(148, 163, 184)',
                        padding: 15
                    }
                }
            }
        }
    });
}

function updateCharts() {
    if (!app.scanHistory.length) return;
    
    const last7Days = [];
    const today = new Date();
    
    for (let i = 6; i >= 0; i--) {
        const date = new Date(today);
        date.setDate(date.getDate() - i);
        last7Days.push(date.toDateString());
    }
    
    const cleanData = last7Days.map(day => {
        return app.scanHistory.filter(item => 
            new Date(item.timestamp).toDateString() === day && 
            item.verdict === 'CLEAN'
        ).length;
    });
    
    const maliciousData = last7Days.map(day => {
        return app.scanHistory.filter(item => 
            new Date(item.timestamp).toDateString() === day && 
            item.verdict === 'MALICIOUS'
        ).length;
    });
    
    if (detectionChart) {
        detectionChart.data.labels = last7Days.map(day => {
            const d = new Date(day);
            return d.toLocaleDateString('en-US', { weekday: 'short' });
        });
        detectionChart.data.datasets[0].data = cleanData;
        detectionChart.data.datasets[1].data = maliciousData;
        detectionChart.update('none');
    }
    
    const familyCounts = {
        'ransomware': 0,
        'trojan': 0,
        'rat': 0,
        'stealer': 0,
        'other': 0
    };
    
    
    if (threatChart) {
    }
}

function createThreatGauge(score, elementId) {
    const canvas = document.getElementById(elementId);
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;
    const radius = 80;
    
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, 0.75 * Math.PI, 2.25 * Math.PI);
    ctx.strokeStyle = 'rgba(148, 163, 184, 0.2)';
    ctx.lineWidth = 15;
    ctx.stroke();
    
    const scoreAngle = 0.75 * Math.PI + (1.5 * Math.PI * (score / 100));
    const gradient = ctx.createLinearGradient(0, 0, canvas.width, 0);
    
    if (score < 30) {
        gradient.addColorStop(0, 'rgb(34, 197, 94)');
        gradient.addColorStop(1, 'rgb(34, 197, 94)');
    } else if (score < 60) {
        gradient.addColorStop(0, 'rgb(234, 179, 8)');
        gradient.addColorStop(1, 'rgb(234, 179, 8)');
    } else {
        gradient.addColorStop(0, 'rgb(239, 68, 68)');
        gradient.addColorStop(1, 'rgb(239, 68, 68)');
    }
    
    ctx.beginPath();
    ctx.arc(centerX, centerY, radius, 0.75 * Math.PI, scoreAngle);
    ctx.strokeStyle = gradient;
    ctx.lineWidth = 15;
    ctx.lineCap = 'round';
    ctx.stroke();
    
    ctx.fillStyle = 'white';
    ctx.font = 'bold 32px Inter';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(score, centerX, centerY);
    
    ctx.font = '14px Inter';
    ctx.fillStyle = 'rgba(148, 163, 184, 0.8)';
    ctx.fillText('Threat Score', centerX, centerY + 25);
}