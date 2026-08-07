// Vrindha Dashboard JS - Connect frontend dashboard with backend APIs per START UP API Integration Prompt
// Requirements: Fetch logs from /logs, send commands to /command, display responses, error handling, loading states, use fetch

const API_BASE = window.location.origin;

async function apiFetch(path, options = {}) {
    const res = await fetch(`${API_BASE}${path}`, {
        headers: { 'Content-Type': 'application/json', ...options.headers },
        ...options
    });
    if (!res.ok) throw new Error(`API ${path} failed: ${res.status}`);
    return await res.json();
}

async function sendCommand(autoConfirm = false) {
    const input = document.getElementById('commandInput');
    const resultBox = document.getElementById('commandResult');
    const cmd = input.value.trim();
    if (!cmd) return alert("Enter a command");

    resultBox.textContent = "⏳ Processing... (Brain classifying Red/Blue, checking Dharma, Authorization...)";
    try {
        const data = await apiFetch('/command', {
            method: 'POST',
            body: JSON.stringify({ command: cmd, auto_confirm: autoConfirm })
        });
        resultBox.textContent = `Mode: ${data.mode?.toUpperCase()} | Action: ${data.action} | Status: ${data.status}\n\nMessage: ${data.message}\n\nData: ${JSON.stringify(data.data, null, 2)}`;
        // If confirmation required and user wants to proceed, show hint
        if (data.status === 'awaiting_confirmation') {
            resultBox.textContent += "\n\n🔴 Type 'yes' in input and send to confirm, or 'no' to cancel per Red Team safety.";
        }
        // Update alerts if threat
        if (data.data?.threat || data.mode === 'blue') {
            loadAlertsFromResult(data);
        }
    } catch (e) {
        // Fallback simulation if API not running
        resultBox.textContent = `[OFFLINE SIMULATION] Command: ${cmd}\nBrain would process this. Start FastAPI backend with: uvicorn api.main:app --reload --port 8000\nError: ${e.message}`;
    }
}

function quickCmd(cmd) {
    document.getElementById('commandInput').value = cmd;
    sendCommand();
}

async function loadLogs() {
    const container = document.getElementById('logsTable');
    container.textContent = "Loading logs from /logs...";
    try {
        const data = await apiFetch('/logs?limit=30');
        const logs = data.logs || [];
        if (logs.length === 0) container.textContent = "No logs yet. Run some commands first.";
        else {
            container.innerHTML = logs.map(log => {
                const l = typeof log === 'string' ? log : `${log.timestamp} | ${log.command} => ${log.result?.slice(0,100)} | RISK: ${log.risk_level}`;
                return `<div style="border-bottom:1px solid #2a2f4a; padding:5px;">${l}</div>`;
            }).join('');
        }
    } catch (e) {
        container.textContent = `[SIMULATION] SIEM logs would appear here. Start API. Error: ${e.message}`;
    }
}

async function loadStatus() {
    const statusEl = document.getElementById('systemStatus');
    const detailsEl = document.getElementById('statusDetails');
    try {
        const data = await apiFetch('/status');
        statusEl.textContent = `✅ ${data.message} | Mode: ${data.mode}`;
        detailsEl.textContent = JSON.stringify(data.data, null, 2);
    } catch (e) {
        statusEl.textContent = "⚠️ API offline - Running in simulation mode";
        detailsEl.textContent = "Start backend: uvicorn api.main:app --reload\nSystem would show: Agents, Tools, Memory stats, Gita status";
    }
}

async function verifyTools() {
    const el = document.getElementById('toolsStatus');
    el.textContent = "Verifying tools (nmap, nikto, gobuster, snort, fail2ban, rkhunter, etc.)...";
    try {
        const data = await apiFetch('/tools/verify');
        el.textContent = `Installed (${data.installed_count}/${data.total}): ${data.installed?.join(', ')}\nMissing (${data.missing_count}): ${data.missing?.join(', ')}\nSuggestion: ${data.suggestion}`;
    } catch (e) {
        el.textContent = `[SIMULATION] Tools verification: Would check nmap, wireshark, nikto, gobuster, snort, fail2ban, rkhunter, amass, dirb, tcpdump, chkrootkit, ufw, suricata, whois\nInstall missing via: sudo apt install <tool>\nError: ${e.message}`;
    }
}

async function loadMLData() {
    const el = document.getElementById('mlData');
    el.textContent = "Loading ML intelligence (Anomaly, Risk, Prediction, Data Pipeline)...";
    try {
        const [anomaly, risk, predict, pipeline] = await Promise.all([
            apiFetch('/ml/anomaly', { method: 'POST', body: JSON.stringify({ command: 'scan network 127.0.0.1 multiple failed logins' }) }),
            apiFetch('/ml/risk', { method: 'POST', body: JSON.stringify({ ip: '192.168.1.50', events: ['5 failed logins', 'unusual port 4444'] }) }),
            apiFetch('/ml/predict'),
            apiFetch('/ml/pipeline')
        ]);
        el.textContent = `ANOMALY: ${JSON.stringify(anomaly, null, 2)}\n\nRISK: ${JSON.stringify(risk, null, 2)}\n\nPREDICTION: ${JSON.stringify(predict, null, 2)}\n\nPIPELINE: ${JSON.stringify(pipeline, null, 2)}`;
    } catch (e) {
        el.textContent = `[SIMULATION] ML Intelligence:\n- Anomaly Detection: IsolationForest + KMeans (Scikit-learn)\n- Risk Scoring: {ip: 192.168.1.10, risk_score: 85, reason: multiple failed + unusual port}\n- Prediction: Attack likely in next 24h based on logs\n- Data Pipeline: Pandas CSV/SQLite cleaning\nError: ${e.message}`;
    }
}

async function loadGita() {
    const el = document.getElementById('gitaDetails');
    const headerVerse = document.getElementById('gitaVerse');
    try {
        const data = await apiFetch('/gita/random');
        el.textContent = `Chapter ${data.chapter}, Verse ${data.verse}\n\nSanskrit: ${data.text}\n\nMeaning: ${data.meaning}\n\nTags: ${data.tags?.join(', ')}\n\nDharma Principle: ${data.tags?.[0]}`;
        headerVerse.textContent = `🕉️ ${data.meaning?.slice(0,100)}...`;
    } catch (e) {
        el.textContent = "True strength lies in protecting, not exploiting. (Simulated Gita wisdom - API offline)\nFocus on duty, not results - Gita 2.47\nPerform your duty aligned with protection (Dharma).";
        headerVerse.textContent = "🕉️ Focus on duty, Dharma protects those who protect Dharma.";
    }
}

function loadAlertsFromResult(data) {
    const alertsBox = document.getElementById('alertsBox');
    const threat = data.data?.threat;
    if (threat) {
        alertsBox.textContent = `🚨 Threat Level: ${threat.threat_level || threat.risk_level}\nIndicators: ${threat.indicators || threat.threat}\nConfidence: ${threat.confidence}\n\nDharma: ${data.data?.gita_guidance?.message || ''}\n\nAutomated Action: ${JSON.stringify(data.data?.automated_action || 'Monitoring', null, 2)}`;
    }
}

// Charts - Dashboard Intelligence per AI ML PDF
async function loadCharts() {
    try {
        const data = await apiFetch('/dashboard-data');
        const viz = data.visualization;
        if (!viz) throw new Error("No viz data");

        // Attack Trends
        const attackCtx = document.getElementById('attackChart')?.getContext('2d');
        if (attackCtx && viz.attack_trends) {
            const at = viz.attack_trends.data || [];
            new Chart(attackCtx, {
                type: 'line',
                data: {
                    labels: at.map(d => d.date),
                    datasets: [
                        { label: 'Attacks', data: at.map(d => d.attacks), borderColor: '#ff5252', backgroundColor: 'rgba(255,82,82,0.1)', tension: 0.4 },
                        { label: 'Blocked', data: at.map(d => d.blocked), borderColor: '#4caf50', backgroundColor: 'rgba(76,175,80,0.1)', tension: 0.4 }
                    ]
                }
            });
        }

        // Port chart
        const portCtx = document.getElementById('portChart')?.getContext('2d');
        if (portCtx && viz.port_stats) {
            const ps = viz.port_stats.data || [];
            new Chart(portCtx, {
                type: 'bar',
                data: {
                    labels: ps.map(p => `${p.port}/${p.service}`),
                    datasets: [{ label: 'Hits', data: ps.map(p => p.hits), backgroundColor: '#7c4dff' }]
                }
            });
        }

        // Risk chart
        const riskCtx = document.getElementById('riskChart')?.getContext('2d');
        if (riskCtx && viz.risk_trends) {
            const rt = viz.risk_trends.data || [];
            new Chart(riskCtx, {
                type: 'line',
                data: {
                    labels: rt.map(r => r.hour),
                    datasets: [{ label: 'Risk Score', data: rt.map(r => r.risk), borderColor: '#ffd740', backgroundColor: 'rgba(255,215,64,0.2)', fill: true, tension: 0.4 }]
                }
            });
        }

    } catch (e) {
        console.log("Charts simulation mode", e);
        // Draw simulated charts
        try {
            const attackCtx = document.getElementById('attackChart')?.getContext('2d');
            if (attackCtx) new Chart(attackCtx, { type: 'line', data: { labels: ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'], datasets: [{ label: 'Attacks', data: [3,5,2,8,4,6,2], borderColor: '#ff5252' }] } });
            const portCtx = document.getElementById('portChart')?.getContext('2d');
            if (portCtx) new Chart(portCtx, { type: 'bar', data: { labels: ['22/ssh','80/http','443/https','445/smb'], datasets: [{ label: 'Hits', data: [45,78,65,12], backgroundColor: '#7c4dff' }] } });
            const riskCtx = document.getElementById('riskChart')?.getContext('2d');
            if (riskCtx) new Chart(riskCtx, { type: 'line', data: { labels: ['0:00','6:00','12:00','18:00','23:00'], datasets: [{ label: 'Risk', data: [20,35,80,60,30], borderColor: '#ffd740', backgroundColor: 'rgba(255,215,64,0.2)', fill: true }] } });
        } catch {}
    }
}

// Init
window.addEventListener('DOMContentLoaded', () => {
    loadStatus();
    loadLogs();
    loadGita();
    loadCharts();
    document.getElementById('commandInput').addEventListener('keypress', (e) => { if (e.key === 'Enter') sendCommand(); });
});
