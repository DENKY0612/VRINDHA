// Vrindha Dashboard JS - Connect frontend dashboard with backend APIs per START UP API Integration Prompt
// Requirements: Fetch logs from /logs, send commands to /command, display responses, error handling, loading states, use fetch

const API_BASE = window.location.origin;
let authToken = sessionStorage.getItem('vrindhaToken') || '';
const escapeHtml = value => String(value).replace(/[&<>'"]/g, char => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[char]));

class ApiError extends Error {
    constructor(message, status) {
        super(message);
        this.name = 'ApiError';
        this.status = status;
    }
}

async function apiFetch(path, options = {}) {
    // Spread request options first so a caller cannot accidentally replace the
    // merged Authorization header with its own headers object.
    const headers = {
        'Content-Type': 'application/json',
        ...(authToken ? {Authorization: `Bearer ${authToken}`} : {}),
        ...(options.headers || {})
    };
    const res = await fetch(`${API_BASE}${path}`, {...options, headers});
    if (!res.ok) {
        let detail = '';
        try { detail = (await res.json()).detail || ''; } catch (_) {}
        if (res.status === 401) {
            authToken = '';
            sessionStorage.removeItem('vrindhaToken');
        }
        throw new ApiError(detail || `API ${path} failed: ${res.status}`, res.status);
    }
    return await res.json();
}

function showApiError(element, error, action) {
    if (!element) return;
    if (error?.status === 401) {
        element.textContent = `${action || 'This action'} requires authentication. Log in, then try again.`;
    } else if (error?.status === 403) {
        element.textContent = `Permission denied: ${error.message}`;
    } else {
        element.textContent = `${action || 'API request'} unavailable: ${error?.message || error}`;
    }
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
        showApiError(resultBox, e, `Command '${cmd}'`);
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
                return `<div style="border-bottom:1px solid #2a2f4a; padding:5px;">${escapeHtml(l)}</div>`;
            }).join('');
        }
    } catch (e) {
        showApiError(container, e, 'Logs');
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
        if (e?.status) {
            statusEl.textContent = `⚠️ API request failed (${e.status})`;
            detailsEl.textContent = e.message;
        } else {
            statusEl.textContent = "⚠️ API offline - Running in simulation mode";
            detailsEl.textContent = "Start backend: python -m uvicorn api.main:app --host 0.0.0.0 --port 8000\nSystem would show: Agents, Tools, Memory stats, Gita status";
        }
    }
}

async function verifyTools() {
    const el = document.getElementById('toolsStatus');
    el.textContent = "Verifying tools (nmap, nikto, gobuster, snort, fail2ban, rkhunter, etc.)...";
    try {
        const data = await apiFetch('/tools/verify');
        el.textContent = `Installed (${data.installed_count}/${data.total}): ${data.installed?.join(', ')}\nMissing (${data.missing_count}): ${data.missing?.join(', ')}\nSuggestion: ${data.suggestion}`;
    } catch (e) {
        showApiError(el, e, 'Tool verification');
    }
}

async function loadMLData() {
    const el = document.getElementById('mlData');
    el.textContent = "Loading ML intelligence (Anomaly, Risk, Prediction, Data Pipeline)...";
    try {
        const [anomaly, risk, feedback, predict, pipeline] = await Promise.all([
            apiFetch('/ml/anomaly', { method: 'POST', body: JSON.stringify({ command: 'scan network 127.0.0.1 multiple failed logins' }) }),
            apiFetch('/ml/risk', { method: 'POST', body: JSON.stringify({ ip: '192.168.1.50', events: ['5 failed logins', 'unusual port 4444'], correlated_alerts: [{type:'auth'}, {type:'network'}] }) }),
            apiFetch('/ml/risk/feedback?limit=5'),
            apiFetch('/ml/predict'),
            apiFetch('/ml/pipeline')
        ]);
        el.textContent = `ANOMALY: ${JSON.stringify(anomaly, null, 2)}\n\nRISK + CONFIDENCE (not yes/no): ${JSON.stringify(risk, null, 2)}\n\nHUMAN FEEDBACK LOOP: ${JSON.stringify(feedback, null, 2)}\n\nPREDICTION: ${JSON.stringify(predict, null, 2)}\n\nPIPELINE: ${JSON.stringify(pipeline, null, 2)}`;
    } catch (e) {
        el.textContent = `[SIMULATION] ML Intelligence:\n- Multi-layer detection: rules + anomaly + TI + behavior + SIEM + AI reasoning\n- Risk Scoring: {ip: 192.168.1.10, risk_score: 85, confidence_score: 82, requires_human_validation: true}\n- Human feedback: true_positive / false_positive labels improve rules/models\n- Prediction: Attack likely in next 24h based on validated logs\n- Data Pipeline: Pandas CSV/SQLite cleaning\nError: ${e.message}`;
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
        const risk = data.data?.risk_assessment || {};
        alertsBox.textContent = `🚨 Threat Level: ${threat.threat_level || threat.risk_level}\nRisk Score: ${risk.risk_score ?? 'n/a'}/100 | Confidence: ${risk.confidence_score ?? threat.confidence}\nIndicators: ${threat.indicators || threat.threat}\nHuman Validation Required: ${risk.requires_human_validation ?? false}\n\nDharma: ${data.data?.gita_guidance?.message || ''}\n\nResponse Gate: ${JSON.stringify(data.data?.response_recommendation || data.data?.automated_action || 'Monitoring', null, 2)}`;
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

// ---------------------------------------------------------------------------
// HIVE Intelligence (coordination layer)
// ---------------------------------------------------------------------------
async function loadCoordinator() {
    const panel = document.getElementById('hiveAgentHealth');
    if (panel) panel.innerHTML = '<small>⏳ Loading coordinator…</small>';
    try {
        const data = await apiFetch('/coordinator/dashboard');
        renderCoordinator(data);
    } catch (e) {
        if (panel) panel.innerHTML = `<small style="color:var(--red-team)">${escapeHtml(e.message)}</small>`;
    }
}

function renderCoordinator(data) {
    const t = data.totals || {};
    const set = (id, value) => { const el = document.getElementById(id); if (el) el.textContent = value; };
    set('hiveAgents', data.agents ? Object.keys(data.agents).length : '–');
    set('hiveIncidents', t.active_incidents ?? 0);
    set('hiveAnomalies', t.anomalies ?? 0);
    set('hiveCritical', t.critical_risks ?? 0);
    set('hiveAvgRisk', t.average_risk != null ? t.average_risk.toFixed(2) : '–');

    const health = document.getElementById('hiveAgentHealth');
    if (health && data.agents) {
        health.innerHTML = Object.entries(data.agents).map(([key, a]) => {
            const color = a.status === 'healthy' ? 'var(--soc-cyan)' : 'var(--red-team)';
            return `<div style="margin:3px 0;font-size:0.85em"><b style="color:${color}">●</b> ${escapeHtml(key)} <span class="badge">${escapeHtml(a.status)}</span> <span style="opacity:0.7">${a.events_processed} events, ${(a.average_latency_ms || 0).toFixed(1)}ms avg</span></div>`;
        }).join('');
    }

    const risk = document.getElementById('hiveRiskTimeline');
    if (risk) {
        risk.innerHTML = (data.risk_timeline || []).length
            ? data.risk_timeline.slice().reverse().map(r =>
                `<div style="font-size:0.8em;margin:2px 0">🕓 ${escapeHtml((r.timestamp || '').slice(11, 19))} — risk <b>${Number(r.risk_score).toFixed(2)}</b> (${escapeHtml(r.severity || '')}) on ${escapeHtml(r.entity || 'system')}</div>`
            ).join('')
            : '<small>No risk events recorded yet.</small>';
    }

    const factors = document.getElementById('hiveTopFactors');
    if (factors) {
        factors.innerHTML = (data.top_risk_factors || []).length
            ? data.top_risk_factors.map(([name, weight]) =>
                `<div style="font-size:0.85em;margin:2px 0">${escapeHtml(name)} <b>${Number(weight).toFixed(2)}</b></div>`
            ).join('')
            : '<small>No risk factors accumulated yet.</small>';
    }

    const models = document.getElementById('hiveModels');
    if (models) {
        models.innerHTML = (data.models || []).map(m =>
            `<div style="font-size:0.85em;margin:2px 0">🧮 <b>${escapeHtml(m.model_name)}</b> ${escapeHtml(m.model_version)} — ${escapeHtml(m.status)}</div>`
        ).join('') + `<div style="font-size:0.8em;margin-top:6px;opacity:0.8">data quality: ${data.data_quality?.seen_events ?? 0} seen, ${data.data_quality?.rejected_total ?? 0} rejected (recorded)</div>`;
    }

    const incidents = document.getElementById('hiveIncidentsList');
    if (incidents) {
        incidents.innerHTML = (data.incidents || []).length
            ? data.incidents.map(i => {
                const badge = i.status === 'awaiting_approval'
                    ? `<button style="margin-left:6px" onclick="coordinatorApprove('${escapeHtml(i.incident_id)}')">Approve</button><button style="margin-left:4px" onclick="coordinatorReject('${escapeHtml(i.incident_id)}')">Reject</button>`
                    : `<span class="badge" style="margin-left:6px">${escapeHtml(i.status)}</span>`;
                return `<div style="font-size:0.85em;margin:4px 0">🗂️ <b>${escapeHtml(i.incident_id)}</b> — ${escapeHtml(i.title)} ${badge}</div>`;
            }).join('')
            : '<small>No active incidents.</small>';
    }
}

async function runCoordinatorDemo() {
    const out = document.getElementById('hiveDemoOutput');
    if (!out) return;
    out.textContent = '⏳ Running labeled SIMULATION end-to-end scenario…';
    try {
        const res = await apiFetch('/coordinator/demo', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ approver: sessionStorage.getItem('vrindhaUser') || 'dashboard-human' }),
        });
        out.textContent = `[SIMULATION] status: ${res.status}\n` +
            `stages: ${res.stages.map(s => s.stage).join(' → ')}\n` +
            `incident: ${res.incident_id}\n` +
            `final: ${res.final_incident?.status} (approved by ${res.final_incident?.approved_by})\n` +
            `response: ${res.final_incident?.response_result?.message || 'none'}`;
        loadCoordinator();
    } catch (e) {
        out.textContent = `Demo failed: ${e.message} (admin role required for high-impact approval)`;
    }
}

async function coordinatorApprove(incidentId) {
    if (!window.confirm(`Approve the proposed defensive action for ${incidentId}?`)) return;
    try {
        const res = await apiFetch(`/commander/approve?incident_id=${encodeURIComponent(incidentId)}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                approver: sessionStorage.getItem('vrindhaUser') || 'dashboard-human',
                conclusion: 'confirmed_attack',
                justification: 'Approved from the HIVE Intelligence dashboard panel',
            }),
        });
        alert(`Approved: ${res.response_result?.message || res.status}`);
        loadCoordinator();
    } catch (e) { alert(`Approval failed: ${e.message}`); }
}

async function coordinatorReject(incidentId) {
    const reason = window.prompt(`Reject incident ${incidentId} — reason:`) || 'Rejected from dashboard';
    try {
        await apiFetch(`/commander/reject?incident_id=${encodeURIComponent(incidentId)}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ approver: sessionStorage.getItem('vrindhaUser') || 'dashboard-human', reason }),
        });
        loadCoordinator();
    } catch (e) { alert(`Reject failed: ${e.message}`); }
}

// Init
window.addEventListener('DOMContentLoaded', () => {
    loadStatus();
    loadLogs();
    loadGita();
    loadCharts();
    document.getElementById('commandInput').addEventListener('keypress', (e) => { if (e.key === 'Enter') sendCommand(); });
});
