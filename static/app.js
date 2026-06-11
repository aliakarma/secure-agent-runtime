/* ══════════════════════════════════════════════════════════
   Secure Agent Runtime — Dashboard Controller
   ══════════════════════════════════════════════════════════ */

let lastEventId = -1;
const POLL_INTERVAL = 500;

let isPaused = false;
let activeAlertFilter = 'all';
let searchQuery = '';
let processedEvents = 0;
let blockedEvents = 0;

/* ── DOM references ──────────────────────────────────────── */
const sidebarTrustScore = document.getElementById('sidebar-trust-score');
const metricTrustScore = document.getElementById('metric-trust-score');
const trustProgress = document.getElementById('trust-progress');
const trustTierBadge = document.getElementById('trust-tier-badge');
const graphStatus = document.getElementById('graph-status');
const currentSession = document.getElementById('current-session');
const graphTraceContainer = document.getElementById('graph-trace-container');
const securityFeed = document.getElementById('security-feed');
const provenanceFeed = document.getElementById('provenance-feed');
const attackForm = document.getElementById('attack-form');
const attackInput = document.getElementById('attack-input');
const eventCountEl = document.getElementById('event-count');
const blockedCountEl = document.getElementById('blocked-count');
const activeNodeEl = document.getElementById('active-node');
const lastUpdateEl = document.getElementById('last-update');
const alertVolumeEl = document.getElementById('alert-volume');
const provenanceCountEl = document.getElementById('provenance-count');
const processingTimeEl = document.getElementById('processing-time');
const graphBadge = document.getElementById('graph-badge');
const latencyVal = document.getElementById('latency-val');
const connectionStateEl = document.getElementById('connection-state');
const filterInput = document.getElementById('event-filter');
const pauseToggle = document.getElementById('pause-toggle');
const clearFeedButton = document.getElementById('clear-feed');
const refreshProvenanceButton = document.getElementById('refresh-provenance');
const copySessionButton = document.getElementById('copy-session');
const autoPollingBadge = document.getElementById('auto-polling-badge');
const pulseDot = document.querySelector('.pulse-dot');

/* ══════════════════════════════════════════════════════════
   TOAST NOTIFICATION SYSTEM
   ══════════════════════════════════════════════════════════ */
function showToast(message, type = 'info', duration = 3500) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);

    setTimeout(() => {
        toast.classList.add('fade-out');
        toast.addEventListener('animationend', () => toast.remove());
    }, duration);
}

/* ══════════════════════════════════════════════════════════
   CONNECTION STATE
   ══════════════════════════════════════════════════════════ */
function setConnectionState(state, label) {
    if (connectionStateEl) {
        connectionStateEl.textContent = label;
    }

    // Sync the pulse dot class
    if (pulseDot) {
        pulseDot.classList.remove('degraded', 'error');
        if (state === 'degraded') {
            pulseDot.classList.add('degraded');
        } else if (state === 'error') {
            pulseDot.classList.add('error');
        }
    }

    if (connectionStateEl) {
        if (state === 'live') {
            connectionStateEl.style.color = 'var(--accent-green)';
        } else if (state === 'degraded') {
            connectionStateEl.style.color = 'var(--accent-orange)';
        } else if (state === 'error') {
            connectionStateEl.style.color = 'var(--accent-red)';
        } else {
            connectionStateEl.style.color = 'var(--text-secondary)';
        }
    }
}

/* ══════════════════════════════════════════════════════════
   COUNTERS & METRICS
   ══════════════════════════════════════════════════════════ */
function updateCounters() {
    if (eventCountEl) eventCountEl.textContent = String(processedEvents);
    if (blockedCountEl) blockedCountEl.textContent = String(blockedEvents);
    if (alertVolumeEl) alertVolumeEl.textContent = String(blockedEvents);
    if (lastUpdateEl) lastUpdateEl.textContent = new Date().toLocaleTimeString();
}

function updateLatency(ms) {
    const rounded = Math.max(0, Math.round(ms || 0));
    if (processingTimeEl) processingTimeEl.textContent = `${rounded}ms`;
    if (latencyVal) latencyVal.textContent = `${rounded}ms avg`;
}

/* ══════════════════════════════════════════════════════════
   TRUST METER
   ══════════════════════════════════════════════════════════ */
function updateTrustMeter(score, tier) {
    const safeScore = Number.isFinite(score) ? score : 0;
    const formattedScore = safeScore.toFixed(2);

    if (sidebarTrustScore) sidebarTrustScore.textContent = formattedScore;
    if (metricTrustScore) metricTrustScore.textContent = formattedScore;

    if (trustProgress) {
        const offset = 283 - (safeScore * 283);
        trustProgress.style.strokeDashoffset = offset;
    }

    if (!trustTierBadge) return;

    trustTierBadge.textContent = `TIER: ${tier}`;

    if (tier === 'HIGH') {
        if (trustProgress) trustProgress.style.stroke = 'var(--accent-green)';
        trustTierBadge.style.color = 'var(--accent-green)';
        trustTierBadge.style.background = 'rgba(16, 185, 129, 0.15)';
        trustTierBadge.style.borderColor = 'rgba(16, 185, 129, 0.25)';
    } else if (tier === 'MEDIUM') {
        if (trustProgress) trustProgress.style.stroke = 'var(--accent-orange)';
        trustTierBadge.style.color = 'var(--accent-orange)';
        trustTierBadge.style.background = 'rgba(245, 158, 11, 0.15)';
        trustTierBadge.style.borderColor = 'rgba(245, 158, 11, 0.25)';
    } else {
        if (trustProgress) trustProgress.style.stroke = 'var(--accent-red)';
        trustTierBadge.style.color = 'var(--accent-red)';
        trustTierBadge.style.background = 'rgba(239, 68, 68, 0.15)';
        trustTierBadge.style.borderColor = 'rgba(239, 68, 68, 0.25)';
    }
}

/* ══════════════════════════════════════════════════════════
   GRAPH TRACE LOG
   ══════════════════════════════════════════════════════════ */
function addTrace(message) {
    if (!graphTraceContainer) return;
    const entry = document.createElement('div');
    entry.className = 'trace-entry';
    entry.textContent = `> ${message}`;
    graphTraceContainer.appendChild(entry);
    graphTraceContainer.scrollTop = graphTraceContainer.scrollHeight;
}

/* ══════════════════════════════════════════════════════════
   SECURITY ALERT ITEMS
   ══════════════════════════════════════════════════════════ */
function renderAlertItem(phase, agent, message, severity) {
    const alertItem = document.createElement('div');
    alertItem.className = `alert-item ${severity === 'WARNING' ? 'warning' : ''}`;
    alertItem.dataset.severity = String(severity || 'INFO').toLowerCase();
    alertItem.dataset.search = `${phase} ${agent} ${message} ${severity}`.toLowerCase();

    const header = document.createElement('div');
    header.className = 'alert-item-header';

    const phaseLabel = document.createElement('span');
    phaseLabel.className = 'alert-phase';
    phaseLabel.textContent = `PHASE ${phase} INTERCEPT (${agent})`;

    const time = document.createElement('span');
    time.className = 'alert-time';
    time.textContent = new Date().toLocaleTimeString();

    const body = document.createElement('div');
    body.className = 'alert-message';
    body.textContent = message;

    header.appendChild(phaseLabel);
    header.appendChild(time);
    alertItem.appendChild(header);
    alertItem.appendChild(body);
    return alertItem;
}

function applyAlertFilters() {
    document.querySelectorAll('.alert-item').forEach((item) => {
        const matchesFilter = activeAlertFilter === 'all' || item.dataset.severity === activeAlertFilter;
        const matchesSearch = !searchQuery || (item.dataset.search || '').includes(searchQuery);
        item.classList.toggle('hidden', !(matchesFilter && matchesSearch));
    });
}

function addSecurityAlert(phase, agent, message, severity) {
    const emptyState = securityFeed?.querySelector('.empty-state');
    if (emptyState) emptyState.remove();

    const alertItem = renderAlertItem(phase, agent, message, severity);
    securityFeed.prepend(alertItem);
    applyAlertFilters();
}

/* ══════════════════════════════════════════════════════════
   NODE GRAPH ACTIVATION
   ══════════════════════════════════════════════════════════ */
function setNodeActive(nodeName) {
    document.querySelectorAll('.node').forEach((n) => n.classList.remove('active'));
    document.querySelectorAll('.edge').forEach((e) => e.classList.remove('active'));

    const node = document.getElementById(`node-${nodeName}`);
    if (node) node.classList.add('active');

    if (nodeName === 'FlightAgent') {
        document.getElementById('edge-to-flight')?.classList.add('active');
    } else if (nodeName === 'HotelAgent') {
        document.getElementById('edge-to-hotel')?.classList.add('active');
    }

    if (activeNodeEl) activeNodeEl.textContent = nodeName || 'Idle';
    const insightNode = document.getElementById('insight-node');
    if (insightNode) insightNode.textContent = nodeName || 'Idle';
}

/* ══════════════════════════════════════════════════════════
   PROVENANCE RENDERING
   ══════════════════════════════════════════════════════════ */
function renderProvenance(records) {
    if (!provenanceFeed) return;
    provenanceFeed.innerHTML = '';

    if (!records || records.length === 0) {
        const emptyState = document.createElement('div');
        emptyState.className = 'empty-state compact';

        const icon = document.createElement('i');
        icon.setAttribute('data-lucide', 'sparkles');
        const text = document.createElement('p');
        text.textContent = 'Load the session to inspect provenance lineage.';

        emptyState.appendChild(icon);
        emptyState.appendChild(text);
        provenanceFeed.appendChild(emptyState);
        window.lucide?.createIcons();
        if (provenanceCountEl) provenanceCountEl.textContent = '0';
        return;
    }

    records.slice().reverse().forEach((record) => {
        const item = document.createElement('div');
        item.className = 'provenance-entry';

        const header = document.createElement('div');
        header.className = 'provenance-entry-header';

        const source = document.createElement('strong');
        source.textContent = record.source || 'unknown source';

        const tier = document.createElement('span');
        tier.className = `provenance-tier ${(record.trust_tier || '').toLowerCase()}`;
        tier.textContent = record.trust_tier || 'UNKNOWN';

        header.appendChild(source);
        header.appendChild(tier);

        const meta = document.createElement('div');
        meta.className = 'provenance-meta';
        meta.textContent = `${record.modality || 'n/a'} • trust ${Number(record.trust_score || 0).toFixed(2)} • ${new Date((record.timestamp || 0) * 1000).toLocaleString()}`;

        const sanitizers = document.createElement('div');
        sanitizers.className = 'provenance-sanitizers';
        sanitizers.textContent = `Sanitizers: ${(record.sanitizers || []).join(', ') || 'none'}`;

        item.appendChild(header);
        item.appendChild(meta);
        item.appendChild(sanitizers);
        provenanceFeed.appendChild(item);
    });

    if (provenanceCountEl) provenanceCountEl.textContent = String(records.length);
    window.lucide?.createIcons();
}

async function loadProvenance(sessionId = currentSession?.textContent?.trim() || 'default') {
    try {
        const response = await fetch(`/api/provenance?session_id=${encodeURIComponent(sessionId)}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        renderProvenance(data.provenance_lineage || []);
    } catch (error) {
        console.error('Failed to load provenance', error);
    }
}

/* ══════════════════════════════════════════════════════════
   EVENT PROCESSING
   ══════════════════════════════════════════════════════════ */
function processEvent(event) {
    const data = event.data || {};
    processedEvents += 1;

    switch (event.type) {
        case 'GRAPH_START':
            if (graphStatus) {
                graphStatus.textContent = 'EXECUTING';
                graphStatus.style.background = 'rgba(59, 130, 246, 0.16)';
                graphStatus.style.color = 'var(--accent-blue)';
            }
            if (graphBadge) graphBadge.textContent = 'EXECUTING';
            if (currentSession) currentSession.textContent = data.session_id || currentSession.textContent;
            if (graphTraceContainer) graphTraceContainer.innerHTML = '';
            addTrace(`Input: "${data.input || ''}"`);
            loadProvenance(currentSession?.textContent?.trim());
            break;

        case 'GRAPH_END':
            if (graphStatus) {
                graphStatus.textContent = 'COMPLETED';
                graphStatus.style.background = 'rgba(16, 185, 129, 0.16)';
                graphStatus.style.color = 'var(--accent-green)';
            }
            if (graphBadge) graphBadge.textContent = 'COMPLETED';
            addTrace('Graph execution finished.');
            loadProvenance(currentSession?.textContent?.trim());
            setTimeout(() => {
                document.querySelectorAll('.node').forEach((n) => n.classList.remove('active'));
                document.querySelectorAll('.edge').forEach((e) => e.classList.remove('active'));
            }, 1000);
            break;

        case 'TRUST_UPDATE':
            updateTrustMeter(data.score, data.tier);
            addTrace(`Trust updated to ${Number(data.score || 0).toFixed(2)} (${data.tier || 'UNKNOWN'})`);
            break;

        case 'NODE_ACTIVE':
            setNodeActive(data.node);
            addTrace(`Node activated: ${data.node}`);
            break;

        case 'SECURITY_ALERT':
            blockedEvents += 1;
            addSecurityAlert(data.phase, data.agent, data.message, data.severity);
            addTrace(`SECURITY BLOCK: Phase ${data.phase}`);
            break;

        default:
            break;
    }

    updateCounters();
}

/* ══════════════════════════════════════════════════════════
   EVENT POLLING
   ══════════════════════════════════════════════════════════ */
async function pollEvents() {
    if (isPaused) {
        setTimeout(pollEvents, POLL_INTERVAL);
        return;
    }

    try {
        setConnectionState('connecting', 'Polling live events');
        const response = await fetch(`/api/events?since_id=${lastEventId}`);
        if (response.ok) {
            const payload = await response.json();
            for (const event of payload.events || []) {
                processEvent(event);
                lastEventId = Math.max(lastEventId, event.id);
            }
            setConnectionState('live', 'Backend Connected');
        } else {
            setConnectionState('degraded', 'Event stream degraded');
        }
    } catch (error) {
        console.error('Polling error', error);
        setConnectionState('degraded', 'Connection unstable');
    }

    setTimeout(pollEvents, POLL_INTERVAL);
}

/* ══════════════════════════════════════════════════════════
   SVG EDGE LINE CALCULATION
   ══════════════════════════════════════════════════════════ */
function updateLines() {
    const sup = document.getElementById('node-Supervisor');
    const fli = document.getElementById('node-FlightAgent');
    const hot = document.getElementById('node-HotelAgent');
    const container = document.querySelector('.edges-container');

    if (!sup || !fli || !hot || !container) return;

    const supIcon = sup.querySelector('.node-icon');
    const fliIcon = fli.querySelector('.node-icon');
    const hotIcon = hot.querySelector('.node-icon');

    const containerRect = container.getBoundingClientRect();
    const supRect = supIcon.getBoundingClientRect();
    const fliRect = fliIcon.getBoundingClientRect();
    const hotRect = hotIcon.getBoundingClientRect();

    const startX = supRect.right - containerRect.left;
    const startY = supRect.top + (supRect.height / 2) - containerRect.top;

    const endXF = fliRect.left - containerRect.left - 5;
    const endYF = fliRect.top + (fliRect.height / 2) - containerRect.top;

    const endXH = hotRect.left - containerRect.left - 5;
    const endYH = hotRect.top + (hotRect.height / 2) - containerRect.top;

    const pathF = document.getElementById('edge-to-flight');
    const pathH = document.getElementById('edge-to-hotel');

    if (pathF) pathF.setAttribute('d', `M ${startX},${startY} C ${startX + 60},${startY} ${endXF - 60},${endYF} ${endXF},${endYF}`);
    if (pathH) pathH.setAttribute('d', `M ${startX},${startY} C ${startX + 60},${startY} ${endXH - 60},${endYH} ${endXH},${endYH}`);
}

/* ══════════════════════════════════════════════════════════
   QUICK PROMPT CHIPS
   ══════════════════════════════════════════════════════════ */
function attachQuickPromptButtons() {
    document.querySelectorAll('.quick-chip').forEach((button) => {
        button.addEventListener('click', () => {
            if (attackInput) attackInput.value = button.dataset.prompt || '';
            attackInput?.focus();
        });
    });
}

/* ══════════════════════════════════════════════════════════
   FORM SUBMISSION
   ══════════════════════════════════════════════════════════ */
attackForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const input = attackInput?.value?.trim();
    if (!input) return;

    attackInput.value = '';
    const submitButton = attackForm.querySelector('button[type="submit"]');
    if (submitButton) submitButton.disabled = true;

    const sessionId = `dash_session_${Date.now()}`;

    try {
        const response = await fetch(`/run-travel-graph?user_input=${encodeURIComponent(input)}&session_id=${encodeURIComponent(sessionId)}`, {
            method: 'POST'
        });

        if (response.ok) {
            const result = await response.json();
            if (Number.isFinite(result.processing_time_ms)) {
                updateLatency(result.processing_time_ms);
            }
            if (Number.isFinite(result.trust_score)) {
                updateTrustMeter(result.trust_score, result.trust_tier || 'HIGH');
            }
            showToast('Payload executed successfully', 'success');
        } else {
            showToast(`Server error: HTTP ${response.status}`, 'error');
        }
    } catch (error) {
        console.error('Failed to run graph', error);
        showToast('Backend unreachable — is the server running?', 'error');
    } finally {
        if (submitButton) submitButton.disabled = false;
    }
});



/* ══════════════════════════════════════════════════════════
   FILTER & SEARCH
   ══════════════════════════════════════════════════════════ */
filterInput?.addEventListener('input', (event) => {
    searchQuery = String(event.target.value || '').toLowerCase();
    applyAlertFilters();
});

document.querySelectorAll('.filter-pill').forEach((pill) => {
    pill.addEventListener('click', () => {
        document.querySelectorAll('.filter-pill').forEach((button) => button.classList.remove('active'));
        pill.classList.add('active');
        activeAlertFilter = pill.dataset.filter || 'all';
        applyAlertFilters();
    });
});

/* ══════════════════════════════════════════════════════════
   TOOLBAR ACTIONS
   ══════════════════════════════════════════════════════════ */
pauseToggle?.addEventListener('click', () => {
    isPaused = !isPaused;
    pauseToggle.innerHTML = isPaused
        ? '<i data-lucide="play"></i>Resume feed'
        : '<i data-lucide="pause"></i>Pause feed';
    window.lucide?.createIcons();

    // Sync auto-polling badge
    if (autoPollingBadge) {
        autoPollingBadge.textContent = isPaused ? 'Paused' : 'Auto-polling';
        autoPollingBadge.style.background = isPaused ? 'rgba(245, 158, 11, 0.14)' : '';
        autoPollingBadge.style.color = isPaused ? 'var(--accent-orange)' : '';
        autoPollingBadge.style.borderColor = isPaused ? 'rgba(245, 158, 11, 0.25)' : '';
    }

    setConnectionState(isPaused ? 'degraded' : 'live', isPaused ? 'Feed paused' : 'Backend Connected');
});

clearFeedButton?.addEventListener('click', () => {
    if (!securityFeed) return;
    securityFeed.innerHTML = '';
    const emptyState = document.createElement('div');
    emptyState.className = 'empty-state';

    const icon = document.createElement('i');
    icon.setAttribute('data-lucide', 'check-circle-2');
    const text = document.createElement('p');
    text.textContent = 'No active threats detected.';

    emptyState.appendChild(icon);
    emptyState.appendChild(text);
    securityFeed.appendChild(emptyState);
    window.lucide?.createIcons();
    showToast('Console cleared', 'info');
});

refreshProvenanceButton?.addEventListener('click', () => {
    loadProvenance(currentSession?.textContent?.trim());
    showToast('Provenance refreshed', 'info');
});

copySessionButton?.addEventListener('click', async () => {
    try {
        await navigator.clipboard.writeText(currentSession?.textContent?.trim() || '');
        copySessionButton.textContent = 'Copied!';
        showToast('Session ID copied to clipboard', 'success');
        setTimeout(() => {
            copySessionButton.innerHTML = '<i data-lucide="copy"></i>Copy';
            window.lucide?.createIcons();
        }, 1200);
    } catch (error) {
        console.error('Copy failed', error);
        showToast('Failed to copy — clipboard access denied', 'warning');
    }
});


/* ══════════════════════════════════════════════════════════
   EDGE RESIZE OBSERVER
   ══════════════════════════════════════════════════════════ */
const nodeSystem = document.querySelector('.node-system');
if (nodeSystem && window.ResizeObserver) {
    const observer = new ResizeObserver(() => updateLines());
    observer.observe(nodeSystem);
    setTimeout(updateLines, 200);
}

/* ══════════════════════════════════════════════════════════
   INITIALIZATION
   ══════════════════════════════════════════════════════════ */
attachQuickPromptButtons();
setConnectionState('connecting', 'Connecting to backend');
updateCounters();
updateLatency(0);
loadProvenance(currentSession?.textContent?.trim() || 'default');
pollEvents();
