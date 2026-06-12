/* ══════════════════════════════════════════════════════════
   Secure Agent Runtime — Dashboard Controller
   Vanilla JS, no build step. All rendering is textContent-based
   (XSS-safe); server data is never injected as HTML.
   ══════════════════════════════════════════════════════════ */

let lastEventId = -1;
const POLL_INTERVAL = 500;
const POLL_BACKOFF_MAX = 5000;
const MAX_TRACE_ENTRIES = 200;
const MAX_ALERT_ITEMS = 100;

let pollDelay = POLL_INTERVAL;
let isPaused = false;
let activeAlertFilter = 'all';
let searchQuery = '';
let processedEvents = 0;
let blockedEvents = 0;
let latencySamples = [];

/* ── DOM references ──────────────────────────────────────── */
const sidebarTrustScore = document.getElementById('sidebar-trust-score');
const metricTrustScore = document.getElementById('metric-trust-score');
const trustProgress = document.getElementById('trust-progress');
const trustTierBadge = document.getElementById('trust-tier-badge');
const trustMeter = document.getElementById('trust-meter');
const trustLiveBadge = document.getElementById('trust-live-badge');
const graphStatus = document.getElementById('graph-status');
const currentSession = document.getElementById('current-session');
const graphTraceContainer = document.getElementById('graph-trace-container');
const securityFeed = document.getElementById('security-feed');
const provenanceFeed = document.getElementById('provenance-feed');
const attackForm = document.getElementById('attack-form');
const attackInput = document.getElementById('attack-input');
const executeBtn = document.getElementById('execute-btn');
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
const connectionDetailEl = document.getElementById('connection-detail');
const filterStateEl = document.getElementById('filter-state');
const filterInput = document.getElementById('event-filter');
const pauseToggle = document.getElementById('pause-toggle');
const clearFeedButton = document.getElementById('clear-feed');
const refreshProvenanceButton = document.getElementById('refresh-provenance');
const copySessionButton = document.getElementById('copy-session');
const autoPollingBadge = document.getElementById('auto-polling-badge');
const statusIndicator = document.querySelector('.status-indicator');
const alertPulse = document.getElementById('alert-pulse');

function refreshIcons() {
    window.lucide?.createIcons();
}

/* ══════════════════════════════════════════════════════════
   TOAST NOTIFICATION SYSTEM
   ══════════════════════════════════════════════════════════ */
const TOAST_ICONS = {
    info: 'info',
    success: 'check-circle-2',
    warning: 'alert-triangle',
    error: 'x-circle',
};

function showToast(message, type = 'info', duration = 3500) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;

    const icon = document.createElement('i');
    icon.setAttribute('data-lucide', TOAST_ICONS[type] || TOAST_ICONS.info);
    icon.setAttribute('aria-hidden', 'true');

    const text = document.createElement('span');
    text.textContent = message;

    toast.appendChild(icon);
    toast.appendChild(text);
    container.appendChild(toast);
    refreshIcons();

    const dismiss = () => {
        if (toast.classList.contains('fade-out')) return;
        toast.classList.add('fade-out');
        toast.addEventListener('animationend', () => toast.remove(), { once: true });
        // Fallback removal in case animations are disabled (reduced motion)
        setTimeout(() => toast.remove(), 400);
    };

    toast.addEventListener('click', dismiss);
    setTimeout(dismiss, duration);
}

/* ══════════════════════════════════════════════════════════
   CONNECTION STATE MACHINE
   Only touches the DOM when the state actually changes, so the
   label doesn't flicker on every poll cycle.
   ══════════════════════════════════════════════════════════ */
let connectionState = null;

function setConnectionState(state, label) {
    if (state === connectionState && connectionStateEl?.textContent === label) return;
    connectionState = state;

    if (connectionStateEl) connectionStateEl.textContent = label;
    if (statusIndicator) statusIndicator.dataset.state = state;
    if (connectionDetailEl) connectionDetailEl.textContent = label;
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

function recordLatency(ms) {
    const value = Math.max(0, Math.round(ms || 0));
    latencySamples.push(value);
    if (latencySamples.length > 50) latencySamples.shift();

    if (processingTimeEl) processingTimeEl.textContent = `${value}ms`;

    if (latencyVal) {
        const avg = Math.round(latencySamples.reduce((a, b) => a + b, 0) / latencySamples.length);
        latencyVal.textContent = `${avg}ms avg (${latencySamples.length} run${latencySamples.length === 1 ? '' : 's'})`;
    }
}

/* ══════════════════════════════════════════════════════════
   TRUST METER
   ══════════════════════════════════════════════════════════ */
function updateTrustMeter(score, tier) {
    const safeScore = Number.isFinite(score) ? Math.min(1, Math.max(0, score)) : 0;
    const formattedScore = safeScore.toFixed(2);
    const safeTier = String(tier || 'HIGH').toUpperCase();

    if (sidebarTrustScore) sidebarTrustScore.textContent = formattedScore;
    if (metricTrustScore) metricTrustScore.textContent = formattedScore;
    if (trustMeter) trustMeter.setAttribute('aria-valuenow', formattedScore);

    if (trustProgress) {
        trustProgress.style.strokeDashoffset = 283 - (safeScore * 283);
        const strokeByTier = {
            HIGH: 'var(--accent-green)',
            MEDIUM: 'var(--accent-orange)',
            LOW: 'var(--accent-red)',
        };
        trustProgress.style.stroke = strokeByTier[safeTier] || strokeByTier.LOW;
    }

    if (trustTierBadge) {
        trustTierBadge.textContent = `TIER: ${safeTier}`;
        trustTierBadge.dataset.tier = ['HIGH', 'MEDIUM'].includes(safeTier) ? safeTier.toLowerCase() : 'low';
    }
}

/* ══════════════════════════════════════════════════════════
   GRAPH STATUS
   ══════════════════════════════════════════════════════════ */
function setGraphState(state) {
    const label = state.toUpperCase();
    if (graphStatus) {
        graphStatus.textContent = label;
        graphStatus.dataset.state = state;
    }
    if (graphBadge) {
        graphBadge.textContent = label;
        graphBadge.dataset.state = state;
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

    while (graphTraceContainer.children.length > MAX_TRACE_ENTRIES) {
        graphTraceContainer.firstChild.remove();
    }

    graphTraceContainer.scrollTop = graphTraceContainer.scrollHeight;
}

/* ══════════════════════════════════════════════════════════
   SECURITY ALERT ITEMS
   ══════════════════════════════════════════════════════════ */
function severityClass(severity) {
    const s = String(severity || 'CRITICAL').toUpperCase();
    if (s === 'WARNING') return 'warning';
    if (s === 'INFO') return 'info';
    return 'critical';
}

function renderAlertItem(phase, agent, message, severity) {
    const sev = severityClass(severity);
    const alertItem = document.createElement('div');
    // 'critical' uses the base red styling; warning/info get modifier classes
    alertItem.className = `alert-item${sev !== 'critical' ? ` ${sev}` : ''}`;
    alertItem.dataset.severity = sev;
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

function updateFilterPillCounts() {
    const items = Array.from(document.querySelectorAll('.alert-item'));
    document.querySelectorAll('.filter-pill').forEach((pill) => {
        const filter = pill.dataset.filter || 'all';
        const count = filter === 'all'
            ? items.length
            : items.filter((item) => item.dataset.severity === filter).length;

        let countEl = pill.querySelector('.pill-count');
        if (count === 0) {
            countEl?.remove();
            return;
        }
        if (!countEl) {
            countEl = document.createElement('span');
            countEl.className = 'pill-count';
            pill.appendChild(countEl);
        }
        countEl.textContent = String(count);
    });
}

function applyAlertFilters() {
    document.querySelectorAll('.alert-item').forEach((item) => {
        const matchesFilter = activeAlertFilter === 'all' || item.dataset.severity === activeAlertFilter;
        const matchesSearch = !searchQuery || (item.dataset.search || '').includes(searchQuery);
        item.classList.toggle('hidden', !(matchesFilter && matchesSearch));
    });
    updateFilterPillCounts();
}

function showFeedEmptyState() {
    if (!securityFeed) return;
    const emptyState = document.createElement('div');
    emptyState.className = 'empty-state';

    const icon = document.createElement('i');
    icon.setAttribute('data-lucide', 'check-circle-2');
    icon.setAttribute('aria-hidden', 'true');
    const text = document.createElement('p');
    text.textContent = 'No active threats detected.';

    emptyState.appendChild(icon);
    emptyState.appendChild(text);
    securityFeed.appendChild(emptyState);
    refreshIcons();
}

function addSecurityAlert(phase, agent, message, severity) {
    if (!securityFeed) return;
    securityFeed.querySelector('.empty-state')?.remove();

    const alertItem = renderAlertItem(phase, agent, message, severity);
    securityFeed.prepend(alertItem);

    while (securityFeed.querySelectorAll('.alert-item').length > MAX_ALERT_ITEMS) {
        securityFeed.querySelector('.alert-item:last-of-type')?.remove();
    }

    alertPulse?.classList.add('armed');
    applyAlertFilters();
}

/* ══════════════════════════════════════════════════════════
   NODE GRAPH ACTIVATION
   ══════════════════════════════════════════════════════════ */
function clearNodeActivation() {
    document.querySelectorAll('.node').forEach((n) => n.classList.remove('active'));
    document.querySelectorAll('.edge').forEach((e) => e.classList.remove('active'));
}

function setNodeActive(nodeName) {
    clearNodeActivation();

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
function showProvenanceSkeleton() {
    if (!provenanceFeed || provenanceFeed.querySelector('.provenance-entry')) return;
    provenanceFeed.innerHTML = '';
    for (let i = 0; i < 3; i += 1) {
        const row = document.createElement('div');
        row.className = 'skeleton-row';
        provenanceFeed.appendChild(row);
    }
}

function renderProvenance(records) {
    if (!provenanceFeed) return;
    provenanceFeed.innerHTML = '';

    if (!records || records.length === 0) {
        const emptyState = document.createElement('div');
        emptyState.className = 'empty-state compact';

        const icon = document.createElement('i');
        icon.setAttribute('data-lucide', 'sparkles');
        icon.setAttribute('aria-hidden', 'true');
        const text = document.createElement('p');
        text.textContent = 'Run a request to inspect provenance lineage.';

        emptyState.appendChild(icon);
        emptyState.appendChild(text);
        provenanceFeed.appendChild(emptyState);
        refreshIcons();
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
            setGraphState('executing');
            if (currentSession) currentSession.textContent = data.session_id || currentSession.textContent;
            if (graphTraceContainer) graphTraceContainer.innerHTML = '';
            addTrace(`Input: "${data.input || ''}"`);
            loadProvenance(currentSession?.textContent?.trim());
            break;

        case 'GRAPH_END':
            setGraphState('completed');
            addTrace('Graph execution finished.');
            loadProvenance(currentSession?.textContent?.trim());
            setTimeout(clearNodeActivation, 1000);
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
   EVENT POLLING (with backoff on failure)
   ══════════════════════════════════════════════════════════ */
async function pollEvents() {
    if (isPaused) {
        setTimeout(pollEvents, POLL_INTERVAL);
        return;
    }

    try {
        const response = await fetch(`/api/events?since_id=${lastEventId}`);
        if (response.ok) {
            const payload = await response.json();
            for (const event of payload.events || []) {
                processEvent(event);
                lastEventId = Math.max(lastEventId, event.id);
            }
            pollDelay = POLL_INTERVAL;
            setConnectionState('live', 'Backend connected');
        } else {
            pollDelay = Math.min(pollDelay * 2, POLL_BACKOFF_MAX);
            setConnectionState('degraded', `Event stream degraded (HTTP ${response.status})`);
        }
    } catch (error) {
        pollDelay = Math.min(pollDelay * 2, POLL_BACKOFF_MAX);
        setConnectionState('error', 'Backend unreachable — retrying');
    }

    setTimeout(pollEvents, pollDelay);
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
   The input is only cleared after a successful run, so a failed
   request never destroys what the user typed.
   ══════════════════════════════════════════════════════════ */
attackForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    const input = attackInput?.value?.trim();
    if (!input) return;

    executeBtn?.classList.add('loading');
    if (executeBtn) executeBtn.disabled = true;

    const sessionId = `dash_session_${Date.now()}`;

    try {
        const response = await fetch(`/run-travel-graph?user_input=${encodeURIComponent(input)}&session_id=${encodeURIComponent(sessionId)}`, {
            method: 'POST'
        });

        if (response.ok) {
            const result = await response.json();
            if (Number.isFinite(result.processing_time_ms)) {
                recordLatency(result.processing_time_ms);
            }
            if (Number.isFinite(result.trust_score)) {
                updateTrustMeter(result.trust_score, result.trust_tier || 'HIGH');
            }
            if (attackInput) attackInput.value = '';
            showToast(
                result.security_blocked ? 'Payload intercepted by the security layer' : 'Run completed',
                result.security_blocked ? 'warning' : 'success'
            );
        } else {
            showToast(`Server error: HTTP ${response.status}`, 'error');
        }
    } catch (error) {
        console.error('Failed to run graph', error);
        showToast('Backend unreachable — is the server running?', 'error');
    } finally {
        executeBtn?.classList.remove('loading');
        if (executeBtn) executeBtn.disabled = false;
    }
});

/* ══════════════════════════════════════════════════════════
   FILTER & SEARCH
   ══════════════════════════════════════════════════════════ */
const FILTER_LABELS = {
    all: 'All severities',
    critical: 'Critical only',
    warning: 'Warning only',
    info: 'Info only',
};

filterInput?.addEventListener('input', (event) => {
    searchQuery = String(event.target.value || '').toLowerCase();
    applyAlertFilters();
});

document.querySelectorAll('.filter-pill').forEach((pill) => {
    pill.addEventListener('click', () => {
        document.querySelectorAll('.filter-pill').forEach((button) => {
            button.classList.remove('active');
            button.setAttribute('aria-pressed', 'false');
        });
        pill.classList.add('active');
        pill.setAttribute('aria-pressed', 'true');
        activeAlertFilter = pill.dataset.filter || 'all';
        if (filterStateEl) filterStateEl.textContent = FILTER_LABELS[activeAlertFilter] || FILTER_LABELS.all;
        applyAlertFilters();
    });
});

/* ══════════════════════════════════════════════════════════
   TOOLBAR ACTIONS
   ══════════════════════════════════════════════════════════ */
function setToolbarButtonContent(button, iconName, label) {
    button.innerHTML = '';
    const icon = document.createElement('i');
    icon.setAttribute('data-lucide', iconName);
    icon.setAttribute('aria-hidden', 'true');
    const text = document.createElement('span');
    text.className = 'btn-label';
    text.textContent = label;
    button.appendChild(icon);
    button.appendChild(text);
    refreshIcons();
}

pauseToggle?.addEventListener('click', () => {
    isPaused = !isPaused;
    pauseToggle.setAttribute('aria-pressed', String(isPaused));
    setToolbarButtonContent(pauseToggle, isPaused ? 'play' : 'pause', isPaused ? 'Resume feed' : 'Pause feed');

    if (autoPollingBadge) {
        autoPollingBadge.textContent = isPaused ? 'Paused' : 'Auto-polling';
        autoPollingBadge.classList.toggle('paused', isPaused);
    }
    if (trustLiveBadge) {
        trustLiveBadge.textContent = isPaused ? 'Paused' : 'Live';
        trustLiveBadge.classList.toggle('paused', isPaused);
    }

    if (isPaused) {
        setConnectionState('paused', 'Feed paused by user');
    } else {
        pollDelay = POLL_INTERVAL;
        setConnectionState('live', 'Backend connected');
    }
});

clearFeedButton?.addEventListener('click', () => {
    if (!securityFeed) return;
    securityFeed.innerHTML = '';
    showFeedEmptyState();
    alertPulse?.classList.remove('armed');
    updateFilterPillCounts();
    showToast('Console cleared', 'info');
});

refreshProvenanceButton?.addEventListener('click', () => {
    showProvenanceSkeleton();
    loadProvenance(currentSession?.textContent?.trim());
});

copySessionButton?.addEventListener('click', async () => {
    try {
        await navigator.clipboard.writeText(currentSession?.textContent?.trim() || '');
        setToolbarButtonContent(copySessionButton, 'check', 'Copied!');
        setTimeout(() => setToolbarButtonContent(copySessionButton, 'copy', 'Copy'), 1200);
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
}

/* ══════════════════════════════════════════════════════════
   INITIALIZATION
   ══════════════════════════════════════════════════════════ */
refreshIcons();
attachQuickPromptButtons();
setConnectionState('degraded', 'Connecting…');
updateCounters();
loadProvenance(currentSession?.textContent?.trim() || 'default');
pollEvents();
setTimeout(updateLines, 200);
