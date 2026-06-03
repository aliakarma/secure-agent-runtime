let lastEventId = -1;
const POLL_INTERVAL = 500; // ms

// UI Elements
const trustScoreText = document.getElementById('trust-score-text');
const trustProgress = document.getElementById('trust-progress');
const trustTierBadge = document.getElementById('trust-tier-badge');
const graphStatus = document.getElementById('graph-status');
const currentSession = document.getElementById('current-session');
const graphTraceContainer = document.getElementById('graph-trace-container');
const securityFeed = document.getElementById('security-feed');
const attackForm = document.getElementById('attack-form');
const attackInput = document.getElementById('attack-input');

// Map trust score (0-1) to circle circumference (283 is full circle)
function updateTrustMeter(score, tier) {
    trustScoreText.innerText = score.toFixed(2);
    const offset = 283 - (score * 283);
    trustProgress.style.strokeDashoffset = offset;
    
    trustTierBadge.innerText = `TIER: ${tier}`;
    
    // Update colors based on tier
    if (tier === 'HIGH') {
        trustProgress.style.stroke = 'var(--accent-green)';
        trustTierBadge.style.color = 'var(--accent-green)';
        trustTierBadge.style.background = 'rgba(16, 185, 129, 0.2)';
        trustTierBadge.style.borderColor = 'rgba(16, 185, 129, 0.3)';
    } else if (tier === 'MEDIUM') {
        trustProgress.style.stroke = 'var(--accent-orange)';
        trustTierBadge.style.color = 'var(--accent-orange)';
        trustTierBadge.style.background = 'rgba(245, 158, 11, 0.2)';
        trustTierBadge.style.borderColor = 'rgba(245, 158, 11, 0.3)';
    } else {
        trustProgress.style.stroke = 'var(--accent-red)';
        trustTierBadge.style.color = 'var(--accent-red)';
        trustTierBadge.style.background = 'rgba(239, 68, 68, 0.2)';
        trustTierBadge.style.borderColor = 'rgba(239, 68, 68, 0.3)';
    }
}

function addTrace(message) {
    const entry = document.createElement('div');
    entry.className = 'trace-entry';
    entry.innerText = `> ${message}`;
    graphTraceContainer.appendChild(entry);
    graphTraceContainer.scrollTop = graphTraceContainer.scrollHeight;
}

function addSecurityAlert(phase, agent, message, severity) {
    // Remove empty state if present
    const emptyState = securityFeed.querySelector('.empty-state');
    if (emptyState) emptyState.remove();

    const alertItem = document.createElement('div');
    alertItem.className = `alert-item ${severity === 'WARNING' ? 'warning' : ''}`;
    
    const time = new Date().toLocaleTimeString();
    
    alertItem.innerHTML = `
        <div class="alert-item-header">
            <span class="alert-phase">PHASE ${phase} INTERCEPT (${agent})</span>
            <span class="alert-time">${time}</span>
        </div>
        <div class="alert-message">${message}</div>
    `;
    
    securityFeed.prepend(alertItem);
}

function setNodeActive(nodeName) {
    // Reset all nodes
    document.querySelectorAll('.node').forEach(n => n.classList.remove('active'));
    document.querySelectorAll('.edge').forEach(e => e.classList.remove('active'));
    
    const node = document.getElementById(`node-${nodeName}`);
    if (node) {
        node.classList.add('active');
    }
    
    // Animate edges
    if (nodeName === 'FlightAgent') {
        document.getElementById('edge-to-flight').classList.add('active');
    } else if (nodeName === 'HotelAgent') {
        document.getElementById('edge-to-hotel').classList.add('active');
    }
}

function processEvent(event) {
    console.log("Event:", event);
    const data = event.data;
    
    switch (event.type) {
        case 'GRAPH_START':
            graphStatus.innerText = 'EXECUTING';
            graphStatus.style.background = 'rgba(59, 130, 246, 0.2)';
            graphStatus.style.color = 'var(--accent-blue)';
            currentSession.innerText = data.session_id;
            graphTraceContainer.innerHTML = '';
            addTrace(`Input: "${data.input}"`);
            break;
            
        case 'GRAPH_END':
            graphStatus.innerText = 'COMPLETED';
            graphStatus.style.background = 'rgba(16, 185, 129, 0.2)';
            graphStatus.style.color = 'var(--accent-green)';
            addTrace('Graph execution finished.');
            // Reset nodes
            setTimeout(() => {
                document.querySelectorAll('.node').forEach(n => n.classList.remove('active'));
                document.querySelectorAll('.edge').forEach(e => e.classList.remove('active'));
            }, 1000);
            break;
            
        case 'TRUST_UPDATE':
            updateTrustMeter(data.score, data.tier);
            addTrace(`Trust updated to ${data.score.toFixed(2)} (${data.tier})`);
            break;
            
        case 'NODE_ACTIVE':
            setNodeActive(data.node);
            addTrace(`Node activated: ${data.node}`);
            break;
            
        case 'SECURITY_ALERT':
            addSecurityAlert(data.phase, data.agent, data.message, data.severity);
            addTrace(`SECURITY BLOCK: Phase ${data.phase}`);
            break;
    }
}

async function pollEvents() {
    try {
        const response = await fetch(`/api/events?since_id=${lastEventId}`);
        if (response.ok) {
            const data = await response.json();
            for (const event of data.events) {
                processEvent(event);
                lastEventId = Math.max(lastEventId, event.id);
            }
        }
    } catch (e) {
        console.error("Polling error", e);
    }
    setTimeout(pollEvents, POLL_INTERVAL);
}

// Form Submission
attackForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const input = attackInput.value;
    if (!input) return;
    
    attackInput.value = '';
    const sessionId = `dash_session_${Date.now()}`;
    
    try {
        await fetch(`/run-travel-graph?user_input=${encodeURIComponent(input)}&session_id=${sessionId}`, {
            method: 'POST'
        });
    } catch (e) {
        console.error("Failed to run graph", e);
    }
});

// Start Polling
pollEvents();
