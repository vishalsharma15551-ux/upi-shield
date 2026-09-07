/* ═══════════════════════════════════════════════════════
   UPI Shield — Frontend Logic
   ═══════════════════════════════════════════════════════ */

const API = '';  // Same origin

// ── Sample scam messages ─────────────────────────────

const SAMPLES = [
    {
        label: '⚡ Electricity Scam',
        text: 'URGENT: Your electricity connection will be disconnected within 2 hours due to pending bill of Rs 1500. Pay immediately to avoid disconnection. Contact: 9876543210. Click: bit.ly/pay-now-electric',
    },
    {
        label: '🏦 KYC Phishing',
        text: 'Dear Customer, Your SBI account has been blocked due to KYC not updated. Click here to update KYC immediately: http://sbi-kyc-update.in. Share OTP sent to your number to verify your account.',
    },
    {
        label: '🎰 Lottery Fraud',
        text: 'Congratulations! You have won Rs 25,00,000 in KBC Season 15 lottery! To claim your prize money, pay processing fee of Rs 5000 via UPI. Send to: kbc.prize@okaxis. Offer expires today only!',
    },
    {
        label: '👮 Cyber Crime Threat',
        text: 'This is from Cyber Crime Branch, Delhi Police. An FIR has been filed against your Aadhaar number for money laundering. Pay fine of Rs 50000 immediately to avoid arrest. Case number: CC/2024/8834.',
    },
    {
        label: '💸 Verification Refund',
        text: 'Your recent transaction of Rs 12000 failed. A verification refund of Rs 11999 has been initiated. To receive refund, share your UPI PIN and OTP sent to your registered mobile number immediately.',
    },
    {
        label: '✅ Legitimate Message',
        text: 'Your order #ORD-78345 has been shipped via Delhivery. Track your package at amazon.in/track. Expected delivery: September 8. Thank you for shopping with us!',
    },
];

// ── DOM references ───────────────────────────────────

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

const dom = {
    messageInput: $('#message-input'),
    charCount: $('#char-count'),
    btnClear: $('#btn-clear'),
    btnAnalyze: $('#btn-analyze'),
    btnText: $('#btn-analyze .btn-text'),
    btnLoader: $('#btn-analyze .btn-loader'),
    sourceTabs: $$('#source-tabs .tab'),
    sampleChips: $('#sample-chips'),
    upiInput: $('#upi-input'),
    btnUpi: $('#btn-upi'),
    upiResult: $('#upi-result'),
    placeholder: $('#results-placeholder'),
    resultsContent: $('#results-content'),
    meterFill: $('#meter-fill'),
    threatScore: $('#threat-score'),
    threatLabel: $('#threat-label'),
    modelInfo: $('#model-info'),
    categoryBars: $('#category-bars'),
    explanationsList: $('#explanations-list'),
    safetyCards: $('#safety-cards'),
    indicatorsGrid: $('#indicators-grid'),
    meterCard: $('#threat-meter-card'),
    modelBadge: $('#model-badge'),
    modelStatusText: $('#model-status-text'),
    badgeDot: $('#model-badge .badge-dot'),
};

let currentSource = 'sms';

// ── Initialization ───────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    renderSampleChips();
    bindEvents();
    checkHealth();
});

function renderSampleChips() {
    dom.sampleChips.innerHTML = SAMPLES.map((s, i) =>
        `<button class="sample-chip" data-idx="${i}">${s.label}</button>`
    ).join('');
}

function bindEvents() {
    // Character count
    dom.messageInput.addEventListener('input', () => {
        dom.charCount.textContent = `${dom.messageInput.value.length} chars`;
    });

    // Clear
    dom.btnClear.addEventListener('click', () => {
        dom.messageInput.value = '';
        dom.charCount.textContent = '0 chars';
        dom.messageInput.focus();
    });

    // Source tabs
    dom.sourceTabs.forEach(tab => {
        tab.addEventListener('click', () => {
            dom.sourceTabs.forEach(t => t.classList.remove('active'));
            tab.classList.add('active');
            currentSource = tab.dataset.source;
        });
    });

    // Sample chips
    dom.sampleChips.addEventListener('click', (e) => {
        const chip = e.target.closest('.sample-chip');
        if (!chip) return;
        const idx = parseInt(chip.dataset.idx);
        dom.messageInput.value = SAMPLES[idx].text;
        dom.charCount.textContent = `${SAMPLES[idx].text.length} chars`;
    });

    // Analyze
    dom.btnAnalyze.addEventListener('click', analyzeMessage);

    // Keyboard shortcut: Ctrl+Enter
    dom.messageInput.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') analyzeMessage();
    });

    // UPI parser
    dom.btnUpi.addEventListener('click', parseUPI);
    dom.upiInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') parseUPI();
    });
}

// ── Health Check ─────────────────────────────────────

async function checkHealth() {
    try {
        const res = await fetch(`${API}/api/health`);
        const data = await res.json();
        if (data.model_loaded) {
            dom.modelStatusText.textContent = 'AI Model Active';
            dom.badgeDot.classList.add('active');
        } else if (data.model_loading) {
            dom.modelStatusText.textContent = 'Model Loading…';
        } else {
            dom.modelStatusText.textContent = data.mode || 'Pattern Mode';
            dom.badgeDot.classList.add('active');
        }
    } catch {
        dom.modelStatusText.textContent = 'Connecting…';
        setTimeout(checkHealth, 3000);
    }
}

// ── Analyze Message ──────────────────────────────────

async function analyzeMessage() {
    const text = dom.messageInput.value.trim();
    if (!text) {
        dom.messageInput.focus();
        return;
    }

    setLoading(true);

    try {
        const res = await fetch(`${API}/api/analyze`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ text, source: currentSource }),
        });

        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        renderResults(data);
    } catch (err) {
        console.error('Analysis failed:', err);
        alert('Analysis failed. Is the server running?');
    } finally {
        setLoading(false);
    }
}

function setLoading(on) {
    dom.btnAnalyze.disabled = on;
    dom.btnText.hidden = on;
    dom.btnLoader.hidden = !on;
}

// ── Render Results ───────────────────────────────────

function renderResults(data) {
    dom.placeholder.hidden = true;
    dom.resultsContent.hidden = false;

    renderThreatMeter(data.threat_score, data.threat_level);
    renderCategories(data.category_scores);
    renderExplanations(data.explanations);
    renderSafetyCards(data.safety_cards);
    renderIndicators(data.indicators);
    dom.modelInfo.textContent = `Engine: ${data.model_used}`;
}

// ── Threat Meter ─────────────────────────────────────

function renderThreatMeter(score, level) {
    const circumference = 2 * Math.PI * 85; // ~534
    const offset = circumference - (score / 100) * circumference;

    const colorMap = {
        LOW: 'var(--success)',
        MEDIUM: 'var(--warning)',
        HIGH: 'var(--danger)',
        CRITICAL: 'var(--critical)',
    };
    const classMap = {
        LOW: 'threat-low', MEDIUM: 'threat-medium',
        HIGH: 'threat-high', CRITICAL: 'threat-critical',
    };

    dom.meterFill.style.strokeDashoffset = offset;
    dom.meterFill.style.stroke = colorMap[level] || colorMap.LOW;
    dom.meterFill.style.filter = `drop-shadow(0 0 10px ${colorMap[level]})`;

    // Animate score number
    animateValue(dom.threatScore, 0, score, 800);
    dom.threatLabel.textContent = level;
    dom.threatLabel.style.color = colorMap[level];
    dom.threatScore.style.color = colorMap[level];

    // Card border glow
    dom.meterCard.className = `threat-meter-card ${classMap[level] || ''}`;
}

function animateValue(el, start, end, duration) {
    const range = end - start;
    const startTime = performance.now();

    function step(ts) {
        const elapsed = ts - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
        el.textContent = Math.round(start + range * eased);
        if (progress < 1) requestAnimationFrame(step);
    }

    requestAnimationFrame(step);
}

// ── Category Bars ────────────────────────────────────

const CATEGORY_LABELS = {
    financial_fraud: { name: 'Financial Fraud', color: 'var(--danger)' },
    urgency_threat: { name: 'Urgency Tactics', color: '#f97316' },
    authority_impersonation: { name: 'Authority Claims', color: '#a78bfa' },
    phishing: { name: 'Information Theft', color: 'var(--warning)' },
    coercion: { name: 'Coercion / Threats', color: '#f472b6' },
};

function renderCategories(scores) {
    if (!scores || Object.keys(scores).length === 0) {
        dom.categoryBars.innerHTML = '<p style="color:var(--text-muted);font-size:0.8rem">No categories scored.</p>';
        return;
    }

    dom.categoryBars.innerHTML = Object.entries(CATEGORY_LABELS).map(([key, meta]) => {
        const val = scores[key] || 0;
        return `
            <div class="category-bar">
                <div class="category-bar-header">
                    <span class="category-bar-name">${meta.name}</span>
                    <span class="category-bar-value" style="color:${meta.color}">${val}%</span>
                </div>
                <div class="category-bar-track">
                    <div class="category-bar-fill" style="background:${meta.color};width:0%" data-width="${val}%"></div>
                </div>
            </div>`;
    }).join('');

    // Animate bars
    requestAnimationFrame(() => {
        dom.categoryBars.querySelectorAll('.category-bar-fill').forEach(bar => {
            bar.style.width = bar.dataset.width;
        });
    });
}

// ── Explanations ─────────────────────────────────────

function renderExplanations(explanations) {
    if (!explanations || explanations.length === 0) {
        dom.explanationsList.innerHTML = '';
        return;
    }

    dom.explanationsList.innerHTML = explanations.map((e, i) => `
        <div class="explanation-item severity-${e.severity}" style="animation-delay:${i * 0.1}s">
            <div class="explanation-category">${e.category}</div>
            <div class="explanation-category-hi">${e.category_hi}</div>
            <div class="explanation-desc">${e.description}</div>
            <div class="explanation-desc-hi">${e.description_hi}</div>
        </div>
    `).join('');
}

// ── Safety Cards ─────────────────────────────────────

function renderSafetyCards(cards) {
    if (!cards || cards.length === 0) {
        dom.safetyCards.innerHTML = '';
        return;
    }

    dom.safetyCards.innerHTML = cards.map((c, i) => {
        const isSafe = c.type === 'safe';
        return `
            <div class="safety-card ${isSafe ? 'safe' : ''}" style="animation-delay:${i * 0.12}s">
                <div class="safety-card-header">
                    <span class="safety-icon">${c.icon}</span>
                    <span class="safety-type">${c.type.replace(/_/g, ' ')}</span>
                </div>
                <div class="safety-text-en">${c.en}</div>
                <div class="safety-text-hi">${c.hi}</div>
            </div>`;
    }).join('');
}

// ── Indicators ───────────────────────────────────────

function renderIndicators(indicators) {
    if (!indicators || indicators.length === 0) {
        dom.indicatorsGrid.innerHTML = '<span style="color:var(--text-muted);font-size:0.8rem">No indicators detected.</span>';
        return;
    }

    dom.indicatorsGrid.innerHTML = indicators.map((ind, i) =>
        `<span class="indicator-tag cat-${ind.category}" style="animation-delay:${i * 0.05}s">
            ${ind.term}
            <span class="indicator-weight">${ind.weight}</span>
        </span>`
    ).join('');
}

// ── UPI Parser ───────────────────────────────────────

async function parseUPI() {
    const upiStr = dom.upiInput.value.trim();
    if (!upiStr) { dom.upiInput.focus(); return; }

    try {
        const res = await fetch(`${API}/api/parse-upi`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ upi_string: upiStr }),
        });

        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        const data = await res.json();
        renderUPIResult(data);
    } catch (err) {
        console.error('UPI parse failed:', err);
        dom.upiResult.hidden = false;
        dom.upiResult.innerHTML = `<div class="upi-warning">⚠️ Failed to parse. Is the server running?</div>`;
    }
}

function renderUPIResult(data) {
    dom.upiResult.hidden = false;

    const fieldLabels = {
        pa: 'Payee Address', pn: 'Payee Name', am: 'Amount',
        cu: 'Currency', tn: 'Transaction Note', tr: 'Reference',
        mc: 'Merchant Code', mode: 'Payment Mode',
    };

    let html = '';

    if (data.parsed && Object.keys(data.parsed).length > 0) {
        html += Object.entries(data.parsed).map(([k, v]) =>
            `<div class="upi-field">
                <span class="upi-field-key">${fieldLabels[k] || k}</span>
                <span class="upi-field-val">${v}</span>
            </div>`
        ).join('');
    }

    if (data.warnings && data.warnings.length > 0) {
        html += data.warnings.map(w => {
            const cls = w.en.toLowerCase().includes('no suspicious') ? 'upi-safe' : '';
            return `<div class="upi-warning ${cls}">
                <span>${cls ? '✅' : '⚠️'}</span>
                <div>
                    <div>${w.en}</div>
                    <div style="font-style:italic;opacity:0.8;margin-top:2px">${w.hi}</div>
                </div>
            </div>`;
        }).join('');
    }

    if (data.risk_score > 0) {
        html += `<div style="text-align:right;margin-top:0.5rem;font-size:0.75rem;color:var(--danger)">
            Risk Score: ${data.risk_score}/100
        </div>`;
    }

    dom.upiResult.innerHTML = html;
}
