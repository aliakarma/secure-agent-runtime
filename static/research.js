/* ══════════════════════════════════════════════════════════
   RESEARCH CONSOLE — publication-grade evaluation dashboard
   Vanilla JS, no build step. All data comes from real backend
   endpoints; charts are dependency-free inline SVG.
   ══════════════════════════════════════════════════════════ */
(function () {
    'use strict';

    /* ---------- auth-aware fetch (shares the app.js token key) ---------- */
    const API_TOKEN_KEY = 'sar_api_token';
    function token() { try { return localStorage.getItem(API_TOKEN_KEY) || ''; } catch { return ''; } }
    async function api(path) {
        const headers = {};
        const tk = token();
        if (tk) headers['Authorization'] = `Bearer ${tk}`;
        const r = await fetch(path, { headers });
        if (!r.ok) throw new Error(`${path} → HTTP ${r.status}`);
        return r.json();
    }

    /* ---------- tiny i18n (EN/AR), follows <html lang> ---------- */
    const STR = {
        en: {
            contributions: 'Contributions', threat: 'Threat Model', detector: 'Detector',
            curves: 'Detector PR / ROC / Calibration', adaptive: 'Adaptive Adversary',
            baselines: 'Defense Baselines', propagation: 'Cross-Agent Propagation',
            trust: 'Trust Engine', experiments: 'Experiment Results', provdag: 'Provenance DAG',
            forensics: 'Multimodal Forensics', repro: 'Reproducibility',
            precision: 'Precision', recall: 'Recall', f1: 'F1', fpr: 'FPR',
            plainFpr: 'Plain benign FPR', hardFpr: 'Hard-negative FPR',
            technique: 'Technique', defense: 'Defense', detection: 'Detection',
            benignFpr: 'Benign FPR', noData: 'No data yet — run the build command.',
            run: 'Run', active: 'Active backend', threshold: 'Threshold',
            weights: 'Weights', tiers: 'Tiers', formula: 'Formula',
            assets: 'Protected assets', adversary: 'Adversary', goals: 'Goals',
            boundaries: 'Trust boundaries', outScope: 'Out of scope',
            nodes: 'nodes', edges: 'edges', emptyDag: 'Run a request to populate the lineage DAG.',
            forensicsHint: 'Provide a sandboxed image path (uploads/ or datasets/) to run metadata + LSB steganalysis.',
            analyze: 'Analyze', metadata: 'Metadata', stego: 'Steganalysis',
            suspected: 'Suspected', clean: 'Clean', manifest: 'Manifest', benchmarks: 'Benchmarks',
            status: 'Status', implemented: 'implemented', optional: 'optional', pending: 'pending',
            asr: 'ASR', tar: 'Task Accuracy', effect: 'Effect size', pValue: 'p-value',
        },
        ar: {
            contributions: 'المساهمات', threat: 'نموذج التهديد', detector: 'الكاشف',
            curves: 'منحنيات الكاشف PR / ROC / المعايرة', adaptive: 'الخصم التكيفي',
            baselines: 'دفاعات مرجعية', propagation: 'الانتشار بين الوكلاء',
            trust: 'محرك الثقة', experiments: 'نتائج التجارب', provdag: 'رسم المنشأ',
            forensics: 'التحليل الجنائي متعدد الوسائط', repro: 'قابلية إعادة الإنتاج',
            precision: 'الدقة', recall: 'الاستدعاء', f1: 'F1', fpr: 'معدل الإيجابيات الخاطئة',
            plainFpr: 'FPR للأمثلة العادية', hardFpr: 'FPR للأمثلة الصعبة',
            technique: 'التقنية', defense: 'الدفاع', detection: 'الكشف',
            benignFpr: 'FPR الحميد', noData: 'لا توجد بيانات بعد — شغّل أمر البناء.',
            run: 'شغّل', active: 'الخلفية النشطة', threshold: 'العتبة',
            weights: 'الأوزان', tiers: 'المستويات', formula: 'الصيغة',
            assets: 'الأصول المحمية', adversary: 'الخصم', goals: 'الأهداف',
            boundaries: 'حدود الثقة', outScope: 'خارج النطاق',
            nodes: 'عُقد', edges: 'حواف', emptyDag: 'شغّل طلباً لملء رسم المنشأ.',
            forensicsHint: 'أدخل مسار صورة آمن لتشغيل تحليل البيانات الوصفية.',
            analyze: 'حلّل', metadata: 'بيانات وصفية', stego: 'تحليل الإخفاء',
            suspected: 'مشتبه', clean: 'نظيف', manifest: 'البيان', benchmarks: 'المعايير',
            status: 'الحالة', implemented: 'منفّذ', optional: 'اختياري', pending: 'معلّق',
            asr: 'معدل نجاح الهجوم', tar: 'دقة المهمة', effect: 'حجم الأثر', pValue: 'القيمة p',
        },
    };
    function lang() { return (document.documentElement.getAttribute('lang') === 'ar') ? 'ar' : 'en'; }
    function T(k) { return (STR[lang()] && STR[lang()][k]) || STR.en[k] || k; }

    /* ---------- safe DOM builder ---------- */
    function el(tag, props, kids) {
        const n = document.createElement(tag);
        if (props) for (const k in props) {
            if (k === 'class') n.className = props[k];
            else if (k === 'text') n.textContent = props[k];
            else if (k === 'html') n.innerHTML = props[k]; // only used with trusted SVG strings
            else n.setAttribute(k, props[k]);
        }
        (kids || []).forEach((c) => n.appendChild(typeof c === 'string' ? document.createTextNode(c) : c));
        return n;
    }
    function cssVar(name, fallback) {
        const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
        return v || fallback;
    }
    function header(panel, iconName, titleKey) {
        panel.appendChild(el('div', { class: 'card-header' }, [
            el('h3', {}, [el('i', { 'data-lucide': iconName, 'aria-hidden': 'true' }), ' ' + T(titleKey)]),
        ]));
    }
    function statRow(label, value, accent) {
        return el('div', { class: 'rv-stat' }, [
            el('span', { class: 'rv-stat-label', text: label }),
            el('strong', { class: 'rv-stat-value' + (accent ? ' ' + accent : ''), text: value }),
        ]);
    }
    function pct(x) { return (x == null) ? '—' : (x * 100).toFixed(1) + '%'; }
    function noData(panel, cmd) {
        const d = el('div', { class: 'rv-empty' }, [el('p', { text: T('noData') })]);
        if (cmd) d.appendChild(el('code', { class: 'rv-code', text: cmd }));
        panel.appendChild(d);
    }

    /* ---------- SVG charts (numeric data only → safe) ---------- */
    function lineChart(series, opts) {
        // series: [{points:[{x,y}], color, label}], axes 0..1
        const W = 320, H = 200, P = 34;
        const grid = cssVar('--border-subtle', 'rgba(148,163,184,.25)');
        const txt = cssVar('--text-secondary', '#94a3b8');
        const sx = (x) => P + x * (W - 2 * P);
        const sy = (y) => H - P - y * (H - 2 * P);
        let s = `<svg viewBox="0 0 ${W} ${H}" class="rv-chart" role="img" aria-label="${opts.aria || 'chart'}">`;
        // axes + gridlines
        for (let i = 0; i <= 4; i++) {
            const gy = sy(i / 4), gx = sx(i / 4);
            s += `<line x1="${P}" y1="${gy}" x2="${W - P}" y2="${gy}" stroke="${grid}" stroke-width="1"/>`;
            s += `<text x="${P - 6}" y="${gy + 3}" fill="${txt}" font-size="8" text-anchor="end">${(i / 4).toFixed(2)}</text>`;
            s += `<text x="${gx}" y="${H - P + 12}" fill="${txt}" font-size="8" text-anchor="middle">${(i / 4).toFixed(1)}</text>`;
        }
        s += `<text x="${W / 2}" y="${H - 4}" fill="${txt}" font-size="9" text-anchor="middle">${opts.xlabel || ''}</text>`;
        series.forEach((ser) => {
            const pts = ser.points.map((p) => `${sx(p.x).toFixed(1)},${sy(p.y).toFixed(1)}`).join(' ');
            s += `<polyline points="${pts}" fill="none" stroke="${ser.color}" stroke-width="2"/>`;
        });
        s += '</svg>';
        const wrap = el('div', { class: 'rv-chart-wrap' });
        wrap.innerHTML = s; // trusted: only numbers + our color vars
        const legend = el('div', { class: 'rv-legend' });
        series.forEach((ser) => legend.appendChild(el('span', { class: 'rv-legend-item' }, [
            el('i', { style: `background:${ser.color}` }), ser.label,
        ])));
        const c = el('div', {}, [el('div', { class: 'rv-chart-title', text: opts.title || '' }), wrap, legend]);
        return c;
    }
    function barChart(rows, opts) {
        // rows: [{label, value 0..1, color?}]
        const list = el('div', { class: 'rv-bars' });
        rows.forEach((r) => {
            const color = r.color || cssVar('--accent-blue', '#3b82f6');
            const bar = el('div', { class: 'rv-bar-row' }, [
                el('span', { class: 'rv-bar-label', text: r.label }),
                el('div', { class: 'rv-bar-track' }, [
                    el('div', { class: 'rv-bar-fill', style: `width:${Math.max(2, r.value * 100).toFixed(1)}%;background:${color}` }),
                ]),
                el('span', { class: 'rv-bar-val', text: opts && opts.raw ? String(r.value) : pct(r.value) }),
            ]);
            list.appendChild(bar);
        });
        return list;
    }

    /* ---------- panel renderers ---------- */
    async function renderContributions() {
        const p = document.getElementById('rv-contributions'); p.replaceChildren();
        header(p, 'award', 'contributions');
        try {
            const d = await api('/api/threat-model');
            const grid = el('div', { class: 'rv-contrib-grid' });
            (d.contributions || []).forEach((c) => {
                const badge = c.status === 'evaluated' ? 'ok' : 'warn';
                grid.appendChild(el('div', { class: 'rv-contrib' }, [
                    el('div', { class: 'rv-contrib-head' }, [
                        el('span', { class: 'rv-chip', text: c.id }),
                        el('span', { class: `rv-pill ${badge}`, text: c.status }),
                    ]),
                    el('p', { class: 'rv-contrib-claim', text: c.claim }),
                    el('p', { class: 'rv-contrib-ev', text: c.evidence }),
                ]));
            });
            p.appendChild(grid);
        } catch (e) { noData(p); }
    }

    async function renderThreat() {
        const p = document.getElementById('rv-threat'); p.replaceChildren();
        header(p, 'crosshair', 'threat');
        try {
            const { threat_model: tm } = await api('/api/threat-model');
            const block = (titleKey, items) => {
                const b = el('div', { class: 'rv-tm-block' }, [el('h4', { text: T(titleKey) })]);
                const ul = el('ul', { class: 'rv-list' });
                items.forEach((i) => ul.appendChild(el('li', { text: i })));
                b.appendChild(ul); return b;
            };
            p.appendChild(block('assets', tm.assets));
            p.appendChild(block('goals', tm.adversary.goals));
            p.appendChild(block('boundaries', tm.trust_boundaries));
            p.appendChild(block('outScope', tm.out_of_scope));
        } catch (e) { noData(p); }
    }

    async function renderDetector() {
        const p = document.getElementById('rv-detector'); p.replaceChildren();
        header(p, 'scan-search', 'detector');
        try {
            const d = await api('/api/detector');
            p.appendChild(statRow(T('active'), d.active_backend, 'mono'));
            p.appendChild(statRow(T('threshold'), String(d.threshold), 'mono'));
            const m = d.metrics;
            if (m && m.operating_point) {
                const op = m.operating_point;
                p.appendChild(statRow(T('precision'), pct(op.precision), 'ok'));
                p.appendChild(statRow(T('recall'), pct(op.recall), 'ok'));
                p.appendChild(statRow(T('f1'), pct(op.f1)));
                p.appendChild(statRow(T('plainFpr'), pct(op.plain_benign_fpr), op.plain_benign_fpr > 0.05 ? 'warn' : 'ok'));
                p.appendChild(statRow(T('hardFpr'), pct(op.hard_negative_fpr), op.hard_negative_fpr > 0.2 ? 'bad' : 'ok'));
            } else { noData(p, d.build_command); }
        } catch (e) { noData(p); }
    }

    async function renderDetectorCurves() {
        const p = document.getElementById('rv-detector-curves'); p.replaceChildren();
        header(p, 'line-chart', 'curves');
        try {
            const d = await api('/api/detector');
            const m = d.metrics;
            if (!m || !m.pr_curve) { noData(p, d && d.build_command); return; }
            const blue = cssVar('--accent-blue', '#3b82f6'), green = cssVar('--accent-green', '#22c55e'), violet = cssVar('--accent-violet', '#8b5cf6');
            p.appendChild(lineChart(
                [{ points: m.pr_curve.map((r) => ({ x: r.recall, y: r.precision })), color: blue, label: 'PR' }],
                { title: 'Precision–Recall', xlabel: T('recall'), aria: 'PR curve' }
            ));
            p.appendChild(lineChart(
                [{ points: m.roc_curve.map((r) => ({ x: r.fpr, y: r.tpr })), color: green, label: 'ROC' },
                 { points: [{ x: 0, y: 0 }, { x: 1, y: 1 }], color: cssVar('--border-subtle', '#475569'), label: 'chance' }],
                { title: 'ROC', xlabel: T('fpr'), aria: 'ROC curve' }
            ));
            if (m.calibration && m.calibration.length) {
                p.appendChild(lineChart(
                    [{ points: m.calibration.map((b) => ({ x: b.mean_pred, y: b.empirical })), color: violet, label: 'model' },
                     { points: [{ x: 0, y: 0 }, { x: 1, y: 1 }], color: cssVar('--border-subtle', '#475569'), label: 'ideal' }],
                    { title: 'Calibration', xlabel: 'predicted', aria: 'calibration' }
                ));
            }
        } catch (e) { noData(p); }
    }

    async function renderAdaptive() {
        const p = document.getElementById('rv-adaptive'); p.replaceChildren();
        header(p, 'shuffle', 'adaptive');
        try {
            const d = await api('/api/research/adaptive');
            const ar = d.adaptive_recall || {};
            const keys = Object.keys(ar);
            if (!keys.length) { noData(p, d.generate_command); return; }
            const red = cssVar('--accent-red', '#ef4444'), green = cssVar('--accent-green', '#22c55e');
            const rows = keys.map((k) => ({ label: k, value: ar[k].recall, color: ar[k].recall >= 0.9 ? green : red }));
            p.appendChild(el('p', { class: 'rv-sub', text: `${T('recall')} (n=${ar[keys[0]].n}/technique)` }));
            p.appendChild(barChart(rows));
        } catch (e) { noData(p); }
    }

    async function renderBaselines() {
        const p = document.getElementById('rv-baselines'); p.replaceChildren();
        header(p, 'shield-half', 'baselines');
        try {
            const d = await api('/api/research/baselines');
            const comp = d.comparison;
            if (comp && comp.rows) {
                p.appendChild(el('p', { class: 'rv-sub', text: comp.metric }));
                const table = el('table', { class: 'rv-table' });
                table.appendChild(el('thead', {}, [el('tr', {}, [
                    el('th', { text: T('defense') }), el('th', { text: T('detection') }),
                    el('th', { text: T('benignFpr') }), el('th', { text: T('hardFpr') }),
                ])]));
                const tb = el('tbody', {});
                comp.rows.forEach((r) => tb.appendChild(el('tr', {}, [
                    el('td', { text: r.defense }),
                    el('td', { class: 'mono', text: pct(r.attack_detection_rate) }),
                    el('td', { class: 'mono' + (r.benign_fpr > 0.1 ? ' bad' : ''), text: pct(r.benign_fpr) }),
                    el('td', { class: 'mono' + (r.hard_negative_fpr > 0.2 ? ' bad' : ''), text: pct(r.hard_negative_fpr) }),
                ])));
                table.appendChild(tb);
                p.appendChild(table);
            } else { noData(p, d.build_command); }
        } catch (e) { noData(p); }
    }

    async function renderPropagation() {
        const p = document.getElementById('rv-propagation'); p.replaceChildren();
        header(p, 'git-fork', 'propagation');
        try {
            const d = await api('/api/research/experiments');
            const prop = d.cross_agent_propagation;
            if (!prop) { noData(p, 'python scripts/evaluate_cross_agent_propagation.py'); return; }
            const red = cssVar('--accent-red', '#ef4444'), green = cssVar('--accent-green', '#22c55e');
            const configs = Object.keys(prop).filter((k) => prop[k] && typeof prop[k] === 'object' && 'asr_pct' in prop[k]);
            if (configs.length) {
                p.appendChild(el('p', { class: 'rv-sub', text: T('asr') + ' by configuration' }));
                const rows = configs.map((c) => ({
                    label: c, value: (prop[c].asr_pct || 0) / 100,
                    color: (prop[c].asr_pct || 0) > 20 ? red : green,
                }));
                p.appendChild(barChart(rows));
                configs.forEach((c) => {
                    const v = prop[c];
                    if (v.asr_ci_low_pct != null) {
                        p.appendChild(statRow(`${c} ${T('asr')} 95% CI`,
                            `${v.asr_pct}% [${v.asr_ci_low_pct}, ${v.asr_ci_high_pct}]`, 'mono'));
                    }
                });
            } else {
                Object.keys(prop).slice(0, 8).forEach((k) => {
                    const v = prop[k];
                    if (typeof v === 'number' || typeof v === 'string') p.appendChild(statRow(k, String(v)));
                });
            }
        } catch (e) { noData(p); }
    }

    async function renderTrust() {
        const p = document.getElementById('rv-trust'); p.replaceChildren();
        header(p, 'gauge', 'trust');
        try {
            const d = await api('/api/trust-model');
            p.appendChild(el('code', { class: 'rv-code', text: d.formula }));
            const w = d.weights;
            const rows = [
                { label: 'α source', value: w.alpha_source },
                { label: 'β policy', value: w.beta_policy },
                { label: 'γ history', value: w.gamma_history },
                { label: 'δ retrieval', value: w.delta_retrieval },
            ];
            p.appendChild(barChart(rows, { raw: false }));
            const tiers = el('div', { class: 'rv-tier-row' });
            Object.keys(d.tiers).forEach((k) => tiers.appendChild(el('span', { class: `rv-pill ${k.toLowerCase()}`, text: `${k} ${d.tiers[k]}` })));
            p.appendChild(tiers);
        } catch (e) { noData(p); }
    }

    async function renderExperiments() {
        const p = document.getElementById('rv-experiments'); p.replaceChildren();
        header(p, 'flask-conical', 'experiments');
        try {
            const d = await api('/api/research/experiments');
            const bs = d.baseline_vs_secured;
            const ss = d.statistical_significance;
            if (bs) {
                const find = (o, keys) => { for (const k of keys) if (o && o[k] != null) return o[k]; return null; };
                const baseAsr = find(bs, ['baseline_asr', 'baseline_attack_success_rate']);
                const secAsr = find(bs, ['secured_asr', 'secured_attack_success_rate']);
                if (baseAsr != null) p.appendChild(statRow('Baseline ' + T('asr'), typeof baseAsr === 'number' ? pct(baseAsr > 1 ? baseAsr / 100 : baseAsr) : String(baseAsr), 'bad'));
                if (secAsr != null) p.appendChild(statRow('Secured ' + T('asr'), typeof secAsr === 'number' ? pct(secAsr > 1 ? secAsr / 100 : secAsr) : String(secAsr), 'ok'));
            }
            if (ss && ss.effect_sizes) {
                p.appendChild(statRow(T('effect'), `${ss.effect_sizes.cohen_h} (${ss.effect_sizes.cohen_h_magnitude})`));
            }
            if (ss && ss.mcnemar_asr) {
                p.appendChild(statRow('McNemar ' + T('pValue'), Number(ss.mcnemar_asr.p_value).toExponential(2), 'mono'));
            }
            if (!bs && !ss) noData(p, 'python scripts/run_all_experiments.py');
        } catch (e) { noData(p); }
    }

    async function renderProvDag() {
        const p = document.getElementById('rv-provdag'); p.replaceChildren();
        header(p, 'fingerprint', 'provdag');
        try {
            const sessionEl = document.getElementById('current-session');
            const sid = (sessionEl && sessionEl.textContent.trim()) || 'default';
            const d = await api('/api/provenance-dag?session_id=' + encodeURIComponent(sid));
            p.appendChild(el('p', { class: 'rv-sub', text: `${d.nodes.length} ${T('nodes')} · ${d.edges.length} ${T('edges')}` }));
            if (!d.nodes.length) { p.appendChild(el('div', { class: 'rv-empty' }, [el('p', { text: T('emptyDag') })])); return; }
            p.appendChild(dagChart(d));
        } catch (e) { noData(p); }
    }

    function dagChart(d) {
        const W = 680, rowH = 64, P = 30;
        const H = Math.max(120, P * 2 + (d.nodes.length - 1) * 0 + 80);
        const tierColor = (t) => t === 'LOW' ? cssVar('--accent-red', '#ef4444')
            : t === 'MEDIUM' ? cssVar('--accent-orange', '#f59e0b') : cssVar('--accent-green', '#22c55e');
        const pos = {};
        const cols = Math.min(d.nodes.length, 6);
        d.nodes.forEach((n, i) => {
            const col = i % cols, row = Math.floor(i / cols);
            pos[n.id] = { x: P + col * ((W - 2 * P) / Math.max(1, cols - 1 || 1)), y: P + 30 + row * rowH };
        });
        const totalRows = Math.ceil(d.nodes.length / cols);
        const realH = P * 2 + 30 + (totalRows - 1) * rowH + 40;
        const grid = cssVar('--border-subtle', '#475569');
        let s = `<svg viewBox="0 0 ${W} ${realH}" class="rv-dag" role="img" aria-label="provenance DAG">`;
        d.edges.forEach((e) => {
            const a = pos[e.from], b = pos[e.to];
            if (a && b) s += `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="${grid}" stroke-width="1.5" marker-end="url(#arr)"/>`;
        });
        s += `<defs><marker id="arr" markerWidth="8" markerHeight="8" refX="7" refY="3" orient="auto"><path d="M0,0 L7,3 L0,6 Z" fill="${grid}"/></marker></defs>`;
        const txt = cssVar('--text-primary', '#e2e8f0');
        d.nodes.forEach((n) => {
            const pp = pos[n.id];
            s += `<circle cx="${pp.x}" cy="${pp.y}" r="9" fill="${tierColor(n.trust_tier)}"/>`;
            s += `<text x="${pp.x}" y="${pp.y + 22}" fill="${txt}" font-size="8" text-anchor="middle">${escapeXml(n.source)}</text>`;
            s += `<text x="${pp.x}" y="${pp.y + 4}" fill="#0a0f1e" font-size="7" text-anchor="middle" font-weight="700">${n.trust_score}</text>`;
        });
        s += '</svg>';
        const wrap = el('div', { class: 'rv-chart-wrap' });
        wrap.innerHTML = s;
        return wrap;
    }
    function escapeXml(x) { return String(x).replace(/[<>&'"]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', "'": '&apos;', '"': '&quot;' }[c])); }

    async function renderForensics() {
        const p = document.getElementById('rv-forensics'); p.replaceChildren();
        header(p, 'search-code', 'forensics');
        p.appendChild(el('p', { class: 'rv-sub', text: T('forensicsHint') }));
        const input = el('input', { class: 'rv-input', type: 'text', placeholder: 'datasets/poisoned_image.png' });
        const btn = el('button', { class: 'toolbar-button primary', type: 'button' }, [T('analyze')]);
        const out = el('div', { class: 'rv-forensics-out' });
        btn.addEventListener('click', async () => {
            out.replaceChildren(el('p', { class: 'rv-sub', text: '…' }));
            try {
                const d = await api('/api/research/forensics?file_path=' + encodeURIComponent(input.value.trim()));
                const rep = d.report || {};
                const st = rep.steganalysis || {};
                out.replaceChildren();
                out.appendChild(statRow(T('stego'), (st.suspected ? T('suspected') : T('clean')) + ` (${st.score})`, st.suspected ? 'bad' : 'ok'));
                out.appendChild(statRow(T('metadata'), String(rep.metadata_count || 0)));
                (rep.metadata || []).slice(0, 12).forEach((mstr) => out.appendChild(el('div', { class: 'rv-meta', text: mstr })));
            } catch (e) { out.replaceChildren(el('p', { class: 'rv-sub bad', text: String(e.message || e) })); }
        });
        p.appendChild(el('div', { class: 'rv-forensics-form' }, [input, btn]));
        p.appendChild(out);
    }

    async function renderRepro() {
        const p = document.getElementById('rv-repro'); p.replaceChildren();
        header(p, 'package-check', 'repro');
        try {
            const d = await api('/api/reproducibility');
            const m = d.manifest;
            const grid = el('div', { class: 'rv-repro-grid' });
            grid.appendChild(statRow('Python', m.python, 'mono'));
            grid.appendChild(statRow('Detector', m.detector_backend, 'mono'));
            grid.appendChild(statRow('Mode', m.deterministic_mode, 'mono'));
            grid.appendChild(statRow('torch', m.key_packages.torch, 'mono'));
            grid.appendChild(statRow('transformers', m.key_packages.transformers, 'mono'));
            grid.appendChild(statRow('langgraph', m.key_packages.langgraph, 'mono'));
            p.appendChild(grid);
            p.appendChild(el('code', { class: 'rv-code', text: m.reproduce_all }));
            // benchmark catalog
            const bench = el('div', { class: 'rv-bench' });
            (d.benchmarks || []).forEach((b) => bench.appendChild(el('span', {
                class: 'rv-pill ' + (b.adapter === 'pending' ? 'warn' : 'ok'),
                text: b.name,
            })));
            p.appendChild(bench);
            const ad = d.agentdojo || {};
            p.appendChild(statRow('AgentDojo', ad.agentdojo ? ('v' + (ad.version || '?')) : (ad.install || 'not installed'), ad.agentdojo ? 'ok' : 'warn'));
        } catch (e) { noData(p); }
    }

    /* ---------- orchestration ---------- */
    let loaded = false;
    async function loadAll() {
        await Promise.allSettled([
            renderContributions(), renderThreat(), renderDetector(), renderDetectorCurves(),
            renderAdaptive(), renderBaselines(), renderPropagation(), renderTrust(),
            renderExperiments(), renderProvDag(), renderForensics(), renderRepro(),
        ]);
        if (window.lucide && window.lucide.createIcons) window.lucide.createIcons();
    }

    function setView(view) {
        const main = document.querySelector('.main-content');
        if (!main) return;
        const research = view === 'research';
        main.classList.toggle('show-research', research);
        document.querySelectorAll('#view-toggle button').forEach((b) => {
            const on = b.dataset.viewValue === view;
            b.setAttribute('aria-pressed', String(on));
            b.classList.toggle('active', on);
        });
        try { localStorage.setItem('sar_view', view); } catch (e) { /* noop */ }
        if (research && !loaded) { loaded = true; loadAll(); }
    }

    function init() {
        document.querySelectorAll('#view-toggle button').forEach((b) => {
            b.addEventListener('click', () => setView(b.dataset.viewValue));
        });
        document.getElementById('rv-refresh')?.addEventListener('click', () => { loaded = true; loadAll(); });
        let saved = 'live';
        try { saved = localStorage.getItem('sar_view') || 'live'; } catch (e) { /* noop */ }
        if (saved === 'research') setView('research');
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
    else init();
})();
