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
   AUTH-AWARE FETCH WRAPPER
   Works unauthenticated in development and attaches a bearer
   token when one has been configured (production deployments).
   Set the token from the browser console:
       setApiToken('your-token')   // persists to localStorage
   ══════════════════════════════════════════════════════════ */
const _nativeFetch = window.fetch.bind(window);
const API_TOKEN_KEY = 'sar_api_token';

function getApiToken() {
    try { return localStorage.getItem(API_TOKEN_KEY) || ''; } catch { return ''; }
}

window.setApiToken = function (token) {
    try {
        if (token) localStorage.setItem(API_TOKEN_KEY, token);
        else localStorage.removeItem(API_TOKEN_KEY);
        showToast(token ? t('toast.tokenSaved') : t('toast.tokenCleared'), 'success');
    } catch { /* localStorage unavailable */ }
};

let _authWarned = false;

async function apiFetch(url, opts = {}) {
    const token = getApiToken();
    const headers = new Headers(opts.headers || {});
    if (token) headers.set('Authorization', `Bearer ${token}`);
    const response = await _nativeFetch(url, { ...opts, headers });
    if (response.status === 401 && !_authWarned) {
        _authWarned = true;
        showToast(t('toast.authRequired'), 'error', 6000);
    }
    return response;
}

/* ══════════════════════════════════════════════════════════
   INTERNATIONALISATION (EN / AR) + THEME
   Professional Modern Standard Arabic with full RTL support.
   ══════════════════════════════════════════════════════════ */
const I18N = {
    en: {
        'brand.kicker': 'Secure AI Core',
        'brand.title': 'Defense Console',
        'theme.light': 'Light',
        'theme.dark': 'Dark',
        'view.live': 'Live',
        'view.research': 'Research',
        'rv.eyebrow': 'Publication-grade evaluation',
        'rv.title': 'Research Console',
        'rv.desc': 'Threat model, detector benchmarks, adaptive adversary, defense baselines, provenance DAG, and reproducibility — the evidence behind every claim.',
        'rv.refresh': 'Refresh data',
        'trust.heading': 'System Trust State',
        'trust.tierPrefix': 'TIER:',
        'status.live': 'Live',
        'status.idle': 'Idle',
        'status.connecting': 'Connecting…',
        'status.backendConnected': 'Backend connected',
        'status.degraded': 'Event stream degraded (HTTP {status})',
        'status.unreachable': 'Backend unreachable — retrying',
        'status.feedPaused': 'Feed paused by user',
        'mini.events': 'Events',
        'mini.blocks': 'Blocks',
        'mini.activeNode': 'Active Node',
        'mini.lastUpdate': 'Last Update',
        'hero.eyebrow': 'Real-time policy enforcement',
        'hero.title': 'Secure Agent Runtime',
        'hero.desc': 'Monitor trust drift, inspect live graph execution, review intercepted payloads, and audit the provenance trail of every multi-agent run.',
        'badge.idle': 'IDLE',
        'badge.executing': 'EXECUTING',
        'badge.completed': 'COMPLETED',
        'badge.autoPolling': 'Auto-polling',
        'badge.paused': 'Paused',
        'badge.avg': '— avg',
        'badge.avgRuns': '{avg}ms avg ({count} run{plural})',
        'badge.latencyTitle': 'Rolling average over completed runs',
        'toolbar.session': 'Session',
        'btn.copy': 'Copy',
        'btn.copied': 'Copied!',
        'btn.refreshProvenance': 'Refresh provenance',
        'btn.pauseFeed': 'Pause feed',
        'btn.resumeFeed': 'Resume feed',
        'btn.clearConsole': 'Clear console',
        'btn.execute': 'Execute',
        'metric.trust': 'Trust Score',
        'metric.trustHint': 'Adaptive confidence across the current run',
        'metric.lastRun': 'Last Run Time',
        'metric.lastRunHint': 'Most recent completed graph runtime',
        'metric.alert': 'Alert Volume',
        'metric.alertHint': 'Blocked and suspicious events this session',
        'metric.provenance': 'Provenance Entries',
        'metric.provenanceHint': 'Lineage records for the active session',
        'card.execution': 'Execution',
        'card.graphFlow': 'Runtime Graph Flow',
        'node.supervisor': 'Supervisor',
        'node.flight': 'FlightAgent',
        'node.hotel': 'HotelAgent',
        'log.graphTrace': 'Graph Trace',
        'log.awaiting': 'Awaiting input…',
        'log.liveInsights': 'Live Insights',
        'insight.connection': 'Connection',
        'insight.filter': 'Filter',
        'insight.node': 'Node',
        'card.defense': 'Defense',
        'card.interceptionFeed': 'Live Interception Feed',
        'filter.searchPlaceholder': 'Filter alerts',
        'filter.all': 'All',
        'filter.critical': 'Critical',
        'filter.warning': 'Warning',
        'filter.info': 'Info',
        'filter.allSeverities': 'All severities',
        'filter.criticalOnly': 'Critical only',
        'filter.warningOnly': 'Warning only',
        'filter.infoOnly': 'Info only',
        'feed.noThreats': 'No active threats detected.',
        'card.evidence': 'Evidence',
        'card.provenanceTrail': 'Provenance Trail',
        'prov.empty': 'Run a request to inspect provenance lineage.',
        'prov.sanitizers': 'Sanitizers: {list}',
        'prov.none': 'none',
        'prov.unknownSource': 'unknown source',
        'tier.unknown': 'UNKNOWN',
        'card.commandLab': 'Command lab',
        'card.payloadSimulator': 'Payload Simulator',
        'tab.text': 'Text',
        'tab.image': 'Image',
        'tab.audio': 'Voice/Audio',
        'tab.video': 'Video',
        'tab.pdf': 'PDF',
        'chip.directInjection': 'Direct Injection',
        'chip.jailbreak': 'Jailbreak',
        'chip.benignFlight': 'Benign flight',
        'chip.indirectPoisoning': 'Indirect Poisoning',
        'chip.benignImage': 'Benign Image',
        'chip.ocrInjection': 'OCR Injection',
        'chip.exifInjection': 'EXIF Metadata Injection',
        'chip.benignAudio': 'Benign Voice Memo',
        'chip.voiceInjection': 'Voice Injection',
        'chip.benignVideo': 'Benign Video Feed',
        'chip.temporalInjection': 'Temporal Injection',
        'chip.benignPdf': 'Benign Itinerary PDF',
        'chip.pdfInjection': 'PDF Text Injection',
        'upload.dropPrefix': 'Drag & drop file here or',
        'upload.browse': 'browse',
        'upload.hintImage': 'Supports PNG, JPG, JPEG',
        'upload.hintAudio': 'Supports WAV, MP3',
        'upload.hintVideo': 'Supports MP4',
        'upload.hintPdf': 'Supports PDF',
        'sidecar.label': 'Extracted Text Payload (OCR / Transcription / Document):',
        'sidecar.placeholder': 'Text extracted via OCR, audio transcription, or PDF parsing...',
        'input.placeholder': 'Enter a request or adversarial payload to run through the secured graph…',
        'input.placeholderModality': 'Command / context for the {modality} agent run…',
        'input.ariaLabel': 'Payload to execute',
        'alert.phase': 'PHASE {phase} INTERCEPT ({agent})',
        'trace.input': 'Input: "{input}"',
        'trace.finished': 'Graph execution finished.',
        'trace.trustUpdated': 'Trust updated to {score} ({tier})',
        'trace.nodeActivated': 'Node activated: {node}',
        'trace.securityBlock': 'SECURITY BLOCK: Phase {phase}',
        'toast.uploadingExtract': 'Uploading and extracting text from {name}...',
        'toast.extractSuccess': 'Text extracted successfully.',
        'toast.extractFailed': 'Failed to extract text from file.',
        'toast.extractError': 'Error uploading file for extraction.',
        'toast.presetGen': 'Generating payload preset: {preset}...',
        'toast.presetLoaded': 'Preset loaded successfully',
        'toast.presetFailed': 'Failed to load preset',
        'toast.presetError': 'Error loading preset from server',
        'toast.uploadNeeded': 'Please upload a file or load a preset for {modality} mode.',
        'toast.intercepted': 'Payload intercepted by the security layer',
        'toast.runCompleted': 'Run completed',
        'toast.serverError': 'Server error: HTTP {status}',
        'toast.backendUnreachable': 'Backend unreachable — is the server running?',
        'toast.authRequired': 'Authentication required — run setApiToken("<token>") in the console.',
        'toast.tokenSaved': 'API token saved',
        'toast.tokenCleared': 'API token cleared',
        'toast.consoleCleared': 'Console cleared',
        'toast.copyFailed': 'Failed to copy — clipboard access denied',
        'a11y.sidebar': 'System status',
        'a11y.display': 'Display settings',
        'a11y.theme': 'Theme',
        'a11y.language': 'Language',
        'a11y.trustScore': 'System trust score',
        'a11y.overview': 'Overview',
        'a11y.sessionControls': 'Session controls',
        'a11y.keyMetrics': 'Key metrics',
        'a11y.severityFilter': 'Severity filter',
        'a11y.securityAlerts': 'Security alerts',
        'a11y.provenanceRecords': 'Provenance records',
        'a11y.modalities': 'Input modalities',
        'a11y.examplePayloads': 'Example payloads',
        'file.remove': 'Remove file',
    },
    ar: {
        'brand.kicker': 'نواة الذكاء الاصطناعي الآمن',
        'brand.title': 'لوحة الدفاع',
        'theme.light': 'فاتح',
        'theme.dark': 'داكن',
        'view.live': 'مباشر',
        'view.research': 'البحث',
        'rv.eyebrow': 'تقييم بمستوى النشر العلمي',
        'rv.title': 'وحدة البحث',
        'rv.desc': 'نموذج التهديد، ومقاييس الكاشف، والخصم التكيّفي، والدفاعات المرجعية، ورسم المنشأ، وقابلية إعادة الإنتاج — الدليل وراء كل ادعاء.',
        'rv.refresh': 'تحديث البيانات',
        'trust.heading': 'حالة ثقة النظام',
        'trust.tierPrefix': 'المستوى:',
        'status.live': 'مباشر',
        'status.idle': 'خامل',
        'status.connecting': 'جارٍ الاتصال…',
        'status.backendConnected': 'تم الاتصال بالخادم',
        'status.degraded': 'تدهور بثّ الأحداث (HTTP {status})',
        'status.unreachable': 'تعذّر الوصول إلى الخادم — تتم إعادة المحاولة',
        'status.feedPaused': 'أوقف المستخدم البثّ مؤقتًا',
        'mini.events': 'الأحداث',
        'mini.blocks': 'الحجب',
        'mini.activeNode': 'العقدة النشطة',
        'mini.lastUpdate': 'آخر تحديث',
        'hero.eyebrow': 'إنفاذ السياسات في الوقت الفعلي',
        'hero.title': 'بيئة تشغيل الوكلاء الآمنة',
        'hero.desc': 'راقب انحراف الثقة، وافحص تنفيذ الرسم البياني المباشر، وراجع الحمولات المُعترَضة، ودقّق سجلّ المصدرية لكلّ تشغيل متعدّد الوكلاء.',
        'badge.idle': 'خامل',
        'badge.executing': 'قيد التنفيذ',
        'badge.completed': 'اكتمل',
        'badge.autoPolling': 'استطلاع تلقائي',
        'badge.paused': 'متوقّف مؤقتًا',
        'badge.avg': '— متوسّط',
        'badge.avgRuns': 'متوسّط {avg} م.ث ({count} تشغيل)',
        'badge.latencyTitle': 'المتوسّط المتحرّك عبر عمليات التشغيل المكتملة',
        'toolbar.session': 'الجلسة',
        'btn.copy': 'نسخ',
        'btn.copied': 'تم النسخ!',
        'btn.refreshProvenance': 'تحديث المصدرية',
        'btn.pauseFeed': 'إيقاف البثّ مؤقتًا',
        'btn.resumeFeed': 'استئناف البثّ',
        'btn.clearConsole': 'مسح السجل',
        'btn.execute': 'تنفيذ',
        'metric.trust': 'درجة الثقة',
        'metric.trustHint': 'ثقة تكيّفية عبر التشغيل الحالي',
        'metric.lastRun': 'زمن آخر تشغيل',
        'metric.lastRunHint': 'أحدث زمن تنفيذ مكتمل للرسم البياني',
        'metric.alert': 'حجم التنبيهات',
        'metric.alertHint': 'الأحداث المحجوبة والمشبوهة في هذه الجلسة',
        'metric.provenance': 'سجلات المصدرية',
        'metric.provenanceHint': 'سجلات التسلسل للجلسة النشطة',
        'card.execution': 'التنفيذ',
        'card.graphFlow': 'تدفّق الرسم البياني للتشغيل',
        'node.supervisor': 'المنسّق',
        'node.flight': 'وكيل الطيران',
        'node.hotel': 'وكيل الفنادق',
        'log.graphTrace': 'تتبّع الرسم البياني',
        'log.awaiting': 'في انتظار الإدخال…',
        'log.liveInsights': 'رؤى مباشرة',
        'insight.connection': 'الاتصال',
        'insight.filter': 'التصفية',
        'insight.node': 'العقدة',
        'card.defense': 'الدفاع',
        'card.interceptionFeed': 'بثّ الاعتراض المباشر',
        'filter.searchPlaceholder': 'تصفية التنبيهات',
        'filter.all': 'الكل',
        'filter.critical': 'حرِج',
        'filter.warning': 'تحذير',
        'filter.info': 'معلومات',
        'filter.allSeverities': 'كل المستويات',
        'filter.criticalOnly': 'الحرِجة فقط',
        'filter.warningOnly': 'التحذيرات فقط',
        'filter.infoOnly': 'المعلومات فقط',
        'feed.noThreats': 'لا توجد تهديدات نشطة.',
        'card.evidence': 'الأدلة',
        'card.provenanceTrail': 'مسار المصدرية',
        'prov.empty': 'شغّل طلبًا لفحص تسلسل المصدرية.',
        'prov.sanitizers': 'المنقّيات: {list}',
        'prov.none': 'لا شيء',
        'prov.unknownSource': 'مصدر غير معروف',
        'tier.unknown': 'غير معروف',
        'card.commandLab': 'مختبر الأوامر',
        'card.payloadSimulator': 'محاكي الحمولات',
        'tab.text': 'نص',
        'tab.image': 'صورة',
        'tab.audio': 'صوت',
        'tab.video': 'فيديو',
        'tab.pdf': 'PDF',
        'chip.directInjection': 'حقن مباشر',
        'chip.jailbreak': 'كسر القيود',
        'chip.benignFlight': 'رحلة آمنة',
        'chip.indirectPoisoning': 'تسميم غير مباشر',
        'chip.benignImage': 'صورة آمنة',
        'chip.ocrInjection': 'حقن عبر التعرّف الضوئي',
        'chip.exifInjection': 'حقن عبر بيانات EXIF',
        'chip.benignAudio': 'مذكّرة صوتية آمنة',
        'chip.voiceInjection': 'حقن صوتي',
        'chip.benignVideo': 'بثّ فيديو آمن',
        'chip.temporalInjection': 'حقن زمني',
        'chip.benignPdf': 'ملفّ PDF لبرنامج رحلة آمن',
        'chip.pdfInjection': 'حقن نصّي عبر PDF',
        'upload.dropPrefix': 'اسحب الملفّ وأفلِته هنا أو',
        'upload.browse': 'تصفّح',
        'upload.hintImage': 'يدعم PNG وJPG وJPEG',
        'upload.hintAudio': 'يدعم WAV وMP3',
        'upload.hintVideo': 'يدعم MP4',
        'upload.hintPdf': 'يدعم PDF',
        'sidecar.label': 'حمولة النصّ المُستخرَج (تعرّف ضوئي / تفريغ صوتي / مستند):',
        'sidecar.placeholder': 'نصّ مُستخرَج عبر التعرّف الضوئي أو التفريغ الصوتي أو تحليل PDF…',
        'input.placeholder': 'أدخل طلبًا أو حمولة عدائية لتشغيلها عبر الرسم البياني المؤمَّن…',
        'input.placeholderModality': 'أمر / سياق لتشغيل وكيل {modality}…',
        'input.ariaLabel': 'الحمولة المراد تنفيذها',
        'alert.phase': 'اعتراض المرحلة {phase} ({agent})',
        'trace.input': 'الإدخال: «{input}»',
        'trace.finished': 'اكتمل تنفيذ الرسم البياني.',
        'trace.trustUpdated': 'حُدِّثت الثقة إلى {score} ({tier})',
        'trace.nodeActivated': 'تنشيط العقدة: {node}',
        'trace.securityBlock': 'حجب أمني: المرحلة {phase}',
        'toast.uploadingExtract': 'جارٍ رفع الملفّ واستخراج النصّ من {name}…',
        'toast.extractSuccess': 'تمّ استخراج النصّ بنجاح.',
        'toast.extractFailed': 'فشل استخراج النصّ من الملفّ.',
        'toast.extractError': 'خطأ أثناء رفع الملفّ للاستخراج.',
        'toast.presetGen': 'جارٍ توليد حمولة تجريبية: {preset}…',
        'toast.presetLoaded': 'تمّ تحميل النموذج بنجاح',
        'toast.presetFailed': 'فشل تحميل النموذج',
        'toast.presetError': 'خطأ في تحميل النموذج من الخادم',
        'toast.uploadNeeded': 'يرجى رفع ملفّ أو تحميل نموذج لوضع {modality}.',
        'toast.intercepted': 'اعترضت طبقة الأمان الحمولة',
        'toast.runCompleted': 'اكتمل التشغيل',
        'toast.serverError': 'خطأ في الخادم: HTTP {status}',
        'toast.backendUnreachable': 'تعذّر الوصول إلى الخادم — هل الخادم يعمل؟',
        'toast.authRequired': 'المصادقة مطلوبة — شغّل ‎setApiToken("<token>")‎ في وحدة التحكّم.',
        'toast.tokenSaved': 'تمّ حفظ رمز الـ API',
        'toast.tokenCleared': 'تمّ مسح رمز الـ API',
        'toast.consoleCleared': 'تمّ مسح السجل',
        'toast.copyFailed': 'تعذّر النسخ — رُفض الوصول إلى الحافظة',
        'a11y.sidebar': 'حالة النظام',
        'a11y.display': 'إعدادات العرض',
        'a11y.theme': 'السمة',
        'a11y.language': 'اللغة',
        'a11y.trustScore': 'درجة ثقة النظام',
        'a11y.overview': 'نظرة عامة',
        'a11y.sessionControls': 'عناصر التحكّم بالجلسة',
        'a11y.keyMetrics': 'المقاييس الرئيسية',
        'a11y.severityFilter': 'تصفية حسب الخطورة',
        'a11y.securityAlerts': 'التنبيهات الأمنية',
        'a11y.provenanceRecords': 'سجلات المصدرية',
        'a11y.modalities': 'أنماط الإدخال',
        'a11y.examplePayloads': 'حمولات نموذجية',
        'file.remove': 'إزالة الملفّ',
    },
};

// Supplementary runtime strings (kept here to keep the main table compact).
Object.assign(I18N.en, {
    'sidecar.extracting': 'Extracting / transcribing payload, please wait…',
    'sidecar.extractFailed': 'Extraction failed: {msg}',
    'toast.pdfExtracting': 'Extracting text from generated PDF…',
    'toast.pdfExtractLoaded': 'PDF preset text extracted and loaded.',
    'toast.pdfExtractFailed': 'Failed to extract text from PDF preset: {msg}',
    'preview.presetPayload': 'Preset Payload',
});
Object.assign(I18N.ar, {
    'sidecar.extracting': 'جارٍ استخراج/تفريغ الحمولة، يُرجى الانتظار…',
    'sidecar.extractFailed': 'فشل الاستخراج: {msg}',
    'toast.pdfExtracting': 'جارٍ استخراج النصّ من ملفّ PDF المُولَّد…',
    'toast.pdfExtractLoaded': 'تمّ استخراج نصّ نموذج PDF وتحميله.',
    'toast.pdfExtractFailed': 'فشل استخراج النصّ من نموذج PDF: {msg}',
    'preview.presetPayload': 'حمولة نموذجية',
});

let currentLang = (document.documentElement.getAttribute('lang') === 'ar') ? 'ar' : 'en';
let currentTheme = (document.documentElement.getAttribute('data-theme') === 'light') ? 'light' : 'dark';

function t(key, vars) {
    const table = I18N[currentLang] || I18N.en;
    let str = (key in table) ? table[key] : (I18N.en[key] !== undefined ? I18N.en[key] : key);
    if (vars) {
        for (const k in vars) str = str.replace(new RegExp('\\{' + k + '\\}', 'g'), String(vars[k]));
    }
    return str;
}

function applyTranslations() {
    document.querySelectorAll('[data-i18n]').forEach((el) => { el.textContent = t(el.getAttribute('data-i18n')); });
    document.querySelectorAll('[data-i18n-ph]').forEach((el) => { el.setAttribute('placeholder', t(el.getAttribute('data-i18n-ph'))); });
    document.querySelectorAll('[data-i18n-aria]').forEach((el) => { el.setAttribute('aria-label', t(el.getAttribute('data-i18n-aria'))); });
    document.querySelectorAll('[data-i18n-title]').forEach((el) => { el.setAttribute('title', t(el.getAttribute('data-i18n-title'))); });
}

const THEME_COLORS = { dark: '#0a0f1e', light: '#eef2f8' };

function applyTheme(theme, persist = true) {
    currentTheme = theme === 'light' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', currentTheme);
    const meta = document.getElementById('meta-theme-color');
    if (meta) meta.setAttribute('content', THEME_COLORS[currentTheme]);
    document.querySelectorAll('#theme-toggle button').forEach((b) => {
        const on = b.dataset.themeValue === currentTheme;
        b.classList.toggle('active', on);
        b.setAttribute('aria-pressed', String(on));
    });
    if (persist) { try { localStorage.setItem('sar_theme', currentTheme); } catch (e) { /* noop */ } }
}

function applyLanguage(lang, persist = true) {
    currentLang = lang === 'ar' ? 'ar' : 'en';
    const el = document.documentElement;
    el.setAttribute('lang', currentLang);
    el.setAttribute('dir', currentLang === 'ar' ? 'rtl' : 'ltr');
    document.querySelectorAll('#lang-toggle button').forEach((b) => {
        const on = b.dataset.langValue === currentLang;
        b.classList.toggle('active', on);
        b.setAttribute('aria-pressed', String(on));
    });
    applyTranslations();
    refreshDynamicLabels();
    refreshIcons();
    if (persist) { try { localStorage.setItem('sar_lang', currentLang); } catch (e) { /* noop */ } }
}

// Re-apply runtime-driven labels after a language switch so live state
// (connection, graph status, trust tier, filters, modality) stays translated.
function refreshDynamicLabels() {
    if (lastConn) setConnectionState(lastConn.state, lastConn.key, lastConn.vars, true);
    if (lastGraphState) setGraphState(lastGraphState);
    updateTrustMeter(lastScore, lastTier);
    if (filterStateEl) filterStateEl.textContent = t(FILTER_LABEL_KEYS[activeAlertFilter] || FILTER_LABEL_KEYS.all);
    if (typeof applyModalityStrings === 'function') applyModalityStrings();
    // Pause button + polling badges
    if (pauseToggle) {
        setToolbarButtonContent(pauseToggle, isPaused ? 'play' : 'pause', isPaused ? t('btn.resumeFeed') : t('btn.pauseFeed'));
    }
    if (autoPollingBadge) autoPollingBadge.textContent = isPaused ? t('badge.paused') : t('badge.autoPolling');
    if (trustLiveBadge) trustLiveBadge.textContent = isPaused ? t('badge.paused') : t('status.live');
    recordLatencyLabel();
}

// Holders for runtime state so labels can be re-rendered on language change.
let lastConn = null;
let lastGraphState = null;
let lastScore = 1.0;
let lastTier = 'HIGH';

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

function setConnectionState(state, key, vars, force = false) {
    const label = t(key, vars);
    if (!force && state === connectionState && connectionStateEl?.textContent === label) return;
    connectionState = state;
    lastConn = { state, key, vars };

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
    recordLatencyLabel();
}

function recordLatencyLabel() {
    if (!latencyVal || latencySamples.length === 0) return;
    const avg = Math.round(latencySamples.reduce((a, b) => a + b, 0) / latencySamples.length);
    latencyVal.textContent = t('badge.avgRuns', {
        avg,
        count: latencySamples.length,
        plural: (currentLang === 'en' && latencySamples.length !== 1) ? 's' : '',
    });
}

/* ══════════════════════════════════════════════════════════
   TRUST METER
   ══════════════════════════════════════════════════════════ */
const TIER_WORDS = {
    en: { HIGH: 'HIGH', MEDIUM: 'MEDIUM', LOW: 'LOW', UNKNOWN: 'UNKNOWN' },
    ar: { HIGH: 'عالٍ', MEDIUM: 'متوسّط', LOW: 'منخفض', UNKNOWN: 'غير معروف' },
};

function updateTrustMeter(score, tier) {
    const safeScore = Number.isFinite(score) ? Math.min(1, Math.max(0, score)) : 0;
    const formattedScore = safeScore.toFixed(2);
    const safeTier = String(tier || 'HIGH').toUpperCase();
    lastScore = safeScore;
    lastTier = safeTier;

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
        const tierWord = (TIER_WORDS[currentLang] || TIER_WORDS.en)[safeTier] || safeTier;
        trustTierBadge.textContent = `${t('trust.tierPrefix')} ${tierWord}`;
        trustTierBadge.dataset.tier = ['HIGH', 'MEDIUM'].includes(safeTier) ? safeTier.toLowerCase() : 'low';
    }
}

/* ══════════════════════════════════════════════════════════
   GRAPH STATUS
   ══════════════════════════════════════════════════════════ */
const GRAPH_STATE_KEYS = { idle: 'badge.idle', executing: 'badge.executing', completed: 'badge.completed' };

function setGraphState(state) {
    lastGraphState = state;
    const label = t(GRAPH_STATE_KEYS[state] || 'badge.idle');
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

function renderAlertItem(phase, agent, message, severity, detector, confidence) {
    const sev = severityClass(severity);
    const alertItem = document.createElement('div');
    // 'critical' uses the base red styling; warning/info get modifier classes
    alertItem.className = `alert-item${sev !== 'critical' ? ` ${sev}` : ''}`;
    alertItem.dataset.severity = sev;
    alertItem.dataset.search = `${phase} ${agent} ${message} ${severity} ${detector || ''}`.toLowerCase();

    const header = document.createElement('div');
    header.className = 'alert-item-header';

    const phaseLabel = document.createElement('span');
    phaseLabel.className = 'alert-phase';
    phaseLabel.textContent = t('alert.phase', { phase, agent });

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

    // Detector provenance: which model flagged this, and how confidently.
    // Makes the detection layer auditable instead of opaque.
    if (detector) {
        const meta = document.createElement('div');
        meta.className = 'alert-detector';
        const hasConf = typeof confidence === 'number' && !Number.isNaN(confidence);
        meta.textContent = hasConf
            ? `${detector} · ${(confidence * 100).toFixed(1)}%`
            : String(detector);
        alertItem.appendChild(meta);
    }
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
    text.textContent = t('feed.noThreats');

    emptyState.appendChild(icon);
    emptyState.appendChild(text);
    securityFeed.appendChild(emptyState);
    refreshIcons();
}

function addSecurityAlert(phase, agent, message, severity, detector, confidence) {
    if (!securityFeed) return;
    securityFeed.querySelector('.empty-state')?.remove();

    const alertItem = renderAlertItem(phase, agent, message, severity, detector, confidence);
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
        text.textContent = t('prov.empty');

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
        source.textContent = record.source || t('prov.unknownSource');

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
        sanitizers.textContent = t('prov.sanitizers', { list: (record.sanitizers || []).join(', ') || t('prov.none') });

        item.appendChild(header);
        item.appendChild(meta);
        item.appendChild(sanitizers);
        provenanceFeed.appendChild(item);
    });

    if (provenanceCountEl) provenanceCountEl.textContent = String(records.length);
}

async function loadProvenance(sessionId = currentSession?.textContent?.trim() || 'default') {
    try {
        const response = await apiFetch(`/api/provenance?session_id=${encodeURIComponent(sessionId)}`);
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
            addTrace(t('trace.input', { input: data.input || '' }));
            loadProvenance(currentSession?.textContent?.trim());
            break;

        case 'GRAPH_END':
            setGraphState('completed');
            addTrace(t('trace.finished'));
            loadProvenance(currentSession?.textContent?.trim());
            setTimeout(clearNodeActivation, 1000);
            break;

        case 'TRUST_UPDATE': {
            updateTrustMeter(data.score, data.tier);
            const tierWord = (TIER_WORDS[currentLang] || TIER_WORDS.en)[String(data.tier || 'UNKNOWN').toUpperCase()] || data.tier;
            addTrace(t('trace.trustUpdated', { score: Number(data.score || 0).toFixed(2), tier: tierWord }));
            break;
        }

        case 'NODE_ACTIVE':
            setNodeActive(data.node);
            addTrace(t('trace.nodeActivated', { node: data.node }));
            break;

        case 'SECURITY_ALERT':
            blockedEvents += 1;
            addSecurityAlert(data.phase, data.agent, data.message, data.severity, data.detector, data.confidence);
            addTrace(t('trace.securityBlock', { phase: data.phase }));
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
        const response = await apiFetch(`/api/events?since_id=${lastEventId}`);
        if (response.ok) {
            const payload = await response.json();
            for (const event of payload.events || []) {
                processEvent(event);
                lastEventId = Math.max(lastEventId, event.id);
            }
            pollDelay = POLL_INTERVAL;
            setConnectionState('live', 'status.backendConnected');
        } else {
            pollDelay = Math.min(pollDelay * 2, POLL_BACKOFF_MAX);
            setConnectionState('degraded', 'status.degraded', { status: response.status });
        }
    } catch (error) {
        pollDelay = Math.min(pollDelay * 2, POLL_BACKOFF_MAX);
        setConnectionState('error', 'status.unreachable');
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
/* ══════════════════════════════════════════════════════════
   MULTIMODAL CONSOLE LOGIC
   ══════════════════════════════════════════════════════════ */
let currentModality = 'text';
let selectedFile = null;
let selectedPresetPath = null;

// DOM references
const modalityTabs = document.querySelectorAll('.modality-tab');
const modalityPanels = document.querySelectorAll('.modality-panel');
const uploadContainer = document.getElementById('upload-container');
const uploadDropzone = document.getElementById('upload-dropzone');
const uploadHint = document.getElementById('upload-hint');
const fileInput = document.getElementById('file-input');
const filePreview = document.getElementById('file-preview');
const previewName = document.getElementById('preview-name');
const previewSize = document.getElementById('preview-size');
const removeFileBtn = document.getElementById('remove-file');
const sidecarContainer = document.getElementById('sidecar-container');
const sidecarInput = document.getElementById('sidecar-input');

// Initialize modality switching
modalityTabs.forEach(tab => {
    tab.addEventListener('click', () => {
        modalityTabs.forEach(tb => {
            tb.classList.remove('active');
            tb.setAttribute('aria-selected', 'false');
        });
        tab.classList.add('active');
        tab.setAttribute('aria-selected', 'true');

        currentModality = tab.dataset.modality;

        // Show active panel, hide others
        modalityPanels.forEach(p => p.classList.remove('active'));
        document.getElementById(`panel-${currentModality}`)?.classList.add('active');

        applyModalityStrings();

        clearSelectedFile();
        if (attackInput) attackInput.value = '';
        if (sidecarInput) sidecarInput.value = '';
    });
});

// Modality-dependent strings + native picker filter, factored out so a
// language switch can re-apply them for the active modality.
const ACCEPT_BY_MODALITY = {
    image: '.png,.jpg,.jpeg',
    audio: '.wav,.mp3',
    video: '.mp4',
    pdf: '.pdf,application/pdf',
};
const HINT_KEY_BY_MODALITY = {
    image: 'upload.hintImage',
    audio: 'upload.hintAudio',
    video: 'upload.hintVideo',
    pdf: 'upload.hintPdf',
};

function applyModalityStrings() {
    if (currentModality === 'text') {
        uploadContainer?.classList.add('hidden');
        sidecarContainer?.classList.add('hidden');
        if (attackInput) {
            attackInput.placeholder = t('input.placeholder');
            attackInput.required = true;
        }
        return;
    }
    uploadContainer?.classList.remove('hidden');
    sidecarContainer?.classList.remove('hidden');
    if (attackInput) {
        attackInput.placeholder = t('input.placeholderModality', { modality: t('tab.' + currentModality) });
        attackInput.required = false;
    }
    if (uploadHint) uploadHint.textContent = t(HINT_KEY_BY_MODALITY[currentModality] || 'upload.hintImage');
    if (fileInput) fileInput.accept = ACCEPT_BY_MODALITY[currentModality] || '';
}

// File Selection Controllers
async function extractTextFromFile(file) {
    if (!file) return;
    
    showToast(t('toast.uploadingExtract', { name: file.name }), 'info', 2000);

    if (sidecarContainer) sidecarContainer.classList.remove('hidden');
    if (sidecarInput) {
        sidecarInput.value = t('sidecar.extracting');
        sidecarInput.disabled = true;
    }
    
    try {
        const formData = new FormData();
        formData.append('modality', currentModality);
        formData.append('file', file);
        
        const response = await apiFetch('/api/extract-text', {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const data = await response.json();
        
        if (data.status === 'success') {
            const isPdf = file && file.name && file.name.toLowerCase().endsWith('.pdf');
            if (isPdf || currentModality === 'pdf') {
                const textVal = data.text || '';
                // Switch active tab to text programmatically
                const textTab = document.querySelector('.modality-tab[data-modality="text"]');
                if (textTab) {
                    textTab.click();
                }
                if (attackInput) {
                    attackInput.value = textVal;
                }
            } else {
                if (sidecarInput) {
                    sidecarInput.value = data.text || '';
                    sidecarInput.disabled = false;
                }
            }
            showToast(t('toast.extractSuccess'), 'success');
        } else {
            if (sidecarInput) {
                sidecarInput.value = t('sidecar.extractFailed', { msg: data.message || 'unknown error' });
                sidecarInput.disabled = false;
            }
            showToast(t('toast.extractFailed'), 'error');
        }
    } catch (err) {
        console.error(err);
        if (sidecarInput) {
            sidecarInput.value = t('sidecar.extractFailed', { msg: err.message });
            sidecarInput.disabled = false;
        }
        showToast(t('toast.extractError'), 'error');
    }
}

function handleFileSelection(file) {
    if (!file) return;
    selectedFile = file;
    selectedPresetPath = null;
    
    if (previewName) previewName.textContent = file.name;
    if (previewSize) previewSize.textContent = `${Math.round(file.size / 1024)} KB`;
    
    filePreview?.classList.remove('hidden');
    uploadDropzone?.classList.add('hidden');
    
    if (attackInput && !attackInput.value) {
        attackInput.value = `Process the uploaded ${currentModality} file.`;
    }
    
    extractTextFromFile(file);
}

function clearSelectedFile() {
    selectedFile = null;
    selectedPresetPath = null;
    if (fileInput) fileInput.value = '';
    filePreview?.classList.add('hidden');
    uploadDropzone?.classList.remove('hidden');
    if (sidecarInput) {
        sidecarInput.value = '';
        sidecarInput.disabled = false;
    }
    sidecarContainer?.classList.add('hidden');
}

removeFileBtn?.addEventListener('click', (e) => {
    e.stopPropagation();
    clearSelectedFile();
});

uploadDropzone?.addEventListener('click', () => {
    fileInput?.click();
});

fileInput?.addEventListener('change', (e) => {
    if (e.target.files && e.target.files.length > 0) {
        handleFileSelection(e.target.files[0]);
    }
});

// Drag & drop triggers
['dragenter', 'dragover'].forEach(eventName => {
    uploadDropzone?.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        uploadDropzone.classList.add('dragover');
    }, false);
});

['dragleave', 'drop'].forEach(eventName => {
    uploadDropzone?.addEventListener(eventName, (e) => {
        e.preventDefault();
        e.stopPropagation();
        uploadDropzone.classList.remove('dragover');
    }, false);
});

uploadDropzone?.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files && files.length > 0) {
        handleFileSelection(files[0]);
    }
});

/* ══════════════════════════════════════════════════════════
   QUICK PROMPT CHIPS (Text & Presets)
   ══════════════════════════════════════════════════════════ */
function attachQuickPromptButtons() {
    // 1. Text modality prompt chips
    document.querySelectorAll('#panel-text .quick-chip').forEach((button) => {
        button.addEventListener('click', () => {
            if (attackInput) attackInput.value = button.dataset.prompt || '';
            attackInput?.focus();
        });
    });

    // 2. Multimodal presets chips
    document.querySelectorAll('.preset-btn').forEach((button) => {
        button.addEventListener('click', async () => {
            const preset = button.dataset.preset;
            showToast(t('toast.presetGen', { preset }), 'info', 1800);
            
            try {
                const response = await apiFetch(`/api/generate-preset?preset_type=${encodeURIComponent(preset)}`, {
                    method: 'POST'
                });
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                const data = await response.json();
                
                if (data.status === 'success') {
                    if (preset === 'benign_pdf' || preset === 'pdf_injection') {
                        // For PDF presets, fetch/extract text, then insert it into attackInput and switch to text tab
                        showToast(t('toast.pdfExtracting'), "info", 2000);
                        try {
                            const extractFormData = new FormData();
                            extractFormData.append('modality', 'pdf');
                            extractFormData.append('file_path', data.file_path);
                            const extractResp = await apiFetch('/api/extract-text', {
                                method: 'POST',
                                body: extractFormData
                            });
                            if (!extractResp.ok) throw new Error(`HTTP ${extractResp.status}`);
                            const extractData = await extractResp.json();
                            if (extractData.status === 'success') {
                                const textVal = extractData.text || '';
                                const textTab = document.querySelector('.modality-tab[data-modality="text"]');
                                if (textTab) {
                                    textTab.click();
                                }
                                if (attackInput) {
                                    attackInput.value = textVal;
                                }
                                showToast(t('toast.pdfExtractLoaded'), 'success');
                            } else {
                                throw new Error(extractData.message || 'unknown extraction error');
                            }
                        } catch (extractErr) {
                            console.error(extractErr);
                            showToast(t('toast.pdfExtractFailed', { msg: extractErr.message }), 'error');
                        }
                    } else {
                        selectedPresetPath = data.file_path;
                        selectedFile = null;
                        
                        if (previewName) previewName.textContent = data.file_path.split('/').pop();
                        if (previewSize) previewSize.textContent = t('preview.presetPayload');

                        filePreview?.classList.remove('hidden');
                        uploadDropzone?.classList.add('hidden');

                        if (attackInput) attackInput.value = data.prompt || '';
                        if (sidecarInput) sidecarInput.value = data.sidecar_text || '';

                        showToast(t('toast.presetLoaded'), 'success');
                    }
                } else {
                    showToast(t('toast.presetFailed'), 'error');
                }
            } catch (err) {
                console.error(err);
                showToast(t('toast.presetError'), 'error');
            }
        });
    });
}

/* ══════════════════════════════════════════════════════════
   FORM SUBMISSION (Multimodal Form Data support)
   ══════════════════════════════════════════════════════════ */
attackForm?.addEventListener('submit', async (event) => {
    event.preventDefault();
    
    const input = attackInput?.value?.trim();
    if (currentModality === 'text' && !input) return;
    
    if (currentModality !== 'text' && !selectedFile && !selectedPresetPath) {
        showToast(t('toast.uploadNeeded', { modality: t('tab.' + currentModality) }), 'warning');
        return;
    }

    executeBtn?.classList.add('loading');
    if (executeBtn) executeBtn.disabled = true;

    const sessionId = `dash_session_${Date.now()}`;

    try {
        let response;
        if (currentModality === 'text') {
            response = await apiFetch(`/run-travel-graph?user_input=${encodeURIComponent(input)}&session_id=${encodeURIComponent(sessionId)}`, {
                method: 'POST'
            });
        } else {
            const formData = new FormData();
            formData.append('modality', currentModality);
            formData.append('user_input', input || '');
            formData.append('session_id', sessionId);
            
            if (selectedFile) {
                formData.append('file', selectedFile);
            } else if (selectedPresetPath) {
                formData.append('file_path', selectedPresetPath);
            }
            
            const sidecarText = sidecarInput?.value?.trim();
            if (sidecarText) {
                formData.append('sidecar_text', sidecarText);
            }
            
            response = await apiFetch('/run-travel-multimodal', {
                method: 'POST',
                body: formData
            });
        }

        if (response.ok) {
            const result = await response.json();
            if (Number.isFinite(result.processing_time_ms)) {
                recordLatency(result.processing_time_ms);
            }
            if (Number.isFinite(result.trust_score)) {
                updateTrustMeter(result.trust_score, result.trust_tier || 'HIGH');
            }
            if (attackInput) attackInput.value = '';
            if (sidecarInput) sidecarInput.value = '';
            clearSelectedFile();
            
            showToast(
                result.security_blocked ? t('toast.intercepted') : t('toast.runCompleted'),
                result.security_blocked ? 'warning' : 'success'
            );
        } else {
            showToast(t('toast.serverError', { status: response.status }), 'error');
        }
    } catch (error) {
        console.error('Failed to run graph', error);
        showToast(t('toast.backendUnreachable'), 'error');
    } finally {
        executeBtn?.classList.remove('loading');
        if (executeBtn) executeBtn.disabled = false;
    }
});

/* ══════════════════════════════════════════════════════════
   FILTER & SEARCH
   ══════════════════════════════════════════════════════════ */
const FILTER_LABEL_KEYS = {
    all: 'filter.allSeverities',
    critical: 'filter.criticalOnly',
    warning: 'filter.warningOnly',
    info: 'filter.infoOnly',
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
        if (filterStateEl) filterStateEl.textContent = t(FILTER_LABEL_KEYS[activeAlertFilter] || FILTER_LABEL_KEYS.all);
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
    setToolbarButtonContent(pauseToggle, isPaused ? 'play' : 'pause', isPaused ? t('btn.resumeFeed') : t('btn.pauseFeed'));

    if (autoPollingBadge) {
        autoPollingBadge.textContent = isPaused ? t('badge.paused') : t('badge.autoPolling');
        autoPollingBadge.classList.toggle('paused', isPaused);
    }
    if (trustLiveBadge) {
        trustLiveBadge.textContent = isPaused ? t('badge.paused') : t('status.live');
        trustLiveBadge.classList.toggle('paused', isPaused);
    }

    if (isPaused) {
        setConnectionState('paused', 'status.feedPaused');
    } else {
        pollDelay = POLL_INTERVAL;
        setConnectionState('live', 'status.backendConnected');
    }
});

clearFeedButton?.addEventListener('click', () => {
    if (!securityFeed) return;
    securityFeed.innerHTML = '';
    showFeedEmptyState();
    alertPulse?.classList.remove('armed');
    updateFilterPillCounts();
    showToast(t('toast.consoleCleared'), 'info');
});

refreshProvenanceButton?.addEventListener('click', () => {
    showProvenanceSkeleton();
    loadProvenance(currentSession?.textContent?.trim());
});

copySessionButton?.addEventListener('click', async () => {
    try {
        await navigator.clipboard.writeText(currentSession?.textContent?.trim() || '');
        setToolbarButtonContent(copySessionButton, 'check', t('btn.copied'));
        setTimeout(() => setToolbarButtonContent(copySessionButton, 'copy', t('btn.copy')), 1200);
    } catch (error) {
        console.error('Copy failed', error);
        showToast(t('toast.copyFailed'), 'warning');
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
   THEME & LANGUAGE TOGGLE WIRING
   ══════════════════════════════════════════════════════════ */
document.getElementById('theme-toggle')?.querySelectorAll('button').forEach((btn) => {
    btn.addEventListener('click', () => applyTheme(btn.dataset.themeValue));
});
document.getElementById('lang-toggle')?.querySelectorAll('button').forEach((btn) => {
    btn.addEventListener('click', () => applyLanguage(btn.dataset.langValue));
});

/* ══════════════════════════════════════════════════════════
   INITIALIZATION
   ══════════════════════════════════════════════════════════ */
// Sync toggle UI + translate the DOM to the persisted theme/language
// (the <html> attributes were already set pre-paint by the head script).
applyTheme(currentTheme, false);
applyLanguage(currentLang, false);

refreshIcons();
attachQuickPromptButtons();
setConnectionState('degraded', 'status.connecting');
updateCounters();
loadProvenance(currentSession?.textContent?.trim() || 'default');
pollEvents();
setTimeout(updateLines, 200);
