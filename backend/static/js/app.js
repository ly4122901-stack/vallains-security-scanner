const API_BASE = '';

const elements = {
    tabs: document.querySelectorAll('.tab-btn'),
    tabContents: document.querySelectorAll('.tab-content'),
    results: document.getElementById('results'),
    resultsBody: document.getElementById('results-body'),
    resultsTitle: document.getElementById('results-title'),
    resultsTarget: document.getElementById('results-target-display'),
    resultsTime: document.getElementById('results-time'),
    loader: document.getElementById('loader'),
    loaderText: document.getElementById('loader-text'),
    loaderSub: document.getElementById('loader-sub')
};

const SCAN_CONFIG = {
    info: { title: 'نتائج جمع المعلومات الشامل', loader: 'جاري جمع المعلومات...', sub: 'WHOIS · DNS · SSL · Headers · Subdomains' },
    resolve: { title: 'نتائج كشف IP', loader: 'جاري كشف عنوان IP...', sub: 'DNS Resolution + GeoIP' },
    reverse: { title: 'نتائج عكس IP', loader: 'جاري البحث العكسي...', sub: 'Reverse DNS + Domains on IP' },
    'threat-malware': { title: 'نتائج فحص البرمجيات الخبيثة', loader: 'جاري فحص Malware...', sub: 'VirusTotal · Google · Sucuri · URLVoid' },
    'threat-phishing': { title: 'نتائج فحص التصيد', loader: 'جاري فحص Phishing...', sub: 'PhishTank · Google Safe Browsing' },
    'threat-spam': { title: 'نتائج فحص الـ Spam', loader: 'جاري فحص Spam...', sub: 'Spamhaus · SURBL · DNSBL' },
    blacklist: { title: 'نتائج فحص القائمة السوداء', loader: 'جاري فحص DNSBL...', sub: '10+ Blacklist Databases' },
    ssl: { title: 'نتائج فحص SSL/TLS', loader: 'جاري فحص الشهادة...', sub: 'Certificate Analysis' },
    ports: { title: 'نتائج فحص المنافذ', loader: 'جاري فحص المنافذ...', sub: '30+ Common Ports' },
    subdomains: { title: 'النطاقات الفرعية المكتشفة', loader: 'جاري البحث عن Subdomains...', sub: 'Certificate Transparency Logs' },
    redirects: { title: 'سلسلة التحويلات', loader: 'جاري تتبع التحويلات...', sub: 'Redirect Chain Analysis' },
    reputation: { title: 'تحليل سمعة IP', loader: 'جاري تحليل السمعة...', sub: 'AbuseIPDB · GeoIP · Hosting Type' }
};

elements.tabs.forEach(tab => {
    tab.addEventListener('click', () => switchTab(tab.dataset.tab));
});

document.querySelectorAll('[data-tab-action]').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tabAction));
});

document.querySelectorAll('.btn-execute').forEach(btn => {
    btn.addEventListener('click', () => executeScan(btn.dataset.action));
});

document.querySelectorAll('.text-input').forEach(input => {
    input.addEventListener('keypress', e => {
        if (e.key === 'Enter') {
            const action = input.closest('.tab-content').id.replace('tab-', '');
            executeScan(action);
        }
    });
});

function switchTab(tabId) {
    elements.tabs.forEach(t => t.classList.toggle('active', t.dataset.tab === tabId));
    elements.tabContents.forEach(c => c.classList.toggle('active', c.id === `tab-${tabId}`));
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

async function executeScan(action) {
    const inputId = action === 'threat-malware' ? 'malware-target' :
                    action === 'threat-phishing' ? 'phishing-target' :
                    action === 'threat-spam' ? 'spam-target' :
                    `${action}-target`;
    const input = document.getElementById(inputId);
    const target = input.value.trim();
    if (!target) {
        input.focus();
        input.style.borderColor = 'var(--danger)';
        setTimeout(() => input.style.borderColor = '', 2000);
        return;
    }
    const config = SCAN_CONFIG[action];
    showLoader(config.loader, config.sub);
    try {
        let endpoint, body = { target };
        switch (action) {
            case 'info': endpoint = '/api/info'; break;
            case 'resolve': endpoint = '/api/resolve'; break;
            case 'reverse': endpoint = '/api/reverse'; break;
            case 'threat-malware':
            case 'threat-phishing':
            case 'threat-spam':
                endpoint = '/api/threat';
                body.type = action.replace('threat-', '');
                break;
            case 'blacklist': endpoint = '/api/blacklist'; break;
            case 'ssl': endpoint = '/api/ssl'; break;
            case 'ports': endpoint = '/api/ports'; break;
            case 'subdomains': endpoint = '/api/subdomains'; break;
            case 'redirects': endpoint = '/api/redirects'; break;
            case 'reputation':
                endpoint = '/api/threat';
                body.type = 'all';
                break;
        }
        const resp = await fetch(`${API_BASE}${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
        const data = await resp.json();
        hideLoader();
        renderResults(action, target, data);
    } catch (err) {
        hideLoader();
        renderError(target, err.message);
    }
}

function showLoader(text, sub) {
    elements.loaderText.textContent = text;
    elements.loaderSub.textContent = sub;
    elements.loader.style.display = 'flex';
}

function hideLoader() {
    elements.loader.style.display = 'none';
}

function renderResults(action, target, data) {
    const config = SCAN_CONFIG[action];
    elements.resultsTitle.textContent = config.title;
    elements.resultsTarget.textContent = target;
    elements.resultsTime.textContent = new Date().toLocaleString('ar-EG', { hour12: false });
    elements.resultsBody.innerHTML = '';
    elements.results.style.display = 'block';
    setTimeout(() => elements.results.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100);
    if (data.error) {
        elements.resultsBody.innerHTML = `<div class="empty-state"><div class="empty-state-icon">⚠</div><h4>${data.error}</h4><p>تأكد من صحة المدخل وحاول مرة أخرى</p></div>`;
        return;
    }
    const result = data.result || data;
    switch (action) {
        case 'info': renderInfo(result); break;
        case 'resolve': renderResolve(result); break;
        case 'reverse': renderReverse(result); break;
        case 'threat-malware': renderMalware(result); break;
        case 'threat-phishing': renderPhishing(result); break;
        case 'threat-spam': renderSpam(result); break;
        case 'blacklist': renderBlacklist(result); break;
        case 'ssl': renderSSL(result); break;
        case 'ports': renderPorts(result); break;
        case 'subdomains': renderSubdomains(result); break;
        case 'redirects': renderRedirects(result); break;
        case 'reputation': renderReputation(result); break;
    }
}

function renderError(target, msg) {
    elements.results.style.display = 'block';
    elements.resultsTitle.textContent = 'خطأ';
    elements.resultsTarget.textContent = target;
    elements.resultsTime.textContent = new Date().toLocaleString('ar-EG');
    elements.resultsBody.innerHTML = `<div class="empty-state"><div class="empty-state-icon">⚠</div><h4>حدث خطأ</h4><p>${msg}</p></div>`;
}

function el(tag, attrs = {}, ...children) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
        if (k === 'class') e.className = v;
        else if (k === 'html') e.innerHTML = v;
        else if (k.startsWith('on')) e.addEventListener(k.slice(2).toLowerCase(), v);
        else e.setAttribute(k, v);
    }
    children.flat().forEach(c => {
        if (c == null) return;
        if (typeof c === 'string') e.appendChild(document.createTextNode(c));
        else e.appendChild(c);
    });
    return e;
}

function section(title, ...content) {
    const wrap = el('div', { class: 'result-section' });
    wrap.appendChild(el('h4', { class: 'result-section-title' }, title));
    content.forEach(c => wrap.appendChild(c));
    return wrap;
}

function kvGrid(items) {
    const grid = el('div', { class: 'kv-grid' });
    items.forEach(([k, v, type = 'text']) => {
        const item = el('div', { class: 'kv-item' });
        item.appendChild(el('div', { class: 'kv-key' }, k));
        const valEl = el('div', { class: 'kv-val' + (type === 'list' ? ' list' : '') });
        if (Array.isArray(v)) {
            if (v.length === 0) valEl.appendChild(document.createTextNode('-'));
            else v.forEach(item => valEl.appendChild(el('span', {}, String(item))));
        } else if (v instanceof HTMLElement) {
            valEl.appendChild(v);
        } else {
            valEl.appendChild(document.createTextNode(v != null ? String(v) : '-'));
        }
        item.appendChild(valEl);
        grid.appendChild(item);
    });
    return grid;
}

function badge(text, type = 'gold') {
    return el('span', { class: `badge badge-${type}` }, text);
}

function renderInfo(r) {
    if (r.resolve && !r.resolve.error) {
        elements.resultsBody.appendChild(section('DNS Resolution',
            kvGrid([
                ['الدومين', r.domain],
                ['IP الرئيسي', r.resolve.ip],
                ['كل الـ IPs', r.resolve.all_ips, 'list'],
                ['IPv4', `${r.resolve.ipv4_count} عنوان`],
                ['IPv6', `${r.resolve.ipv6_count} عنوان`]
            ])
        ));
    }
    if (r.geoip && !r.geoip.error) {
        elements.resultsBody.appendChild(geoipSection(r.geoip));
    }
    if (r.dns) {
        const dnsItems = [];
        for (const [k, v] of Object.entries(r.dns)) {
            if (v && v.length) dnsItems.push([k, v, 'list']);
        }
        if (dnsItems.length) {
            elements.resultsBody.appendChild(section('سجلات DNS', kvGrid(dnsItems)));
        } else {
            elements.resultsBody.appendChild(section('سجلات DNS',
                el('div', { class: 'empty-state' }, el('p', {}, 'لا توجد سجلات'))
            ));
        }
    }
    if (r.whois && !r.whois.error) {
        const whoisItems = [];
        for (const [k, v] of Object.entries(r.whois)) {
            if (v && v !== '' && v !== 'None') {
                const labelAr = WHOIS_LABELS[k] || k;
                whoisItems.push([labelAr, Array.isArray(v) ? v : v]);
            }
        }
        if (whoisItems.length) {
            const grid = el('div', { class: 'kv-grid' });
            whoisItems.forEach(([k, v]) => {
                const item = el('div', { class: 'kv-item' });
                item.appendChild(el('div', { class: 'kv-key' }, k));
                const valEl = el('div', { class: 'kv-val' + (Array.isArray(v) ? ' list' : '') });
                if (Array.isArray(v)) v.forEach(x => valEl.appendChild(el('span', {}, String(x))));
                else valEl.appendChild(document.createTextNode(String(v)));
                item.appendChild(valEl);
                grid.appendChild(item);
            });
            elements.resultsBody.appendChild(section('WHOIS', grid));
        }
    }
    if (r.headers && !r.headers.error) {
        elements.resultsBody.appendChild(headersSection(r.headers));
    }
    if (r.ssl && !r.ssl.error) {
        elements.resultsBody.appendChild(sslSection(r.ssl));
    }
    if (r.crt && r.crt.subdomains && r.crt.subdomains.length) {
        elements.resultsBody.appendChild(subdomainSection(r.crt));
    }
}

const WHOIS_LABELS = {
    domain_name: 'اسم الدومين',
    registrar: 'المُسجِّل',
    whois_server: 'سيرفر WHOIS',
    creation_date: 'تاريخ الإنشاء',
    expiration_date: 'تاريخ الانتهاء',
    updated_date: 'تاريخ التحديث',
    name_servers: 'سيرفرات الأسماء',
    status: 'الحالة',
    emails: 'البريد الإلكتروني',
    org: 'المنظمة',
    country: 'الدولة',
    state: 'الولاية/المحافظة',
    city: 'المدينة',
    address: 'العنوان',
    registrant: 'صاحب التسجيل'
};

function geoipSection(g) {
    const card = el('div', { class: 'geoip-card' });
    const header = el('div', { class: 'geoip-header' });
    header.appendChild(el('div', { class: 'geoip-ip' }, g.ip));
    const flag = el('span', { class: 'badge badge-gold' }, g.country || 'Unknown');
    header.appendChild(flag);
    card.appendChild(header);
    const items = [
        ['الدولة', g.country],
        ['المحافظة/المنطقة', g.region],
        ['المدينة', g.city],
        ['الرمز البريدي', g.zip || '-'],
        ['خط العرض', g.lat],
        ['خط الطول', g.lon],
        ['المنطقة الزمنية', g.timezone],
        ['مزود الخدمة (ISP)', g.isp],
        ['المنظمة', g.org],
        ['ASN', g.as],
        ['نوع المضيف', g.hosting ? '🏢 استضافة/سيرفر' : '🏠 سكني/موبايل'],
        ['Reverse DNS', g.reverse || '-']
    ];
    card.appendChild(kvGrid(items));
    return card;
}

function renderResolve(r) {
    if (r.geoip && !r.geoip.error) {
        elements.resultsBody.appendChild(geoipSection(r.geoip));
    } else {
        elements.resultsBody.appendChild(section('نتيجة الكشف',
            kvGrid([
                ['الدومين', r.domain],
                ['IP', r.ip],
                ['كل العناوين', r.all_ips, 'list']
            ])
        ));
    }
}

function renderReverse(r) {
    if (r.geoip && !r.geoip.error) {
        elements.resultsBody.appendChild(geoipSection(r.geoip));
    }
    elements.resultsBody.appendChild(section('نتيجة الـ Reverse DNS',
        kvGrid([
            ['IP المُدخل', r.ip],
            ['Hostname', r.hostname || 'لا يوجد'],
            ['عدد المواقع على نفس الـ IP', r.domains_on_ip ? r.domains_on_ip.length : 0]
        ])
    ));
    if (r.domains_on_ip && r.domains_on_ip.length) {
        const list = el('div', { class: 'subdomain-list' });
        r.domains_on_ip.forEach(d => {
            const item = el('div', { class: 'subdomain-item' }, d);
            item.addEventListener('click', () => {
                document.getElementById('reverse-target').value = d;
                switchTab('info');
            });
            list.appendChild(item);
        });
        elements.resultsBody.appendChild(section('🌐 المواقع المستضافة على نفس السيرفر', list));
    } else {
        elements.resultsBody.appendChild(section('المواقع المستضافة',
            el('div', { class: 'empty-state' }, el('p', {}, 'لم يتم العثور على مواقع أخرى'))
        ));
    }
}

function renderMalware(r) {
    scannersSection(r);
    if (r.dnsbl && r.dnsbl.length) {
        elements.resultsBody.appendChild(dnsblSection(r.dnsbl));
    }
}

function renderPhishing(r) {
    scannersSection(r);
}

function renderSpam(r) {
    if (r.dnsbl && r.dnsbl.length) {
        elements.resultsBody.appendChild(dnsblSection(r.dnsbl));
    }
    if (r.scanners) scannersSection(r);
}

function scannersSection(r) {
    if (!r.scanners) return;
    const grid = el('div', { class: 'scanner-grid' });
    const labels = {
        google_safebrowsing: 'Google Safe Browsing',
        virustotal: 'VirusTotal',
        urlvoid: 'URLVoid',
        phishtank: 'PhishTank',
        scamadviser: 'ScamAdviser',
        sucuri: 'Sucuri SiteCheck',
        threatcrowd: 'ThreatCrowd',
        abuseipdb: 'AbuseIPDB'
    };
    for (const [k, v] of Object.entries(r.scanners)) {
        if (!v) continue;
        const card = el('div', { class: 'scanner-card' });
        const header = el('div', { class: 'scanner-card-header' });
        header.appendChild(el('h5', { class: 'scanner-name' }, labels[k] || k));
        header.appendChild(badge('🔗 فحص', 'gold'));
        card.appendChild(header);
        if (v.note) card.appendChild(el('p', { class: 'scanner-note' }, v.note));
        if (v.url) {
            const link = el('a', { class: 'scanner-link', href: v.url, target: '_blank', rel: 'noopener' }, 'فتح في تبويب جديد ←');
            card.appendChild(link);
        }
        if (v.ip_url) {
            const link = el('a', { class: 'scanner-link', href: v.ip_url, target: '_blank', rel: 'noopener', style: 'margin-right: 6px;' }, 'فحص IP ←');
            card.appendChild(link);
        }
        grid.appendChild(card);
    }
    elements.resultsBody.appendChild(section('🛡️ محركات الفحص العالمية', grid));
}

function renderBlacklist(r) {
    if (r.geoip && !r.geoip.error) {
        elements.resultsBody.appendChild(geoipSection(r.geoip));
    }
    elements.resultsBody.appendChild(section('ملخص',
        kvGrid([
            ['IP المُفحوص', r.ip],
            ['عدد القوائم المفحوصة', r.total_checked],
            ['مُدرج في', `${r.listed_count} قائمة`],
            ['الحالة', r.listed_count > 0 ? badge('⚠ مُدرج في قوائم سوداء', 'danger') : badge('✓ نظيف', 'success')]
        ])
    ));
    elements.resultsBody.appendChild(dnsblSection(r.checks || []));
}

function dnsblSection(checks) {
    const grid = el('div', { class: 'dnsbl-grid' });
    checks.forEach(c => {
        const item = el('div', { class: 'dnsbl-item' + (c.listed ? ' listed' : '') });
        item.appendChild(el('div', { class: 'dnsbl-name' }, c.server));
        const status = el('div', { class: 'dnsbl-status ' + (c.listed ? 'listed' : (c.error ? 'error' : 'clean')) });
        if (c.listed) status.appendChild(document.createTextNode('⚠ مُدرج'));
        else if (c.error) status.appendChild(document.createTextNode('✗ خطأ'));
        else status.appendChild(document.createTextNode('✓ نظيف'));
        item.appendChild(status);
        grid.appendChild(item);
    });
    return section('🗂️ نتائج DNSBL', grid);
}

function sslSection(s) {
    const wrap = el('div');
    const grade = el('div', { class: 'ssl-grade' });
    const circle = el('div', { class: 'ssl-grade-circle' });
    let gradeText = 'A';
    let gradeClass = '';
    if (s.is_expired) { gradeText = 'F'; gradeClass = 'danger'; }
    else if (s.days_remaining < 14) { gradeText = 'B'; gradeClass = 'warning'; }
    else if (s.days_remaining < 30) { gradeText = 'A'; gradeClass = 'warning'; }
    circle.textContent = gradeText;
    if (gradeClass) circle.classList.add(gradeClass);
    grade.appendChild(circle);
    const info = el('div', { class: 'ssl-grade-info' });
    info.appendChild(el('h4', {}, s.is_expired ? '⚠ الشهادة منتهية الصلاحية' : `✓ الشهادة صالحة لمدة ${s.days_remaining} يوم`));
    info.appendChild(el('p', {}, `TLS ${s.tls_version} · ${s.cipher.name} (${s.cipher.bits} bit)`));
    grade.appendChild(info);
    wrap.appendChild(grade);
    const issuerItems = [
        ['الجهة المُصدرة (CN)', s.issuer.CN || s.issuer.O || '-'],
        ['المنظمة المُصدرة', s.issuer.O || '-'],
        ['الدولة', s.issuer.C || '-'],
        ['صالح من', new Date(s.valid_from).toLocaleString('ar-EG')],
        ['صالح حتى', new Date(s.valid_until).toLocaleString('ar-EG')],
        ['الأيام المتبقية', badge(s.days_remaining + ' يوم', s.is_expired ? 'danger' : (s.days_remaining < 30 ? 'warning' : 'success'))],
        ['نوع المفتاح', s.key_type],
        ['خوارزمية التوقيع', s.signature_algorithm],
        ['الرقم التسلسلي', s.serial_number],
        ['TLS Version', s.tls_version],
        ['الشفرة المستخدمة', `${s.cipher.name} (${s.cipher.bits} bit)`],
        ['عدد SANs', s.san_count]
    ];
    wrap.appendChild(section('تفاصيل الشهادة', kvGrid(issuerItems)));
    wrap.appendChild(section('SHA-256 Fingerprint',
        el('div', { class: 'fingerprint' }, s.fingerprint_sha256)
    ));
    wrap.appendChild(section('SHA-1 Fingerprint',
        el('div', { class: 'fingerprint' }, s.fingerprint_sha1)
    ));
    if (s.san && s.san.length) {
        const sanList = el('div', { class: 'subdomain-list' });
        s.san.forEach(d => sanList.appendChild(el('div', { class: 'subdomain-item' }, d)));
        wrap.appendChild(section(`📜 Subject Alternative Names (${s.san_count})`, sanList));
    }
    return wrap;
}

function renderSSL(r) {
    if (r.error) {
        elements.resultsBody.innerHTML = `<div class="empty-state"><div class="empty-state-icon">🔒</div><h4>${r.error}</h4><p>الموقع قد لا يدعم HTTPS</p></div>`;
        return;
    }
    elements.resultsBody.appendChild(sslSection(r));
}

function renderPorts(r) {
    elements.resultsBody.appendChild(section('ملخص الفحص',
        kvGrid([
            ['IP المُفحوص', r.ip],
            ['عدد المنافذ المفحوصة', r.scanned],
            ['المنافذ المفتوحة', r.open_ports.length],
            ['الحالة', r.open_ports.length > 0 ? badge(`⚠ ${r.open_ports.length} منفذ مفتوح`, 'warning') : badge('✓ لا توجد منافذ مفتوحة', 'success')]
        ])
    ));
    if (r.open_ports.length) {
        const grid = el('div', { class: 'ports-grid' });
        r.open_ports.forEach(p => {
            const item = el('div', { class: 'port-item' });
            item.appendChild(el('div', { class: 'port-status' }));
            item.appendChild(el('div', { class: 'port-num' }, String(p.port)));
            item.appendChild(el('div', { class: 'port-service' }, p.service));
            grid.appendChild(item);
        });
        elements.resultsBody.appendChild(section('🚪 المنافذ المفتوحة', grid));
    } else {
        elements.resultsBody.appendChild(section('المنافذ',
            el('div', { class: 'empty-state' },
                el('div', { class: 'empty-state-icon' }, '🛡️'),
                el('h4', {}, 'لا توجد منافذ مفتوحة'),
                el('p', {}, 'جميع المنافذ الشائعة مغلقة أو مُحمّية بجدار ناري')
            )
        ));
    }
}

function renderSubdomains(r) {
    elements.resultsBody.appendChild(section('الملخص',
        kvGrid([
            ['إجمالي السجلات', r.count],
            ['النطاقات الفرعية الفريدة', r.unique_subdomains]
        ])
    ));
    if (r.subdomains && r.subdomains.length) {
        elements.resultsBody.appendChild(subdomainSection(r));
    } else {
        elements.resultsBody.appendChild(el('div', { class: 'empty-state' },
            el('div', { class: 'empty-state-icon' }, '🔍'),
            el('h4', {}, 'لم يتم العثور على نطاقات فرعية')
        ));
    }
}

function subdomainSection(r) {
    const list = el('div', { class: 'subdomain-list' });
    r.subdomains.forEach(d => {
        const item = el('div', { class: 'subdomain-item' }, d);
        item.addEventListener('click', () => {
            document.getElementById('subdomains-target').value = d;
            switchTab('info');
        });
        list.appendChild(item);
    });
    return section(`🌐 النطاقات الفرعية (${r.subdomains.length})`, list);
}

function renderRedirects(r) {
    if (!r.length) {
        elements.resultsBody.innerHTML = `<div class="empty-state"><div class="empty-state-icon">↬</div><h4>لا توجد تحويلات</h4><p>الموقع لا يحتوي على redirect chain</p></div>`;
        return;
    }
    const grid = el('div', { class: 'kv-grid' });
    r.forEach((step, i) => {
        const item = el('div', { class: 'kv-item' });
        item.appendChild(el('div', { class: 'kv-key' }, `القفزة ${i + 1}`));
        const valEl = el('div', { class: 'kv-val' });
        if (step.error) {
            valEl.textContent = step.error;
        } else {
            valEl.appendChild(document.createTextNode(step.url));
            valEl.appendChild(document.createElement('br'));
            valEl.appendChild(badge(`HTTP ${step.status}`, step.status < 400 ? 'success' : 'warning'));
            if (step.headers_security) {
                valEl.appendChild(document.createElement('br'));
                valEl.appendChild(badge('HSTS: ' + (step.headers_security.HSTS ? '✓' : '✗'), step.headers_security.HSTS ? 'success' : 'danger'));
                valEl.appendChild(el('span', { style: 'margin: 0 4px;' }));
                valEl.appendChild(badge('CSP: ' + (step.headers_security.CSP ? '✓' : '✗'), step.headers_security.CSP ? 'success' : 'danger'));
                valEl.appendChild(el('span', { style: 'margin: 0 4px;' }));
                valEl.appendChild(badge('X-Frame: ' + step.headers_security['X-Frame-Options'], step.headers_security['X-Frame-Options'] !== '❌' ? 'success' : 'danger'));
            }
        }
        item.appendChild(valEl);
        grid.appendChild(item);
    });
    elements.resultsBody.appendChild(section(`↬ سلسلة التحويلات (${r.length} قفزة)`, grid));
}

function renderReputation(r) {
    if (r.geoip && !r.geoip.error) {
        elements.resultsBody.appendChild(geoipSection(r.geoip));
    }
    if (r.dnsbl && r.dnsbl.length) {
        elements.resultsBody.appendChild(dnsblSection(r.dnsbl));
    }
    if (r.scanners) {
        const filtered = {};
        if (r.scanners.abuseipdb) filtered.abuseipdb = r.scanners.abuseipdb;
        if (r.scanners.scamadviser) filtered.scamadviser = r.scanners.scamadviser;
        if (r.scanners.threatcrowd) filtered.threatcrowd = r.scanners.threatcrowd;
        if (Object.keys(filtered).length) {
            r.scanners = filtered;
            scannersSection(r);
        }
    }
}

function headersSection(h) {
    const wrap = el('div');
    const summary = kvGrid([
        ['Status Code', h.status_code],
        ['Server', h.server || '-'],
        ['X-Powered-By', h.powered_by || '-'],
        ['Content-Type', h.content_type || '-'],
        ['Final URL', h.final_url]
    ]);
    wrap.appendChild(section('HTTP Headers - ملخص', summary));
    if (h.security_headers) {
        const secItems = [];
        for (const [k, v] of Object.entries(h.security_headers)) {
            if (k === 'msg') continue;
            secItems.push([k, v === '❌ غير موجود' ? badge('❌ غير موجود', 'danger') : badge('✓ ' + v, 'success')]);
        }
        wrap.appendChild(section('🛡️ Security Headers', kvGrid(secItems)));
    }
    if (h.headers) {
        const allHeaders = Object.entries(h.headers).map(([k, v]) => [k, v]);
        const grid = el('div', { class: 'kv-grid' });
        allHeaders.forEach(([k, v]) => {
            const item = el('div', { class: 'kv-item' });
            item.appendChild(el('div', { class: 'kv-key' }, k));
            const valEl = el('div', { class: 'kv-val' });
            valEl.textContent = v;
            item.appendChild(valEl);
            grid.appendChild(item);
        });
        wrap.appendChild(section('📋 كل الـ Headers', grid));
    }
    return wrap;
}
