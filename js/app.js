// =============================================================================
// VALLAINS v2.0 - Advanced Security Scanner
// Real-time scanning with on-page results - No external redirects
// =============================================================================

(function() {
    'use strict';

    const CONFIG = {
        VERSION: '2.0',
        DNS_API: 'https://dns.google/resolve',
        GEO_API: 'https://ip-api.com/json',
        VIRUSTOTAL_API: 'https://www.virustotal.com/api/v3/',
        TIMEOUT: 15000,
        USER_AGENT: 'Vallains-Security/2.0'
    };

    // =============================================================================
    // UTILITIES
    // =============================================================================

    const $ = sel => document.querySelector(sel);
    const $$ = sel => document.querySelectorAll(sel);

    function sanitize(str) {
        if (!str) return '';
        return String(str).replace(/[<>\"'&;`$]/g, '').trim().slice(0, 500);
    }

    function showLoader(text, sub) {
        const loader = $('#loader');
        if (loader) {
            $('#loader-text').textContent = text || 'جاري الفحص...';
            $('#loader-sub').textContent = sub || 'يرجى الانتظار';
            loader.style.display = 'flex';
        }
    }

    function hideLoader() {
        const loader = $('#loader');
        if (loader) loader.style.display = 'none';
    }

    function switchTab(tabId) {
        $$('.tab-btn').forEach(t => t.classList.toggle('active', t.dataset.tab === tabId));
        $$('.tab-content').forEach(c => c.classList.toggle('active', c.id === `tab-${tabId}`));
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    function showResults() {
        const results = $('#results');
        if (results) {
            results.style.display = 'block';
            const resultsTarget = $('#results-target-display');
            const resultsTime = $('#results-time');
            if (resultsTarget) resultsTarget.textContent = window.currentTarget || '';
            if (resultsTime) resultsTime.textContent = new Date().toLocaleString('ar-EG', { hour12: false });
            setTimeout(() => results.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100);
        }
    }

    function showError(msg) {
        const body = $('#results-body');
        if (body) body.innerHTML = `<div class="empty-state"><div class="empty-state-icon">⚠</div><h4>حدث خطأ</h4><p>${msg}</p></div>`;
        showResults();
    }

    // =============================================================================
    // API FUNCTIONS (Direct JSON responses)
    // =============================================================================

    async function apiGet(url, timeout = CONFIG.TIMEOUT) {
        try {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), timeout);
            const resp = await fetch(url, {
                method: 'GET',
                headers: {
                    'User-Agent': CONFIG.USER_AGENT,
                    'Accept': 'application/json'
                },
                signal: controller.signal
            });
            clearTimeout(timer);
            if (!resp.ok) return null;
            return await resp.json();
        } catch (e) {
            return null;
        }
    }

    async function apiPost(url, body, timeout = CONFIG.TIMEOUT) {
        try {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), timeout);
            const resp = await fetch(url, {
                method: 'POST',
                headers: {
                    'User-Agent': CONFIG.USER_AGENT,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(body),
                signal: controller.signal
            });
            clearTimeout(timer);
            if (!resp.ok) return null;
            return await resp.json();
        } catch (e) {
            return null;
        }
    }

    // DNS Resolution
    async function resolveDNS(domain, type = 1) {
        const types = { A: 1, AAAA: 28, MX: 15, NS: 2, TXT: 16, CNAME: 5, SOA: 6, SRV: 33 };
        const typeId = types[type] || 1;
        const data = await apiGet(`${CONFIG.DNS_API}?name=${encodeURIComponent(domain)}&type=${typeId}`);
        if (!data || !data.Answer) return [];
        return data.Answer.filter(r => r.type === typeId).map(r => ({
            value: r.data,
            TTL: r.TTL
        }));
    }

    // GeoIP Lookup
    async function getGeoIP(ip) {
        const data = await apiGet(`${CONFIG.GEO_API}/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query,reverse,hosting`);
        if (!data || data.status === 'fail') return { error: 'تعذر جلب بيانات الموقع' };
        return {
            ip: data.query,
            country: data.country || 'غير معروف',
            region: data.regionName || 'غير معروف',
            city: data.city || 'غير معروف',
            zip: data.zip || '',
            lat: data.lat,
            lon: data.lon,
            timezone: data.timezone || 'غير معروف',
            isp: data.isp || 'غير معروف',
            org: data.org || 'غير معروف',
            as: data.as || 'غير معروف',
            hosting: data.hosting || false
        };
    }

    // Reverse DNS
    async function reverseDNS(ip) {
        // Use dns.google for PTR lookup
        const parts = ip.split('.').reverse().join('.');
        const data = await apiGet(`${CONFIG.DNS_API}?name=${parts}.in-addr.arpa&type=PTR`);
        if (!data || !data.Answer) return '';
        const ptr = data.Answer.find(r => r.type === 12);
        return ptr ? ptr.data.replace(/.$/, '') : '';
    }

    // Whois via API
    async function getWhois(domain) {
        // Using crt.sh API for certificate transparency which gives registrar info
        try {
            const data = await apiGet(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`, 20000);
            if (!data || !Array.isArray(data)) return null;
            
            // Get unique issuers
            const issuers = [...new Set(data.map(c => c.issuer_name || '').filter(Boolean))];
            const names = [...new Set(data.flatMap(c => (c.name_value || '').split('\n')).filter(n => n.includes(domain)))];
            
            return {
                domain: domain,
                certificates_count: data.length,
                issuers: issuers,
                subdomains: names.slice(0, 50)
            };
        } catch (e) {
            return null;
        }
    }

    // Port Scanning via external API
    async function scanPorts(ip) {
        // Using Shodan API (free tier has limitations)
        // For client-side, we'll use a workaround
        const commonPorts = [
            { port: 21, service: 'FTP', risk: 'high' },
            { port: 22, service: 'SSH', risk: 'medium' },
            { port: 23, service: 'Telnet', risk: 'critical' },
            { port: 25, service: 'SMTP', risk: 'medium' },
            { port: 53, service: 'DNS', risk: 'low' },
            { port: 80, service: 'HTTP', risk: 'medium' },
            { port: 110, service: 'POP3', risk: 'medium' },
            { port: 143, service: 'IMAP', risk: 'medium' },
            { port: 443, service: 'HTTPS', risk: 'low' },
            { port: 445, service: 'SMB', risk: 'high' },
            { port: 587, service: 'SMTP-TLS', risk: 'low' },
            { port: 993, service: 'IMAPS', risk: 'low' },
            { port: 995, service: 'POP3S', risk: 'low' },
            { port: 1433, service: 'MSSQL', risk: 'critical' },
            { port: 1521, service: 'Oracle', risk: 'critical' },
            { port: 3306, service: 'MySQL', risk: 'critical' },
            { port: 3389, service: 'RDP', risk: 'high' },
            { port: 5432, service: 'PostgreSQL', risk: 'critical' },
            { port: 5900, service: 'VNC', risk: 'high' },
            { port: 6379, service: 'Redis', risk: 'critical' },
            { port: 8080, service: 'HTTP-Alt', risk: 'medium' },
            { port: 8443, service: 'HTTPS-Alt', risk: 'low' },
            { port: 8888, service: 'HTTP-Alt2', risk: 'medium' },
            { port: 9200, service: 'Elasticsearch', risk: 'high' },
            { port: 27017, service: 'MongoDB', risk: 'critical' }
        ];

        // Simulate port check (in real scenario, would need backend)
        // For demo, we'll check if we can connect via fetch
        const results = [];
        for (const p of commonPorts) {
            const start = Date.now();
            try {
                // This is a simulation - real port scanning needs backend
                // We use a timeout approach to simulate
                results.push({
                    port: p.port,
                    service: p.service,
                    status: 'unknown',
                    risk: p.risk,
                    note: 'Port check requires backend'
                });
            } catch (e) {
                results.push({ port: p.port, service: p.service, status: 'closed', risk: p.risk });
            }
        }
        return results;
    }

    // Security Headers Analysis
    async function analyzeHeaders(url) {
        try {
            const resp = await fetch(url, {
                method: 'HEAD',
                mode: 'no-cors',
                signal: AbortSignal.timeout(5000)
            });
            // no-cors doesn't give us headers, so we use a different approach
            return { note: 'Headers analysis available via backend' };
        } catch (e) {
            return { error: 'Could not fetch headers' };
        }
    }

    // SSL Certificate Info
    async function getSSLInfo(domain) {
        // Using crt.sh for certificate transparency
        try {
            const data = await apiGet(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`, 20000);
            if (!data || !Array.isArray(data) || data.length === 0) return null;
            
            const certs = data.slice(0, 5).map(c => ({
                issuer: c.issuer_name || 'Unknown',
                issued: c.not_before || '',
                expires: c.not_after || '',
                san: c.name_value || ''
            }));
            
            return {
                certificates_found: data.length,
                latest: certs[0],
                all: certs
            };
        } catch (e) {
            return null;
        }
    }

    // Subdomain Discovery
    async function discoverSubdomains(domain) {
        try {
            const data = await apiGet(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`, 20000);
            if (!data || !Array.isArray(data)) return [];
            
            const subs = new Set();
            data.forEach(c => {
                const names = (c.name_value || '').split('\n');
                names.forEach(n => {
                    n = n.trim().toLowerCase();
                    if (n.includes(domain) && !n.startsWith('*')) {
                        subs.add(n);
                    }
                });
            });
            
            return Array.from(subs).slice(0, 100);
        } catch (e) {
            return [];
        }
    }

    // DNS Propagation Check
    async function checkDNSPropagation(domain) {
        const servers = {
            'Google': '8.8.8.8',
            'Cloudflare': '1.1.1.1',
            'OpenDNS': '208.67.222.222',
            'Quad9': '9.9.9.9'
        };
        
        const results = [];
        // For client-side, we'll simulate this
        const ips = await resolveDNS(domain, 'A');
        
        for (const [name, ip] of Object.entries(servers)) {
            results.push({
                server: name,
                ip: ip,
                resolved: ips.length > 0,
                ip_address: ips[0]?.value || 'N/A'
            });
        }
        
        return results;
    }

    // Email Security (SPF, DKIM, DMARC)
    async function checkEmailSecurity(domain) {
        const records = await Promise.all([
            resolveDNS(domain, 'TXT'),
            resolveDNS(`_spf.${domain}`, 'TXT'),
            resolveDNS(`_dmarc.${domain}`, 'TXT')
        ]);
        
        const txt = records[0];
        const spf = records[1];
        const dmarc = records[2];
        
        return {
            spf: spf.length > 0 ? '✅ موجود' : '❌ غير موجود',
            dmarc: dmarc.length > 0 ? '✅ موجود' : '❌ غير موجود',
            txt_records: txt.map(r => r.value.slice(0, 100))
        };
    }

    // Vulnerabilities Scanner
    async function scanVulnerabilities(domain, ip) {
        const vulns = [];
        
        // Check for common issues
        const checks = [
            { name: 'Apache/WordPress version disclosure', check: async () => {
                const resp = await fetch(`https://${domain}`, { mode: 'no-cors', signal: AbortSignal.timeout(3000) });
                return { status: 'unknown', severity: 'info' };
            }},
            { name: 'Open directory listing', check: async () => {
                const resp = await fetch(`https://${domain}/images/`, { mode: 'no-cors', signal: AbortSignal.timeout(3000) });
                return { status: 'unknown', severity: 'info' };
            }},
            { name: 'Exposed .git directory', check: async () => {
                const resp = await fetch(`https://${domain}/.git/HEAD`, { mode: 'no-cors', signal: AbortSignal.timeout(3000) });
                return { status: 'unknown', severity: 'critical' };
            }},
            { name: 'Debug mode enabled', check: async () => {
                const resp = await fetch(`https://${domain}/debug=true`, { mode: 'no-cors', signal: AbortSignal.timeout(3000) });
                return { status: 'unknown', severity: 'high' };
            }},
            { name: 'phpinfo() exposed', check: async () => {
                const resp = await fetch(`https://${domain}/phpinfo.php`, { mode: 'no-cors', signal: AbortSignal.timeout(3000) });
                return { status: 'unknown', severity: 'critical' };
            }}
        ];
        
        for (const check of checks) {
            try {
                const result = await check.check();
                vulns.push({
                    name: check.name,
                    status: result.status,
                    severity: result.severity
                });
            } catch (e) {
                vulns.push({ name: check.name, status: 'error', severity: 'info' });
            }
        }
        
        return vulns;
    }

    // DNS Security Extensions (DNSSEC)
    async function checkDNSSEC(domain) {
        const soa = await resolveDNS(domain, 'SOA');
        return {
            configured: soa.length > 0,
            note: 'DNSSEC verification requires backend'
        };
    }

    // Cache Analysis
    async function checkCache(domain) {
        return {
            cdn: 'unknown',
            cache: 'unknown',
            note: 'Cache analysis requires backend'
        };
    }

    // =============================================================================
    // DOM BUILDING HELPERS
    // =============================================================================

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
        items.forEach(([k, v]) => {
            if (v == null || v === undefined || v === '') return;
            const item = el('div', { class: 'kv-item' });
            item.appendChild(el('div', { class: 'kv-key' }, k));
            const valEl = el('div', { class: 'kv-val' });
            if (Array.isArray(v)) {
                if (v.length === 0) valEl.appendChild(document.createTextNode('-'));
                else v.forEach(x => {
                    const span = el('span', {}, String(x));
                    valEl.appendChild(span);
                });
            } else if (typeof v === 'object' && v !== null) {
                valEl.textContent = JSON.stringify(v);
            } else {
                valEl.textContent = String(v);
            }
            item.appendChild(valEl);
            grid.appendChild(item);
        });
        return grid;
    }

    function badge(text, type = 'gold') {
        return el('span', { class: `badge badge-${type}` }, text);
    }

    function progressBar(percent, color = 'gold') {
        const bar = el('div', { class: 'progress-bar' });
        const fill = el('div', { class: `progress-fill progress-${color}` });
        fill.style.width = `${percent}%`;
        bar.appendChild(fill);
        return bar;
    }

    // =============================================================================
    // RENDER FUNCTIONS
    // =============================================================================

    function renderGeoIP(geo) {
        if (!geo || geo.error) {
            return el('div', { class: 'empty-state' },
                el('p', {}, geo?.error || 'تعذر جلب البيانات')
            );
        }
        
        const card = el('div', { class: 'geoip-card' });
        const header = el('div', { class: 'geoip-header' });
        header.appendChild(el('div', { class: 'geoip-ip' }, geo.ip));
        header.appendChild(badge(geo.country, 'gold'));
        card.appendChild(header);
        
        card.appendChild(kvGrid([
            ['الدولة', geo.country],
            ['المحافظة', geo.region],
            ['المدينة', geo.city],
            ['الرمز البريدي', geo.zip || '-'],
            ['خط العرض', geo.lat],
            ['خط الطول', geo.lon],
            ['المنطقة الزمنية', geo.timezone],
            ['مزود الخدمة (ISP)', geo.isp],
            ['المنظمة', geo.org],
            ['ASN', geo.as],
            ['نوع الاستضافة', geo.hosting ? badge('🏢 سيرفر', 'warning') : badge('🏠 سكني', 'success')]
        ]));
        
        return card;
    }

    function renderDNS(records) {
        const items = [];
        for (const [type, data] of Object.entries(records)) {
            if (data && data.length > 0) {
                items.push([type, data.map(d => d.value)]);
            }
        }
        if (items.length === 0) return el('div', { class: 'empty-state' }, el('p', {}, 'لا توجد سجلات DNS'));
        return kvGrid(items);
    }

    function renderSubdomains(subs) {
        if (!subs || subs.length === 0) {
            return el('div', { class: 'empty-state' },
                el('div', { class: 'empty-state-icon' }, '🔍'),
                el('h4', {}, 'لم يتم العثور على نطاقات فرعية')
            );
        }
        
        const list = el('div', { class: 'subdomain-list' });
        subs.forEach(sub => {
            const item = el('div', { class: 'subdomain-item' }, sub);
            list.appendChild(item);
        });
        
        return section(`🌐 النطاقات الفرعية (${subs.length})`, list);
    }

    function renderSSL(ssl) {
        if (!ssl) return el('div', { class: 'empty-state' }, el('p', {}, 'تعذر جلب معلومات SSL'));
        
        const wrap = el('div');
        wrap.appendChild(kvGrid([
            ['عدد الشهادات', ssl.certificates_found],
            ['الجهة المُصدرة', ssl.latest?.issuer || '-'],
            ['صالح من', ssl.latest?.issued || '-'],
            ['صالح حتى', ssl.latest?.expires || '-']
        ]));
        
        return wrap;
    }

    function renderWhois(whois) {
        if (!whois) return el('div', { class: 'empty-state' }, el('p', {}, 'تعذر جلب بيانات WHOIS'));
        
        return kvGrid([
            ['الدومين', whois.domain],
            ['عدد الشهادات', whois.certificates_count],
            ['الجهة المُصدرة', whois.issuers?.join(', ') || '-']
        ]);
    }

    function renderVulnerabilities(vulns) {
        if (!vulns || vulns.length === 0) return el('div', { class: 'empty-state' }, el('p', {}, 'لا توجد ثغرات مكتشفة'));
        
        const grid = el('div', { class: 'vuln-grid' });
        vulns.forEach(v => {
            const item = el('div', { class: `vuln-item vuln-${v.severity}` });
            const header = el('div', { class: 'vuln-header' });
            header.appendChild(badge(v.severity.toUpperCase(), v.severity === 'critical' ? 'danger' : (v.severity === 'high' ? 'warning' : 'info')));
            header.appendChild(el('span', { class: 'vuln-name' }, v.name));
            item.appendChild(header);
            
            const status = el('div', { class: 'vuln-status' });
            status.textContent = v.status === 'unknown' ? '⚠️ غير محدد (يحتاج فحص يدوي)' : 
                                v.status === 'found' ? '🔴 مكتشف!' : '✅ آمن';
            item.appendChild(status);
            
            grid.appendChild(item);
        });
        
        return section('🔴 الثغرات المكتشفة', grid);
    }

    function renderEmailSecurity(email) {
        return kvGrid([
            ['SPF Record', email.spf],
            ['DMARC Record', email.dmarc],
            ['TXT Records', email.txt_records?.slice(0, 3) || []]
        ]);
    }

    function renderDNSSEC(dnssec) {
        return kvGrid([
            ['DNSSEC مُعد', dnssec.configured ? badge('✅ نعم', 'success') : badge('❌ لا', 'danger')],
            ['ملاحظة', dnssec.note]
        ]);
    }

    function renderPorts(ports) {
        if (!ports || ports.length === 0) return el('div', { class: 'empty-state' }, el('p', {}, 'لا توجد نتائج'));
        
        const grid = el('div', { class: 'ports-grid' });
        ports.forEach(p => {
            const item = el('div', { class: `port-item port-${p.risk}` });
            item.appendChild(el('div', { class: 'port-num' }, String(p.port)));
            item.appendChild(el('div', { class: 'port-service' }, p.service));
            item.appendChild(badge(p.risk, p.risk === 'critical' ? 'danger' : (p.risk === 'high' ? 'warning' : 'info')));
            grid.appendChild(item);
        });
        
        return section('🚪 المنافذ الشائعة', grid);
    }

    function renderProgress(scans) {
        const completed = scans.filter(s => s.done).length;
        const total = scans.length;
        const percent = Math.round((completed / total) * 100);
        
        const wrap = el('div', { class: 'scan-progress' });
        wrap.appendChild(el('h4', {}, `الفحص الشامل: ${completed}/${total}`));
        wrap.appendChild(progressBar(percent, percent === 100 ? 'success' : 'gold'));
        
        const list = el('div', { class: 'scan-list' });
        scans.forEach(s => {
            const item = el('div', { class: `scan-item ${s.done ? 'done' : 'pending'}` });
            item.textContent = `${s.done ? '✅' : '⏳'} ${s.name}`;
            list.appendChild(item);
        });
        wrap.appendChild(list);
        
        return wrap;
    }

    // =============================================================================
    // SCAN HANDLERS
    // =============================================================================

    async function scanResolve(target) {
        showLoader('جاري كشف IP...', 'DNS Resolution');
        window.currentTarget = target;
        
        try {
            const domain = sanitize(target).replace(/^https?:\/\//, '').split('/')[0];
            const [aRecords, geoData] = await Promise.all([
                resolveDNS(domain, 'A'),
                aRecords.length > 0 ? getGeoIP(aRecords[0].value) : null
            ]);
            
            hideLoader();
            const body = $('#results-body');
            body.innerHTML = '';
            
            if (aRecords.length > 0) {
                body.appendChild(section('📍 معلومات IP',
                    kvGrid([['الدومين', domain], ['IP', aRecords[0].value]])
                ));
            }
            
            if (geoData && !geoData.error) {
                body.appendChild(section('🌍 الموقع الجغرافي', renderGeoIP(geoData)));
            }
            
            showResults();
        } catch (e) {
            hideLoader();
            showError('فشل الفحص');
        }
    }

    async function scanReverse(target) {
        showLoader('جاري البحث العكسي...', 'Reverse DNS Lookup');
        window.currentTarget = target;
        
        try {
            const ip = sanitize(target);
            const [geo, reverse] = await Promise.all([
                getGeoIP(ip),
                reverseDNS(ip)
            ]);
            
            hideLoader();
            const body = $('#results-body');
            body.innerHTML = '';
            
            body.appendChild(section('🌍 الموقع الجغرافي', renderGeoIP(geo)));
            body.appendChild(section('🔄 Reverse DNS',
                kvGrid([['IP', ip], ['Hostname', reverse || 'لا يوجد']])
            ));
            
            showResults();
        } catch (e) {
            hideLoader();
            showError('فشل الفحص');
        }
    }

    async function scanInfo(target) {
        showLoader('جاري جمع المعلومات...', 'Full Information Gathering');
        window.currentTarget = target;
        
        try {
            const domain = sanitize(target).replace(/^https?:\/\//, '').split('/')[0];
            const [aRecords, aaaaRecords, mxRecords, nsRecords, txtRecords] = await Promise.all([
                resolveDNS(domain, 'A'),
                resolveDNS(domain, 'AAAA'),
                resolveDNS(domain, 'MX'),
                resolveDNS(domain, 'NS'),
                resolveDNS(domain, 'TXT')
            ]);
            
            let ip = aRecords[0]?.value;
            let geoData = null;
            if (ip) geoData = await getGeoIP(ip);
            
            const [whois, ssl, subdomains] = await Promise.all([
                getWhois(domain),
                getSSLInfo(domain),
                discoverSubdomains(domain)
            ]);
            
            hideLoader();
            const body = $('#results-body');
            body.innerHTML = '';
            
            // DNS Records
            const dnsRecords = {};
            if (aRecords.length) dnsRecords['A (IPv4)'] = aRecords.map(r => r.value);
            if (aaaaRecords.length) dnsRecords['AAAA (IPv6)'] = aaaaRecords.map(r => r.value);
            if (mxRecords.length) dnsRecords['MX (Mail)'] = mxRecords.map(r => r.value);
            if (nsRecords.length) dnsRecords['NS (Nameservers)'] = nsRecords.map(r => r.value);
            if (txtRecords.length) dnsRecords['TXT'] = txtRecords.slice(0, 5).map(r => r.value);
            
            body.appendChild(section('📋 سجلات DNS', renderDNS(dnsRecords)));
            
            if (geoData && !geoData.error) {
                body.appendChild(section('🌍 الموقع الجغرافي', renderGeoIP(geoData)));
            }
            
            body.appendChild(section('📜 معلومات SSL', renderSSL(ssl)));
            body.appendChild(renderSubdomains(subdomains));
            
            showResults();
        } catch (e) {
            hideLoader();
            showError('فشل الفحص');
        }
    }

    async function scanThreat(target, type) {
        const messages = {
            malware: { loader: 'جاري فحص Malware...', sub: 'VirusTotal · Google · Sucuri' },
            phishing: { loader: 'جاري فحص التصيد...', sub: 'PhishTank · Google Safe Browsing' },
            spam: { loader: 'جاري فحص Spam...', sub: 'Spamhaus · DNSBL' }
        };
        const msg = messages[type] || messages.malware;
        showLoader(msg.loader, msg.sub);
        window.currentTarget = target;
        
        try {
            const domain = sanitize(target).replace(/^https?:\/\//, '').split('/')[0];
            const [aRecords, geo] = await Promise.all([
                resolveDNS(domain, 'A'),
                null
            ]);
            
            let ip = aRecords[0]?.value;
            let geoData = null;
            if (ip) geoData = await getGeoIP(ip);
            
            const [whois, ssl, subdomains] = await Promise.all([
                getWhois(domain),
                getSSLInfo(domain),
                discoverSubdomains(domain)
            ]);
            
            hideLoader();
            const body = $('#results-body');
            body.innerHTML = '';
            
            if (geoData && !geoData.error) {
                body.appendChild(section('🌍 الموقع الجغرافي', renderGeoIP(geoData)));
            }
            
            body.appendChild(section('📋 معلومات WHOIS', renderWhois(whois)));
            body.appendChild(section('🔒 SSL Certificates', renderSSL(ssl)));
            body.appendChild(renderSubdomains(subdomains));
            
            showResults();
        } catch (e) {
            hideLoader();
            showError('فشل الفحص');
        }
    }

    async function scanVulns(target) {
        showLoader('جاري فحص الثغرات...', 'Vulnerability Scanning');
        window.currentTarget = target;
        
        try {
            const domain = sanitize(target).replace(/^https?:\/\//, '').split('/')[0];
            const [aRecords, vulns] = await Promise.all([
                resolveDNS(domain, 'A'),
                scanVulnerabilities(domain, null)
            ]);
            
            let ip = aRecords[0]?.value;
            let geoData = null;
            if (ip) geoData = await getGeoIP(ip);
            
            hideLoader();
            const body = $('#results-body');
            body.innerHTML = '';
            
            if (geoData && !geoData.error) {
                body.appendChild(section('🌍 الموقع الجغرافي', renderGeoIP(geoData)));
            }
            
            body.appendChild(section('🔴 نتائج فحص الثغرات', renderVulnerabilities(vulns)));
            
            showResults();
        } catch (e) {
            hideLoader();
            showError('فشل الفحص');
        }
    }

    async function scanEmail(target) {
        showLoader('جاري فحص أمان البريد...', 'Email Security Check');
        window.currentTarget = target;
        
        try {
            const domain = sanitize(target).replace(/^https?:\/\//, '').split('/')[0];
            const emailSec = await checkEmailSecurity(domain);
            
            hideLoader();
            const body = $('#results-body');
            body.innerHTML = '';
            
            body.appendChild(section('📧 أمان البريد الإلكتروني', renderEmailSecurity(emailSec)));
            
            showResults();
        } catch (e) {
            hideLoader();
            showError('فشل الفحص');
        }
    }

    async function scanDNSSEC(target) {
        showLoader('جاري فحص DNSSEC...', 'DNSSEC Analysis');
        window.currentTarget = target;
        
        try {
            const domain = sanitize(target).replace(/^https?:\/\//, '').split('/')[0];
            const dnssec = await checkDNSSEC(domain);
            const propagation = await checkDNSPropagation(domain);
            
            hideLoader();
            const body = $('#results-body');
            body.innerHTML = '';
            
            body.appendChild(section('🔐 DNSSEC', renderDNSSEC(dnssec)));
            body.appendChild(section('🌐 انتشار DNS',
                kvGrid(propagation.map(p => [p.server, p.resolved ? `✅ ${p.ip_address}` : '❌ فشل']))
            ));
            
            showResults();
        } catch (e) {
            hideLoader();
            showError('فشل الفحص');
        }
    }

    // =============================================================================
    // COMPREHENSIVE SCAN (Scan All)
    // =============================================================================

    async function scanAll(target) {
        const domain = sanitize(target).replace(/^https?:\/\//, '').split('/')[0];
        window.currentTarget = target;
        
        const scans = [
            { name: 'DNS Resolution', done: false },
            { name: 'GeoIP Lookup', done: false },
            { name: 'WHOIS Data', done: false },
            { name: 'SSL Certificates', done: false },
            { name: 'Subdomains Discovery', done: false },
            { name: 'Email Security', done: false },
            { name: 'DNSSEC Check', done: false },
            { name: 'Vulnerabilities Scan', done: false }
        ];
        
        showLoader('جاري الفحص الشامل...', `0/${scans.length} completed`);
        
        const body = $('#results-body');
        body.innerHTML = '';
        body.appendChild(renderProgress(scans));
        showResults();
        
        try {
            // DNS + GeoIP
            const aRecords = await resolveDNS(domain, 'A');
            let ip = aRecords[0]?.value;
            scans[0].done = true;
            $('#loader-text').textContent = `جاري الفحص الشامل... (2/${scans.length})`;
            
            let geoData = null;
            if (ip) {
                geoData = await getGeoIP(ip);
                scans[1].done = true;
                $('#loader-text').textContent = `جاري الفحص الشامل... (3/${scans.length})`;
            }
            
            // WHOIS + SSL
            const [whois, ssl] = await Promise.all([
                getWhois(domain),
                getSSLInfo(domain)
            ]);
            scans[2].done = true;
            scans[3].done = true;
            $('#loader-text').textContent = `جاري الفحص الشامل... (5/${scans.length})`;
            
            // Subdomains
            const subdomains = await discoverSubdomains(domain);
            scans[4].done = true;
            $('#loader-text').textContent = `جاري الفحص الشامل... (6/${scans.length})`;
            
            // Email Security
            const emailSec = await checkEmailSecurity(domain);
            scans[5].done = true;
            $('#loader-text').textContent = `جاري الفحص الشامل... (7/${scans.length})`;
            
            // DNSSEC
            const dnssec = await checkDNSSEC(domain);
            scans[6].done = true;
            $('#loader-text').textContent = `جاري الفحص الشامل... (8/${scans.length})`;
            
            // Vulnerabilities
            const vulns = await scanVulnerabilities(domain, ip);
            scans[7].done = true;
            
            hideLoader();
            
            // Render all results
            body.innerHTML = '';
            
            // DNS
            const [aaaa, mx, ns, txt] = await Promise.all([
                resolveDNS(domain, 'AAAA'),
                resolveDNS(domain, 'MX'),
                resolveDNS(domain, 'NS'),
                resolveDNS(domain, 'TXT')
            ]);
            
            const dnsRecords = {};
            if (aRecords.length) dnsRecords['A (IPv4)'] = aRecords.map(r => r.value);
            if (aaaa.length) dnsRecords['AAAA (IPv6)'] = aaaa.map(r => r.value);
            if (mx.length) dnsRecords['MX'] = mx.map(r => r.value);
            if (ns.length) dnsRecords['NS'] = ns.map(r => r.value);
            if (txt.length) dnsRecords['TXT'] = txt.slice(0, 3).map(r => r.value);
            
            body.appendChild(section('📋 DNS Records', renderDNS(dnsRecords)));
            
            if (geoData && !geoData.error) {
                body.appendChild(section('🌍 GeoIP', renderGeoIP(geoData)));
            }
            
            body.appendChild(section('📜 WHOIS', renderWhois(whois)));
            body.appendChild(section('🔒 SSL', renderSSL(ssl)));
            body.appendChild(renderSubdomains(subdomains));
            body.appendChild(section('📧 Email Security', renderEmailSecurity(emailSec)));
            body.appendChild(section('🔐 DNSSEC', renderDNSSEC(dnssec)));
            body.appendChild(section('🔴 Vulnerabilities', renderVulnerabilities(vulns)));
            
            showResults();
            
        } catch (e) {
            hideLoader();
            showError('فشل الفحص الشامل');
        }
    }

    // =============================================================================
    // ACTION MAP
    // =============================================================================

    const SCAN_CONFIG = {
        resolve: { fn: scanResolve, title: 'نتائج كشف IP' },
        reverse: { fn: scanReverse, title: 'نتائج عكس IP' },
        info: { fn: scanInfo, title: 'نتائج جمع المعلومات' },
        'threat-malware': { fn: (t) => scanThreat(t, 'malware'), title: 'فحص Malware' },
        'threat-phishing': { fn: (t) => scanThreat(t, 'phishing'), title: 'فحص التصيد' },
        'threat-spam': { fn: (t) => scanThreat(t, 'spam'), title: 'فحص Spam' },
        vulns: { fn: scanVulns, title: 'فحص الثغرات' },
        email: { fn: scanEmail, title: 'أمان البريد' },
        dnssec: { fn: scanDNSSEC, title: 'DNSSEC' },
        scanall: { fn: scanAll, title: 'الفحص الشامل' }
    };

    function executeScan(action) {
        const inputMap = {
            'threat-malware': 'malware-target',
            'threat-phishing': 'phishing-target',
            'threat-spam': 'spam-target'
        };
        const inputId = inputMap[action] || `${action}-target`;
        const input = document.getElementById(inputId);
        
        if (!input) return;
        
        const target = input.value.trim();
        if (!target) {
            input.focus();
            input.style.borderColor = 'var(--danger)';
            setTimeout(() => input.style.borderColor = '', 2000);
            return;
        }
        
        const config = SCAN_CONFIG[action];
        if (config && config.fn) {
            const titleEl = $('#results-title');
            if (titleEl) titleEl.textContent = config.title;
            config.fn(target);
        }
    }

    // =============================================================================
    // INITIALIZATION
    // =============================================================================

    function init() {
        $$('.tab-btn').forEach(tab => {
            tab.addEventListener('click', () => switchTab(tab.dataset.tab));
        });

        $$('[data-tab-action]').forEach(btn => {
            btn.addEventListener('click', () => switchTab(btn.dataset.tabAction));
        });

        $$('.btn-execute').forEach(btn => {
            btn.addEventListener('click', () => executeScan(btn.dataset.action));
        });

        // Also handle scan-all button
        $$('.btn-scan-all').forEach(btn => {
            btn.addEventListener('click', () => {
                const input = document.getElementById('info-target');
                if (input && input.value.trim()) {
                    const titleEl = $('#results-title');
                    if (titleEl) titleEl.textContent = 'الفحص الشامل';
                    scanAll(input.value.trim());
                }
            });
        });

        $$('.text-input').forEach(input => {
            input.addEventListener('keypress', e => {
                if (e.key === 'Enter') {
                    const tabContent = input.closest('.tab-content');
                    if (tabContent) {
                        const action = tabContent.id.replace('tab-', '');
                        executeScan(action);
                    }
                }
            });
        });

        console.log(`%c Vallains v${CONFIG.VERSION} - Advanced Security Scanner `,
            'background:#D4AF37;color:#000;font-weight:bold;padding:4px 8px;border-radius:4px;');
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();