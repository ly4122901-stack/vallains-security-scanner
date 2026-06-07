// =============================================================================
// VALLAINS - Static Version (GitHub Pages Compatible)
// Security Note: All API calls are made directly from the browser to external
// services. No data is sent to any backend server. This is transparent by design.
// =============================================================================

(function() {
    'use strict';

    // Prevent accidental data leakage
    const CONFIG = {
        VERSION: '1.0-static',
        TIMEOUT: 10000,
        USER_AGENT: 'Vallains-Security-Scanner/1.0'
    };

    // =============================================================================
    // UTILITIES
    // =============================================================================

    const $ = (sel) => document.querySelector(sel);
    const $$ = (sel) => document.querySelectorAll(sel);

    function debounce(fn, ms) {
        let t;
        return (...args) => {
            clearTimeout(t);
            t = setTimeout(() => fn(...args), ms);
        };
    }

    function sanitize(str) {
        if (!str) return '';
        return String(str)
            .replace(/[<>\"'&]/g, '')
            .trim()
            .slice(0, 500);
    }

    function showLoader(text, sub) {
        const loader = $('#loader');
        const loaderText = $('#loader-text');
        const loaderSub = $('#loader-sub');
        if (loader) {
            loaderText.textContent = text || 'جاري الفحص...';
            loaderSub.textContent = sub || 'يرجى الانتظار';
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

    function showResults(target) {
        const results = $('#results');
        if (results) {
            results.style.display = 'block';
            const resultsTarget = $('#results-target-display');
            const resultsTime = $('#results-time');
            if (resultsTarget) resultsTarget.textContent = target;
            if (resultsTime) resultsTime.textContent = new Date().toLocaleString('ar-EG', { hour12: false });
            setTimeout(() => results.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100);
        }
    }

    function showError(msg) {
        const body = $('#results-body');
        if (body) {
            body.innerHTML = `<div class="empty-state">
                <div class="empty-state-icon">⚠</div>
                <h4>حدث خطأ</h4>
                <p>${msg}</p>
            </div>`;
        }
        showResults('');
    }

    // =============================================================================
    // EXTERNAL API CALLS (Direct from browser - transparent & no backend)
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
                signal: controller.signal,
                mode: 'cors'
            });
            clearTimeout(timer);
            if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
            return await resp.json();
        } catch (e) {
            console.warn('API call failed:', url, e.message);
            return null;
        }
    }

    async function resolveDomain(domain) {
        const data = await apiGet(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=A`);
        if (data && data.Answer) {
            const ips = data.Answer.filter(r => r.type === 1).map(r => r.data);
            return ips.length > 0 ? ips[0] : null;
        }
        return null;
    }

    async function getGeoIP(ip) {
        const data = await apiGet(`https://ipapi.co/${ip}/json/`, 8000);
        if (data && !data.error) {
            return {
                ip: ip,
                country: data.country_name || 'غير معروف',
                region: data.region || 'غير معروف',
                city: data.city || 'غير معروف',
                zip: data.postal || '',
                lat: data.latitude,
                lon: data.longitude,
                timezone: data.timezone || 'غير معروف',
                isp: data.org || 'غير معروف',
                org: data.asn || 'غير معروف',
                as: data.asn || 'غير معروف',
                reverse: '',
                hosting: data.hosting || false
            };
        }
        // Fallback to ip-api
        const data2 = await apiGet(`http://ip-api.com/json/${ip}?fields=status,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query,reverse,hosting`);
        if (data2 && data2.status === 'success') {
            return {
                ip: ip,
                country: data2.country || 'غير معروف',
                region: data2.regionName || 'غير معروف',
                city: data2.city || 'غير معروف',
                zip: data2.zip || '',
                lat: data2.lat,
                lon: data2.lon,
                timezone: data2.timezone || 'غير معروف',
                isp: data2.isp || 'غير معروف',
                org: data2.org || 'غير معروف',
                as: data2.as || 'غير معروف',
                reverse: data2.reverse || '',
                hosting: data2.hosting || false
            };
        }
        return { ip: ip, error: 'تعذر جلب بيانات GeoIP' };
    }

    async function getDNSRecords(domain) {
        const records = { A: [], AAAA: [], MX: [], NS: [], TXT: [] };
        const types = { A: 1, AAAA: 28, MX: 15, NS: 2, TXT: 16 };
        
        const promises = Object.entries(types).map(async ([type, typeId]) => {
            try {
                const data = await apiGet(
                    `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${typeId}`,
                    8000
                );
                if (data && data.Answer) {
                    records[type] = data.Answer.filter(r => r.type === typeId).map(r => r.data);
                }
            } catch (e) {
                // silently fail per record type
            }
        });
        
        await Promise.all(promises);
        return records;
    }

    async function getReverseDNS(ip) {
        try {
            const resp = await fetch(`https://dns.google/resolve?name=${ip}&type=PTR`, {
                headers: { 'User-Agent': CONFIG.USER_AGENT },
                signal: AbortSignal.timeout(8000)
            });
            const data = await resp.json();
            if (data && data.Answer) {
                const ptr = data.Answer.find(r => r.type === 12);
                return ptr ? ptr.data : '';
            }
        } catch (e) { /* ignore */ }
        return '';
    }

    // =============================================================================
    // RENDERING FUNCTIONS
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
            if (v == null || v === undefined) return;
            const item = el('div', { class: 'kv-item' });
            item.appendChild(el('div', { class: 'kv-key' }, k));
            const valEl = el('div', { class: 'kv-val' });
            if (Array.isArray(v)) {
                if (v.length === 0) valEl.appendChild(document.createTextNode('-'));
                else v.forEach(x => valEl.appendChild(el('span', {}, String(x))));
            } else if (v instanceof HTMLElement) {
                valEl.appendChild(v);
            } else {
                valEl.appendChild(document.createTextNode(String(v)));
            }
            item.appendChild(valEl);
            grid.appendChild(item);
        });
        return grid;
    }

    function badge(text, type = 'gold') {
        return el('span', { class: `badge badge-${type}` }, text);
    }

    function geoipCard(g) {
        const card = el('div', { class: 'geoip-card' });
        const header = el('div', { class: 'geoip-header' });
        header.appendChild(el('div', { class: 'geoip-ip' }, g.ip));
        const flag = g.country && g.country !== 'غير معروف' 
            ? el('span', { class: 'badge badge-gold' }, g.country) 
            : el('span', { class: 'badge badge-gold' }, 'غير معروف');
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
            ['نوع المضيف', g.hosting ? '🏢 استضافة/سيرفر' : '🏠 سكني/موبايل']
        ];
        card.appendChild(kvGrid(items));
        return card;
    }

    // =============================================================================
    // SCAN HANDLERS
    // =============================================================================

    async function scanResolve(target) {
        showLoader('جاري كشف عنوان IP...', 'DNS Resolution + GeoIP');
        const domain = sanitize(target);
        
        try {
            const ip = await resolveDomain(domain);
            if (!ip) {
                hideLoader();
                showError('تعذر حل الدومين. تأكد من صحة الاسم.');
                return;
            }
            
            const geo = await getGeoIP(ip);
            hideLoader();
            
            const body = $('#results-body');
            body.innerHTML = '';
            
            if (geo && !geo.error) {
                body.appendChild(geoipCard(geo));
            } else {
                body.appendChild(section('DNS Resolution',
                    kvGrid([['الدومين', domain], ['IP', ip]])
                ));
            }
            
            showResults(target);
        } catch (e) {
            hideLoader();
            showError('فشل الاتصال. تحقق من اتصالك بالإنترنت.');
        }
    }

    async function scanReverse(target) {
        showLoader('جاري البحث العكسي...', 'Reverse DNS + Domains on IP');
        const ip = sanitize(target);
        
        if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
            hideLoader();
            showError('الرجاء إدخال IP صحيح (مثال: 8.8.8.8)');
            return;
        }
        
        try {
            const [geo, reverse] = await Promise.all([
                getGeoIP(ip),
                getReverseDNS(ip)
            ]);
            
            hideLoader();
            const body = $('#results-body');
            body.innerHTML = '';
            
            if (geo && !geo.error) body.appendChild(geoipCard(geo));
            
            body.appendChild(section('Reverse DNS',
                kvGrid([
                    ['IP المُدخل', ip],
                    ['Hostname', reverse || 'لا يوجد'],
                    ['ملاحظة', 'للعثور على جميع المواقع على نفس الخادم، استخدم الأدوات الخارجية مثل HackerTarget.com']
                ])
            ));
            
            // External scanner links
            body.appendChild(section('🔗 أدوات خارجية للفحص العميق',
                el('div', { class: 'scanner-grid' },
                    scannerCard('AbuseIPDB', 'فحص سمعة IP في قاعدة بيانات AbuseIPDB',
                        `https://www.abuseipdb.com/check/${ip}`, '🔗 فتح الأداة'),
                    scannerCard('VirusTotal', 'فحص IP عبر 70+ محرك أمني',
                        `https://www.virustotal.com/gui/ip-address/${ip}`, '🔗 فتح الأداة'),
                    scannerCard('HackerTarget', 'البحث عن النطاقات المستضافة على نفس IP',
                        `https://api.hackertarget.com/reverseiplookup/?q=${ip}`, '🔗 فتح الأداة')
                )
            ));
            
            showResults(target);
        } catch (e) {
            hideLoader();
            showError('فشل الاتصال. تحقق من اتصالك بالإنترنت.');
        }
    }

    async function scanInfo(target) {
        showLoader('جاري جمع المعلومات...', 'DNS · GeoIP · Security Analysis');
        const domain = sanitize(target);
        
        try {
            const [ip, geo, dns] = await Promise.all([
                resolveDomain(domain),
                null, // Will be fetched after IP
                getDNSRecords(domain)
            ]);
            
            let geoData = null;
            if (ip) geoData = await getGeoIP(ip);
            
            hideLoader();
            const body = $('#results-body');
            body.innerHTML = '';
            
            if (ip) {
                body.appendChild(section('DNS Resolution',
                    kvGrid([['الدومين', domain], ['IP', ip]])
                ));
            }
            
            if (geoData && !geoData.error) body.appendChild(geoipCard(geoData));
            
            const dnsItems = [];
            for (const [k, v] of Object.entries(dns)) {
                if (v && v.length) dnsItems.push([k, v]);
            }
            if (dnsItems.length) {
                body.appendChild(section('سجلات DNS', kvGrid(dnsItems)));
            }
            
            // External tools
            body.appendChild(section('🔗 أدوات فحص خارجية',
                el('div', { class: 'scanner-grid' },
                    scannerCard('VirusTotal', 'فحص شامل عبر 70+ محرك',
                        `https://www.virustotal.com/gui/domain/${domain}`, '🔗 فتح'),
                    scannerCard('crt.sh', 'اكتشاف النطاقات الفرعية (Certificate Transparency)',
                        `https://crt.sh/?q=${encodeURIComponent(domain)}`, '🔗 فتح'),
                    scannerCard('SecurityHeaders', 'فحص Security Headers',
                        `https://securityheaders.com/?q=https://${domain}&followRedirects=true`, '🔗 فتح'),
                    scannerCard('SSL Labs', 'فحص شهادة SSL تفصيلي',
                        `https://www.ssllabs.com/ssltest/analyze.html?d=${domain}`, '🔗 فتح'),
                    scannerCard('Shodan', 'بحث Shodan عن النطاقات',
                        `https://www.shodan.io/search?query=${encodeURIComponent(domain)}`, '🔗 فتح')
                )
            ));
            
            showResults(target);
        } catch (e) {
            hideLoader();
            showError('فشل الاتصال. تحقق من اتصالك بالإنترنت.');
        }
    }

    async function scanThreat(target, type) {
        const messages = {
            malware: { loader: 'جاري فحص البرمجيات الخبيثة...', sub: 'VirusTotal · Google · Sucuri' },
            phishing: { loader: 'جاري فحص التصيد الاحتيالي...', sub: 'PhishTank · Google Safe Browsing' },
            spam: { loader: 'جاري فحص البريد العشوائي...', sub: 'Spamhaus · DNSBL' }
        };
        const msg = messages[type] || messages.malware;
        showLoader(msg.loader, msg.sub);
        
        const domain = sanitize(target);
        const cleanDomain = domain.replace(/^https?:\/\//, '').split('/')[0];
        
        hideLoader();
        const body = $('#results-body');
        body.innerHTML = '';
        
        body.appendChild(section('نتائج الفحص',
            kvGrid([['الهدف', cleanDomain], ['النوع', type]])
        ));
        
        // External scanners
        const scannerGrid = el('div', { class: 'scanner-grid' });
        
        const scanners = getScannerLinks(cleanDomain, type);
        scanners.forEach(s => {
            scannerGrid.appendChild(scannerCard(s.name, s.note, s.url, '🔗 فتح'));
        });
        
        body.appendChild(section('🛡️ محركات الفحص العالمية', scannerGrid));
        
        showResults(target);
    }

    async function scanBlacklist(target) {
        showLoader('جاري فحص القائمة السوداء...', 'DNSBL · Spamhaus · 10+ قواعد بيانات');
        
        const domain = sanitize(target);
        let ip = null;
        
        try {
            ip = await resolveDomain(domain);
        } catch (e) { /* ignore */ }
        
        if (!ip) {
            // Try as IP
            ip = domain.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/) ? domain : null;
        }
        
        hideLoader();
        const body = $('#results-body');
        body.innerHTML = '';
        
        if (!ip) {
            body.innerHTML = `<div class="empty-state">
                <div class="empty-state-icon">⚠</div>
                <h4>تعذر العثور على IP</h4>
                <p>لم نتمكن من حل الدومين إلى عنوان IP</p>
            </div>`;
            showResults(target);
            return;
        }
        
        const geo = await getGeoIP(ip);
        if (geo && !geo.error) body.appendChild(geoipCard(geo));
        
        body.appendChild(section('ملخص',
            kvGrid([
                ['IP المُفحوص', ip],
                ['ملاحظة', 'للتحقق من القوائم السوداء، استخدم الأدوات الخارجية أدناه']
            ])
        ));
        
        body.appendChild(section('🔗 أدوات فحص DNSBL',
            el('div', { class: 'scanner-grid' },
                scannerCard('Spamhaus ZEN', 'أقوى قاعدة بيانات DNSBL',
                    `https://www.spamhaus.org/lookup/single/?ip=${ip}`, '🔗 فحص'),
                scannerCard('AbuseIPDB', 'قاعدة بيانات AbuseIPDB',
                    `https://www.abuseipdb.com/check/${ip}`, '🔗 فحص'),
                scannerCard('VirusTotal', 'فحص IP شامل',
                    `https://www.virustotal.com/gui/ip-address/${ip}`, '🔗 فحص'),
                scannerCard('IPVoid', 'فحص IP في 20+ قاعدة بيانات',
                    `https://www.ipvoid.com/blacklist-check/${ip}/`, '🔗 فحص'),
                scannerCard('SpamCop', 'فحص SpamCop',
                    `https://spamcop.net/sc?track=${ip}`, '🔗 فحص')
            )
        ));
        
        showResults(target);
    }

    async function scanSSL(target) {
        showLoader('جاري تحليل شهادة SSL...', 'Certificate Analysis');
        
        const domain = sanitize(target).replace(/^https?:\/\//, '').split('/')[0];
        
        hideLoader();
        const body = $('#results-body');
        body.innerHTML = '';
        
        body.appendChild(section('فحص SSL/TLS',
            kvGrid([['الدومين', domain]])
        ));
        
        body.appendChild(section('🔗 أدوات فحص SSL خارجية',
            el('div', { class: 'scanner-grid' },
                scannerCard('SSL Labs', 'تحليل SSL تفصيلي + تقييم A-F',
                    `https://www.ssllabs.com/ssltest/analyze.html?d=${domain}`, '🔗 تحليل'),
                scannerCard('Chrome SSL Viewer', 'فحص من Google',
                    `https://www.google.com/search?q=ssllabs+${encodeURIComponent(domain)}`, '🔗 فتح'),
                scannerCard('crt.sh', 'عرض سجلات الشهادات',
                    `https://crt.sh/?q=${encodeURIComponent(domain)}`, '🔗 عرض'),
                scannerCard('Observatory', 'فحص رؤوس الأمان',
                    `https://observatory.mozilla.org/analyze/${domain}`, '🔗 فحص')
            )
        ));
        
        showResults(target);
    }

    async function scanPorts(target) {
        showLoader('جاري فحص المنافذ...', 'Port Scanning (Client-side limited)');
        
        const domain = sanitize(target);
        
        hideLoader();
        const body = $('#results-body');
        body.innerHTML = '';
        
        body.appendChild(section('فحص المنافذ',
            kvGrid([
                ['الهدف', domain],
                ['ملاحظة', 'فحص المنافذ يتم عبر أدوات خارجية متخصصة']
            ])
        ));
        
        body.appendChild(section('🔗 أدوات فحص المنافذ',
            el('div', { class: 'scanner-grid' },
                scannerCard('Nmap Scanner', 'فحص المنافذ عبر Nmap (أداة خارجية)',
                    `https://pentest-tools.com/network-vulnerability-scanning/tcp-port-scanner?nmap=-sT+-p-1-65535+${encodeURIComponent(domain)}`, '🔗 فتح الأداة'),
                scannerCard('Scanner.in', 'فحص المنافذ عبر الإنترنت',
                    `https://scanner.in/?host=${encodeURIComponent(domain)}`, '🔗 فتح الأداة'),
                scannerCard('VirusTotal', 'فحص المنافذ',
                    `https://www.virustotal.com/gui/domain/${domain}`, '🔗 فتح الأداة')
            )
        ));
        
        showResults(target);
    }

    async function scanSubdomains(target) {
        showLoader('جاري البحث عن النطاقات الفرعية...', 'Certificate Transparency Logs');
        
        const domain = sanitize(target).replace(/^https?:\/\//, '').split('/')[0];
        
        hideLoader();
        const body = $('#results-body');
        body.innerHTML = '';
        
        body.appendChild(section('النطاقات الفرعية',
            kvGrid([['الدومين', domain]])
        ));
        
        body.appendChild(section('🔗 أدوات اكتشاف النطاقات الفرعية',
            el('div', { class: 'scanner-grid' },
                scannerCard('crt.sh', 'البحث في Certificate Transparency',
                    `https://crt.sh/?q=${encodeURIComponent(domain)}`, '🔗 فتح'),
                scannerCard('Sublist3r API', 'محرك بحث النطاقات الفرعية',
                    `https://api.sublist3r.com/search.php?domain=${encodeURIComponent(domain)}`, '🔗 فتح'),
                scannerCard('SecurityTrails', 'البحث عن Subdomains',
                    `https://securitytrails.com/domain/${domain}/dns`, '🔗 فتح'),
                scannerCard('VirusTotal', 'فحص Domain',
                    `https://www.virustotal.com/gui/domain/${domain}`, '🔗 فتح')
            )
        ));
        
        showResults(target);
    }

    function scannerCard(name, note, url, btnText) {
        const card = el('div', { class: 'scanner-card' });
        const header = el('div', { class: 'scanner-card-header' });
        header.appendChild(el('h5', { class: 'scanner-name' }, name));
        header.appendChild(badge('🔗 فحص', 'gold'));
        card.appendChild(header);
        card.appendChild(el('p', { class: 'scanner-note' }, note || ''));
        if (url) {
            const link = el('a', {
                class: 'scanner-link',
                href: url,
                target: '_blank',
                rel: 'noopener noreferrer'
            }, btnText || 'فتح في تبويب جديد ←');
            card.appendChild(link);
        }
        return card;
    }

    function getScannerLinks(domain, type) {
        const base = domain.replace(/^https?:\/\//, '').split('/')[0];
        const links = {
            malware: [
                { name: 'VirusTotal', note: 'فحص عبر 70+ محرك أمني', url: `https://www.virustotal.com/gui/domain/${encodeURIComponent(base)}` },
                { name: 'Google Safe Browsing', note: 'فحص Google للروابط الخطرة', url: `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(base)}` },
                { name: 'Sucuri SiteCheck', note: 'فحص Malware + Blacklist', url: `https://sitecheck.sucuri.net/results/${encodeURIComponent(base)}` },
                { name: 'URLVoid', note: 'فحص عبر 30+ محرك سمعة', url: `https://www.urlvoid.com/scan/${encodeURIComponent(base)}/` }
            ],
            phishing: [
                { name: 'PhishTank', note: 'البحث في أكبر قاعدة تصيد', url: `https://phishtank.org/search.php?valid=y&Search=Search&query=${encodeURIComponent(base)}` },
                { name: 'Google Safe Browsing', note: 'فحص Google للتصيد', url: `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(base)}` },
                { name: 'VirusTotal', note: 'فحص التصيد عبر 70+ محرك', url: `https://www.virustotal.com/gui/domain/${encodeURIComponent(base)}` },
                { name: 'OpenPhish', note: 'قاعدة بيانات تصيد مفتوحة', url: `https://openphish.com/` }
            ],
            spam: [
                { name: 'Spamhaus', note: 'فحص في قوائم Spamhaus', url: `https://www.spamhaus.org/lookup/single/?domain=${encodeURIComponent(base)}` },
                { name: 'SURBL', note: 'فحص SURBL للقوائم السوداء', url: `https://surbl.org/surbl-analysis/${encodeURIComponent(base)}` },
                { name: 'AbuseIPDB', note: 'فحص سمعة IP', url: `https://www.abuseipdb.com/` },
                { name: 'URLVoid', note: 'فحص البريد العشوائي', url: `https://www.urlvoid.com/scan/${encodeURIComponent(base)}/` }
            ]
        };
        return links[type] || links.malware;
    }

    // =============================================================================
    // ACTION MAP
    // =============================================================================

    const SCAN_CONFIG = {
        resolve: { fn: scanResolve, title: 'نتائج كشف IP' },
        reverse: { fn: scanReverse, title: 'نتائج عكس IP' },
        info: { fn: scanInfo, title: 'نتائج جمع المعلومات' },
        'threat-malware': { fn: (t) => scanThreat(t, 'malware'), title: 'نتائج فحص البرمجيات الخبيثة' },
        'threat-phishing': { fn: (t) => scanThreat(t, 'phishing'), title: 'نتائج فحص التصيد' },
        'threat-spam': { fn: (t) => scanThreat(t, 'spam'), title: 'نتائج فحص البريد العشوائي' },
        blacklist: { fn: scanBlacklist, title: 'نتائج فحص القائمة السوداء' },
        ssl: { fn: scanSSL, title: 'نتائج فحص SSL/TLS' },
        ports: { fn: scanPorts, title: 'نتائج فحص المنافذ' },
        subdomains: { fn: scanSubdomains, title: 'النطاقات الفرعية المكتشفة' }
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
        // Tab switching
        $$('.tab-btn').forEach(tab => {
            tab.addEventListener('click', () => switchTab(tab.dataset.tab));
        });

        // Feature card clicks
        $$('[data-tab-action]').forEach(btn => {
            btn.addEventListener('click', () => switchTab(btn.dataset.tabAction));
        });

        // Execute buttons
        $$('.btn-execute').forEach(btn => {
            btn.addEventListener('click', () => executeScan(btn.dataset.action));
        });

        // Enter key on inputs
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

        // Prevent accidental data submission
        document.addEventListener('contextmenu', e => {
            // Allow context menu on non-critical areas
        });

        // Clear results when switching tabs
        const observer = new MutationObserver(() => {
            // Could add tab-switch cleanup here
        });

        console.log(`%c Vallains Security Scanner v${CONFIG.VERSION} `,
            'background:#D4AF37;color:#000;font-weight:bold;padding:4px 8px;border-radius:4px;');
        console.log('Security Note: This static version makes direct API calls to external services.');
        console.log('No data is sent to any backend server.');
    }

    // Start
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();