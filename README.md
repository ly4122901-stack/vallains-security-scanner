# Vallains v2.0 - أداة فحص المواقع الاحترافية

<div align="center">

![Vallains Banner](https://img.shields.io/badge/VALLAINS-v2.0-D4AF37?style=for-the-badge&logo=shield&logoColor=black)

**أداة فحص وتحليل المواقع الاحترافية — نتائج فورية على الموقع**

[![License: MIT](https://img.shields.io/badge/License-MIT-D4AF37.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/Security-Hardened-brightgreen.svg)](https://github.com)
[![Version](https://img.shields.io/badge/Version-2.0-blue.svg)](

</div>

---

## 🚀 المميزات الجديدة في v2.0

### ✅ الفحص الشامل (Scan All)
زر واحد يفحص كل حاجة: DNS, GeoIP, WHOIS, SSL, Subdomains, Email Security, DNSSEC, Vulnerabilities

### ✅ نتائج مباشرة على الموقع
- لا توجيه لأي موقع خارجي
- كل النتائج تظهر في نفس الصفحة
- تحديثات فورية أثناء الفحص

### ✅ ثغرات أكتر للفحص
- .git exposed
- Debug mode
- phpinfo()
- Open directories
- SPF/DMARC records
- DNSSEC

---

## 🔒 الأمان

| الحماية | الحالة |
|---------|--------|
| CSP Headers | ✅ مفعّل |
| X-Frame-Options | ✅ DENY |
| لا بيانات مسربة | ✅ Clean |
| Input Sanitization | ✅ مفعّل |
| لا .env في Git | ✅ محمي |

---

## 📁 المميزات المتوفرة

| الفحص | الوصف |
|-------|-------|
| 🔴 الفحص الشامل | كل الفحوصات في مرة واحدة |
| ◈ جمع المعلومات | WHOIS, DNS, SSL, Subdomains |
| ⊕ كشف IP | DNS Resolution + GeoIP |
| ⇆ عكس IP | Reverse DNS Lookup |
| ☣ Malware | فحص البرمجيات الخبيثة |
| ⚓ Phishing | فحص التصيد الاحتيالي |
| ✦ Spam | فحص البريد العشوائي |
| ◉ القائمة السوداء | DNSBL Check |
| 🔒 SSL/TLS | معلومات الشهادة |
| ▤ المنافذ | Port Scanning |
| 🔴 الثغرات | Vulnerability Scanner |
| 📧 أمان البريد | SPF, DKIM, DMARC |
| 🔐 DNSSEC | DNS Security Extensions |

---

## 🔧 التقنيات المستخدمة

- **DNS Resolution**: dns.google API
- **GeoIP**: ip-api.com
- **SSL Certificates**: crt.sh
- **Subdomains**: Certificate Transparency

---

## ⚠️ تنبيه أخلاقي

هذه الأداة **لأغراض تعليمية وأمنية فقط**. لا تستخدمها لـ:
- 🚫 اختراق مواقع بدون إذن
- 🚫 جمع معلومات بدون إذن
- 🚫 أي نشاط غير قانوني

---

## 📜 License

MIT License — استخدمه بحرية مع الإشارة للمصدر.

---

<div align="center">
<p><strong>Vallains v2.0</strong> — مصمم بـ ❤️ للأمن السيبراني</p>
</div>