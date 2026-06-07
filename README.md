# Vallains - أداة فحص المواقع الاحترافية

<div align="center">

![Vallains Banner](https://img.shields.io/badge/VALLAINS-Security%20Scanner-D4AF37?style=for-the-badge&logo=shield&logoColor=black)

**أداة فحص وتحليل المواقع الاحترافية — مفتوحة المصدر**

[![License: MIT](https://img.shields.io/badge/License-MIT-D4AF37.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/Security-Hardened-brightgreen.svg)](https://github.com)
[![Deploy](https://img.shields.io/badge/Deploy-GitHub%20Pages-2b3137?style=for-the-badge&logo=github)]

</div>

---

## 🔒 الأمان أولا

هذا المشروع مُصلح ومُتقن من ناحية الحماية:

| الحماية | الحالة |
|---------|--------|
| Rate Limiting (Flask) | ✅ مفعّل — 30 طلب/دقيقة |
| CORS Restrictive | ✅ مُقيّد — Origins محددة |
| Security Headers | ✅ مُفعّل — HSTS, X-Frame-Options, CSP |
| Input Sanitization | ✅ مُفعّل — منع SQL/NoSQL Injection |
| Secret Key Random | ✅ مُولّد عشوائيا |
| SSL Verification | ✅ مفعّل |
| لا بيانات مسربة | ✅ تم التدقيق |
| لا `.env` في Git | ✅ مُضاف لـ .gitignore |

---

## 🚀 النشر على GitHub Pages (النسخة Static)

### الطريقة السهلة — Drag & Drop

1. حمّل مجلد `vallains-static/` فقط
2. ادخل على **GitHub.com → New Repository**
3. اسم Repository: `vallains` أو أي اسم
4. ارفع كل الملفات من `vallains-static/`
5. Settings → Pages → Source: **main branch** → Save
6. انتظر 2-3 دقائق — الموقع هيبان تلقائيا! ✅

### الطريقة بالأ GitHub Actions (تحديث تلقائي)

المجلد فيه `.github/workflows/deploy.yml` — لو رفعت الكود هيشتغل تلقائيا.

---

## 🖥️ تشغيل النسخة Flask محلياً

```bash
cd vallains

# إنشاء بيئة افتراضية
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\\Scripts\\activate  # Windows

# تثبيت المكتبات
pip install -r requirements.txt

# تشغيل
python app.py
# افتح: http://localhost:5000
```

---

## 🔧 الحماية — ما الذي تم إصلاحه؟

### الثغرات التي تم حلها:

1. **CORS مفتوح** → تم تقييده بـ Origins محددة
2. **لا Rate Limiting** → تم إضافة 30 طلب/دقيقة لكل IP
3. **SSL Verify معطل** → تم تفعيله + fallback آمن
4. **Secret Key افتراضي** → يتم توليده عشوائيا
5. **لا Security Headers** → تم إضافة 10+ headers
6. **لا Input Validation** → تم إضافة sanitization قوي
7. **/health يُسرب معلومات** → تم إزالة المعلومات الحساسة
8. **لا .gitignore شامل** → تم تقويته
9. **Logger يعرض بيانات** → تم تحسينه

---

## 📁 هيكل المشروع

```
vallains/
├── app.py                 # Flask backend (مُصلح)
├── requirements.txt      # المكتبات
├── run.sh               # سكريبت التشغيل
├── .gitignore           # ملفات مستبعدة من Git
├── SECURITY.md          # تقرير الأمان
├──vallains-static/      # نسخة GitHub Pages
│   ├── index.html       # الصفحة الرئيسية
│   ├── css/style.css    # الأنماط
│   ├── js/app.js        # JavaScript (static API calls)
│   ├── robots.txt       # حظر الزحف
│   ├── security.txt     # سياسة الأمان
│   └── README.md        # هذا الملف
└── templates/           # قوالب Flask
    └── index.html
```

---

## ⚠️ تنبيه أخلاقي

هذه الأداة **لأغراض تعليمية وأمنية فقط**. لا تستخدمها لـ:
- 🚫 اختراق مواقع بدون إذن
- 🚫 جمع معلومات بدون إذن
- 🚫 أي نشاط غير قانوني

**المستخدم مسؤول عن أي استخدام غير أخلاقي.**

---

## 🛡️ Security Note — Static Version

النسخة Static (GitHub Pages) تعمل بالكامل في المتصفح — **لا يوجد Backend**. 
جميع طلبات API تُنفذ مباشرة من المتصفح إلى الخدمات الخارجية:
- `dns.google` — DNS resolution
- `ip-api.com` — GeoIP
- `ipapi.co` — GeoIP (fallback)

**لا بيانات تُرسل لأي سيرفر خاص بك.**

---

## 📜 License

MIT License — استخدمه بحرية مع الإشارة للمصدر.

---

<div align="center">
<p><strong>Vallains</strong> — مصمم بـ ❤️ للأمن السيبراني</p>
<p>النسخة: 1.0 | الحماية: مُتقنة</p>
</div>