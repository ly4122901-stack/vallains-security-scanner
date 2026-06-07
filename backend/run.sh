#!/bin/bash

cd "$(dirname "$0")"

if [ ! -d "venv" ]; then
    echo "🔧 جاري إنشاء البيئة الافتراضية..."
    python3 -m venv venv
    source venv/bin/activate
    echo "📦 جاري تثبيت المكتبات..."
    pip install -r requirements.txt
else
    source venv/bin/activate
fi

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║         ⚜  VALLAINS SCANNER  ⚜          ║"
echo "║      أداة فحص المواقع الاحترافية         ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "🚀 السيرفر شغال على: http://localhost:5000"
echo "📡 اضغط Ctrl+C للإيقاف"
echo ""

python3 app.py
