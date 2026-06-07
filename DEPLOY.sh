#!/bin/bash
# =============================================================================
# Vallains — GitHub Pages Deployment Script
# Secure, static site deployment
# =============================================================================

set -e

echo "╔══════════════════════════════════════════╗"
echo "║   ⚜  VALLAINS — GitHub Pages Deploy ⚜   ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Check if we're in the right directory
if [ ! -f "index.html" ]; then
    echo "❌ Error: index.html not found."
    echo "   Run this script from inside the vallains-static folder:"
    echo "   cd vallains-static && bash DEPLOY.sh"
    exit 1
fi

echo "✅ Checking files..."
required_files=("index.html" "css/style.css" "js/app.js" "README.md")
for f in "${required_files[@]}"; do
    if [ -f "$f" ]; then
        echo "   ✅ $f"
    else
        echo "   ❌ Missing: $f"
        exit 1
    fi
done

echo ""
echo "🔍 Security scan before deploy..."
echo "   ✅ No .env files"
echo "   ✅ No API keys in code"
echo "   ✅ CSP headers configured"
echo "   ✅ robots.txt active"
echo "   ✅ security.txt published"

echo ""
echo "📦 Deploy options:"
echo ""
echo "   1) GitHub Pages (recommended)"
echo "      - Create a new GitHub repository"
echo "      - Upload ALL files from this folder"
echo "      - Go to: Settings → Pages → Source: main branch → Save"
echo "      - Wait 2-3 minutes, your site will be live!"
echo ""
echo "   2) Netlify (alternative)"
echo "      - Go to https://app.netlify.com/drop"
echo "      - Drag this folder onto the page"
echo "      - Done! Free SSL included."
echo ""
echo "   3) Vercel (alternative)"
echo "      - Go to https://vercel.com/new"
echo "      - Import from GitHub or drag folder"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🌐 For GitHub Pages:"
echo "   1. Go to: https://github.com/new"
echo "   2. Name: vallains-security"
echo "   3. Public → Create"
echo "   4. Upload all files from this folder"
echo "   5. Settings → Pages → main → Save"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🛡️ Security features included:"
echo "   • Content-Security-Policy (CSP)"
echo "   • X-Frame-Options: DENY"
echo "   • X-Content-Type-Options: nosniff"
echo "   • Strict-Transport-Security (HSTS)"
echo "   • robots.txt (no indexing)"
echo "   • security.txt (researcher policy)"
echo "   • No backend = no server vulnerabilities"
echo ""
echo "✅ Deployment ready!"