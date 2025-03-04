#!/bin/bash

# GitHub-Repository
REPO_URL="https://github.com/mprotogerakis/route_advertiser.git"
PROJECT_DIR="route_advertiser"

# Sicherstellen, dass Git und Python installiert sind
echo "🔍 Überprüfe Git und Python..."
if ! command -v git &> /dev/null; then
    echo "❌ Git ist nicht installiert! Bitte installiere Git."
    exit 1
fi

if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 ist nicht installiert! Bitte installiere Python3."
    exit 1
fi

# Repository klonen
if [ ! -d "$PROJECT_DIR" ]; then
    echo "📥 Klone Repository von GitHub..."
    git clone "$REPO_URL"
else
    echo "🔄 Repository existiert bereits. Ziehe neueste Änderungen..."
    cd "$PROJECT_DIR"
    git pull origin main
    cd ..
fi

cd "$PROJECT_DIR"

# Virtuelle Umgebung erstellen, falls sie nicht existiert
if [ ! -d "venv" ]; then
    echo "🐍 Erstelle virtuelle Umgebung..."
    python3 -m venv venv
fi

# Aktivieren der virtuellen Umgebung
echo "✅ Aktiviere virtuelle Umgebung..."
source venv/bin/activate

# Aktualisieren von pip
echo "🔄 Aktualisiere pip..."
pip install --upgrade pip

# Pakete aus requirements.txt installieren
if [ -f "requirements.txt" ]; then
    echo "📦 Installiere benötigte Pakete..."
    pip install -r requirements.txt
else
    echo "⚠️ Keine requirements.txt gefunden!"
fi

echo "🚀 Setup abgeschlossen! Um das Skript auszuführen:"
echo "➡️  cd route_advertiser"
echo "➡️  source venv/bin/activate"
echo "➡️  python client.py start"
