# Route Advertiser

## 🛠️ Projektbeschreibung

Der **Route Advertiser** ermöglicht das automatische Verteilen von Netzwerk-Routen in einem lokalen Netzwerk mittels eines **Server-Client-Modells** über **UDP**. Der **Server** sendet regelmäßig Routing-Informationen an Clients, die diese empfangen, validieren und temporär in ihre Routing-Tabelle aufnehmen.

**Typische Anwendungsszenarien:**
- Automatische Verteilung von statischen Routen in einem lokalen Netzwerk
- Zentrale Steuerung und Verwaltung von Routen für mehrere Clients, z.B. wenn alle Clients bereits funktionierende Default-Routen haben aber zusätzlich noch durch einen Router mehrere VLANs bzw. deren Subnetze verbunden werden sollen.

---

## 💻 Komponenten

### **Server**
Der Server läuft auf einem Router ermittelt die für ihn erreichbaren Subnetze und sendet in diese in regelmäßigen Abständen per **UDP-Broadcast** an alle Clients. Die Nachrichten sind **digital signiert**, um Manipulationen zu verhindern.

**Hauptfunktionen:**
- Signiert die Routing-Informationen mit einem **privaten RSA-Schlüssel**
- Sendet regelmäßig UDP-Broadcast-Pakete mit zur Verfügung stellbaren Routen an seine Interfaces

### **Client**
Der Client empfängt Routing-Updates vom Server, überprüft deren **Signatur mit dem öffentlichen Schlüssel**, fügt fehlende Routen hinzu sofern er selbst noch keine Routen in diese Netze kennt und entfernt sie nach Ablauf eines **Timeouts** automatisch.

**Hauptfunktionen:**
- Empfängt UDP-Pakete mit Routen
- Überprüft die digitale Signatur mit dem **öffentlichen Schlüssel**
- Fügt neue Routen zur lokalen Routing-Tabelle hinzu
- Entfernt Routen nach Ablauf des definierten **Timeouts**

---

## 🛠️ Installation & Setup

### **1️⃣ Voraussetzungen**
- **Python 3.10+**
- **Windows / Linux mit Administratorrechten** (zum Ändern der Routing-Tabelle)
- **RSA-Schlüsselpaare** für Signaturprüfung

### **2️⃣ Installation**
```bash
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
```

```bat
@echo off
setlocal enabledelayedexpansion

:: GitHub-Repository
set REPO_URL=https://github.com/mprotogerakis/route_advertiser.git
set PROJECT_DIR=route_advertiser

:: Sicherstellen, dass Git installiert ist
where git >nul 2>nul
if %errorlevel% neq 0 (
    echo ❌ Git ist nicht installiert! Bitte installiere Git.
    exit /b 1
)

:: Sicherstellen, dass Python installiert ist
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo ❌ Python ist nicht installiert! Bitte installiere Python.
    exit /b 1
)

:: Repository klonen, falls nicht vorhanden
if not exist %PROJECT_DIR% (
    echo 📥 Klone Repository von GitHub...
    git clone %REPO_URL%
) else (
    echo 🔄 Repository existiert bereits. Ziehe neueste Änderungen...
    cd %PROJECT_DIR%
    git pull origin main
    cd ..
)

cd %PROJECT_DIR%

:: Virtuelle Umgebung erstellen, falls nicht vorhanden
if not exist venv (
    echo 🐍 Erstelle virtuelle Umgebung...
    python -m venv venv
)

:: Aktivieren der virtuellen Umgebung
echo ✅ Aktiviere virtuelle Umgebung...
call venv\Scripts\activate.bat

:: Aktualisieren von pip
echo 🔄 Aktualisiere pip...
python -m pip install --upgrade pip

:: Pakete aus requirements.txt installieren
if exist requirements.txt (
    echo 📦 Installiere benötigte Pakete...
    pip install -r requirements.txt
) else (
    echo ⚠️ Keine requirements.txt gefunden!
)

echo 🚀 Setup abgeschlossen! Um das Skript auszuführen:
echo ➡️  cd route_advertiser
echo ➡️  venv\Scripts\activate
echo ➡️  python client.py start

endlocal
pause
```


### **3️⃣ RSA-Schlüssel generieren** (falls noch nicht vorhanden)
```bash
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in private.pem -pubout -out public.pem
```

### **4️⃣ Konfiguration anpassen**
#### **Server (`server_config.yaml`)**
```yaml
udp_port: 5005
broadcast_interval: 30
private_key_file: "private.pem"
log_file: "server.log"
debug: true
```

#### **Client (`client_config.yaml`)**
```yaml
udp_port: 5005
public_key_file: "public.pem"
```

---

## 🛠️ Nutzung

### **Server starten**
```bash
python server.py
```

### **Client starten** (mit Admin-Rechten, falls notwendig)
```bash
python client.py start
```

### **Client im Testmodus** (zeigt nur Befehle, ohne sie auszuführen)
```bash
python client.py test
```

---

## 🔧 Fehlerbehebung

### **1 Signaturprüfung schlägt fehl**
- Stelle sicher, dass Client & Server den **gleichen öffentlichen Schlüssel** verwenden
- Prüfe die korrekte JSON-Sortierung vor der Signierung

### **2 Routen werden nicht hinzugefügt**
- Prüfe mit `route print` (Windows) oder `ip route show` (Linux), ob die Route bereits existiert
- Logs im Debug-Modus prüfen (`logging.DEBUG` aktivieren)

---

**🌟 Viel Erfolg mit dem Route Advertiser!**

