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
# Repository klonen
git clone https://github.com/dein-repo/route-advertiser.git
cd route-advertiser

# Abhängigkeiten installieren
pip install -r requirements.txt
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

