import socket
import json
import time
import subprocess
import logging
import typer
import yaml
from pathlib import Path
from ipaddress import ip_network
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

# CLI-Framework initialisieren
app = typer.Typer()

# Standardwerte für Konfiguration
DEFAULT_CONFIG = {
    "udp_port": 5005,
    "listen_interface": "0.0.0.0",
    "route_timeout": 300,
    "public_key_file": "public.pem",
    "log_file": "client.log",
    "test_mode": False
}

CONFIG_FILE = Path("client_config.yaml")  # Datei umbenannt

def load_config():
    """Lädt die Konfiguration aus einer YAML-Datei oder nutzt Standardwerte."""
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, "r") as f:
            return yaml.safe_load(f)
    else:
        return DEFAULT_CONFIG

CONFIG = load_config()

# Logging einrichten
logging.basicConfig(
    level=logging.DEBUG if CONFIG.get("test_mode", False) else logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(CONFIG["log_file"]),
        logging.StreamHandler()
    ]
)

# Lade den **öffentlichen** Schlüssel zur Verifikation der Signatur
public_key_path = Path(CONFIG["public_key_file"])
if not public_key_path.exists():
    typer.echo(f"❌ Fehler: Public-Key Datei {CONFIG['public_key_file']} nicht gefunden!", err=True)
    raise typer.Exit(1)

with open(public_key_path, "rb") as f:
    public_key = RSA.import_key(f.read())

# Route-Speicher für Timeout-Handling
active_routes = {}

def verify_signature(data, signature):
    """Überprüft die Signatur der empfangenen Routen."""
    hash_obj = SHA256.new(data.encode())
    signature_bytes = bytes.fromhex(signature)
    
    try:
        pkcs1_15.new(public_key).verify(hash_obj, signature_bytes)
        return True
    except (ValueError, TypeError):
        return False

def is_route_reachable(subnet):
    """Prüft, ob bereits eine Route zu diesem Subnetz existiert."""
    try:
        result = subprocess.run(["ip", "route", "show", subnet], capture_output=True, text=True, check=True)
        return bool(result.stdout.strip())  # Wenn eine Route existiert, ist die Ausgabe nicht leer
    except subprocess.CalledProcessError:
        return False
    
def is_own_subnet(subnet):
    """Prüft, ob der Client eine eigene IP im angegebenen Subnetz hat."""
    try:
        result = subprocess.run(["ip", "-o", "addr"], capture_output=True, text=True, check=True)
        for line in result.stdout.split("\n"):
            parts = line.split()
            if len(parts) > 3 and "inet" in parts:
                client_subnet = ip_network(parts[3], strict=False)  # Ermittelt das Subnetz der Interface-IP
                if client_subnet.overlaps(ip_network(subnet, strict=False)):
                    return True  # Der Client gehört zu diesem Subnetz
    except subprocess.CalledProcessError:
        pass
    return False
    
def add_route(subnet, gateway, test_mode):
    """Fügt eine Route nur hinzu, wenn sie bislang unerreichbar ist und nicht zum eigenen Subnetz gehört."""
    if is_route_reachable(subnet):
        logging.info(f"⚠️ Route {subnet} ist bereits erreichbar, wird nicht hinzugefügt.")
        return

    if is_own_subnet(subnet):
        logging.info(f"⚠️ Client gehört bereits zu {subnet}, Route wird nicht hinzugefügt.")
        return

    command = f"ip route add {subnet} via {gateway}"
    
    if test_mode:
        logging.info(f"TESTMODE: {command}")
    else:
        try:
            subprocess.run(command.split(), check=True)
            logging.info(f"✅ Route hinzugefügt: {subnet} via {gateway}")
        except subprocess.CalledProcessError as e:
            logging.error(f"❌ Fehler beim Hinzufügen der Route {subnet}: {e}")

def delete_route(subnet, test_mode):
    """Löscht eine Route aus dem System."""
    command = f"ip route del {subnet}"
    
    if test_mode:
        logging.info(f"TESTMODE: Timeout erreicht. Route {subnet} würde jetzt entfernt.")
    else:
        try:
            subprocess.run(command.split(), check=True)
            logging.info(f"✅ Route entfernt: {subnet}")
        except subprocess.CalledProcessError as e:
            logging.error(f"❌ Fehler beim Entfernen der Route {subnet}: {e}")

def listen_for_routes():
    """Hört auf UDP-Broadcasts und verarbeitet Routen."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((CONFIG["listen_interface"], CONFIG["udp_port"]))

    logging.info(f"🎧 Lausche auf UDP-Port {CONFIG['udp_port']} für Routen-Updates...")

    while True:
        data, addr = sock.recvfrom(4096)
        logging.info(f"📩 Empfangene Daten von {addr}: {data.decode()}")

        try:
            message = json.loads(data.decode())

            # Überprüfe die Signatur
            if not verify_signature(json.dumps(message["routes"]), message["signature"]):
                logging.error("❌ Signaturprüfung fehlgeschlagen! Nachricht ignoriert.")
                continue

            # Routen verarbeiten
            for route in message["routes"]:
                subnet = route["subnet"]
                gateway = route["gateway"]
                timeout = route.get("timeout", CONFIG["route_timeout"])

                add_route(subnet, gateway, CONFIG["test_mode"])

                # Speichere Route für spätere Entfernung
                if CONFIG["test_mode"]:
                    logging.info(f"TESTMODE: Route {subnet} wird für {timeout} Sekunden gespeichert.")
                else:
                    active_routes[subnet] = time.time() + timeout

        except json.JSONDecodeError:
            logging.error("❌ Fehler beim Dekodieren der empfangenen Daten.")

        # Entferne abgelaufene Routen
        current_time = time.time()
        for subnet in list(active_routes.keys()):
            if current_time > active_routes[subnet]:
                delete_route(subnet, CONFIG["test_mode"])
                del active_routes[subnet]


@app.command()
def start():
    """Startet den Route Client und hört auf UDP-Broadcasts."""
    listen_for_routes()

@app.command()
def test():
    """Startet den Route Client im Testmodus."""
    CONFIG["test_mode"] = True
    listen_for_routes()

@app.command()
def show_config():
    """Zeigt die aktuelle Konfiguration an."""
    typer.echo(yaml.dump(CONFIG, default_flow_style=False))

if __name__ == "__main__":
    app()