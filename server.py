import socket
import json
import time
import logging
import subprocess
import typer
import yaml
from pathlib import Path
from ipaddress import ip_network
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

# CLI-Framework initialisieren
app = typer.Typer()

# Standardwerte für die Konfiguration
DEFAULT_CONFIG = {
    "udp_port": 5005,
    "broadcast_interval": 30,
    "private_key_file": "private.pem",
    "log_file": "server.log",
    "debug": False
}

# **WICHTIG**: CONFIG erst innerhalb von `start()` laden!
CONFIG = None  
private_key = None  # Globaler Speicher für den Schlüssel

def load_config(config_path: Path):
    """Lädt eine alternative Konfigurationsdatei, falls angegeben"""
    if config_path.exists():
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    return DEFAULT_CONFIG

@app.command()
def start(config: Path = typer.Option("config.yaml", help="Pfad zur Konfigurationsdatei")):
    """Startet den Route Broadcast Server mit einer optionalen Konfigurationsdatei"""
    global CONFIG, private_key

    CONFIG = load_config(config)

    # Logging erst hier initialisieren
    logging.basicConfig(
        level=logging.DEBUG if CONFIG["debug"] else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(CONFIG["log_file"]),
            logging.StreamHandler()
        ]
    )

    # Privaten Schlüssel laden
    private_key_path = Path(CONFIG["private_key_file"])
    if not private_key_path.exists():
        logging.error(f"❌ Fehler: Private-Key Datei {CONFIG['private_key_file']} nicht gefunden!")
        raise typer.Exit(1)

    with open(private_key_path, "rb") as f:
        private_key = RSA.import_key(f.read())

    logging.info("✅ Route Broadcast Server gestartet")
    send_routes()

def sign_data(data):
    """Signiert JSON-Daten mit RSA."""
    hash_obj = SHA256.new(data.encode())
    return pkcs1_15.new(private_key).sign(hash_obj).hex()

def send_routes():
    """Broadcastet IPv4-Routen (keine IPv6) mit korrektem Gateway."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    while True:
        logging.info("🔄 `send_routes()` läuft...")

        routes = get_routing_table()
        interfaces = get_interfaces()

        logging.info(f"🌍 Routen gefunden: {routes}")
        logging.info(f"🌐 Interfaces erkannt: {interfaces}")

        if not routes:
            logging.warning("⚠️ Keine gültigen Routen gefunden, überspringe Broadcast.")
            time.sleep(CONFIG["broadcast_interval"])
            continue

        if not interfaces:
            logging.warning("⚠️ Keine Netzwerkschnittstellen gefunden, kann keine Routen senden.")
            time.sleep(CONFIG["broadcast_interval"])
            continue

        for interface, data in interfaces.items():
            local_subnet = ip_network(data["subnet"], strict=False)
            broadcast_ip = data["broadcast"]
            router_ip = data["gateway"]

            if not broadcast_ip:
                logging.warning(f"⚠️ Keine Broadcast-Adresse für {interface}, überspringe.")
                continue

            logging.info(f"🌐 Sende Routen auf {interface} → Broadcast: {broadcast_ip}")

            # ❌ Filtere IPv6-Routen heraus (nur IPv4 erlaubt)
            valid_routes = []
            for route in routes:
                if ":" in route["subnet"]:
                    logging.info(f"❌ Ignoriere IPv6-Route: {route['subnet']}")
                    continue  # IPv6-Route überspringen
                if ip_network(route["subnet"], strict=False).overlaps(local_subnet):
                    continue
                valid_routes.append({"subnet": route["subnet"], "gateway": router_ip, "timeout": 300})

            if not valid_routes:
                logging.info(f"❌ Keine gültigen IPv4-Routen für {interface}, überspringe Broadcast.")
                continue

            message = json.dumps({
                "routes": valid_routes,
                "signature": sign_data(json.dumps(valid_routes, separators=(',', ':'), sort_keys=True))
            })
            sock.sendto(message.encode(), (broadcast_ip, CONFIG["udp_port"]))

            logging.info(f"✅ IPv4 Broadcast gesendet an {broadcast_ip}: {message}")

        time.sleep(CONFIG["broadcast_interval"])

if __name__ == "__main__":
    app()