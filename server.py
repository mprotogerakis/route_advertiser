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

CONFIG = None  
private_key = None  

def load_config(config_path: Path):
    """Lädt eine alternative Konfigurationsdatei, falls angegeben"""
    if config_path.exists():
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    return DEFAULT_CONFIG

def get_routing_table():
    """Ermittelt die IPv4-Routing-Tabelle für FreeBSD und OPNsense."""
    routes = []
    
    try:
        result = subprocess.run(["netstat", "-rn"], capture_output=True, text=True, check=True)
        for line in result.stdout.split("\n"):
            parts = line.split()
            if len(parts) < 3:
                continue
            destination, gateway, *flags, interface = parts[:4]
            
            # Nur IPv4-Routen speichern (keine IPv6-Adressen)
            if ":" in destination:
                continue  
            
            routes.append({"subnet": destination, "interface": interface, "timeout": 300})

    except subprocess.CalledProcessError as e:
        logging.error(f"❌ Fehler beim Auslesen der Routing-Tabelle: {e}")

    return routes

def get_interfaces():
    """Ermittelt Netzwerkschnittstellen für FreeBSD/OPNsense."""
    interfaces = {}

    try:
        result = subprocess.run(["ifconfig"], capture_output=True, text=True, check=True)
        lines = result.stdout.split("\n")
        
        current_interface = None
        for line in lines:
            if not line.startswith("\t"):  # Neue Interface-Zeile
                current_interface = line.split(":")[0]
                continue

            if "inet " in line and current_interface:
                parts = line.split()
                ip_addr = parts[1]
                netmask_hex = parts[3]
                broadcast = parts[5] if "broadcast" in line else None

                interfaces[current_interface] = {
                    "ip": ip_addr,
                    "subnet": f"{ip_addr}/24",
                    "broadcast": broadcast,
                    "gateway": ip_addr
                }

    except subprocess.CalledProcessError as e:
        logging.error(f"❌ Fehler beim Ermitteln der Netzwerkschnittstellen: {e}")

    return interfaces

def sign_data(data):
    """Signiert JSON-Daten mit RSA."""
    hash_obj = SHA256.new(data.encode())
    return pkcs1_15.new(private_key).sign(hash_obj).hex()

def send_routes():
    """Broadcastet IPv4-Routen mit korrektem Gateway."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    while True:
        logging.info("🔄 `send_routes()` läuft...")

        routes = get_routing_table()
        interfaces = get_interfaces()

        logging.info(f"🌍 Routen gefunden: {routes}")
        logging.info(f"🌐 Interfaces erkannt: {interfaces}")

        if not routes or not interfaces:
            logging.warning("⚠️ Keine gültigen Routen oder Interfaces gefunden, überspringe Broadcast.")
            time.sleep(CONFIG["broadcast_interval"])
            continue

        for interface, data in interfaces.items():
            local_subnet = ip_network(data["subnet"], strict=False)
            broadcast_ip = data["broadcast"]
            router_ip = data["gateway"]

            if not broadcast_ip:
                logging.warning(f"⚠️ Keine Broadcast-Adresse für {interface}, überspringe.")
                continue

            valid_routes = []
            for route in routes:
                if ":" in route["subnet"]:  # IPv6 ignorieren
                    continue
                if ip_network(route["subnet"], strict=False).overlaps(local_subnet):
                    continue
                valid_routes.append({"subnet": route["subnet"], "gateway": router_ip, "timeout": 300})

            if not valid_routes:
                continue

            message = json.dumps({
                "routes": valid_routes,
                "signature": sign_data(json.dumps(valid_routes, separators=(',', ':'), sort_keys=True))
            })
            sock.sendto(message.encode(), (broadcast_ip, CONFIG["udp_port"]))

            logging.info(f"✅ IPv4 Broadcast gesendet an {broadcast_ip}: {message}")

        time.sleep(CONFIG["broadcast_interval"])

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

if __name__ == "__main__":
    app()