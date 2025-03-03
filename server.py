import socket
import json
import time
import logging
import subprocess
import typer
import yaml
from ipaddress import ip_network, ip_interface
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from pathlib import Path
import subprocess
import logging
from ipaddress import ip_network, ip_interface

# CLI-Framework initialisieren
app = typer.Typer()

# Standardwerte für Konfiguration
DEFAULT_CONFIG = {
    "udp_port": 5005,
    "broadcast_interval": 30,
    "private_key_file": "private.pem",
    "log_file": "server.log",
    "debug": False
}

CONFIG_FILE = Path("config.yaml")

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
    level=logging.DEBUG if CONFIG["debug"] else logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(CONFIG["log_file"]),
        logging.StreamHandler()
    ]
)

# Lade privaten Schlüssel für die Signatur der Routen
private_key_path = Path(CONFIG["private_key_file"])
if not private_key_path.exists():
    typer.echo(f"❌ Fehler: Private-Key Datei {CONFIG['private_key_file']} nicht gefunden!", err=True)
    raise typer.Exit(1)

import binascii

with open(private_key_path, "rb") as f:
    private_key = RSA.import_key(f.read())
    # Extrahiere den Public Key aus dem Private Key
    public_key = private_key.publickey()
    public_hex = binascii.hexlify(public_key.export_key()).decode()
    typer.echo("\n🟢 Öffentlicher Schlüssel (HEX-Format, gekürzt):")
    typer.echo(public_hex[:128] + "...")  # Nur ein Teil für Übersichtlichkeit

def get_interfaces():
    """Ermittelt Netzwerkschnittstellen, IPs, Subnetze und Broadcast-Adressen."""
    interfaces = {}

    try:
        # Führe `ip -o addr` aus und bereinige die Ausgabe
        result = subprocess.run(["ip", "-o", "addr"], capture_output=True, text=True, check=True)
        logging.info(f"DEBUG: Raw Output:\n{result.stdout}")

        # Verarbeite jede Zeile der Ausgabe
        for line in result.stdout.split("\n"):
            line = line.strip().replace("\\", "")  # Entferne `\`, die für Zeilenumbrüche stehen
            logging.info(f"DEBUG: Processing line: {line}")

            parts = line.split()

            if len(parts) > 4 and "inet" in parts:
                # Bestimme, an welcher Stelle der Interface-Name steht
                if parts[1] == "inet":
                    interface = parts[2]
                else:
                    interface = parts[1]

                ip_with_cidr = parts[3]  # IP-Adresse mit CIDR-Notation

                # Falls es sich um eine IPv4-Adresse handelt (ignoriert IPv6)
                if "." in ip_with_cidr:
                    net = ip_interface(ip_with_cidr).network  # Subnetz berechnen
                    broadcast = str(net.broadcast_address)  # Broadcast-Adresse bestimmen
                    router_ip = ip_with_cidr.split('/')[0]  # Eigene IP als Gateway

                    interfaces[interface] = {
                        "ip": router_ip,
                        "subnet": str(net),
                        "broadcast": broadcast,
                        "gateway": router_ip
                    }

                    logging.info(f"✅ Erkannte Schnittstelle: {interface}, IP: {router_ip}, Subnetz: {net}, Broadcast: {broadcast}")

    except subprocess.CalledProcessError as e:
        logging.error(f"❌ Fehler beim Ermitteln der Netzwerkschnittstellen: {e}")

    return interfaces

def get_routing_table():
    """
    Liest die Routing-Tabelle aus und gibt erreichbare Subnetze zurück.
    Ignoriert die Default-Route.
    """
    routes = []

    try:
        result = subprocess.run(["ip", "route"], capture_output=True, text=True, check=True)
        logging.info(f"DEBUG: Routing-Tabelle:\n{result.stdout}")

        for line in result.stdout.split("\n"):
            parts = line.split()
            if len(parts) >= 4 and parts[0] != "default":
                subnet = parts[0]  # Ziel-Subnetz
                device = parts[-1]  # Interface, über das das Subnetz erreichbar ist
                routes.append({"subnet": subnet, "interface": device, "timeout": 300})

    except subprocess.CalledProcessError as e:
        logging.error(f"Fehler beim Auslesen der Routing-Tabelle: {e}")

    return routes

def sign_data(data):
    """Signiert JSON-Daten mit RSA."""
    hash_obj = SHA256.new(data.encode())
    logging.info(f"SHA256-hash: {hash_obj.hexdigest()}")
    signature = pkcs1_15.new(private_key).sign(hash_obj)
    
    return signature.hex()

import socket
import json
import time
import logging
import subprocess
from ipaddress import ip_network, ip_interface
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

def send_routes():
    """Broadcastet genau `n-1` Routen pro Subnetz mit korrektem Gateway."""
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

        total_networks = len(interfaces)

        for interface, data in interfaces.items():
            local_subnet = ip_network(data["subnet"], strict=False)  # Fix: Umwandlung in `IPv4Network`
            broadcast_ip = data["broadcast"]
            router_ip = data["gateway"]

            logging.info(f"🌐 Sende Routen auf {interface} → Broadcast: {broadcast_ip}")

            valid_routes = [
                {"subnet": route["subnet"], "gateway": router_ip, "timeout": 300}
                for route in routes
                if not ip_network(route["subnet"], strict=False).overlaps(local_subnet)  # Fix hier!
            ]

            if len(valid_routes) != (total_networks - 1):
                logging.warning(f"⚠️ Falsche Anzahl an Routen für {interface}: {len(valid_routes)} (erwartet: {total_networks - 1})")

            if not valid_routes:
                logging.info(f"❌ Keine gültigen Routen für {interface}, überspringe Broadcast.")
                continue


            message = json.dumps({"routes": valid_routes, "signature": sign_data(json.dumps(valid_routes, separators=(',', ':'), sort_keys=True))})
            sock.sendto(message.encode(), (broadcast_ip, CONFIG["udp_port"]))

            logging.info(f"✅ Broadcast gesendet an {broadcast_ip}: {message}")

        time.sleep(CONFIG["broadcast_interval"])

@app.command()
def start():
    """Startet den Route Broadcast Server"""
    logging.info("Route Broadcast Server gestartet")
    send_routes()

@app.command()
def show_interfaces():
    """Zeigt erkannte Netzwerkschnittstellen und deren Subnetze"""
    interfaces = get_interfaces()
    typer.echo(yaml.dump(interfaces, default_flow_style=False))

@app.command()
def show_routes():
    """Zeigt die erkannten Routen in der Routing-Tabelle"""
    routes = get_routing_table()
    typer.echo(yaml.dump(routes, default_flow_style=False))

if __name__ == "__main__":
    app()