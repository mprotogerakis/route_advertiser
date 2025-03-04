import socket
import json
import time
import logging
import subprocess
import typer
import yaml
import platform
from ipaddress import ip_network, ip_interface
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from pathlib import Path
import binascii
import re

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

with open(private_key_path, "rb") as f:
    private_key = RSA.import_key(f.read())

def convert_netmask_to_cidr(netmask):
    """Konvertiert eine Netzmaske in CIDR-Notation"""
    if netmask.startswith("0x"):  # Hex-Notation (FreeBSD/OPNsense)
        netmask = '.'.join(str(int(netmask[i:i+2], 16)) for i in range(2, 10, 2))
    return str(ip_network(f"0.0.0.0/{netmask}").prefixlen)

def get_interfaces():
    """Ermittelt Netzwerkschnittstellen, IPs, Subnetze und Broadcast-Adressen für Linux und FreeBSD/OPNsense."""
    interfaces = {}
    try:
        if "freebsd" in platform.system().lower():
            # FreeBSD / OPNsense nutzt `ifconfig`
            result = subprocess.run(["ifconfig"], capture_output=True, text=True, check=True)
            lines = result.stdout.split("\n")

            interface = None
            for line in lines:
                if not line.startswith("\t"):  # Neue Schnittstelle
                    interface = line.split(":")[0]
                elif "inet " in line and "netmask" in line:
                    parts = line.split()
                    ip_addr = parts[1]
                    netmask_hex = parts[3]
                    netmask = convert_netmask_to_cidr(netmask_hex)
                    subnet = f"{ip_addr}/{netmask}"
                    broadcast = parts[5] if "broadcast" in line else None

                    interfaces[interface] = {
                        "ip": ip_addr,
                        "subnet": subnet,
                        "broadcast": broadcast,
                        "gateway": ip_addr
                    }
        else:
            # Linux nutzt `ip -o addr`
            result = subprocess.run(["ip", "-o", "addr"], capture_output=True, text=True, check=True)
            for line in result.stdout.split("\n"):
                parts = line.split()
                if len(parts) > 4 and "inet" in parts:
                    interface = parts[1]
                    ip_with_cidr = parts[3]
                    net = ip_interface(ip_with_cidr).network
                    broadcast = str(net.broadcast_address)
                    router_ip = ip_with_cidr.split('/')[0]

                    interfaces[interface] = {
                        "ip": router_ip,
                        "subnet": str(net),
                        "broadcast": broadcast,
                        "gateway": router_ip
                    }

    except subprocess.CalledProcessError as e:
        logging.error(f"❌ Fehler beim Ermitteln der Netzwerkschnittstellen: {e}")

    return interfaces

def get_routing_table():
    """Liest die Routing-Tabelle aus und gibt erreichbare Subnetze zurück. Ignoriert die Default-Route."""
    routes = []
    try:
        if "freebsd" in platform.system().lower():
            result = subprocess.run(["netstat", "-rn"], capture_output=True, text=True, check=True)
            lines = result.stdout.split("\n")

            for line in lines:
                parts = re.split(r'\s+', line.strip())
                if len(parts) >= 3 and not parts[0].startswith("default"):
                    subnet = parts[0]
                    device = parts[-1]
                    if "." in subnet:  # Nur IPv4-Routen speichern
                        routes.append({"subnet": subnet, "interface": device, "timeout": 300})
        else:
            result = subprocess.run(["ip", "route"], capture_output=True, text=True, check=True)
            for line in result.stdout.split("\n"):
                parts = line.split()
                if len(parts) >= 4 and parts[0] != "default":
                    subnet = parts[0]
                    device = parts[-1]
                    routes.append({"subnet": subnet, "interface": device, "timeout": 300})

    except subprocess.CalledProcessError as e:
        logging.error(f"Fehler beim Auslesen der Routing-Tabelle: {e}")

    return routes

def sign_data(data):
    """Signiert JSON-Daten mit RSA."""
    hash_obj = SHA256.new(data.encode())
    signature = pkcs1_15.new(private_key).sign(hash_obj)
    return signature.hex()

import json

def chunk_list(lst, chunk_size):
    """Teilt eine Liste in kleinere Teile auf."""
    for i in range(0, len(lst), chunk_size):
        yield lst[i:i + chunk_size]

def send_routes():
    """Broadcastet Routen in kleineren UDP-Paketen."""
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

        max_routes_per_packet = 5  # Empirischer Wert, um UDP-Fehler zu vermeiden

        for interface, data in interfaces.items():
            local_subnet = ip_network(data["subnet"], strict=False)
            broadcast_ip = data["broadcast"]
            router_ip = data["gateway"]

            valid_routes = [
                {"subnet": route["subnet"], "gateway": router_ip, "timeout": 300}
                for route in routes
                if not ip_network(route["subnet"], strict=False).overlaps(local_subnet)
            ]

            if not valid_routes:
                logging.info(f"❌ Keine gültigen Routen für {interface}, überspringe Broadcast.")
                continue

            # Aufteilen der Routenliste in kleinere Pakete
            for chunk in chunk_list(valid_routes, max_routes_per_packet):
                message = json.dumps({
                    "routes": chunk,
                    "signature": sign_data(json.dumps(chunk, separators=(',', ':'), sort_keys=True))
                })
                try:
                    sock.sendto(message.encode(), (broadcast_ip, CONFIG["udp_port"]))
                    logging.info(f"✅ Broadcast gesendet an {broadcast_ip}: {message}")
                except OSError as e:
                    logging.error(f"❌ Fehler beim Senden des UDP-Pakets: {e}")

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