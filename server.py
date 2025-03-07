import socket
import json
import time
import logging
import subprocess
import typer
import yaml
from pathlib import Path
from ipaddress import ip_network, ip_address, IPv4Network
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
        lines = result.stdout.split("\n")
        
        found_header = False
        for line in lines:
            parts = line.split()

            if len(parts) < 3 or "Destination" in parts[0] or "Flags" in parts[1]:
                found_header = True
                continue  

            if not found_header:
                continue  

            if len(parts) < 4:
                continue

            destination = parts[0]
            interface = parts[-1]

            if ":" in destination:
                continue  

            if destination == "default":
                continue

            try:
                if ip_address(destination).is_loopback:
                    continue
            except ValueError:
                if ip_network(destination, strict=False).subnet_of(ip_network("127.0.0.0/8")):
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
            if not line.startswith("\t"):  
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
                if ":" in route["subnet"]:
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

def generate_121_string():
    """Erstellt den 121-String für den OPNsense-DHCP-Server."""
    routes = get_routing_table()
    dhcp_121_entries = []

    for route in routes:
        try:
            net = IPv4Network(route["subnet"], strict=False)
            gateway = ip_address(route["gateway"])

            # Berechne die Anzahl der Netzmaske-Bits
            netmask_bits = net.prefixlen

            # Nur signifikante Oktette für das Netzwerk senden
            network_octets = list(net.network_address.packed)
            significant_octets = network_octets[: (netmask_bits + 7) // 8]

            # Gateway in Oktetten umwandeln
            gateway_octets = list(gateway.packed)

            # Baue den String für diese Route
            route_entry = f"{netmask_bits:02X}:" + ":".join(f"{x:02X}" for x in significant_octets) + ":" + ":".join(f"{x:02X}" for x in gateway_octets)
            dhcp_121_entries.append(route_entry)

        except ValueError as e:
            logging.warning(f"⚠️ Fehlerhafte Route übersprungen: {route} ({e})")
            continue

    dhcp_121_string = ":".join(dhcp_121_entries)
    print(dhcp_121_string)

@app.command()
def start(config: Path = typer.Option("config.yaml", help="Pfad zur Konfigurationsdatei")):
    """Startet den Route Broadcast Server mit einer optionalen Konfigurationsdatei"""
    global CONFIG, private_key

    CONFIG = load_config(config)

    logging.basicConfig(
        level=logging.DEBUG if CONFIG["debug"] else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(CONFIG["log_file"]),
            logging.StreamHandler()
        ]
    )

    private_key_path = Path(CONFIG["private_key_file"])
    if not private_key_path.exists():
        logging.error(f"❌ Fehler: Private-Key Datei {CONFIG['private_key_file']} nicht gefunden!")
        raise typer.Exit(1)

    with open(private_key_path, "rb") as f:
        private_key = RSA.import_key(f.read())

    logging.info("✅ Route Broadcast Server gestartet")
    send_routes()

@app.command()
def generate_121():
    """Generiert den 121-DHCP-Optionen-String für OPNsense."""
    generate_121_string()

if __name__ == "__main__":
    app()