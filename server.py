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
    """Lädt eine alternative Konfigurationsdatei, falls angegeben."""
    if config_path.exists():
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    return DEFAULT_CONFIG

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
                interfaces[current_interface] = ip_addr

    except subprocess.CalledProcessError as e:
        logging.error(f"❌ Fehler beim Ermitteln der Netzwerkschnittstellen: {e}")

    return interfaces

def get_routing_table():
    """Ermittelt die IPv4-Routing-Tabelle für FreeBSD und OPNsense."""
    routes = []
    interfaces = get_interfaces()  # Lade Interface-IP-Adressen
    
    try:
        result = subprocess.run(["netstat", "-rn"], capture_output=True, text=True, check=True)
        lines = result.stdout.split("\n")
        
        found_header = False
        for line in lines:
            parts = line.split()

            # Header der Tabelle ignorieren
            if len(parts) < 3 or "Destination" in parts[0] or "Flags" in parts[1]:
                found_header = True
                continue
            
            if not found_header:
                continue

            # Mindestens drei Spalten nötig: Zielnetz, Gateway, Interface
            if len(parts) < 4:
                continue

            destination = parts[0]
            gateway = parts[1]
            interface = parts[-1]

            # IPv6-Routen ignorieren
            if ":" in destination or ":" in gateway:
                continue  

            # Default-Route ignorieren
            if destination == "default":
                continue

            # Loopback-Routen ignorieren
            try:
                if ip_address(destination).is_loopback:
                    continue
            except ValueError:
                if ip_network(destination, strict=False).subnet_of(ip_network("127.0.0.0/8")):
                    continue

            # Gateways wie "link#X" durch Interface-IP ersetzen
            if gateway.startswith("link#"):
                if interface in interfaces:
                    gateway = interfaces[interface]  # Ersetze mit der Interface-IP
                else:
                    logging.warning(f"⚠️ Fehlerhafte Route übersprungen: {destination} -> {gateway} (kein passendes Interface gefunden)")
                    continue

            routes.append({"subnet": destination, "gateway": gateway, "interface": interface, "timeout": 300})

    except subprocess.CalledProcessError as e:
        logging.error(f"❌ Fehler beim Auslesen der Routing-Tabelle: {e}")

    return routes

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

        for interface, ip in interfaces.items():
            broadcast_ip = ip  # Verwende Interface-IP als Broadcast (evtl. anpassen)
            router_ip = ip  # Interface-IP als Gateway

            valid_routes = [
                {"subnet": route["subnet"], "gateway": router_ip, "timeout": 300}
                for route in routes if route["subnet"] != router_ip
            ]

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
def generate_121():
    """Generiert den 121-DHCP-Optionen-String für OPNsense und zeigt eine Übersicht pro Interface."""
    routes = get_routing_table()
    interfaces = get_interfaces()
    
    # Dictionary für die Interface-spezifischen Routen
    routes_per_interface = {iface: [] for iface in interfaces}

    # Routen den entsprechenden Interfaces zuordnen
    for route in routes:
        interface = route["interface"]
        gateway = route["gateway"]
        subnet = route["subnet"]

        if interface in routes_per_interface:
            routes_per_interface[interface].append({"subnet": subnet, "gateway": gateway})
        else:
            logging.warning(f"⚠️ Route konnte nicht zugeordnet werden: {route}")

    print("\n=== DHCP Option 121 Konfiguration ===")
    
    for interface, interface_routes in routes_per_interface.items():
        if not interface_routes:
            continue
        
        print(f"\n🔹 **Interface {interface}**")
        dhcp_121_entries = []

        for route in interface_routes:
            try:
                net = IPv4Network(route["subnet"], strict=False)
                gateway = ip_address(route["gateway"])
                netmask_bits = net.prefixlen
                net_octets = net.network_address.packed

                # Kürze die Netzadresse (RFC 3442 Compact Format)
                significant_octets = net_octets[: (netmask_bits + 7) // 8]
                route_str = f"{netmask_bits:02X}:" + ":".join(f"{b:02X}" for b in significant_octets) + ":" + ":".join(f"{b:02X}" for b in gateway.packed)
                dhcp_121_entries.append(route_str)

                print(f"  ➝ {route['subnet']} via {route['gateway']}")

            except ValueError as e:
                logging.warning(f"⚠️ Fehlerhafte Route übersprungen: {route} ({e})")

        dhcp_121_string = ":".join(dhcp_121_entries)
        print(f"  📝 **Option 121 String**: {dhcp_121_string}")

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

if __name__ == "__main__":
    app()