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

app = typer.Typer()

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
            
            if not found_header or len(parts) < 4:
                continue

            destination = parts[0]
            gateway = parts[1]
            interface = parts[-1]  

            if ":" in destination:  # IPv6 ignorieren
                continue

            if destination == "default":
                continue

            # "link#X" Einträge als Gateway ignorieren (ungültig für DHCP)
            if gateway.startswith("link#"):
                logging.warning(f"⚠️ Fehlerhafte Route übersprungen: {destination} -> {gateway}")
                continue

            # Loopback-Routen ignorieren
            try:
                if ip_address(destination).is_loopback:
                    continue
            except ValueError:
                if ip_network(destination, strict=False).subnet_of(ip_network("127.0.0.0/8")):
                    continue

            routes.append({"subnet": destination, "gateway": gateway, "interface": interface, "timeout": 300})

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

@app.command()
def generate_121():
    """Generiert den 121-DHCP-Optionen-String für OPNsense pro Interface."""
    routes = get_routing_table()
    interfaces = get_interfaces()

    print("\n=== DHCP Option 121 Konfiguration ===")

    for interface, data in interfaces.items():
        local_subnet = ip_network(data["subnet"], strict=False)
        router_ip = data["gateway"]
        dhcp_121_entries = []
        filtered_routes = []

        for route in routes:
            route_subnet = route["subnet"]
            route_gateway = route["gateway"]

            # Routen im gleichen Netz wie das Interface ignorieren
            if ip_network(route_subnet, strict=False).overlaps(local_subnet):
                continue

            try:
                net = IPv4Network(route_subnet, strict=False)
                gateway = ip_address(router_ip)

                netmask_bits = net.prefixlen
                net_octets = net.network_address.packed

                significant_octets = net_octets[: (netmask_bits + 7) // 8]
                route_str = f"{netmask_bits:02X}:" + ":".join(f"{b:02X}" for b in significant_octets) + ":" + ":".join(f"{b:02X}" for b in gateway.packed)
                dhcp_121_entries.append(route_str)

                filtered_routes.append(f"  ➝ {route_subnet} via {router_ip}")

            except ValueError as e:
                logging.warning(f"⚠️ Fehlerhafte Route übersprungen: {route_subnet} ({e})")

        if dhcp_121_entries:
            print(f"\n🔹 **Interface {interface} ({data['subnet']})**")
            print("\n".join(filtered_routes))
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

if __name__ == "__main__":
    app()