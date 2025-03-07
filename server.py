import socket
import json
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

def get_interfaces_and_subnets():
    """Liest die Netzwerkschnittstellen & Subnetze aus `ifconfig`."""
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

                # Netzmaske umwandeln
                netmask_bits = sum(bin(int(x, 16)).count("1") for x in netmask_hex.split("."))
                subnet = f"{ip_addr}/{netmask_bits}"
                network = str(ip_network(subnet, strict=False).network_address)

                interfaces[current_interface] = {
                    "ip": ip_addr,
                    "subnet": subnet,
                    "network": f"{network}/{netmask_bits}",
                    "broadcast": broadcast
                }

    except subprocess.CalledProcessError as e:
        logging.error(f"❌ Fehler beim Ermitteln der Netzwerkschnittstellen: {e}")

    return interfaces

@app.command()
def generate_121():
    """Generiert den 121-DHCP-Optionen-String für OPNsense pro Interface."""
    interfaces = get_interfaces_and_subnets()
    print("\n=== DHCP Option 121 Konfiguration ===")

    for interface, data in interfaces.items():
        local_subnet = ip_network(data["subnet"], strict=False)
        router_ip = data["ip"]
        dhcp_121_entries = []
        filtered_routes = []

        # **Erstelle Routing-Tabellen für jedes Interface**
        for other_iface, other_data in interfaces.items():
            if other_iface == interface:
                continue  # Keine Route ins eigene Netz

            route_network = other_data["network"]
            route_gateway = router_ip  # Standard: Interface-IP als Gateway

            try:
                net = IPv4Network(route_network, strict=False)
                gateway = ip_address(route_gateway)

                # Berechne