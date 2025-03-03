import json
import logging
import socket
import subprocess
import time
import threading
import typer
import yaml
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import ipaddress
import re
import platform
import binascii
import ctypes

# CLI-Setup mit Typer
app = typer.Typer()

# Konfigurationsdatei laden
CONFIG_PATH = Path("client_config.yaml")

if CONFIG_PATH.exists():
    with open(CONFIG_PATH, "r", encoding="utf-8") as file:
        CONFIG = yaml.safe_load(file)
else:
    typer.echo("? Konfigurationsdatei client_config.yaml nicht gefunden!", err=True)
    raise typer.Exit(code=1)

# Logging konfigurieren (Unicode-kompatibel für Windows)
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)

# Prüfen, ob das Skript als Administrator ausgeführt wird
def is_admin():
    """Überprüft, ob das Skript mit Admin-Rechten läuft."""
    if platform.system() == "Windows":
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        return os.geteuid() == 0  # Linux: Prüfen, ob root

if not is_admin():
    logging.error("? Fehler: Dieses Skript muss mit Administratorrechten ausgeführt werden!")
    typer.echo("Bitte starten Sie das Skript als Administrator (Rechtsklick -> 'Als Administrator ausführen').")
    raise typer.Exit(code=1)

# Globale Variable für geplante Löschungen
route_expiry = {}

def get_existing_routes():
    """Liest die vorhandenen Routen aus dem System und gibt sie als Set im Format x.x.x.x/y zurück."""
    existing_routes = set()
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output(["route", "print"], text=True, encoding="cp1252")
            lines = output.splitlines()
            for line in lines:
                match = re.match(r"\s*(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)", line)
                if match:
                    network, netmask = match.groups()
                    try:
                        cidr_suffix = ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
                        existing_routes.add(f"{network}/{cidr_suffix}")
                    except ValueError:
                        logging.warning(f"?? Ungültige Netzmaske: {netmask} für {network}")
        else:
            output = subprocess.check_output(["ip", "route", "show"], text=True, encoding="utf-8")
            existing_routes = {line.split()[0] for line in output.splitlines() if "/" in line.split()[0]}
        logging.debug(f"? Bekannte Routen: {existing_routes}")
    except FileNotFoundError as e:
        logging.error(f"? Fehler beim Abrufen der Routing-Tabelle: {e}")
    except Exception as e:
        logging.error(f"? Fehler beim Parsen der Routing-Tabelle: {e}")
    return existing_routes

def verify_signature(data, signature_hex, public_key_path):
    """Überprüft eine digitale Signatur mit detailliertem Debugging"""
    try:
        with open(public_key_path, "rb") as key_file:
            public_key = RSA.import_key(key_file.read())
        h = SHA256.new(data.encode("utf-8"))
        signature_bytes = binascii.unhexlify(signature_hex.strip())

        try:
            pkcs1_15.new(public_key).verify(h, signature_bytes)
            logging.info("? Signatur ist gültig!")
            return True
        except ValueError:
            logging.error("? Signaturprüfung fehlgeschlagen: Ungültige Signatur!")
            return False

    except FileNotFoundError:
        logging.error("? Fehler: Public-Key-Datei nicht gefunden!")
        return False
    except Exception as e:
        logging.error(f"? Unerwarteter Fehler während der Signaturprüfung: {e}")
        return False

def add_route(subnet, gateway, test_mode=False):
    """Fügt eine Route hinzu, abhängig vom Betriebssystem."""
    if platform.system() == "Windows":
        cmd = f"route add {subnet} {gateway}"
    else:
        cmd = f"ip route add {subnet} via {gateway}"

    if test_mode:
        logging.info(f"TESTMODE: {cmd}")
    else:
        try:
            subprocess.run(cmd.split(), check=True)
            logging.info(f"? Route hinzugefügt: {subnet} via {gateway}")
        except subprocess.CalledProcessError as e:
            logging.error(f"? Fehler beim Hinzufügen der Route: {e}")

def remove_route(subnet, gateway, test_mode=False):
    """Entfernt eine Route, abhängig vom Betriebssystem."""
    if platform.system() == "Windows":
        cmd = f"route delete {subnet}"
    else:
        cmd = f"ip route del {subnet} via {gateway}"

    if test_mode:
        logging.info(f"TESTMODE: {cmd}")
    else:
        try:
            subprocess.run(cmd.split(), check=True)
            logging.info(f"?? Route entfernt: {subnet}")
        except subprocess.CalledProcessError as e:
            logging.error(f"? Fehler beim Entfernen der Route: {e}")

def schedule_route_removal(subnet, gateway, timeout, test_mode=False):
    """Führt das Entfernen der Route nach einer Verzögerung aus, falls sie nicht erneut erhalten wurde."""
    global route_expiry
    expiry_time = time.time() + timeout
    route_expiry[(subnet, gateway)] = expiry_time

    def remove_route_thread():
        time.sleep(timeout)
        # Prüfen, ob die Route immer noch zur Entfernung vorgesehen ist
        if (subnet, gateway) in route_expiry and route_expiry[(subnet, gateway)] == expiry_time:
            remove_route(subnet, gateway, test_mode)
            del route_expiry[(subnet, gateway)]  # Aus der Liste der geplanten Löschungen entfernen

    threading.Thread(target=remove_route_thread, daemon=True).start()

def listen_for_routes(test_mode=False):
    """Lauscht auf UDP-Pakete und verarbeitet empfangene Routen."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", CONFIG["udp_port"]))

    logging.info(f"? Lausche auf UDP-Port {CONFIG['udp_port']} für Routen-Updates...")

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            decoded_data = json.loads(data.decode())

            signature = decoded_data.get("signature", "")
            message_data = json.dumps(decoded_data["routes"], separators=(",", ":"), sort_keys=True)

            if not verify_signature(message_data, signature, CONFIG["public_key_file"]):
                logging.error("? Signaturprüfung fehlgeschlagen! Nachricht ignoriert.")
                continue

            logging.info(f"? Empfangene Daten von {addr}: {decoded_data}")

            existing_routes = get_existing_routes()
            for route in decoded_data["routes"]:
                subnet = route["subnet"]
                gateway = route["gateway"]

                if subnet in existing_routes:
                    logging.info(f"? Route {subnet} ist bereits erreichbar, wird nicht hinzugefügt.")
                    continue

                add_route(subnet, gateway, test_mode)
                timeout = route.get("timeout", 300)
                schedule_route_removal(subnet, gateway, timeout, test_mode)

            logging.info("? Alle Routen erfolgreich verarbeitet.")

        except KeyboardInterrupt:
            logging.info("? Beende Route Listener...")
            break
        except Exception as e:
            logging.error(f"? Fehler beim Empfangen von UDP-Paketen: {e}")

@app.command()
def start():
    """Startet den Route-Client."""
    listen_for_routes(test_mode=False)

@app.command()
def test():
    """Testmodus: Zeigt Befehle, führt sie aber nicht aus."""
    listen_for_routes(test_mode=True)

if __name__ == "__main__":
    app()