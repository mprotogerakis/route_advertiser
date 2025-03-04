import json
import logging
import socket
import subprocess
import threading
import time
import typer
import yaml
import ipaddress
import re
import platform
import binascii
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# CLI-Setup mit Typer
app = typer.Typer()

# Konfigurationsdatei laden
CONFIG_PATH = Path("client_config.yaml")

if CONFIG_PATH.exists():
    with open(CONFIG_PATH, "r", encoding="utf-8") as file:
        CONFIG = yaml.safe_load(file)
else:
    typer.echo("?? Konfigurationsdatei client_config.yaml nicht gefunden!", err=True)
    raise typer.Exit(code=1)

# Logging konfigurieren
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)

# Globale Variable für geplante Routenlöschungen
route_expiry = {}

# Ermitteln des Betriebssystems
OS_TYPE = platform.system()


def get_existing_routes():
    """Ermittelt die aktuellen Routing-Tabelle für Windows, Linux und macOS"""
    existing_routes = set()

    try:
        if OS_TYPE == "Windows":
            output = subprocess.check_output(["route", "print"], text=True, encoding="cp850")
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

        elif OS_TYPE == "Linux":
            output = subprocess.check_output(["ip", "route", "show"], text=True)
            existing_routes = {line.split()[0] for line in output.splitlines() if "/" in line.split()[0]}

        elif OS_TYPE == "Darwin":  # macOS
            output = subprocess.check_output(["netstat", "-rn"], text=True)
            for line in output.splitlines():
                parts = line.split()
                if len(parts) > 1 and re.match(r"\d+\.\d+\.\d+\.\d+", parts[0]):
                    try:
                        net = ipaddress.IPv4Network(parts[0], strict=False)
                        existing_routes.add(f"{net.network_address}/{net.prefixlen}")
                    except ValueError:
                        pass

        logging.debug(f"? Bekannte Routen: {existing_routes}")

    except Exception as e:
        logging.error(f"? Fehler beim Abrufen der Routing-Tabelle: {e}")

    return existing_routes


def get_local_ip():
    """Ermittelt die lokale IP-Adresse für Windows, Linux und macOS"""
    try:
        if OS_TYPE == "Windows":
            output = subprocess.check_output(["ipconfig"], text=True, encoding="cp850")
            match = re.search(r"IPv4-Adresse.*?: (\d+\.\d+\.\d+\.\d+)", output)
            return match.group(1) if match else None

        elif OS_TYPE == "Linux":
            output = subprocess.check_output(["ip", "-4", "addr", "show"], text=True)
            match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/", output)
            return match.group(1) if match else None

        elif OS_TYPE == "Darwin":  # macOS
            output = subprocess.check_output(["scutil", "--nwi"], text=True)
            match = re.search(r"address\s+:\s+(\d+\.\d+\.\d+\.\d+)", output)
            return match.group(1) if match else None

    except Exception as e:
        logging.error(f"? Fehler beim Ermitteln der lokalen IP-Adresse: {e}")
        return None


def verify_signature(data, signature_hex, public_key_path):
    """Überprüft eine digitale Signatur"""
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

    except Exception as e:
        logging.error(f"? Unerwarteter Fehler während der Signaturprüfung: {e}")
        return False


def schedule_route_removal(subnet, gateway, timeout, test_mode=False):
    """Führt das Entfernen der Route nach einer Verzögerung aus"""
    global route_expiry
    expiry_time = time.time() + timeout
    route_expiry[(subnet, gateway)] = expiry_time

    def remove_route():
        time.sleep(timeout)
        if (subnet, gateway) in route_expiry and route_expiry[(subnet, gateway)] == expiry_time:
            remove_cmd = f"route del {subnet} {gateway}" if OS_TYPE == "Windows" else f"ip route del {subnet} via {gateway}"
            if test_mode:
                logging.info(f"TESTMODE: {remove_cmd}")
            else:
                try:
                    subprocess.run(remove_cmd.split(), check=True)
                    logging.info(f"?? Route entfernt: {subnet}")
                except subprocess.CalledProcessError as e:
                    logging.error(f"? Fehler beim Entfernen der Route: {e}")

            del route_expiry[(subnet, gateway)]

    threading.Thread(target=remove_route, daemon=True).start()


def listen_for_routes(test_mode=False):
    """Lauscht auf UDP-Pakete und verarbeitet empfangene Routen"""
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

                cmd = f"route add {subnet} {gateway}" if OS_TYPE == "Windows" else f"ip route add {subnet} via {gateway}"
                if test_mode:
                    logging.info(f"TESTMODE: {cmd}")
                else:
                    try:
                        subprocess.run(cmd.split(), check=True)
                        logging.info(f"? Route hinzugefügt: {subnet} via {gateway}")
                    except subprocess.CalledProcessError as e:
                        logging.error(f"? Fehler beim Hinzufügen der Route: {e}")

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
    listen_for_routes(test_mode=False)


@app.command()
def test():
    listen_for_routes(test_mode=True)


if __name__ == "__main__":
    app()