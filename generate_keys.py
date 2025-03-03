from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Schlüsselpaar erzeugen
key = RSA.generate(4096)
private_key = key.export_key()
public_key = key.publickey().export_key()

# Private Key speichern (Server)
with open("private.pem", "wb") as f:
    f.write(private_key)

# Public Key speichern (für Clients)
with open("public.pem", "wb") as f:
    f.write(public_key)

print("🔑 Schlüssel erstellt: private.pem & public.pem")