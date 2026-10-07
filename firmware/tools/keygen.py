"""Create a release signing key pair: private PEM (keep secret) + raw public key (commit).

    python tools/keygen.py secrets/release.pem keys/release.pub

Refuses to overwrite either file: a new key means every node needs the new public key.
"""
import os
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, os.path.dirname(__file__))
import release  # noqa: E402

pem_path, pub_path = sys.argv[1], sys.argv[2]
for p in (pem_path, pub_path):
    if os.path.exists(p):
        sys.exit(f"{p} already exists; not overwriting")

key = ec.generate_private_key(ec.SECP256R1())
pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption())
fd = os.open(pem_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "wb") as f:
    f.write(pem)
pub = release.public_raw(key)
with open(pub_path, "wb") as f:
    f.write(pub)
print(f"{pub_path}: fingerprint {release.fingerprint(pub)}")
