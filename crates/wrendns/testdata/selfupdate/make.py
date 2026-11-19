"""Regenerates the self-update fixtures (REQ: OPS-004): `SHA256SUMS` for `release-binary` under each
release asset name, signed with a new throwaway minisign key (NOT the release key), and `test.pub`.
Needs the `cryptography` package. Prints the public key: paste it into `TEST_KEY` in
`src/selfupdate_tests.rs`. The signature is minisign's prehashed `ED` form, as in
`../updates/make.py`."""
import base64, hashlib, os
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

here = os.path.dirname(os.path.abspath(__file__))
sk = Ed25519PrivateKey.generate()
pk = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
key_id = os.urandom(8)


def sign(data: bytes, name: str) -> str:
    sig = sk.sign(hashlib.blake2b(data, digest_size=64).digest())
    trusted = f"timestamp:1791201600\tfile:{name}\thashed"
    glob = sk.sign(sig + trusted.encode())
    return (
        "untrusted comment: signature from a WrenDNS test key\n"
        + base64.b64encode(b"ED" + key_id + sig).decode() + "\n"
        + f"trusted comment: {trusted}\n"
        + base64.b64encode(glob).decode() + "\n"
    )


binary = open(os.path.join(here, "release-binary"), "rb").read()
digest = hashlib.sha256(binary).hexdigest()
sums = "".join(f"{digest}  wrendns-{a}-linux\n" for a in ("x86_64", "aarch64", "armv7")).encode()
open(os.path.join(here, "SHA256SUMS"), "wb").write(sums)
open(os.path.join(here, "SHA256SUMS.minisig"), "w", newline="\n").write(sign(sums, "SHA256SUMS"))
pub = base64.b64encode(b"Ed" + key_id + pk).decode()
open(os.path.join(here, "test.pub"), "w", newline="\n").write(pub + "\n")
print(pub)
