"""Independent compact ECDH-ES fixture using only cryptography primitives.

The RFC 7518 section 4.6.2 ConcatKDF parameters and RFC 7516 protected
header AAD are assembled here, without a JOSE implementation. This helper
is test-only and processes synthetic keys supplied by the parity test.
"""

import base64
import json
import os
import struct
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash


def encode64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def decode64(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def public_key(jwk):
    assert jwk["kty"] == "EC" and jwk["crv"] == "P-256"
    x = int.from_bytes(decode64(jwk["x"]), "big")
    y = int.from_bytes(decode64(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


def private_key(jwk):
    public = public_key(jwk).public_numbers()
    scalar = int.from_bytes(decode64(jwk["d"]), "big")
    return ec.EllipticCurvePrivateNumbers(scalar, public).private_key()


def public_jwk(key):
    numbers = key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": encode64(numbers.x.to_bytes(32, "big")),
        "y": encode64(numbers.y.to_bytes(32, "big")),
    }


def length_prefixed(value):
    return struct.pack(">I", len(value)) + value


def content_key(secret, header):
    assert header["alg"] == "ECDH-ES"
    bits = {"A128GCM": 128, "A256GCM": 256}[header["enc"]]
    # For direct ECDH-ES, AlgorithmID identifies enc, rather than alg.
    other_info = (
        length_prefixed(header["enc"].encode("ascii"))
        + length_prefixed(decode64(header.get("apu", "")))
        + length_prefixed(decode64(header.get("apv", "")))
        + struct.pack(">I", bits)
    )
    return ConcatKDFHash(
        algorithm=hashes.SHA256(), length=bits // 8, otherinfo=other_info
    ).derive(secret)


def encrypt(request):
    recipient = public_key(request["key"])
    ephemeral = ec.generate_private_key(ec.SECP256R1())
    header = dict(request["header"])
    assert "epk" not in header
    header["epk"] = public_jwk(ephemeral.public_key())
    encoded_header = encode64(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    secret = ephemeral.exchange(ec.ECDH(), recipient)
    cek = content_key(secret, header)
    iv = os.urandom(12)
    sealed = AESGCM(cek).encrypt(
        iv, decode64(request["plaintext"]), encoded_header.encode("ascii")
    )
    compact = ".".join(
        [encoded_header, "", encode64(iv), encode64(sealed[:-16]), encode64(sealed[-16:])]
    )
    return {"compact": compact, "header": header}


def decrypt(request):
    protected, encrypted_key, iv, ciphertext, tag = request["compact"].split(".")
    assert encrypted_key == ""
    assert len(decode64(iv)) == 12 and len(decode64(tag)) == 16
    header = json.loads(decode64(protected))
    secret = private_key(request["key"]).exchange(ec.ECDH(), public_key(header["epk"]))
    cek = content_key(secret, header)
    plaintext = AESGCM(cek).decrypt(
        decode64(iv), decode64(ciphertext) + decode64(tag), protected.encode("ascii")
    )
    return {"plaintext": encode64(plaintext), "header": header}


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8") as source:
        request = json.load(source)
    operation = {"encrypt": encrypt, "decrypt": decrypt}[request["operation"]]
    print(json.dumps(operation(request), separators=(",", ":")))
