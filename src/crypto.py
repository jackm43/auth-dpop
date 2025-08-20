# pip install jwcrypto cryptography
from jwcrypto import jwk
from pathlib import Path
from base64 import urlsafe_b64encode
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta
import json, os

BASE = Path("assets")
(CC_DIR, DPOP_DIR) = (BASE, BASE)  # same assets dir as your repo

def b64u(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode()

def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

def rsa_keypair_jwk_rs256():
    k = jwk.JWK.generate(kty='RSA', size=2048)
    # Compute RFC7638 thumbprint as kid
    kid = k.thumbprint()  # base64url(SHA-256) over {"e","kty","n"}
    # annotate use/alg/kid on both private and public JWK exports
    pub = jwk.JWK()
    pub.import_key(**json.loads(k.export_public()))
    pub['use'] = 'sig'
    pub['alg'] = 'RS256'
    pub['kid'] = kid

    priv = jwk.JWK()
    priv.import_key(**json.loads(k.export_private()))
    priv['use'] = 'sig'
    priv['alg'] = 'RS256'
    priv['kid'] = kid

    # JWKS
    jwks = {"keys": [json.loads(pub.export(private_key=False))]}
    return priv, pub, jwks, kid

def write_pem_and_jwks(prefix: str, target_dir: Path, priv: jwk.JWK, pub: jwk.JWK, jwks: dict):
    ensure_dir(target_dir)
    # Private key PEM (PKCS#8)
    (target_dir / f"{prefix}_private_key.pem").write_bytes(
        priv.export_to_pem(private_key=True, password=None)
    )
    # Public key PEM
    (target_dir / f"{prefix}_public_key.pem").write_bytes(
        pub.export_to_pem()
    )
    # Public JWKS JSON
    (target_dir / f"{prefix}_public_key.json").write_text(
        json.dumps(jwks, indent=2)
    )

def self_signed_cert_from_pem(priv_pem: bytes, pub_pem: bytes, cn: str) -> bytes:
    # Build a short self-signed X.509 cert for display/reference
    private_key = serialization.load_pem_private_key(priv_pem, password=None)
    public_key = serialization.load_pem_public_key(pub_pem)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow() - timedelta(minutes=5))
        .not_valid_after(datetime.utcnow() + timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.PEM)

def run():
    ensure_dir(CC_DIR)
    ensure_dir(DPOP_DIR)

    # ---- Client Credentials (private_key_jwt) keypair ----
    cc_priv, cc_pub, cc_jwks, cc_kid = rsa_keypair_jwk_rs256()
    write_pem_and_jwks("cc", CC_DIR, cc_priv, cc_pub, cc_jwks)
    cc_cert_pem = self_signed_cert_from_pem(
        (CC_DIR / "cc_private_key.pem").read_bytes(),
        (CC_DIR / "cc_public_key.pem").read_bytes(),
        "okta-client"
    )
    (CC_DIR / "cc_cert.pem").write_bytes(cc_cert_pem)

    # ---- DPoP signing keypair ----
    dpop_priv, dpop_pub, dpop_jwks, dpop_kid = rsa_keypair_jwk_rs256()
    write_pem_and_jwks("dpop", DPOP_DIR, dpop_priv, dpop_pub, dpop_jwks)
    dpop_cert_pem = self_signed_cert_from_pem(
        (DPOP_DIR / "dpop_private_key.pem").read_bytes(),
        (DPOP_DIR / "dpop_public_key.pem").read_bytes(),
        "dpop"
    )
    (DPOP_DIR / "dpop_cert.pem").write_bytes(dpop_cert_pem)

    # Minimal console output for verification
    pub_cc = json.loads((CC_DIR / "cc_public_key.json").read_text())["keys"][0]
    pub_dp = json.loads((DPOP_DIR / "dpop_public_key.json").read_text())["keys"][0]
    print("Client kid:", pub_cc["kid"])
    print("DPoP kid:  ", pub_dp["kid"])
    # Okta requires at least kty, n, e, kid; alg/use optional but fine
    for lbl, jwk_pub in [("client", pub_cc), ("dpop", pub_dp)]:
        assert all(k in jwk_pub for k in ("kty", "n", "e", "kid"))

if __name__ == "__main__":
    run()
