from __future__ import annotations

import datetime as dt
import ipaddress
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_lock = threading.Lock()
_cert_cache: dict[str, tuple[bytes, bytes]] = {}


def certs_dir(base: Path | None = None) -> Path:
    root = base or Path(__file__).resolve().parent.parent / "data" / "certs"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _new_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def ensure_ca(base: Path | None = None) -> tuple[Path, Path]:
    d = certs_dir(base)
    cert_path = d / "vkpm-ca.crt"
    key_path = d / "vkpm-ca.key"
    if cert_path.is_file() and key_path.is_file():
        return cert_path, key_path

    key = _new_key()
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "RU"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VKPM Fix Local CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "VKPM Fix Local CA"),
        ]
    )
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def issue_host_cert(hostname: str, base: Path | None = None) -> tuple[bytes, bytes]:
    host = hostname.lower().strip(".")
    with _lock:
        if host in _cert_cache:
            return _cert_cache[host]

        ca_cert_path, ca_key_path = ensure_ca(base)
        ca_cert = x509.load_pem_x509_certificate(ca_cert_path.read_bytes())
        ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)

        key = _new_key()
        now = dt.datetime.now(dt.timezone.utc)
        san: list[x509.GeneralName] = [x509.DNSName(host)]
        if host.startswith("*."):
            san.append(x509.DNSName(host[2:]))
        try:
            san.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            pass

        cert = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
            )
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        _cert_cache[host] = (cert_pem, key_pem)
        return cert_pem, key_pem
