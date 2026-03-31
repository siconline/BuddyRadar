from __future__ import annotations

import ipaddress
import os
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def _collect_hostnames() -> set[str]:
    names = {'localhost'}
    try:
        hostname = socket.gethostname().strip()
        if hostname:
            names.add(hostname)
    except Exception:
        pass
    try:
        fqdn = socket.getfqdn().strip()
        if fqdn:
            names.add(fqdn)
    except Exception:
        pass
    return {name for name in names if name}


def _collect_ip_addresses() -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    result: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = {
        ipaddress.ip_address('127.0.0.1'),
        ipaddress.ip_address('::1'),
    }

    try:
        infos = socket.getaddrinfo(socket.gethostname(), None)
        for info in infos:
            address = info[4][0]
            try:
                result.add(ipaddress.ip_address(address))
            except ValueError:
                continue
    except Exception:
        pass

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(('8.8.8.8', 80))
            result.add(ipaddress.ip_address(sock.getsockname()[0]))
    except Exception:
        pass

    return result


def _set_permissions(path: Path, mode: int) -> None:
    try:
        os.chmod(path, mode)
    except Exception:
        pass


def _existing_cert_is_usable(
    cert_path: Path,
    expected_names: set[str],
    expected_ips: set[ipaddress.IPv4Address | ipaddress.IPv6Address],
) -> bool:
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    except Exception:
        return False

    now = datetime.now(timezone.utc)
    if hasattr(cert, 'not_valid_after_utc'):
        not_after = cert.not_valid_after_utc
    else:
        not_after = cert.not_valid_after.replace(tzinfo=timezone.utc)
    if now + timedelta(days=7) >= not_after:
        return False

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return False

    cert_names = set(san_ext.value.get_values_for_type(x509.DNSName))
    cert_ips = set(san_ext.value.get_values_for_type(x509.IPAddress))
    return expected_names.issubset(cert_names) and expected_ips.issubset(cert_ips)


def ensure_dev_certificate(cert_path: Path, key_path: Path) -> tuple[Path, Path]:
    cert_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    expected_names = _collect_hostnames()
    expected_ips = _collect_ip_addresses()

    if cert_path.exists() and key_path.exists() and _existing_cert_is_usable(cert_path, expected_names, expected_ips):
        _set_permissions(key_path, 0o600)
        _set_permissions(cert_path, 0o644)
        return cert_path, key_path

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, 'DE'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Buddy Radar'),
            x509.NameAttribute(NameOID.COMMON_NAME, 'Buddy Radar Development Certificate'),
        ]
    )

    sans: list[x509.GeneralName] = []
    sans.extend(x509.DNSName(name) for name in sorted(expected_names))
    sans.extend(x509.IPAddress(ip) for ip in sorted(expected_ips, key=str))

    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _set_permissions(key_path, 0o600)
    _set_permissions(cert_path, 0o644)
    return cert_path, key_path
