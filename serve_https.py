#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import os
import ssl
import subprocess
import tempfile
from functools import partial
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
CERT_FILE = BASE_DIR / "cert.pem"
KEY_FILE = BASE_DIR / "key.pem"
PORT = int(os.environ.get("PORT", "8443"))


def run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, check=True, capture_output=True, text=True)
    return result.stdout.strip()


def detect_ip() -> str | None:
    candidates = []
    for iface in ("en0", "en1"):
        try:
            ip = run(["ipconfig", "getifaddr", iface])
            if ip:
                candidates.append(ip)
        except Exception:
            pass
    for ip in candidates:
        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            continue
    return None


def ensure_cert(ip: str | None) -> None:
    openssl_conf = f"""
    [req]
    distinguished_name=req_distinguished_name
    x509_extensions=v3_req
    prompt=no

    [req_distinguished_name]
    CN=localhost

    [v3_req]
    subjectAltName=@alt_names

    [alt_names]
    DNS.1=localhost
    IP.1=127.0.0.1
    """
    if ip:
        openssl_conf += f"IP.2={ip}\n"

    with tempfile.TemporaryDirectory() as tmpdir:
        conf_path = Path(tmpdir) / "openssl.cnf"
        conf_path.write_text(openssl_conf, encoding="utf-8")
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-nodes",
                "-newkey",
                "rsa:2048",
                "-days",
                "3650",
                "-keyout",
                str(KEY_FILE),
                "-out",
                str(CERT_FILE),
                "-config",
                str(conf_path),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def main() -> int:
    os.chdir(BASE_DIR)
    ip = detect_ip()
    ensure_cert(ip)

    handler = partial(SimpleHTTPRequestHandler, directory=str(BASE_DIR))
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    print(f"HTTPS server running on https://localhost:{PORT}/")
    if ip:
        print(f"LAN access: https://{ip}:{PORT}/")
    print("Press Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
