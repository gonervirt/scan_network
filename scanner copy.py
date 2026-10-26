"""Conservative, explicitly scoped TCP service inventory for private IPv4 networks."""

from __future__ import annotations

import argparse
import csv
import html.parser
import ipaddress
import json
import os
import socket
import ssl
import tempfile
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


DEFAULT_PORTS = (21, 22, 23, 25, 53, 80, 110, 443, 445, 3389, 8080, 8443)
MAX_HOSTS = 1024
MAX_WORKERS = 128
MAX_RATE = 10
STATE_CHECKPOINT_INTERVAL = 64
MAX_RESPONSE_BYTES = 1_000_000
CSV_FIELDS = (
    "scan_time", "ip", "port", "status", "service", "banner", "fqdn",
    "tls_subject", "tls_issuer", "tls_valid_from", "tls_valid_to",
    "tls_dns_names", "http_status", "http_title", "snapshot_path", "error",
)
PRIVATE_V4 = tuple(ipaddress.ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))


class ScopeError(ValueError):
    pass


class RateLimiter:
    def __init__(self, rate: float) -> None:
        self.interval = 1.0 / rate
        self.lock = threading.Lock()
        self.next_allowed = 0.0

    def wait(self) -> None:
        with self.lock:
            now = time.monotonic()
            delay = max(0.0, self.next_allowed - now)
            self.next_allowed = max(now, self.next_allowed) + self.interval
        if delay:
            time.sleep(delay)


class TitleParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.in_title = False
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() == "title":
            self.in_title = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.parts.append(data.strip())


def parse_addresses(cidr_values: Iterable[str], ip_file: str | None, exclusions: Iterable[str], limit: int) -> list[str]:
    if limit < 1 or limit > MAX_HOSTS:
        raise ScopeError(f"--max-hosts must be between 1 and {MAX_HOSTS}")
    networks: list[ipaddress.IPv4Network] = []
    addresses: set[ipaddress.IPv4Address] = set()
    for value in cidr_values:
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ScopeError(f"Invalid CIDR: {value}") from exc
        if not isinstance(network, ipaddress.IPv4Network) or not any(network.subnet_of(private) for private in PRIVATE_V4):
            raise ScopeError(f"Only IPv4 addresses wholly inside RFC1918 private ranges are allowed: {value}")
        networks.append(network)
    if ip_file:
        try:
            lines = Path(ip_file).read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            raise ScopeError(f"Cannot read IP file: {exc}") from exc
        for line_number, raw in enumerate(lines, start=1):
            value = raw.split("#", 1)[0].strip()
            if not value:
                continue
            try:
                address = ipaddress.ip_address(value)
            except ValueError as exc:
                raise ScopeError(f"Invalid IP on line {line_number}: {value}") from exc
            if not isinstance(address, ipaddress.IPv4Address) or not any(address in private for private in PRIVATE_V4):
                raise ScopeError(f"Only RFC1918 private IPv4 addresses are allowed: {value}")
            addresses.add(address)
            if len(addresses) > limit:
                raise ScopeError(f"Resolved scope exceeds the configured limit of {limit} hosts")
    for network in networks:
        host_count = max(0, network.num_addresses - (0 if network.prefixlen >= 31 else 2))
        if host_count > limit:
            raise ScopeError(f"CIDR {network} exceeds the configured limit of {limit} hosts")
        addresses.update(network.hosts())
        if len(addresses) > limit:
            raise ScopeError(f"Resolved scope exceeds the configured limit of {limit} hosts")
    excluded_addresses: set[ipaddress.IPv4Address] = set()
    excluded_networks: list[ipaddress.IPv4Network] = []
    for value in exclusions:
        try:
            if "/" in value:
                network = ipaddress.ip_network(value, strict=False)
                if not isinstance(network, ipaddress.IPv4Network):
                    raise ValueError
                excluded_networks.append(network)
            else:
                address = ipaddress.ip_address(value)
                if not isinstance(address, ipaddress.IPv4Address):
                    raise ValueError
                excluded_addresses.add(address)
        except ValueError as exc:
            raise ScopeError(f"Invalid exclusion: {value}") from exc
    result = sorted(
        address for address in addresses
        if address not in excluded_addresses and not any(address in network for network in excluded_networks)
    )
    if len(result) > limit:
        raise ScopeError(f"Resolved scope exceeds the configured limit of {limit} hosts")
    if not result:
        raise ScopeError("No hosts remain in scope after exclusions")
    return [str(address) for address in result]


def safe_ip_dir(work_dir: Path, ip: str) -> Path:
    address = ipaddress.ip_address(ip)
    path = work_dir / f"{address.version}_{address.compressed.replace(':', '_')}"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _tls_metadata(sock: ssl.SSLSocket) -> dict[str, str]:
    cert = sock.getpeercert()
    subject = ", ".join("=".join(part) for group in cert.get("subject", ()) for part in group)
    issuer = ", ".join("=".join(part) for group in cert.get("issuer", ()) for part in group)
    names = ", ".join(value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS")
    return {
        "tls_subject": subject,
        "tls_issuer": issuer,
        "tls_valid_from": cert.get("notBefore", ""),
        "tls_valid_to": cert.get("notAfter", ""),
        "tls_dns_names": names,
    }


def _probe_http(ip: str, port: int, work_dir: Path, timeout: float, limiter: RateLimiter) -> dict[str, str]:
    scheme = "https" if port in (443, 8443) else "http"
    request = urllib.request.Request(f"{scheme}://{ip}:{port}/", headers={"User-Agent": "AuthorizedInventory/1.0"})
    opener = urllib.request.build_opener(_NoRedirect())
    limiter.wait()
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(MAX_RESPONSE_BYTES)
            status = str(response.status)
    except urllib.error.HTTPError as response:
        body = response.read(MAX_RESPONSE_BYTES)
        status = str(response.code)
    parser = TitleParser()
    try:
        parser.feed(body.decode("utf-8", errors="replace"))
    except Exception:
        pass
    destination = safe_ip_dir(work_dir, ip) / f"port_{port}_homepage.html"
    destination.write_bytes(body)
    return {"http_status": status, "http_title": " ".join(parser.parts)[:300], "snapshot_path": str(destination)}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def port_is_open(ip: str, port: int, timeout: float, limiter: RateLimiter) -> bool:
    limiter.wait()
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except (OSError, TimeoutError):
        return False


def probe_port(ip: str, port: int, work_dir: Path, timeout: float, limiter: RateLimiter) -> dict[str, str]:
    try:
        service = socket.getservbyport(port, "tcp")
    except OSError:
        service = "unknown"
    result = {"ip": ip, "port": str(port), "status": "open", "service": service, "banner": ""}
    try:
        result["fqdn"] = socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        result["fqdn"] = ""
    if port in (443, 8443):
        try:
            context = ssl.create_default_context()
            limiter.wait()
            with socket.create_connection((ip, port), timeout=timeout) as connection:
                with context.wrap_socket(connection, server_hostname=ip) as tls_connection:
                    result.update(_tls_metadata(tls_connection))
        except (OSError, ssl.SSLError) as exc:
            result["error"] = f"TLS metadata unavailable: {exc.__class__.__name__}"
    if port in (80, 443, 8000, 8080, 8443):
        try:
            result.update(_probe_http(ip, port, work_dir, timeout, limiter))
        except (OSError, urllib.error.URLError, TimeoutError) as exc:
            result["error"] = f"HTTP metadata unavailable: {exc.__class__.__name__}"
    else:
        try:
            limiter.wait()
            with socket.create_connection((ip, port), timeout=timeout) as connection:
                connection.settimeout(min(timeout, 0.4))
                result["banner"] = connection.recv(1024).decode("utf-8", errors="replace").strip()[:500]
        except (OSError, TimeoutError):
            pass
    return result


def scan(hosts: list[str], ports: tuple[int, ...], output: Path, work_dir: Path, workers: int, rate: int, timeout: float) -> None:
    work_dir.mkdir(parents=True, exist_ok=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    state_path = work_dir / "scan_state.json"
    completed: set[tuple[str, str]] = set()
    closed: set[tuple[str, str]] = set()
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
        closed.update((item[0], item[1]) for item in state.get("closed", []))
        completed.update(closed)
    except (OSError, ValueError, TypeError, IndexError):
        pass
    if output.exists():
        existing_rows = []
        try:
            with output.open(newline="", encoding="utf-8") as stream:
                existing_rows = list(csv.DictReader(stream))
        except (OSError, csv.Error):
            existing_rows = []
        for row in existing_rows:
            pair = (row.get("ip", ""), row.get("port", ""))
            if all(pair):
                completed.add(pair)
        open_rows = [row for row in existing_rows if row.get("status") != "closed"]
        if len(open_rows) != len(existing_rows):
            with tempfile.NamedTemporaryFile("w", newline="", encoding="utf-8", dir=output.parent, delete=False) as temp_stream:
                temp_path = Path(temp_stream.name)
                writer = csv.DictWriter(temp_stream, fieldnames=CSV_FIELDS)
                writer.writeheader()
                writer.writerows({field: row.get(field, "") for field in CSV_FIELDS} for row in open_rows)
            os.replace(temp_path, output)
    new_file = not output.exists() or output.stat().st_size == 0
    limiter = RateLimiter(rate)
    since_checkpoint = 0
    try:
        with output.open("a", newline="", encoding="utf-8") as stream:
            writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS)
            if new_file:
                writer.writeheader()
                stream.flush()
            futures = {}
            with ThreadPoolExecutor(max_workers=workers) as executor:
                for ip in hosts:
                    for port in ports:
                        if (ip, str(port)) not in completed:
                            futures[executor.submit(port_is_open, ip, port, timeout, limiter)] = (ip, port)
                results = {}
                open_ports = []
                for future in as_completed(futures):
                    try:
                        is_open = future.result()
                    except Exception as exc:
                        ip, port = futures[future]
                        result = {"ip": ip, "port": str(port), "status": "error", "error": exc.__class__.__name__}
                        is_open = False
                    else:
                        ip, port = futures[future]
                        result = {"ip": ip, "port": str(port), "status": "open" if is_open else "closed"}
                    results[(ip, port)] = result
                    if is_open:
                        open_ports.append((ip, port))
                    else:
                        completed.add((ip, str(port)))
                        closed.add((ip, str(port)))
                        since_checkpoint += 1
                        if since_checkpoint >= STATE_CHECKPOINT_INTERVAL:
                            _save_completed(state_path, closed)
                            since_checkpoint = 0
                detail_futures = {
                    executor.submit(probe_port, ip, port, work_dir, timeout, limiter): (ip, port)
                    for ip, port in open_ports
                }
                for future in as_completed(detail_futures):
                    ip, port = detail_futures[future]
                    try:
                        result = future.result()
                    except Exception as exc:
                        result = {"ip": ip, "port": str(port), "status": "error", "error": exc.__class__.__name__}
                    results[(ip, port)] = result
                for key in sorted(results):
                    result = results[key]
                    if result.get("status") != "closed":
                        result["scan_time"] = datetime.now(timezone.utc).isoformat()
                        writer.writerow({field: result.get(field, "") for field in CSV_FIELDS})
                        stream.flush()
                    completed.add((key[0], str(key[1])))
                    since_checkpoint += 1
                    if since_checkpoint >= STATE_CHECKPOINT_INTERVAL:
                        _save_completed(state_path, closed)
                        since_checkpoint = 0
        _save_completed(state_path, closed)
    except KeyboardInterrupt:
        _save_completed(state_path, closed)
        print("Interruption reçue : les résultats écrits restent disponibles pour la reprise.")


def _save_completed(state_path: Path, completed: set[tuple[str, str]]) -> None:
    state_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=state_path.parent, delete=False) as temp_stream:
        temp_path = Path(temp_stream.name)
        json.dump({"closed": sorted(completed)}, temp_stream)
    os.replace(temp_path, state_path)


def _ports(value: str) -> tuple[int, ...]:
    try:
        ports = tuple(dict.fromkeys(int(item.strip()) for item in value.split(",")))
    except ValueError as exc:
        raise argparse.ArgumentTypeError("Ports must be comma-separated integers") from exc
    if not ports or any(port < 1 or port > 65535 for port in ports) or len(ports) > 100:
        raise argparse.ArgumentTypeError("Provide 1-100 TCP ports in the range 1..65535")
    return ports


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Inventaire TCP limité aux réseaux IPv4 privés RFC1918.")
    parser.add_argument("--cidr", action="append", default=[], help="CIDR privé IPv4 (répétable)")
    parser.add_argument("--ip-file", help="Fichier texte avec une IP par ligne")
    parser.add_argument("--exclude", action="append", default=[], help="IP ou CIDR à exclure (répétable)")
    parser.add_argument("--ports", type=_ports, default=DEFAULT_PORTS, help="Ports TCP séparés par des virgules")
    parser.add_argument("--max-hosts", type=int, default=MAX_HOSTS, help=f"Plafond d'hôtes (maximum {MAX_HOSTS})")
    parser.add_argument("--workers", type=int, default=MAX_WORKERS, help=f"Concurrence (1-{MAX_WORKERS})")
    parser.add_argument("--rate", type=int, default=MAX_RATE, help=f"Tentatives TCP par seconde (1-{MAX_RATE})")
    parser.add_argument("--timeout", type=float, default=1.5, help="Délai de connexion en secondes")
    parser.add_argument("--output", type=Path, default=Path("results.csv"), help="CSV de sortie, reprise par défaut")
    parser.add_argument("--work-dir", type=Path, default=Path("intermediate"), help="Répertoire des fichiers intermédiaires")
    args = parser.parse_args(argv)
    if not args.cidr and not args.ip_file:
        parser.error("Provide at least one --cidr or --ip-file")
    if not 1 <= args.workers <= MAX_WORKERS or not 1 <= args.rate <= MAX_RATE or not 0.1 <= args.timeout <= 30:
        parser.error("workers, rate or timeout is outside the supported safe bounds")
    try:
        hosts = parse_addresses(args.cidr, args.ip_file, args.exclude, args.max_hosts)
    except ScopeError as exc:
        parser.error(str(exc))
    if args.output.exists() and args.output.stat().st_size:
        answer = input(f"Le fichier {args.output} existe. Ajouter/reprendre les résultats ? [o/N] ").strip().lower()
        if answer not in ("o", "oui", "y", "yes"):
            return 1
    if args.work_dir.exists() and any(args.work_dir.iterdir()):
        answer = input(f"Le répertoire {args.work_dir} contient déjà des fichiers. Les réutiliser et remplacer les captures concernées ? [o/N] ").strip().lower()
        if answer not in ("o", "oui", "y", "yes"):
            return 1
    print(f"Périmètre confirmé à examiner : {len(hosts)} hôtes privés, ports TCP {', '.join(map(str, args.ports))}")
    answer = input("Démarrer le scan ? [o/N] ").strip().lower()
    if answer not in ("o", "oui", "y", "yes"):
        return 1
    scan(hosts, args.ports, args.output, args.work_dir, args.workers, args.rate, args.timeout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())