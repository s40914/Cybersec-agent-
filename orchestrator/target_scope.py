from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


def _is_private_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False

    return any(ip in network for network in PRIVATE_NETWORKS)


def _resolve_host(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []

    addresses = set()

    for info in infos:
        address = info[4][0]
        addresses.add(address)

    return sorted(addresses)


def validate_target(target: str) -> tuple[bool, str]:
    """
    Bezpieczny gate dla zakresu testowego.

    Domyślnie akceptujemy wyłącznie:
      - localhost
      - loopback
      - prywatne adresy IPv4/IPv6
      - hosty DNS, które rozwiązują się WYŁĄCZNIE do adresów prywatnych

    Publiczne adresy są odrzucane.
    """

    target = target.strip()

    if not target:
        return False, "Pusty target."

    if target.lower() in {
        "localhost",
        "localhost.localdomain",
    }:
        return True, "localhost"

    # Najpierw rozpoznajemy bezpośredni adres IP.
    # Jest to ważne dla IPv6, np. fc00::1, ponieważ urlparse()
    # potraktowałby "fc00" jako schemat URL.
    try:
        direct_ip = ipaddress.ip_address(target)
    except ValueError:
        direct_ip = None

    if direct_ip is not None:
        return (
            True,
            "prywatny adres IP",
        ) if _is_private_ip(target) else (
            False,
            f"Publiczny adres IP odrzucony: {target}",
        )

    parsed = urlparse(target)

    if parsed.scheme:
        if parsed.scheme not in {"http", "https"}:
            return False, f"Niedozwolony schemat: {parsed.scheme}"

        host = parsed.hostname

        if not host:
            return False, "URL nie zawiera hosta."

    else:
        host = target.split("/")[0]

        # IPv6 nie może być parsowane przez zwykłe split(":").
        try:
            ipaddress.ip_address(host)
        except ValueError:
            # Obsługa host:port dla IPv4 / hostname.
            if host.count(":") == 1:
                host = host.rsplit(":", 1)[0]

    if host.lower() in {"localhost", "localhost.localdomain"}:
        return True, "localhost"

    if _is_private_ip(host):
        return True, "prywatny adres IP"

    addresses = _resolve_host(host)

    if not addresses:
        return False, f"Nie można rozwiązać hosta: {host}"

    public_addresses = [
        address
        for address in addresses
        if not _is_private_ip(address)
    ]

    if public_addresses:
        return (
            False,
            "Target odrzucony: host rozwiązuje się do publicznego adresu "
            f"({', '.join(public_addresses)}).",
        )

    return True, "host rozwiązuje się wyłącznie do adresów prywatnych"


def validate_network(network: str) -> tuple[bool, str]:
    """
    Waliduje CIDR dla skanowania sieci.

    Pozwala wyłącznie na prywatne/loopback zakresy.
    """

    try:
        parsed = ipaddress.ip_network(network, strict=False)
    except ValueError:
        return False, f"Nieprawidłowa sieć CIDR: {network}"

    if not any(
        parsed.version == private.version
        and parsed.subnet_of(private)
        for private in PRIVATE_NETWORKS
    ):
        return False, f"Sieć publiczna odrzucona: {network}"

    return True, "prywatny zakres CIDR"


import re as _re

_CIDR_SUFFIX_RE = _re.compile(r"/\d{1,3}$")


def _looks_like_cidr(value: str) -> bool:
    """
    Odroznia zapis CIDR (np. 192.168.0.0/24) od URL-a zawierajacego
    ukosnik w sciezce (np. http://IP/page?id=1). Samo sprawdzanie
    "/" in target bylo bledne - kazdy URL z parametrem zapytania ma
    ukosnik w sciezce i byl bledczasnie kierowany do walidatora CIDR,
    co odrzucalo poprawne, dozwolone URL-e (np. dla sqlmap_scan)
    komunikatem "Nieprawidlowa siec CIDR".
    """
    if value.startswith(("http://", "https://")):
        return False
    return bool(_CIDR_SUFFIX_RE.search(value))


def target_scope(target: str) -> dict:
    """
    Zwraca jawny opis decyzji scope.
    """

    target = target.strip()

    if _looks_like_cidr(target):
        allowed, reason = validate_network(target)
    else:
        allowed, reason = validate_target(target)

    return {
        "target": target,
        "allowed": allowed,
        "reason": reason,
        "scope": "private" if allowed else "blocked",
    }
