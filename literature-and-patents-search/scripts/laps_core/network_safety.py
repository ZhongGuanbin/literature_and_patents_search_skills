from __future__ import annotations

"""Fail-closed HTTP(S) outbound-target validation shared by LAPS.

This module deliberately performs a fresh DNS lookup for every hostname
validation.  Callers which subsequently open a socket must still pin or
re-check the connection peer; this predicate is the common pre-I/O and
redirect/challenge-response boundary.
"""

from dataclasses import dataclass
import ipaddress
import socket
from typing import Any, Callable, Sequence
from urllib.parse import urlsplit


DNSResolver = Callable[..., Sequence[tuple[Any, ...]]]

_FORBIDDEN_EXACT_HOSTS = frozenset(
    {
        "local",
        "localhost",
        "localhost.localdomain",
        "localhost6.localdomain6",
        "metadata.google.internal",
        "metadata.azure.internal",
        "metadata.aws.internal",
    }
)
_FORBIDDEN_HOST_SUFFIXES = (".localhost", ".local", ".internal")
_FORBIDDEN_IP_ADDRESSES = frozenset(
    {
        # Cloud instance metadata/platform endpoints.  Most are already
        # non-global, but the explicit set also covers Azure WireServer's
        # globally classified virtual address.
        "100.100.100.200",
        "168.63.129.16",
        "169.254.169.254",
        "169.254.170.2",
        "192.0.0.192",
        "fd00:ec2::254",
    }
)


@dataclass(frozen=True)
class OutboundURLValidation:
    allowed: bool
    reason_code: str
    host: str = ""
    addresses: tuple[str, ...] = ()


def _normalized_host(value: str) -> str:
    host = str(value or "").strip().rstrip(".").casefold()
    if not host:
        return ""
    try:
        return host.encode("idna").decode("ascii").casefold()
    except (UnicodeError, ValueError):
        return ""


def _looks_like_legacy_numeric_host(host: str) -> bool:
    """Reject alternate IPv4 spellings before the platform resolver sees them."""

    labels = host.split(".")
    if not labels or any(not label for label in labels):
        return False
    return all(
        label.isdecimal()
        or (
            label.casefold().startswith("0x")
            and len(label) > 2
            and all(character in "0123456789abcdef" for character in label[2:].casefold())
        )
        for label in labels
    )


def address_is_global(value: str | ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    try:
        address = value if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)) else ipaddress.ip_address(str(value).split("%", 1)[0])
    except ValueError:
        return False
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        return address_is_global(mapped)
    return bool(
        str(address) not in _FORBIDDEN_IP_ADDRESSES
        and address.is_global
        and not address.is_private
        and not address.is_loopback
        and not address.is_link_local
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
    )


def outbound_http_url_syntax_allowed(value: str) -> bool:
    text = str(value or "").strip()
    if not text or "\\" in text or any(ord(character) <= 0x20 for character in text):
        return False
    try:
        parsed = urlsplit(text)
    except (TypeError, ValueError):
        return False
    if parsed.scheme.casefold() not in {"http", "https"} or not parsed.netloc:
        return False
    if parsed.username is not None or parsed.password is not None:
        return False
    try:
        port = parsed.port
    except ValueError:
        return False
    if port is not None and not 1 <= port <= 65535:
        return False
    host = _normalized_host(parsed.hostname or "")
    if not host:
        return False
    if host in _FORBIDDEN_EXACT_HOSTS or host.endswith(_FORBIDDEN_HOST_SUFFIXES):
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return not _looks_like_legacy_numeric_host(host)
    return address_is_global(address)


def inspect_outbound_http_url(
    value: str,
    *,
    resolver: DNSResolver | None = None,
) -> OutboundURLValidation:
    text = str(value or "").strip()
    if not outbound_http_url_syntax_allowed(text):
        return OutboundURLValidation(False, "outbound_url_syntax_rejected")
    parsed = urlsplit(text)
    host = _normalized_host(parsed.hostname or "")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        normalized = str(literal)
        return OutboundURLValidation(
            address_is_global(literal),
            "outbound_url_allowed" if address_is_global(literal) else "outbound_address_non_global",
            host,
            (normalized,),
        )

    selected_resolver = resolver or socket.getaddrinfo
    port = parsed.port or (443 if parsed.scheme.casefold() == "https" else 80)
    try:
        answers = selected_resolver(host, port, type=socket.SOCK_STREAM)
    except (OSError, TypeError, ValueError, UnicodeError):
        return OutboundURLValidation(False, "outbound_dns_resolution_failed", host)

    addresses: list[str] = []
    seen: set[str] = set()
    try:
        for answer in answers:
            if not isinstance(answer, tuple) or len(answer) < 5:
                return OutboundURLValidation(False, "outbound_dns_answer_invalid", host)
            if answer[0] not in {socket.AF_INET, socket.AF_INET6}:
                return OutboundURLValidation(False, "outbound_dns_answer_invalid", host)
            sockaddr = answer[4]
            if not isinstance(sockaddr, tuple) or not sockaddr:
                return OutboundURLValidation(False, "outbound_dns_answer_invalid", host)
            raw_address = str(sockaddr[0]).split("%", 1)[0]
            address = ipaddress.ip_address(raw_address)
            if (answer[0] == socket.AF_INET and address.version != 4) or (
                answer[0] == socket.AF_INET6 and address.version != 6
            ):
                return OutboundURLValidation(False, "outbound_dns_answer_invalid", host)
            normalized = str(address)
            if normalized not in seen:
                seen.add(normalized)
                addresses.append(normalized)
            if not address_is_global(address):
                return OutboundURLValidation(
                    False,
                    "outbound_dns_answer_non_global",
                    host,
                    tuple(addresses),
                )
    except (TypeError, ValueError, IndexError):
        return OutboundURLValidation(False, "outbound_dns_answer_invalid", host)
    if not addresses:
        return OutboundURLValidation(False, "outbound_dns_no_addresses", host)
    return OutboundURLValidation(True, "outbound_url_allowed", host, tuple(addresses))


def outbound_http_url_allowed(
    value: str,
    *,
    resolver: DNSResolver | None = None,
) -> bool:
    return inspect_outbound_http_url(value, resolver=resolver).allowed


def outbound_host_is_public(
    host: str,
    *,
    port: int = 443,
    resolver: DNSResolver | None = None,
) -> bool:
    normalized = _normalized_host(host)
    try:
        selected_port = int(port)
    except (TypeError, ValueError):
        return False
    if not normalized or not 1 <= selected_port <= 65535:
        return False
    # Bracket IPv6 literals for URL parsing while preserving ordinary DNS names.
    try:
        literal = ipaddress.ip_address(normalized)
    except ValueError:
        authority = normalized
    else:
        authority = f"[{literal}]" if literal.version == 6 else str(literal)
    scheme = "https" if selected_port == 443 else "http"
    return outbound_http_url_allowed(
        f"{scheme}://{authority}:{selected_port}/",
        resolver=resolver,
    )


__all__ = [
    "DNSResolver",
    "OutboundURLValidation",
    "address_is_global",
    "inspect_outbound_http_url",
    "outbound_host_is_public",
    "outbound_http_url_allowed",
    "outbound_http_url_syntax_allowed",
]
