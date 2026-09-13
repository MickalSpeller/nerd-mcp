"""Fixed FortiOS VPN commands and pure operational-output parsing."""

from __future__ import annotations

import re

from ....domain.models import VpnStatus, VpnTunnel
from ...commands import command_error


COMMANDS = {
    "ipsec_summary": "get vpn ipsec tunnel summary",
    "ipsec_details": "diagnose vpn tunnel list",
    "ssl_sessions": "get vpn ssl monitor",
}

MOCK_OUTPUTS = {
    "ipsec_summary": (
        "'Branch-HQ' 198.51.100.10:0 selectors(total,up): 2/2  "
        "rx(pkt,err): 120/0  tx(pkt,err): 118/0\n"
        "'Backup-HQ' 203.0.113.10:0 selectors(total,up): 1/0  "
        "rx(pkt,err): 0/0  tx(pkt,err): 0/0"
    ),
    "ipsec_details": (
        "list all ipsec tunnel in vd 0\n"
        "name=Branch-HQ ver=2 serial=1 192.0.2.10:0->198.51.100.10:0 "
        "status=up dst_mtu=1500"
    ),
    "ssl_sessions": (
        "SSL VPN Login Users:\n\n"
        "SSL VPN sessions:\n"
        "Index User Group Source IP Duration I/O Bytes Tunnel/Dest IP\n"
        "0 operator remote-users 203.0.113.25 00:14:10 2048/1024 10.212.134.2"
    ),
}


def _clean(output: str) -> str:
    return re.sub(r"(?m)^\[MOCK DATA[^\n]*\]\n?", "", output).strip()


def parse_ipsec_summary(output: str) -> tuple[tuple[VpnTunnel, ...], bool]:
    """Parse FortiOS IPsec summary rows, including down selectors."""
    text = _clean(output)
    if not text or command_error(text):
        return (), False
    tunnels = []
    for line in text.splitlines():
        match = re.search(
            r"^\s*'(?P<name>[^']+)'\s+(?P<remote>\S+).*?"
            r"selectors\(total,up\):\s*(?P<total>\d+)\s*/\s*(?P<up>\d+)",
            line,
        )
        if not match:
            continue
        total, up = int(match.group("total")), int(match.group("up"))
        rx = re.search(r"rx\(pkt,err\):\s*(\d+)\s*/", line)
        tx = re.search(r"tx\(pkt,err\):\s*(\d+)\s*/", line)
        tunnels.append(VpnTunnel(
            name=match.group("name"),
            status="up" if up else "down",
            remote_gateway=match.group("remote").rsplit(":", 1)[0],
            selectors_total=total,
            selectors_up=up,
            rx_packets=int(rx.group(1)) if rx else None,
            tx_packets=int(tx.group(1)) if tx else None,
        ))
    return tuple(tunnels), bool(tunnels)


def parse_ipsec_details(output: str) -> tuple[tuple[VpnTunnel, ...], bool]:
    """Parse the documented diagnostic form when the summary is unavailable."""
    text = _clean(output)
    if not text or command_error(text):
        return (), False
    tunnels = []
    for line in text.splitlines():
        match = re.search(
            r"(?i)^\s*name=(?P<name>\S+).*?\bstatus=(?P<status>up|down)\b",
            line,
        )
        if not match:
            continue
        remote = re.search(r"->([^\s:]+)(?::\d+)?", line)
        tunnels.append(VpnTunnel(
            name=match.group("name"), status=match.group("status").casefold(),
            remote_gateway=remote.group(1) if remote else None,
        ))
    recognized = bool(tunnels) or bool(re.search(r"(?i)list all ipsec tunnel", text))
    return tuple(tunnels), recognized


def parse_ssl_session_count(output: str) -> tuple[int, bool]:
    """Count active SSL-VPN tunnel sessions without returning user identities."""
    text = _clean(output)
    if not text or command_error(text):
        return 0, False
    marker = re.search(r"(?im)^\s*SSL VPN sessions:\s*$", text)
    if not marker:
        return 0, False
    session_text = text[marker.end():]
    count = sum(
        bool(re.match(r"^\s*\d+\s+\S+", line))
        for line in session_text.splitlines()
    )
    return count, True


def parse_status(outputs: dict[str, str]) -> VpnStatus:
    summary, summary_complete = parse_ipsec_summary(outputs.get("ipsec_summary", ""))
    details, details_complete = parse_ipsec_details(outputs.get("ipsec_details", ""))
    tunnels = summary if summary_complete else details
    ipsec_complete = summary_complete or details_complete
    ssl_count, ssl_complete = parse_ssl_session_count(outputs.get("ssl_sessions", ""))
    active_ipsec = sum(row.status == "up" for row in tunnels)
    active: bool | None = (
        True if active_ipsec or ssl_count else
        False if ipsec_complete and ssl_complete else None
    )
    warnings = []
    if not ipsec_complete:
        warnings.append("IPsec tunnel status was unavailable or unrecognized.")
    if not ssl_complete:
        warnings.append("SSL-VPN session status was unavailable or unrecognized.")
    return VpnStatus(
        has_active_vpn=active,
        ipsec_tunnels=tunnels,
        ipsec_complete=ipsec_complete,
        ssl_vpn_session_count=ssl_count if ssl_complete else None,
        ssl_vpn_complete=ssl_complete,
        complete=ipsec_complete and ssl_complete,
        warnings=tuple(warnings),
    )
