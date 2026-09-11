from __future__ import annotations

import re
import subprocess
from datetime import datetime, timezone

from security_models import Asset
from evidence_store import EvidenceStore


class InternalSensor:
    """
    Internal Sensor v1.

    Discovery-only:
        192.168.50.0/24 -> nmap -sn -> Asset inventory

    Nie wykonuje port-scanu ani prób logowania.
    """

    def __init__(
        self,
        evidence_store: EvidenceStore,
        network: str = "192.168.0.0/24",
    ) -> None:
        self.evidence_store = evidence_store
        self.network = network

    def discover(self) -> list[Asset]:
        result = subprocess.run(
            [
                "nmap",
                "-sn",
                "-n",
                "-PR",
                self.network,
            ],
            capture_output=True,
            text=True,
            check=True,
        )

        assets = self._parse_nmap_output(result.stdout)

        stored: list[Asset] = []

        for asset in assets:
            stored.append(
                self.evidence_store.upsert_asset(asset)
            )

        return stored

    def _parse_nmap_output(self, output: str) -> list[Asset]:
        assets: list[Asset] = []

        current_ip: str | None = None
        current_hostname: str | None = None
        current_mac: str | None = None

        now = datetime.now(timezone.utc)

        for line in output.splitlines():
            line = line.strip()

            host_match = re.match(
                r"Nmap scan report for (.+)",
                line,
            )

            if host_match:
                if current_ip:
                    assets.append(
                        Asset(
                            target=self.network,
                            ip_address=current_ip,
                            hostname=current_hostname,
                            mac_address=current_mac,
                            first_seen_at=now,
                            last_seen_at=now,
                            metadata={
                                "discovery_method": "nmap_ping",
                            },
                        )
                    )

                value = host_match.group(1)

                # -n powoduje, że normalnie dostajemy samo IP.
                # Zostawiamy jednak obsługę potencjalnego:
                # hostname (IP)
                ip_match = re.search(
                    r"\((\d+\.\d+\.\d+\.\d+)\)$",
                    value,
                )

                if ip_match:
                    current_hostname = value[:ip_match.start()].strip()
                    current_ip = ip_match.group(1)
                else:
                    current_hostname = None
                    current_ip = value

                current_mac = None
                continue

            mac_match = re.match(
                r"MAC Address:\s+([0-9A-Fa-f:]{17})\s*(?:\((.+)\))?",
                line,
            )

            if mac_match:
                current_mac = mac_match.group(1).upper()

        if current_ip:
            assets.append(
                Asset(
                    target=self.network,
                    ip_address=current_ip,
                    hostname=current_hostname,
                    mac_address=current_mac,
                    first_seen_at=now,
                    last_seen_at=now,
                    metadata={
                        "discovery_method": "nmap_ping",
                    },
                )
            )

        return assets


def discover_internal_assets(
    evidence_store: EvidenceStore,
    network: str = "192.168.0.0/24",
) -> list[Asset]:
    sensor = InternalSensor(
        evidence_store=evidence_store,
        network=network,
    )

    return sensor.discover()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Internal Sensor v1 - network asset discovery"
    )

    parser.add_argument(
        "--network",
        default="192.168.0.0/24",
        help="CIDR network to discover (default: 192.168.0.0/24)",
    )

    parser.add_argument(
        "--store",
        default="data/evidence.jsonl",
        help="Evidence store path (default: data/evidence.jsonl)",
    )

    args = parser.parse_args()

    store = EvidenceStore(args.store)

    assets = discover_internal_assets(
        evidence_store=store,
        network=args.network,
    )

    print("=" * 70)
    print("INTERNAL SENSOR v1")
    print("=" * 70)
    print(f"Network: {args.network}")
    print(f"Assets discovered: {len(assets)}")
    print()

    for asset in sorted(
        assets,
        key=lambda item: item.ip_address or "",
    ):
        print(
            f"{asset.ip_address:<15} "
            f"MAC={asset.mac_address or '-':<17} "
            f"HOSTNAME={asset.hostname or '-'}"
        )

    print("=" * 70)
