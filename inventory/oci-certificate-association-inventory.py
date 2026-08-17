#!/usr/bin/env python3
"""Read-only OCI certificate, Load Balancer and listener inventory.

Designed for OCI Cloud Shell. By default, scans the Sao Paulo and Vinhedo
regions and writes timestamped JSON and CSV reports to the user's home folder.
No OCI resource is created, updated, associated, rotated or deleted.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import oci


DEFAULT_REGIONS = ("sa-saopaulo-1", "sa-vinhedo-1")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Inventaria certificados OCI, associacoes, Load Balancers e "
            "listeners sem realizar alteracoes."
        )
    )
    parser.add_argument(
        "--regions",
        nargs="+",
        default=list(DEFAULT_REGIONS),
        help="Regioes OCI a consultar (padrao: sa-saopaulo-1 sa-vinhedo-1).",
    )
    parser.add_argument(
        "--compartment-id",
        help=(
            "Limita a consulta a um compartment. Sem este parametro, consulta "
            "a tenancy root e todos os compartments acessiveis."
        ),
    )
    parser.add_argument(
        "--certificate-name",
        help="Filtra certificados pelo nome exato (case-insensitive).",
    )
    parser.add_argument(
        "--certificate-id",
        help="Filtra por um OCID de certificado especifico.",
    )
    parser.add_argument(
        "--warning-days",
        type=int,
        default=30,
        help="Janela para alerta de vencimento em dias (padrao: 30).",
    )
    parser.add_argument(
        "--output-dir",
        default=str(Path.home()),
        help="Diretorio dos relatorios (padrao: pasta home do usuario).",
    )
    return parser.parse_args()


def to_dict(value: Any) -> Any:
    if value is None:
        return None
    try:
        return oci.util.to_dict(value)
    except Exception:
        return str(value)


def all_results(label: str, errors: list[dict[str, str]], func: Any, **kwargs: Any) -> list[Any]:
    try:
        data = oci.pagination.list_call_get_all_results(func, **kwargs).data
        # Certificates Management list APIs return collection models whose
        # records are exposed through .items; older OCI APIs return a list.
        if hasattr(data, "items") and not isinstance(data, (dict, list, tuple)):
            return list(data.items or [])
        return list(data or [])
    except Exception as exc:
        errors.append({"operation": label, "error": str(exc)})
        print(f"[WARN] {label}: {exc}", file=sys.stderr)
        return []


def get_one(label: str, errors: list[dict[str, str]], func: Any, *args: Any, **kwargs: Any) -> Any:
    try:
        return func(*args, **kwargs).data
    except Exception as exc:
        errors.append({"operation": label, "error": str(exc)})
        print(f"[WARN] {label}: {exc}", file=sys.stderr)
        return None


def parse_oci_time(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def expiry_status(expiry: Any, warning_days: int) -> tuple[str, int | None]:
    parsed = parse_oci_time(expiry)
    if parsed is None:
        return "UNKNOWN", None
    remaining = int((parsed.astimezone(timezone.utc) - datetime.now(timezone.utc)).total_seconds() // 86400)
    if remaining < 0:
        return "EXPIRED", remaining
    if remaining <= warning_days:
        return "EXPIRING_SOON", remaining
    return "OK", remaining


def accessible_compartments(config: dict[str, Any], requested_id: str | None, errors: list[dict[str, str]]) -> list[tuple[str, str]]:
    if requested_id:
        return [(requested_id, "FILTERED_COMPARTMENT")]

    identity = oci.identity.IdentityClient(config)
    tenancy_id = config["tenancy"]
    compartments = all_results(
        "list accessible compartments",
        errors,
        identity.list_compartments,
        compartment_id=tenancy_id,
        compartment_id_in_subtree=True,
        access_level="ACCESSIBLE",
    )
    scope = [(tenancy_id, "TENANCY_ROOT")]
    scope.extend(
        (item.id, item.name)
        for item in compartments
        if getattr(item, "lifecycle_state", None) == "ACTIVE"
    )
    return scope


def certificate_expiry(certificate: Any) -> Any:
    current = getattr(certificate, "current_version", None)
    validity = getattr(current, "validity", None)
    return getattr(validity, "not_after", None) or getattr(certificate, "time_of_expiry", None)


def listener_rows(load_balancer: Any, certificate_id: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    listeners = getattr(load_balancer, "listeners", None) or {}
    iterable = listeners.items() if isinstance(listeners, dict) else []
    for listener_name, listener in iterable:
        ssl_config = getattr(listener, "ssl_configuration", None)
        certificate_ids = list(getattr(ssl_config, "certificate_ids", None) or [])
        if certificate_id not in certificate_ids:
            continue
        rows.append(
            {
                "listener_name": listener_name,
                "listener_port": getattr(listener, "port", None),
                "listener_protocol": getattr(listener, "protocol", None),
                "listener_certificate_ids": certificate_ids,
            }
        )
    return rows


def main() -> int:
    args = parse_args()
    if args.warning_days < 0:
        raise ValueError("--warning-days deve ser maior ou igual a zero")

    config = oci.config.from_file()
    errors: list[dict[str, str]] = []
    scope = accessible_compartments(config, args.compartment_id, errors)
    rows: list[dict[str, Any]] = []
    certificate_count = 0

    for region in dict.fromkeys(args.regions):
        print(f"[INFO] Scanning region: {region}")
        regional_config = dict(config)
        regional_config["region"] = region
        certificates = oci.certificates_management.CertificatesManagementClient(regional_config)
        load_balancers = oci.load_balancer.LoadBalancerClient(regional_config)

        for compartment_id, compartment_name in scope:
            listed = all_results(
                f"certificates/{region}/{compartment_name}",
                errors,
                certificates.list_certificates,
                compartment_id=compartment_id,
            )
            for summary in listed:
                if args.certificate_id and summary.id != args.certificate_id:
                    continue
                if args.certificate_name and (summary.name or "").casefold() != args.certificate_name.casefold():
                    continue

                certificate_count += 1
                certificate = get_one(
                    f"certificate/{region}/{summary.id}",
                    errors,
                    certificates.get_certificate,
                    summary.id,
                ) or summary
                expiry = certificate_expiry(certificate)
                status, days_remaining = expiry_status(expiry, args.warning_days)

                associations = all_results(
                    f"associations/{region}/{summary.id}",
                    errors,
                    certificates.list_associations,
                    compartment_id=compartment_id,
                    certificates_resource_id=summary.id,
                )

                base = {
                    "region": region,
                    "compartment_name": compartment_name,
                    "compartment_id": compartment_id,
                    "certificate_name": summary.name,
                    "certificate_id": summary.id,
                    "certificate_state": getattr(certificate, "lifecycle_state", None),
                    "certificate_expiry": str(expiry) if expiry else None,
                    "expiry_status": status,
                    "days_remaining": days_remaining,
                }

                if not associations:
                    rows.append({**base, "association_state": "UNASSOCIATED"})
                    continue

                for association in associations:
                    resource_id = getattr(association, "associated_resource_id", None)
                    association_base = {
                        **base,
                        "association_name": getattr(association, "name", None),
                        "association_id": getattr(association, "id", None),
                        "association_state": getattr(association, "lifecycle_state", None),
                        "associated_resource_id": resource_id,
                    }
                    if not resource_id or not resource_id.startswith("ocid1.loadbalancer."):
                        rows.append(association_base)
                        continue

                    load_balancer = get_one(
                        f"load-balancer/{region}/{resource_id}",
                        errors,
                        load_balancers.get_load_balancer,
                        resource_id,
                    )
                    if load_balancer is None:
                        rows.append(association_base)
                        continue

                    ip_addresses = [getattr(item, "ip_address", None) for item in (load_balancer.ip_addresses or [])]
                    lb_base = {
                        **association_base,
                        "load_balancer_name": load_balancer.display_name,
                        "load_balancer_state": load_balancer.lifecycle_state,
                        "load_balancer_private": load_balancer.is_private,
                        "load_balancer_ip_addresses": [ip for ip in ip_addresses if ip],
                    }
                    matched_listeners = listener_rows(load_balancer, summary.id)
                    if matched_listeners:
                        rows.extend({**lb_base, **listener} for listener in matched_listeners)
                    else:
                        rows.append({**lb_base, "listener_name": "NOT_FOUND_ON_LB_CONFIGURATION"})

    generated_at = datetime.now(timezone.utc)
    association_ids = {row.get("association_id") for row in rows if row.get("association_id")}
    listener_keys = {
        (row.get("region"), row.get("associated_resource_id"), row.get("listener_name"))
        for row in rows
        if row.get("listener_port") is not None
    }
    report = {
        "metadata": {
            "generated_at_utc": generated_at.isoformat(),
            "regions": list(dict.fromkeys(args.regions)),
            "read_only": True,
            "warning_days": args.warning_days,
            "certificate_filter_name": args.certificate_name,
            "certificate_filter_id": args.certificate_id,
        },
        "summary": {
            "certificates": certificate_count,
            "rows": len(rows),
            "associations": len(association_ids),
            "listeners": len(listener_keys),
            "errors": len(errors),
        },
        "inventory": rows,
        "errors": errors,
    }

    output_dir = Path(args.output_dir).expanduser()
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = generated_at.strftime("%Y%m%d_%H%M%S")
    json_path = output_dir / f"oci_certificate_association_inventory_{stamp}.json"
    csv_path = output_dir / f"oci_certificate_association_inventory_{stamp}.csv"

    with json_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False, default=str)

    fields = [
        "region", "compartment_name", "compartment_id", "certificate_name",
        "certificate_id", "certificate_state", "certificate_expiry",
        "expiry_status", "days_remaining", "association_name", "association_id",
        "association_state", "associated_resource_id", "load_balancer_name",
        "load_balancer_state", "load_balancer_private", "load_balancer_ip_addresses",
        "listener_name", "listener_port", "listener_protocol",
        "listener_certificate_ids",
    ]
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            normalized = dict(row)
            for key in ("load_balancer_ip_addresses", "listener_certificate_ids"):
                normalized[key] = ",".join(normalized.get(key) or [])
            writer.writerow(normalized)

    print("\n=== OCI CERTIFICATE ASSOCIATION INVENTORY ===")
    print(f"Certificates : {certificate_count}")
    print(f"Associations : {report['summary']['associations']}")
    print(f"Listeners    : {report['summary']['listeners']}")
    print(f"Errors       : {len(errors)}")
    print(f"JSON         : {json_path}")
    print(f"CSV          : {csv_path}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
