#!/usr/bin/env python3
"""Read-only OCI Logging/SIEM inventory optimized for OCI Cloud Shell.

Collects all accessible compartments in the current region:
- Log Groups and Logs
- Service Connector Hub connectors and their sources/targets
- Streams
- WAF policies and WAF firewalls
- Load Balancers

Outputs JSON + CSV. It does not modify OCI resources.
"""

import csv
import json
import os
from datetime import datetime, timezone

import oci

ERRORS = []


def all_results(label, func, *args, **kwargs):
    try:
        return oci.pagination.list_call_get_all_results(func, *args, **kwargs).data
    except Exception as exc:
        ERRORS.append({"operation": label, "error": str(exc)})
        print(f"[WARN] {label}: {exc}")
        return []


def get_one(label, func, *args, **kwargs):
    try:
        return func(*args, **kwargs).data
    except Exception as exc:
        ERRORS.append({"operation": label, "error": str(exc)})
        print(f"[WARN] {label}: {exc}")
        return None


def to_dict(obj):
    if obj is None:
        return None
    try:
        return oci.util.to_dict(obj)
    except Exception:
        return str(obj)


def security_priority(log):
    text = " ".join([
        str(getattr(log, "service", "") or ""),
        str(getattr(log, "log_category", "") or ""),
        str(getattr(log, "display_name", "") or ""),
        str(getattr(log, "resource", "") or ""),
    ]).lower()
    if any(x in text for x in ["waf", "firewall", "flow", "subnet", "vcn", "audit"]):
        return "HIGH"
    if any(x in text for x in ["loadbalancer", "load balancer", "bastion", "cloudguard", "api gateway", "dns", "vpn", "objectstorage"]):
        return "MEDIUM"
    return "REVIEW"


# Cloud Shell commonly has ~/.oci/config without a region entry because the
# active region is injected by environment. Normalize both cases here.
config = oci.config.from_file()
region = (
    config.get("region")
    or os.environ.get("OCI_CLI_REGION")
    or os.environ.get("OCI_REGION")
    or os.environ.get("OCI_CLOUD_SHELL_REGION")
)
if not region:
    raise RuntimeError(
        "OCI region was not found. Run: export OCI_CLI_REGION=sa-saopaulo-1"
    )
config["region"] = region

tenancy_id = config["tenancy"]

identity = oci.identity.IdentityClient(config)
logging = oci.logging.LoggingManagementClient(config)
connector = oci.sch.ServiceConnectorClient(config)
streaming = oci.streaming.StreamAdminClient(config)
waf = oci.waf.WafClient(config)
lb = oci.load_balancer.LoadBalancerClient(config)

compartments = all_results(
    "list compartments",
    identity.list_compartments,
    tenancy_id,
    compartment_id_in_subtree=True,
    access_level="ACCESSIBLE",
)

scope = [(tenancy_id, "TENANCY_ROOT")]
for c in compartments:
    if getattr(c, "lifecycle_state", None) == "ACTIVE":
        scope.append((c.id, c.name))

report = {
    "metadata": {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "region": region,
        "tenancy_id": tenancy_id,
        "read_only": True,
    },
    "compartments": [],
    "log_groups": [],
    "logs": [],
    "connectors": [],
    "streams": [],
    "waf_policies": [],
    "waf_firewalls": [],
    "load_balancers": [],
    "findings": [],
    "errors": ERRORS,
}

for compartment_id, compartment_name in scope:
    print(f"[INFO] Scanning compartment: {compartment_name}")
    report["compartments"].append({"id": compartment_id, "name": compartment_name})

    groups = all_results(
        f"log groups / {compartment_name}",
        logging.list_log_groups,
        compartment_id=compartment_id,
    )
    for group in groups:
        report["log_groups"].append({
            "compartment": compartment_name,
            "compartment_id": compartment_id,
            "name": group.display_name,
            "id": group.id,
            "state": getattr(group, "lifecycle_state", None),
            "description": getattr(group, "description", None),
        })
        logs = all_results(
            f"logs / {compartment_name} / {group.display_name}",
            logging.list_logs,
            log_group_id=group.id,
        )
        for log in logs:
            report["logs"].append({
                "compartment": compartment_name,
                "compartment_id": compartment_id,
                "log_group": group.display_name,
                "log_group_id": group.id,
                "name": getattr(log, "display_name", None),
                "id": getattr(log, "id", None),
                "state": getattr(log, "lifecycle_state", None),
                "is_enabled": getattr(log, "is_enabled", None),
                "log_type": getattr(log, "log_type", None),
                "service": getattr(log, "service", None),
                "resource": getattr(log, "resource", None),
                "resource_id": getattr(log, "resource_id", None),
                "category": getattr(log, "log_category", None),
                "retention_duration": getattr(log, "retention_duration", None),
                "security_priority": security_priority(log),
            })

    connectors = all_results(
        f"connectors / {compartment_name}",
        connector.list_service_connectors,
        compartment_id=compartment_id,
    )
    for item in connectors:
        details = get_one(
            f"connector details / {item.display_name}",
            connector.get_service_connector,
            item.id,
        ) or item
        report["connectors"].append({
            "compartment": compartment_name,
            "compartment_id": compartment_id,
            "name": getattr(details, "display_name", None),
            "id": getattr(details, "id", None),
            "state": getattr(details, "lifecycle_state", None),
            "description": getattr(details, "description", None),
            "source_kind": getattr(getattr(details, "source", None), "kind", None),
            "target_kind": getattr(getattr(details, "target", None), "kind", None),
            "source": to_dict(getattr(details, "source", None)),
            "target": to_dict(getattr(details, "target", None)),
            "tasks": to_dict(getattr(details, "tasks", None)),
        })

    streams = all_results(
        f"streams / {compartment_name}",
        streaming.list_streams,
        compartment_id=compartment_id,
    )
    for item in streams:
        report["streams"].append({
            "compartment": compartment_name,
            "name": getattr(item, "name", None),
            "id": getattr(item, "id", None),
            "state": getattr(item, "lifecycle_state", None),
            "partitions": getattr(item, "partitions", None),
            "stream_pool_id": getattr(item, "stream_pool_id", None),
        })

    policies = all_results(
        f"WAF policies / {compartment_name}",
        waf.list_web_app_firewall_policies,
        compartment_id=compartment_id,
    )
    for policy in policies:
        report["waf_policies"].append({
            "compartment": compartment_name,
            "name": getattr(policy, "display_name", None),
            "id": getattr(policy, "id", None),
            "state": getattr(policy, "lifecycle_state", None),
        })
        firewalls = all_results(
            f"WAF firewalls / {compartment_name} / {policy.display_name}",
            waf.list_web_app_firewalls,
            compartment_id=compartment_id,
            web_app_firewall_policy_id=policy.id,
        )
        for fw in firewalls:
            report["waf_firewalls"].append({
                "compartment": compartment_name,
                "policy": getattr(policy, "display_name", None),
                "policy_id": getattr(policy, "id", None),
                "name": getattr(fw, "display_name", None),
                "id": getattr(fw, "id", None),
                "state": getattr(fw, "lifecycle_state", None),
                "backend_type": getattr(fw, "backend_type", None),
            })

    load_balancers = all_results(
        f"load balancers / {compartment_name}",
        lb.list_load_balancers,
        compartment_id=compartment_id,
    )
    for item in load_balancers:
        report["load_balancers"].append({
            "compartment": compartment_name,
            "name": getattr(item, "display_name", None),
            "id": getattr(item, "id", None),
            "state": getattr(item, "lifecycle_state", None),
            "is_private": getattr(item, "is_private", None),
            "shape": getattr(item, "shape_name", None),
        })

# Discover which log groups/logs are explicitly selected by any Logging connector.
covered_groups = set()
covered_logs = set()
for sc in report["connectors"]:
    source = sc.get("source") or {}
    sources = source.get("log_sources") or source.get("logSources") or []
    for src in sources:
        group_id = src.get("log_group_id") or src.get("logGroupId")
        log_id = src.get("log_id") or src.get("logId")
        if group_id:
            covered_groups.add(group_id)
        if log_id:
            covered_logs.add(log_id)

for log in report["logs"]:
    log["covered_by_connector"] = (
        log.get("log_group_id") in covered_groups or log.get("id") in covered_logs
    )
    if (
        log.get("security_priority") in ("HIGH", "MEDIUM")
        and log.get("is_enabled") is not False
        and not log["covered_by_connector"]
    ):
        report["findings"].append({
            "severity": "MEDIUM",
            "type": "SECURITY_LOG_NOT_IN_CONNECTOR",
            "compartment": log.get("compartment"),
            "log_group": log.get("log_group"),
            "log": log.get("name"),
            "service": log.get("service"),
            "resource": log.get("resource"),
            "recommendation": "Review for inclusion in the approved SOC/SIEM baseline.",
        })

# Correlate WAF resources with enabled WAF service logs.
enabled_waf_ids = {
    str(x.get("resource_id") or "").lower()
    for x in report["logs"]
    if str(x.get("service") or "").lower() == "waf" and x.get("is_enabled") is not False
}
enabled_waf_names = {
    str(x.get("resource") or "").lower()
    for x in report["logs"]
    if str(x.get("service") or "").lower() == "waf" and x.get("is_enabled") is not False
}
for fw in report["waf_firewalls"]:
    if (
        str(fw.get("id") or "").lower() not in enabled_waf_ids
        and str(fw.get("name") or "").lower() not in enabled_waf_names
    ):
        report["findings"].append({
            "severity": "HIGH",
            "type": "WAF_WITHOUT_DISCOVERED_ENABLED_LOG",
            "compartment": fw.get("compartment"),
            "policy": fw.get("policy"),
            "resource": fw.get("name"),
            "recommendation": "Validate WAF logging before adding the source to SIEM; review expected volume and cost first.",
        })

stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
json_file = f"oci_logging_siem_inventory_{stamp}.json"
csv_file = f"oci_logging_siem_inventory_{stamp}.csv"

with open(json_file, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2, ensure_ascii=False, default=str)

fields = [
    "compartment", "log_group", "name", "service", "resource", "category",
    "log_type", "is_enabled", "state", "retention_duration",
    "security_priority", "covered_by_connector", "id", "log_group_id",
]
with open(csv_file, "w", encoding="utf-8", newline="") as fh:
    writer = csv.DictWriter(fh, fieldnames=fields)
    writer.writeheader()
    for row in report["logs"]:
        writer.writerow({k: row.get(k) for k in fields})

print("\n=== OCI LOGGING / SIEM INVENTORY COMPLETE ===")
print(f"Region..............: {region}")
print(f"Compartments........: {len(report['compartments'])}")
print(f"Log groups..........: {len(report['log_groups'])}")
print(f"Logs................: {len(report['logs'])}")
print(f"Connectors..........: {len(report['connectors'])}")
print(f"Streams.............: {len(report['streams'])}")
print(f"WAF policies........: {len(report['waf_policies'])}")
print(f"WAF firewalls.......: {len(report['waf_firewalls'])}")
print(f"Load balancers......: {len(report['load_balancers'])}")
print(f"Findings............: {len(report['findings'])}")
print(f"Errors..............: {len(report['errors'])}")
print(f"JSON................: {json_file}")
print(f"CSV.................: {csv_file}")

print("\nTop findings:")
for finding in report["findings"][:30]:
    print(
        f"- [{finding.get('severity')}] {finding.get('type')}: "
        f"{finding.get('resource') or finding.get('log')} "
        f"({finding.get('compartment')})"
    )
