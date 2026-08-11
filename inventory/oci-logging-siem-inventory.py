#!/usr/bin/env python3
"""OCI Logging/SIEM inventory collector.

Read-only inventory for OCI Cloud Shell / OCI SDK environments.
Collects compartments, log groups, logs, Connector Hub connectors,
streams, WAF policies/firewalls, load balancers and likely security-log gaps.

Outputs:
  - oci_logging_siem_inventory_<timestamp>.json
  - oci_logging_siem_inventory_<timestamp>.csv

No changes are made to OCI resources.
"""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import oci


def obj_to_dict(value: Any) -> Any:
    if value is None:
        return None
    try:
        return oci.util.to_dict(value)
    except Exception:
        return str(value)


def safe_call(label: str, fn, *args, **kwargs):
    try:
        return oci.pagination.list_call_get_all_results(fn, *args, **kwargs).data
    except Exception as exc:
        errors.append({"operation": label, "error": str(exc)})
        print(f"[WARN] {label}: {exc}")
        return []


def safe_get(label: str, fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs).data
    except Exception as exc:
        errors.append({"operation": label, "error": str(exc)})
        print(f"[WARN] {label}: {exc}")
        return None


def get_signer_and_config():
    # Cloud Shell normally works with a regular OCI config file. Fall back to
    # instance principals when running from a compatible OCI compute context.
    try:
        cfg = oci.config.from_file()
        return cfg, None
    except Exception:
        signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
        region = os.environ.get("OCI_REGION") or os.environ.get("OCI_CLI_REGION")
        if not region:
            raise RuntimeError("Could not load ~/.oci/config and OCI region is not set")
        return {"region": region}, signer


def client(cls, config, signer=None):
    return cls(config, signer=signer) if signer else cls(config)


def compartment_name(compartment_id: str) -> str:
    return compartment_names.get(compartment_id, compartment_id)


def flatten_connector_source(connector: Any) -> List[Dict[str, Any]]:
    data = obj_to_dict(getattr(connector, "source", None)) or {}
    rows = []
    log_sources = data.get("log_sources") or data.get("logSources") or []
    for src in log_sources:
        rows.append({
            "compartment_id": src.get("compartment_id") or src.get("compartmentId"),
            "log_group_id": src.get("log_group_id") or src.get("logGroupId"),
            "log_id": src.get("log_id") or src.get("logId"),
        })
    return rows


def classify_log(log: Any) -> str:
    svc = (getattr(log, "service", None) or "").lower()
    cat = (getattr(log, "log_category", None) or "").lower()
    name = (getattr(log, "display_name", None) or "").lower()
    text = f"{svc} {cat} {name}"
    if "waf" in text:
        return "HIGH"
    if "networkfirewall" in text or "network firewall" in text or "firewall" in text:
        return "HIGH"
    if "flow" in text or "vcn" in text or "subnet" in text:
        return "HIGH"
    if "loadbalancer" in text or "load balancer" in text:
        return "MEDIUM"
    if "audit" in text:
        return "HIGH"
    if any(x in text for x in ["bastion", "cloudguard", "api gateway", "apigateway", "dns", "vpn", "objectstorage", "object storage"]):
        return "MEDIUM"
    return "REVIEW"


config, signer = get_signer_and_config()
region = config["region"]
identity = client(oci.identity.IdentityClient, config, signer)
logging = client(oci.logging.LoggingManagementClient, config, signer)
connector = client(oci.sch.ServiceConnectorClient, config, signer)
streaming = client(oci.streaming.StreamAdminClient, config, signer)
waf = client(oci.waf.WafClient, config, signer)
lb = client(oci.load_balancer.LoadBalancerClient, config, signer)

errors: List[Dict[str, str]] = []

# Tenancy ID
if signer:
    tenancy_id = signer.tenancy_id
else:
    tenancy_id = config["tenancy"]

compartments = safe_call(
    "list compartments",
    identity.list_compartments,
    tenancy_id,
    compartment_id_in_subtree=True,
    access_level="ACCESSIBLE",
)

compartment_names: Dict[str, str] = {tenancy_id: "TENANCY_ROOT"}
active_compartments = []
for c in compartments:
    if getattr(c, "lifecycle_state", None) == "ACTIVE":
        compartment_names[c.id] = c.name
        active_compartments.append(c)

scope = [(tenancy_id, "TENANCY_ROOT")] + [(c.id, c.name) for c in active_compartments]

report: Dict[str, Any] = {
    "metadata": {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "region": region,
        "tenancy_id": tenancy_id,
        "collector": "oci-logging-siem-inventory.py",
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
    "errors": errors,
}

for cid, cname in scope:
    report["compartments"].append({"id": cid, "name": cname})

    groups = safe_call(f"list log groups in {cname}", logging.list_log_groups, compartment_id=cid)
    group_name_by_id = {}
    for g in groups:
        group_name_by_id[g.id] = g.display_name
        report["log_groups"].append({
            "compartment": cname,
            "compartment_id": cid,
            "name": g.display_name,
            "id": g.id,
            "lifecycle_state": getattr(g, "lifecycle_state", None),
            "description": getattr(g, "description", None),
            "time_created": str(getattr(g, "time_created", "")),
        })

    # Logs are listed per log group.
    for g in groups:
        logs = safe_call(
            f"list logs in {cname}/{g.display_name}",
            logging.list_logs,
            log_group_id=g.id,
        )
        for log in logs:
            report["logs"].append({
                "compartment": cname,
                "compartment_id": cid,
                "log_group": g.display_name,
                "log_group_id": g.id,
                "name": getattr(log, "display_name", None),
                "id": getattr(log, "id", None),
                "log_type": getattr(log, "log_type", None),
                "lifecycle_state": getattr(log, "lifecycle_state", None),
                "is_enabled": getattr(log, "is_enabled", None),
                "service": getattr(log, "service", None),
                "resource": getattr(log, "resource", None),
                "resource_id": getattr(log, "resource_id", None),
                "log_category": getattr(log, "log_category", None),
                "retention_duration": getattr(log, "retention_duration", None),
                "security_priority": classify_log(log),
            })

    connectors = safe_call(f"list connectors in {cname}", connector.list_service_connectors, compartment_id=cid)
    for sc in connectors:
        details = safe_get(f"get connector {sc.display_name}", connector.get_service_connector, sc.id) or sc
        report["connectors"].append({
            "compartment": cname,
            "compartment_id": cid,
            "name": getattr(details, "display_name", None),
            "id": getattr(details, "id", None),
            "lifecycle_state": getattr(details, "lifecycle_state", None),
            "description": getattr(details, "description", None),
            "source_kind": getattr(getattr(details, "source", None), "kind", None),
            "target_kind": getattr(getattr(details, "target", None), "kind", None),
            "source": obj_to_dict(getattr(details, "source", None)),
            "target": obj_to_dict(getattr(details, "target", None)),
            "tasks": obj_to_dict(getattr(details, "tasks", None)),
        })

    streams = safe_call(f"list streams in {cname}", streaming.list_streams, compartment_id=cid)
    for s in streams:
        report["streams"].append({
            "compartment": cname,
            "compartment_id": cid,
            "name": getattr(s, "name", None),
            "id": getattr(s, "id", None),
            "lifecycle_state": getattr(s, "lifecycle_state", None),
            "partitions": getattr(s, "partitions", None),
            "stream_pool_id": getattr(s, "stream_pool_id", None),
        })

    policies = safe_call(f"list WAF policies in {cname}", waf.list_web_app_firewall_policies, compartment_id=cid)
    for p in policies:
        report["waf_policies"].append({
            "compartment": cname,
            "compartment_id": cid,
            "name": getattr(p, "display_name", None),
            "id": getattr(p, "id", None),
            "lifecycle_state": getattr(p, "lifecycle_state", None),
        })
        firewalls = safe_call(f"list WAF firewalls in policy {p.display_name}", waf.list_web_app_firewalls, compartment_id=cid, web_app_firewall_policy_id=p.id)
        for fw in firewalls:
            report["waf_firewalls"].append({
                "compartment": cname,
                "compartment_id": cid,
                "policy": getattr(p, "display_name", None),
                "policy_id": getattr(p, "id", None),
                "name": getattr(fw, "display_name", None),
                "id": getattr(fw, "id", None),
                "lifecycle_state": getattr(fw, "lifecycle_state", None),
                "backend_type": getattr(fw, "backend_type", None),
                "web_app_firewall_policy_id": getattr(fw, "web_app_firewall_policy_id", None),
            })

    lbs = safe_call(f"list load balancers in {cname}", lb.list_load_balancers, compartment_id=cid)
    for item in lbs:
        report["load_balancers"].append({
            "compartment": cname,
            "compartment_id": cid,
            "name": getattr(item, "display_name", None),
            "id": getattr(item, "id", None),
            "lifecycle_state": getattr(item, "lifecycle_state", None),
            "is_private": getattr(item, "is_private", None),
            "shape_name": getattr(item, "shape_name", None),
        })

# Correlate connector coverage with actual logs.
covered_log_ids = set()
covered_log_group_ids = set()
connector_source_rows = []
for sc in report["connectors"]:
    src = sc.get("source") or {}
    for entry in src.get("log_sources", []) or src.get("logSources", []) or []:
        lgid = entry.get("log_group_id") or entry.get("logGroupId")
        lid = entry.get("log_id") or entry.get("logId")
        if lgid:
            covered_log_group_ids.add(lgid)
        if lid:
            covered_log_ids.add(lid)
        connector_source_rows.append({"connector": sc.get("name"), "log_group_id": lgid, "log_id": lid})

for log in report["logs"]:
    log["covered_by_connector"] = bool(
        log.get("id") in covered_log_ids or log.get("log_group_id") in covered_log_group_ids
    )

    if log.get("security_priority") in ("HIGH", "MEDIUM") and log.get("is_enabled") is not False and not log["covered_by_connector"]:
        report["findings"].append({
            "severity": "MEDIUM",
            "type": "ENABLED_SECURITY_LOG_NOT_IN_CONNECTOR",
            "compartment": log.get("compartment"),
            "resource": log.get("resource") or log.get("name"),
            "log_group": log.get("log_group"),
            "log": log.get("name"),
            "service": log.get("service"),
            "recommendation": "Review whether this enabled security-relevant log should be added to the SIEM Connector source.",
        })

# WAF resources without a corresponding enabled WAF log by resource id/name.
enabled_waf_resources = {
    (l.get("resource_id") or "").lower() for l in report["logs"]
    if (l.get("service") or "").lower() == "waf" and l.get("is_enabled") is not False
}
enabled_waf_names = {
    (l.get("resource") or "").lower() for l in report["logs"]
    if (l.get("service") or "").lower() == "waf" and l.get("is_enabled") is not False
}
for fw in report["waf_firewalls"]:
    if (fw.get("id") or "").lower() not in enabled_waf_resources and (fw.get("name") or "").lower() not in enabled_waf_names:
        report["findings"].append({
            "severity": "HIGH",
            "type": "WAF_WITHOUT_DISCOVERED_ENABLED_LOG",
            "compartment": fw.get("compartment"),
            "resource": fw.get("name"),
            "policy": fw.get("policy"),
            "recommendation": "Validate WAF logging. If logging is disabled, enable the required WAF log category and route it to the approved SIEM log group/connector after cost review.",
        })

# Connector summary finding.
for sc in report["connectors"]:
    src = sc.get("source") or {}
    if (sc.get("source_kind") or "").lower() == "logging":
        sources = src.get("log_sources", []) or src.get("logSources", []) or []
        report["findings"].append({
            "severity": "INFO",
            "type": "CONNECTOR_SOURCE_SUMMARY",
            "compartment": sc.get("compartment"),
            "resource": sc.get("name"),
            "source_count": len(sources),
            "target_kind": sc.get("target_kind"),
            "recommendation": "Confirm that the connector source list matches the approved SOC logging baseline.",
        })

stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
json_name = f"oci_logging_siem_inventory_{stamp}.json"
csv_name = f"oci_logging_siem_inventory_{stamp}.csv"

with open(json_name, "w", encoding="utf-8") as fh:
    json.dump(report, fh, indent=2, ensure_ascii=False, default=str)

with open(csv_name, "w", encoding="utf-8", newline="") as fh:
    fieldnames = [
        "compartment", "log_group", "name", "service", "resource", "log_category",
        "log_type", "is_enabled", "lifecycle_state", "retention_duration",
        "security_priority", "covered_by_connector", "id", "log_group_id"
    ]
    writer = csv.DictWriter(fh, fieldnames=fieldnames)
    writer.writeheader()
    for row in report["logs"]:
        writer.writerow({k: row.get(k) for k in fieldnames})

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
print(f"JSON................: {json_name}")
print(f"CSV.................: {csv_name}")
print("\nTop findings:")
for f in report["findings"][:30]:
    print(f"- [{f.get('severity')}] {f.get('type')}: {f.get('resource')} ({f.get('compartment')})")
