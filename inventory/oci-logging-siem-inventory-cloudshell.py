#!/usr/bin/env python3
"""Deep read-only OCI Logging/SIEM inventory for OCI Cloud Shell.

Purpose: assess which OCI security/traffic logs exist, are enabled, and are
selected by Service Connector Hub for delivery to Streaming/SIEM.
No OCI resource is created, updated or deleted.
"""
import csv, json, os
from datetime import datetime, timezone
import oci

ERRORS=[]
def all_results(label, func, *args, **kwargs):
    try: return oci.pagination.list_call_get_all_results(func,*args,**kwargs).data
    except Exception as exc:
        ERRORS.append({"operation":label,"error":str(exc)}); print(f"[WARN] {label}: {exc}"); return []
def get_one(label, func, *args, **kwargs):
    try: return func(*args,**kwargs).data
    except Exception as exc:
        ERRORS.append({"operation":label,"error":str(exc)}); print(f"[WARN] {label}: {exc}"); return None
def d(obj):
    try: return oci.util.to_dict(obj) if obj is not None else None
    except Exception: return str(obj)
def pick(obj,*names):
    for n in names:
        v=getattr(obj,n,None)
        if v is not None: return v
    return None
def priority(row):
    text=" ".join(str(row.get(k) or "") for k in ("service","category","name","resource","log_group")).lower()
    if any(x in text for x in ("waf","firewall","audit")): return "HIGH"
    if any(x in text for x in ("flow","vcn","subnet","loadbalancer","load balancer","bastion","cloudguard","api gateway","apigateway","dns","vpn")): return "MEDIUM"
    return "REVIEW"

config=oci.config.from_file()
region=config.get("region") or os.environ.get("OCI_CLI_REGION") or os.environ.get("OCI_REGION") or os.environ.get("OCI_CLOUD_SHELL_REGION")
if not region: raise RuntimeError("Region not found. Run: export OCI_CLI_REGION=sa-saopaulo-1")
config["region"]=region; tenancy_id=config["tenancy"]
identity=oci.identity.IdentityClient(config); logging=oci.logging.LoggingManagementClient(config)
connector=oci.sch.ServiceConnectorClient(config); streaming=oci.streaming.StreamAdminClient(config)
waf=oci.waf.WafClient(config); lb=oci.load_balancer.LoadBalancerClient(config)

comps=all_results("list compartments",identity.list_compartments,tenancy_id,compartment_id_in_subtree=True,access_level="ACCESSIBLE")
scope=[(tenancy_id,"TENANCY_ROOT")]+[(x.id,x.name) for x in comps if getattr(x,"lifecycle_state",None)=="ACTIVE"]
report={"metadata":{"generated_at_utc":datetime.now(timezone.utc).isoformat(),"region":region,"tenancy_id":tenancy_id,"read_only":True},"compartments":[],"log_groups":[],"logs":[],"connectors":[],"connector_sources":[],"streams":[],"waf_policies":[],"waf_firewalls":[],"load_balancers":[],"findings":[],"errors":ERRORS}

for cid,cname in scope:
    print(f"[INFO] Scanning {cname}"); report["compartments"].append({"id":cid,"name":cname})
    groups=all_results(f"log groups/{cname}",logging.list_log_groups,compartment_id=cid)
    for g in groups:
        report["log_groups"].append({"compartment":cname,"name":g.display_name,"id":g.id,"state":getattr(g,"lifecycle_state",None),"description":getattr(g,"description",None)})
        for summary in all_results(f"logs/{cname}/{g.display_name}",logging.list_logs,log_group_id=g.id):
            # IMPORTANT: list_logs returns LogSummary. get_log returns full Log with configuration.
            full=get_one(f"log details/{summary.display_name}",logging.get_log,g.id,summary.id) or summary
            cfg=getattr(full,"configuration",None); source=getattr(cfg,"source",None)
            row={"compartment":cname,"compartment_id":cid,"log_group":g.display_name,"log_group_id":g.id,"name":getattr(full,"display_name",None),"id":getattr(full,"id",None),"state":getattr(full,"lifecycle_state",None),"is_enabled":getattr(full,"is_enabled",None),"log_type":getattr(full,"log_type",None),"service":pick(source,"service"),"resource":pick(source,"resource"),"resource_id":pick(source,"resource"),"category":pick(source,"category"),"source_type":pick(source,"source_type"),"retention_duration":getattr(full,"retention_duration",None),"configuration":d(cfg)}
            row["security_priority"]=priority(row); report["logs"].append(row)

    for s in all_results(f"connectors/{cname}",connector.list_service_connectors,compartment_id=cid):
        sc=get_one(f"connector details/{s.display_name}",connector.get_service_connector,s.id) or s
        src=d(getattr(sc,"source",None)) or {}; tgt=d(getattr(sc,"target",None)) or {}
        rec={"compartment":cname,"name":getattr(sc,"display_name",None),"id":getattr(sc,"id",None),"state":getattr(sc,"lifecycle_state",None),"description":getattr(sc,"description",None),"source_kind":src.get("kind"),"target_kind":tgt.get("kind"),"source":src,"target":tgt,"tasks":d(getattr(sc,"tasks",None))}
        report["connectors"].append(rec)
        # SDK serialization normally exposes log_sources. Preserve each selector explicitly.
        for ls in src.get("log_sources",[]) or []:
            report["connector_sources"].append({"connector":rec["name"],"connector_id":rec["id"],"connector_compartment":cname,"source_compartment_id":ls.get("compartment_id"),"log_group_id":ls.get("log_group_id"),"log_id":ls.get("log_id"),"raw":ls})

    for s in all_results(f"streams/{cname}",streaming.list_streams,compartment_id=cid): report["streams"].append({"compartment":cname,"name":getattr(s,"name",None),"id":getattr(s,"id",None),"state":getattr(s,"lifecycle_state",None),"partitions":getattr(s,"partitions",None),"stream_pool_id":getattr(s,"stream_pool_id",None)})
    for p in all_results(f"WAF policies/{cname}",waf.list_web_app_firewall_policies,compartment_id=cid):
        report["waf_policies"].append({"compartment":cname,"name":getattr(p,"display_name",None),"id":getattr(p,"id",None),"state":getattr(p,"lifecycle_state",None)})
        for f in all_results(f"WAF firewalls/{cname}/{p.display_name}",waf.list_web_app_firewalls,compartment_id=cid,web_app_firewall_policy_id=p.id): report["waf_firewalls"].append({"compartment":cname,"policy":p.display_name,"policy_id":p.id,"name":getattr(f,"display_name",None),"id":getattr(f,"id",None),"state":getattr(f,"lifecycle_state",None),"load_balancer_id":getattr(f,"load_balancer_id",None)})
    for x in all_results(f"load balancers/{cname}",lb.list_load_balancers,compartment_id=cid): report["load_balancers"].append({"compartment":cname,"name":getattr(x,"display_name",None),"id":getattr(x,"id",None),"state":getattr(x,"lifecycle_state",None),"is_private":getattr(x,"is_private",None),"shape":getattr(x,"shape_name",None)})

# Resolve connector selection semantics, including special _Audit source.
for log in report["logs"]:
    matches=[]
    for cs in report["connector_sources"]:
        gid=cs.get("log_group_id"); lid=cs.get("log_id"); scid=cs.get("source_compartment_id")
        # A source can select a specific log, a whole group, or (for Audit) _Audit.
        if lid and lid==log.get("id"): matches.append(cs["connector"])
        elif gid and gid==log.get("log_group_id") and not lid: matches.append(cs["connector"])
    log["connectors"]=sorted(set(matches)); log["covered_by_connector"]=bool(matches)

# Record Audit separately because _Audit is not a normal Logging log OCID.
audit_connectors=[]
for cs in report["connector_sources"]:
    if cs.get("log_group_id")=="_Audit" or cs.get("log_id")=="_Audit": audit_connectors.append(cs["connector"])
report["metadata"]["audit_connectors"]=sorted(set(audit_connectors))

for log in report["logs"]:
    if log["security_priority"] in ("HIGH","MEDIUM") and log.get("is_enabled") is not False and not log["covered_by_connector"]:
        report["findings"].append({"severity":"MEDIUM","type":"ENABLED_SECURITY_LOG_NOT_IN_SIEM_CONNECTOR","compartment":log["compartment"],"log_group":log["log_group"],"log":log["name"],"service":log["service"],"resource":log["resource"],"recommendation":"Evaluate for the approved SOC/SIEM baseline; validate volume and cost before enabling delivery."})

# WAF logging gap based on full service-log configuration.
waf_logged={str(x.get("resource") or "").lower() for x in report["logs"] if str(x.get("service") or "").lower()=="waf" and x.get("is_enabled") is not False}
for fw in report["waf_firewalls"]:
    if str(fw.get("id") or "").lower() not in waf_logged:
        report["findings"].append({"severity":"HIGH","type":"WAF_WITHOUT_DISCOVERED_ENABLED_LOG","compartment":fw["compartment"],"resource":fw["name"],"policy":fw["policy"],"recommendation":"Validate/enable WAF service logging, then assess inclusion in SIEM."})

stamp=datetime.now().strftime("%Y%m%d_%H%M%S"); jf=f"oci_logging_siem_inventory_{stamp}.json"; cf=f"oci_logging_siem_inventory_{stamp}.csv"
with open(jf,"w",encoding="utf-8") as f: json.dump(report,f,indent=2,ensure_ascii=False,default=str)
fields=["compartment","log_group","name","service","resource","category","source_type","log_type","is_enabled","state","retention_duration","security_priority","covered_by_connector","connectors","id","log_group_id"]
with open(cf,"w",encoding="utf-8",newline="") as f:
    w=csv.DictWriter(f,fieldnames=fields); w.writeheader()
    for r in report["logs"]:
        z={k:r.get(k) for k in fields}; z["connectors"]=",".join(r.get("connectors",[])); w.writerow(z)
print("\n=== OCI LOGGING / SIEM DEEP INVENTORY COMPLETE ===")
for label,key in (("Compartments","compartments"),("Log groups","log_groups"),("Logs","logs"),("Connectors","connectors"),("Connector sources","connector_sources"),("Streams","streams"),("WAF policies","waf_policies"),("WAF firewalls","waf_firewalls"),("Load balancers","load_balancers"),("Findings","findings"),("Errors","errors")): print(f"{label:20}: {len(report[key])}")
print(f"Audit connectors     : {', '.join(report['metadata']['audit_connectors']) or 'NONE DISCOVERED'}")
print(f"JSON                 : {jf}\nCSV                  : {cf}")
