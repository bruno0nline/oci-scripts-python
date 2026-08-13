#!/usr/bin/env python3
"""Read-only OCI Backup & DR audit report for OCI Cloud Shell."""
import argparse, csv
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
import oci

ERRORS=[]

def all_results(label, func, *args, **kwargs):
    try: return oci.pagination.list_call_get_all_results(func,*args,**kwargs).data
    except Exception as exc:
        ERRORS.append({"operation":label,"error":str(exc)}); print(f"[WARN] {label}: {exc}"); return []

def client(cls, config, region):
    cfg=dict(config); cfg["region"]=region; return cls(cfg)

def assignment(block, label, asset_id):
    try: return block.get_volume_backup_policy_asset_assignment(asset_id=asset_id).data or []
    except Exception as exc:
        if getattr(exc,"status",None)==404: return []
        ERRORS.append({"operation":label,"error":str(exc)}); print(f"[WARN] {label}: {exc}"); return []

def days(seconds): return round(seconds/86400,2) if seconds is not None else ""
def iso(value): return value.isoformat() if value else ""

def write_csv(path, rows):
    if not rows: return
    fields=[]
    for row in rows:
        for key in row:
            if key not in fields: fields.append(key)
    with path.open("w",newline="",encoding="utf-8-sig") as f:
        w=csv.DictWriter(f,fieldnames=fields); w.writeheader(); w.writerows(rows)

def write_xlsx(path,sheets):
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font
        from openpyxl.utils import get_column_letter
    except ImportError:
        print("[WARN] openpyxl not installed; CSV output is available."); return False
    wb=Workbook(); wb.remove(wb.active)
    for name,rows in sheets:
        ws=wb.create_sheet(name[:31])
        if not rows: ws.append(["No data returned"]); continue
        fields=[]
        for row in rows:
            for key in row:
                if key not in fields: fields.append(key)
        ws.append(fields)
        for c in ws[1]: c.font=Font(bold=True)
        for row in rows: ws.append([row.get(k,"") for k in fields])
        ws.freeze_panes="A2"; ws.auto_filter.ref=ws.dimensions
        for i,k in enumerate(fields,1):
            width=max([len(k)]+[len(str(r.get(k,""))) for r in rows]); ws.column_dimensions[get_column_letter(i)].width=min(width+2,60)
    wb.save(path); return True

def args():
    p=argparse.ArgumentParser(description="OCI Backup & DR read-only audit")
    p.add_argument("--source-region",default="sa-saopaulo-1"); p.add_argument("--dr-region",default="sa-vinhedo-1")
    p.add_argument("--output-dir",default=str(Path.home())); p.add_argument("--prefix",default="oci_backup_dr_audit")
    return p.parse_args()

def main():
    a=args(); out=Path(a.output_dir).expanduser().resolve(); out.mkdir(parents=True,exist_ok=True)
    config=oci.config.from_file(); tenancy_id=config["tenancy"]
    identity=client(oci.identity.IdentityClient,config,a.source_region); tenancy=identity.get_tenancy(tenancy_id).data
    comps=all_results("list compartments",identity.list_compartments,tenancy_id,compartment_id_in_subtree=True,access_level="ACCESSIBLE")
    scope=[(tenancy_id,tenancy.name)]+[(c.id,c.name) for c in comps if c.lifecycle_state=="ACTIVE"]
    data=defaultdict(list); policy_by_id={}; instance_by_id={}; boot_to_instance={}; volume_to_instance={}
    print(f"[INFO] Tenancy: {tenancy.name}\n[INFO] Source: {a.source_region} | DR: {a.dr_region}\n[INFO] Accessible scope: {len(scope)} compartments including root")
    block=client(oci.core.BlockstorageClient,config,a.source_region)

    # Policies and schedules. OCI assignment lookup is asset-driven, not policy-driven.
    for cid,cname in scope:
        for p in all_results(f"policies/{cname}",block.list_volume_backup_policies,compartment_id=cid):
            policy_by_id[p.id]=p.display_name
            data["policies"].append({"region":a.source_region,"compartment":cname,"policy":p.display_name,"policy_ocid":p.id,"destination_region":getattr(p,"destination_region",None) or "","schedule_count":len(p.schedules or [])})
            for n,s in enumerate(p.schedules or [],1):
                data["schedules"].append({"compartment":cname,"policy":p.display_name,"schedule":n,"backup_type":s.backup_type,"period":s.period,"day_of_week":s.day_of_week or "","day_of_month":s.day_of_month or "","month":s.month or "","hour_of_day":s.hour_of_day,"time_zone":s.time_zone or "","retention_days":days(s.retention_seconds),"prevent_deletion":getattr(s,"is_prevent_deletion_enabled",None),"retention_lock":getattr(s,"is_retention_lock_enabled",None)})

    # Compute inventory from BOTH primary and DR regions.
    for region in dict.fromkeys([a.source_region,a.dr_region]):
        compute=client(oci.core.ComputeClient,config,region)
        for cid,cname in scope:
            for inst in all_results(f"instances/{region}/{cname}",compute.list_instances,cid):
                if inst.lifecycle_state=="TERMINATED": continue
                data["instances"].append({"region":region,"compartment":cname,"instance":inst.display_name,"instance_ocid":inst.id,"state":inst.lifecycle_state,"availability_domain":inst.availability_domain,"shape":inst.shape})
                if region!=a.source_region: continue
                instance_by_id[inst.id]=inst
                for x in all_results(f"boot attachments/{inst.display_name}",compute.list_boot_volume_attachments,availability_domain=inst.availability_domain,compartment_id=cid,instance_id=inst.id): boot_to_instance[x.boot_volume_id]=inst.id
                for x in all_results(f"block attachments/{inst.display_name}",compute.list_volume_attachments,compartment_id=cid,instance_id=inst.id): volume_to_instance[x.volume_id]=inst.id

    ads=all_results("availability domains",identity.list_availability_domains,tenancy_id)
    for cid,cname in scope:
        for ad in ads:
            for b in all_results(f"boot volumes/{cname}/{ad.name}",block.list_boot_volumes,availability_domain=ad.name,compartment_id=cid):
                inst=instance_by_id.get(boot_to_instance.get(b.id)); reps=getattr(b,"boot_volume_replicas",None) or []
                assigns=assignment(block,f"assignment/{b.display_name}",b.id); pname=""
                for x in assigns:
                    pid=getattr(x,"policy_id","") or ""; pname=policy_by_id.get(pid,pid)
                    data["assignments"].append({"compartment":cname,"policy":pname,"policy_ocid":pid,"asset_type":"bootvolume","asset_name":b.display_name,"asset_ocid":b.id})
                data["boot_volumes"].append({"compartment":cname,"instance":getattr(inst,"display_name",""),"boot_volume":b.display_name,"boot_volume_ocid":b.id,"size_gb":b.size_in_gbs,"state":b.lifecycle_state,"direct_policy":pname,"replica_count":len(reps)})
                for r in reps:
                    rid=getattr(r,"boot_volume_replica_id","") or ""; parts=rid.split("."); target=parts[3] if len(parts)>3 else ""
                    data["boot_replicas"].append({"compartment":cname,"instance":getattr(inst,"display_name",""),"source_region":a.source_region,"source_boot_volume":b.display_name,"source_boot_volume_ocid":b.id,"target_region":target,"target_ad":getattr(r,"availability_domain",""),"replica_name":getattr(r,"display_name",""),"replica_ocid":rid})
        for v in all_results(f"block volumes/{cname}",block.list_volumes,compartment_id=cid):
            inst=instance_by_id.get(volume_to_instance.get(v.id)); assigns=assignment(block,f"assignment/{v.display_name}",v.id); pname=""
            for x in assigns:
                pid=getattr(x,"policy_id","") or ""; pname=policy_by_id.get(pid,pid)
                data["assignments"].append({"compartment":cname,"policy":pname,"policy_ocid":pid,"asset_type":"volume","asset_name":v.display_name,"asset_ocid":v.id})
            data["block_volumes"].append({"compartment":cname,"instance":getattr(inst,"display_name",""),"block_volume":v.display_name,"block_volume_ocid":v.id,"size_gb":v.size_in_gbs,"state":v.lifecycle_state,"direct_policy":pname})
        for g in all_results(f"volume groups/{cname}",block.list_volume_groups,compartment_id=cid):
            reps=getattr(g,"volume_group_replicas",None) or []; assigns=assignment(block,f"assignment/{g.display_name}",g.id); pname=""
            for x in assigns:
                pid=getattr(x,"policy_id","") or ""; pname=policy_by_id.get(pid,pid)
                data["assignments"].append({"compartment":cname,"policy":pname,"policy_ocid":pid,"asset_type":"volumegroup","asset_name":g.display_name,"asset_ocid":g.id})
            data["volume_groups"].append({"compartment":cname,"volume_group":g.display_name,"volume_group_ocid":g.id,"state":g.lifecycle_state,"backup_policy":pname,"volume_count":len(g.volume_ids or []),"volume_ocids":",".join(g.volume_ids or []),"replica_count":len(reps)})
            for r in reps:
                rid=getattr(r,"volume_group_replica_id","") or ""; parts=rid.split("."); target=parts[3] if len(parts)>3 else ""
                data["vg_replicas"].append({"compartment":cname,"source_region":a.source_region,"source_volume_group":g.display_name,"source_volume_group_ocid":g.id,"target_region":target,"target_ad":getattr(r,"availability_domain",""),"replica_name":getattr(r,"display_name",""),"replica_ocid":rid})

    for region in dict.fromkeys([a.source_region,a.dr_region]):
        rb=client(oci.core.BlockstorageClient,config,region)
        for cid,cname in scope:
            for b in all_results(f"VG backups/{region}/{cname}",rb.list_volume_group_backups,compartment_id=cid):
                data["vg_backups"].append({"region":region,"compartment":cname,"backup_name":b.display_name,"backup_ocid":b.id,"volume_group_ocid":getattr(b,"volume_group_id",""),"backup_type":getattr(b,"type",""),"source_type":getattr(b,"source_type",""),"state":b.lifecycle_state,"size_gb":getattr(b,"size_in_gbs",""),"created":iso(getattr(b,"time_created",None)),"expiration":iso(getattr(b,"expiration_time",None))})

    dr_boots={r["source_boot_volume_ocid"] for r in data["boot_replicas"] if r["target_region"]==a.dr_region}
    dr_groups={r["source_volume_group_ocid"] for r in data["vg_replicas"] if r["target_region"]==a.dr_region}
    for r in data["boot_volumes"]:
        if not r["direct_policy"]: data["gaps"].append({"severity":"REVIEW","resource_type":"BOOT_VOLUME","resource":r["boot_volume"],"instance":r["instance"],"finding":"No direct policy discovered; validate whether protection is provided through a Volume Group."})
        if r["boot_volume_ocid"] not in dr_boots: data["gaps"].append({"severity":"INFO","resource_type":"BOOT_VOLUME","resource":r["boot_volume"],"instance":r["instance"],"finding":f"No direct Boot Volume replica discovered to {a.dr_region}; validate Volume Group replication."})
    for r in data["volume_groups"]:
        if not r["backup_policy"]: data["gaps"].append({"severity":"REVIEW","resource_type":"VOLUME_GROUP","resource":r["volume_group"],"instance":"","finding":"No Backup Policy assignment discovered for this Volume Group."})
        if r["volume_group_ocid"] not in dr_groups: data["gaps"].append({"severity":"INFO","resource_type":"VOLUME_GROUP","resource":r["volume_group"],"instance":"","finding":f"No Volume Group replica discovered to {a.dr_region}."})

    src_count=sum(1 for r in data["instances"] if r["region"]==a.source_region); dr_count=sum(1 for r in data["instances"] if r["region"]==a.dr_region)
    summary=[{"metric":"Tenancy","value":tenancy.name},{"metric":"Source region","value":a.source_region},{"metric":"DR region","value":a.dr_region},{"metric":"Accessible compartments incl. root","value":len(scope)},{"metric":"Instances total (source + DR)","value":len(data["instances"])},{"metric":f"Instances {a.source_region}","value":src_count},{"metric":f"Instances {a.dr_region}","value":dr_count},{"metric":"Backup policies","value":len(data["policies"])},{"metric":"Policy schedules","value":len(data["schedules"])},{"metric":"Policy assignments","value":len(data["assignments"])},{"metric":"Volume Groups","value":len(data["volume_groups"])},{"metric":"Volume Group backups","value":len(data["vg_backups"])},{"metric":f"Boot replicas to {a.dr_region}","value":len(dr_boots)},{"metric":f"VG replicas to {a.dr_region}","value":len(dr_groups)},{"metric":"Items for review","value":len(data["gaps"])},{"metric":"API warnings","value":len(ERRORS)},{"metric":"Generated UTC","value":datetime.now(timezone.utc).isoformat()},{"metric":"Execution mode","value":"READ-ONLY"}]
    sheets=[("00_Resumo",summary),("01_Instancias",data["instances"]),("02_Boot_Volumes",data["boot_volumes"]),("03_Block_Volumes",data["block_volumes"]),("04_Volume_Groups",data["volume_groups"]),("05_Backup_Policies",data["policies"]),("06_Policy_Schedules",data["schedules"]),("07_Assignments",data["assignments"]),("08_VG_Backups",data["vg_backups"]),("09_DR_Boot_Replicas",data["boot_replicas"]),("10_DR_VG_Replicas",data["vg_replicas"]),("11_Gaps",data["gaps"]),("12_Errors",ERRORS)]
    stamp=datetime.now().strftime("%Y%m%d_%H%M%S"); base=f"{a.prefix}_{stamp}"
    for name,rows in sheets: write_csv(out/f"{base}_{name}.csv",rows)
    xlsx=out/f"{base}.xlsx"; ok=write_xlsx(xlsx,sheets)
    print("\n=== OCI BACKUP & DR AUDIT COMPLETE ===")
    for name,rows in sheets: print(f"{name:24}: {len(rows)}")
    print(f"Output directory        : {out}")
    if ok: print(f"Excel report            : {xlsx}")
    print("Execution mode          : READ-ONLY")

if __name__=="__main__": main()
