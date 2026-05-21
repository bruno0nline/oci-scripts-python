#!/usr/bin/env python3
import oci
import csv
from datetime import datetime

# Regiões que deseja consultar.
# Se quiser somente uma região, deixe apenas uma na lista.
REGIONS = [
    "sa-saopaulo-1",
    "sa-vinhedo-1",
    "us-ashburn-1",
]

CSV_FILE = f"oci_imds_inventory_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"

config = oci.config.from_file()
identity_client = oci.identity.IdentityClient(config)
tenancy_id = config["tenancy"]


def get_compartments():
    compartments = oci.pagination.list_call_get_all_results(
        identity_client.list_compartments,
        tenancy_id,
        compartment_id_in_subtree=True,
        access_level="ANY"
    ).data

    root_compartment = identity_client.get_compartment(tenancy_id).data
    compartments.append(root_compartment)

    return [c for c in compartments if c.lifecycle_state == "ACTIVE"]


def get_imds_status(instance):
    options = getattr(instance, "instance_options", None)
    disabled = getattr(options, "are_legacy_imds_endpoints_disabled", None) if options else None

    if disabled is True:
        return "IMDSv2 only", "OK", True
    if disabled is False:
        return "IMDSv1 + IMDSv2", "CORRIGIR", False
    return "Não identificado", "VALIDAR", ""


def main():
    compartments = get_compartments()
    rows = []

    for region in REGIONS:
        print(f"\n🔎 Consultando região: {region}")
        region_config = config.copy()
        region_config["region"] = region
        compute_client = oci.core.ComputeClient(region_config)

        for compartment in compartments:
            try:
                instances = oci.pagination.list_call_get_all_results(
                    compute_client.list_instances,
                    compartment_id=compartment.id
                ).data
            except Exception as e:
                print(f"⚠️ Erro ao listar compartment {compartment.name} em {region}: {e}")
                continue

            for instance in instances:
                imds_version, action, legacy_disabled = get_imds_status(instance)

                rows.append({
                    "Region": region,
                    "Compartment": compartment.name,
                    "Instance Name": instance.display_name,
                    "State": instance.lifecycle_state,
                    "Shape": instance.shape,
                    "OCID": instance.id,
                    "Legacy IMDS Disabled": legacy_disabled,
                    "IMDS Status": imds_version,
                    "Recommendation": action
                })

                icon = "✅" if action == "OK" else "⚠️" if action == "CORRIGIR" else "❔"
                print(f"{icon} {instance.display_name} | {compartment.name} | {region} | {imds_version} | {action}")

    with open(CSV_FILE, mode="w", newline="", encoding="utf-8") as file:
        fieldnames = [
            "Region", "Compartment", "Instance Name", "State", "Shape", "OCID",
            "Legacy IMDS Disabled", "IMDS Status", "Recommendation"
        ]
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    total = len(rows)
    corrigir = sum(1 for r in rows if r["Recommendation"] == "CORRIGIR")
    ok = sum(1 for r in rows if r["Recommendation"] == "OK")
    validar = sum(1 for r in rows if r["Recommendation"] == "VALIDAR")

    print("\n📊 Resumo")
    print(f"Total de instâncias: {total}")
    print(f"OK - IMDSv2 only: {ok}")
    print(f"Corrigir - IMDSv1 habilitado: {corrigir}")
    print(f"Validar manualmente: {validar}")
    print(f"\n📁 CSV gerado: {CSV_FILE}")


if __name__ == "__main__":
    main()
