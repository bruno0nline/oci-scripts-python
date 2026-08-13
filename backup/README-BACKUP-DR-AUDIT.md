# OCI Backup & DR Audit Report

Script read-only para inventário consolidado de Backup & DR no OCI, pensado para execução nativa no **OCI Cloud Shell**.

## Objetivo

O relatório complementa o projeto `OCI-Relatorio-Backups` (OCI-ShowBackups). Enquanto o projeto antigo lista os backups individuais de Boot/Block Volumes, este script consolida a **configuração de proteção** do ambiente:

- Compartments acessíveis
- Compute Instances
- Boot Volumes e Block Volumes
- Volume Groups
- Backup Policies
- Schedules das policies
- Assignments de policy
- Volume Group Backups
- Boot Volume Replicas
- Volume Group Replicas
- Itens para revisão (gaps informativos)

## Segurança

O script é **somente leitura**. Não chama APIs de create/update/delete/restore/move.

## Pré-requisitos

No Cloud Shell, o OCI SDK e o arquivo `~/.oci/config` já estão disponíveis.

Para gerar também XLSX:

```bash
python3 -m pip install --user openpyxl
```

Sem `openpyxl`, o script continua funcionando e gera os CSVs.

## Execução padrão

Por padrão considera São Paulo como região primária e Vinhedo como DR:

```bash
python3 backup/oci-backup-dr-audit-report.py
```

## Regiões customizadas

```bash
python3 backup/oci-backup-dr-audit-report.py \
  --source-region sa-saopaulo-1 \
  --dr-region sa-vinhedo-1
```

## Diretório de saída

Por padrão os relatórios são gravados no HOME do usuário do Cloud Shell.

```bash
python3 backup/oci-backup-dr-audit-report.py \
  --output-dir "$HOME"
```

## Saídas

O script gera CSVs separados e, quando `openpyxl` estiver instalado, um Excel consolidado com abas:

- `00_Resumo`
- `01_Instancias`
- `02_Boot_Volumes`
- `03_Block_Volumes`
- `04_Volume_Groups`
- `05_Backup_Policies`
- `06_Policy_Schedules`
- `07_Assignments`
- `08_VG_Backups`
- `09_DR_Boot_Replicas`
- `10_DR_VG_Replicas`
- `11_Gaps`
- `12_Errors`

## Observação sobre Gaps

A aba `11_Gaps` é um mecanismo de **triagem**, não uma conclusão automática de não conformidade.

Exemplo: um Boot Volume pode não possuir uma policy direta porque está protegido dentro de um Volume Group. Por isso os itens aparecem como `REVIEW` ou `INFO` e devem ser validados antes de qualquer recomendação ao cliente.

## Relação com OCI-Relatorio-Backups

Use os dois relatórios em conjunto:

1. `oci-backup-dr-audit-report.py`: arquitetura/configuração de Backup & DR.
2. `OCI-Relatorio-Backups`: histórico detalhado de backups existentes de Boot/Block Volumes.

Essa separação mantém este repositório Cloud Shell-native e evita duplicar a coleta histórica mais pesada do OCI-ShowBackups.
