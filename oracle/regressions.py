#!/usr/bin/env python3
"""(Re)generate tests/virtual/fuzz/: the minimized documents of every mismatch class the
differential fuzzer found (and that is now fixed), with the oracle's verdict recorded as
the expected result. `cargo test` (tests/scrutiny_parity.rs) checks them without Go.

Usage: python oracle/regressions.py --oracle PATH/scrutiny-oracle.exe
"""
import argparse
import json
import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.normpath(os.path.join(HERE, "..", "tests", "virtual", "fuzz"))

# name -> (what it pins, minimized document found by oracle/fuzz.py)
CASES = {
    "no-protocol-ata": ("device.protocol missing: Scrutiny evaluates no attribute",
        {"rotation_rate": 1, "ata_smart_attributes": {"table": [{"id": 5, "raw": {"value": 387}}]}}),
    "no-protocol-scsi": ("device.protocol missing on SCSI data",
        {"smart_status": {"passed": True}, "scsi_error_counter_log": {"verify": {"errors_corrected_by_rereads_rewrites": 1}}}),
    "no-protocol-nvme": ("device.protocol missing on NVMe data",
        {"nvme_smart_health_information_log": {"critical_warning": 1}}),
    "nvme-absent-spare": ("absent NVMe field reads as 0 (available_spare 0 < threshold 2)",
        {"device": {"protocol": "NVMe"}, "nvme_smart_health_information_log": {"available_spare_threshold": 2}}),
    "nvme-absent-log": ("NVMe protocol without a health log: all-zero log",
        {"device": {"protocol": "NVMe"}, "smart_status": {"passed": True}}),
    "ata-duplicate-backblaze": ("duplicate id: last occurrence reported, overwritten failure still fails the device",
        {"device": {"protocol": "ATA"}, "smart_status": {"passed": True}, "rotation_rate": 1,
         "ata_smart_attributes": {"table": [{"id": 5, "raw": {"value": 387}}, {"id": 5}]}}),
    "ata-duplicate-when-failed": ("duplicate id: an overwritten when_failed=now is dropped",
        {"device": {"protocol": "ATA"}, "smart_status": {"passed": True},
         "ata_smart_attributes": {"table": [{"id": 12, "when_failed": "now"}, {"id": 12}]}}),
    "ata-duplicate-last-fails": ("duplicate id: the last occurrence is the one that counts",
        {"device": {"protocol": "ATA"}, "smart_status": {"passed": True}, "rotation_rate": 1,
         "ata_smart_attributes": {"table": [{"id": 5}, {"id": 5, "raw": {"value": 387}}]}}),
    "sas-phy-bad-type": ("SAS PHY with a wrongly typed field is dropped, like Go's per-PHY decode",
        {"device": {"protocol": "SCSI"}, "smart_status": {"passed": True},
         "scsi_sas_port_0": {"phy_0": {"negotiated_logical_link_rate": True, "invalid_dword_count": 8}}}),
    "sas-phy-fractional": ("SAS PHY with a fractional counter is dropped",
        {"device": {"protocol": "SCSI"}, "smart_status": {"passed": True},
         "scsi_sas_port_1": {"phy_0": {"invalid_dword_count": -0.5, "phy_reset_problem_count": 8}}}),
    "sas-phy-null-ok": ("SAS PHY with null fields is kept (null leaves the zero value)",
        {"device": {"protocol": "SCSI"}, "smart_status": {"passed": True},
         "scsi_sas_port_0": {"phy_0": {"negotiated_logical_link_rate": None, "invalid_dword_count": 8}}}),
    "ata-missing-id": ("attribute without id reads as id 0 instead of rejecting the document",
        {"device": {"protocol": "ATA"}, "ata_smart_attributes": {"table": [{}]}}),
    "ata-null-table": ("null attribute table is an empty table",
        {"device": {"protocol": "ATA"}, "smart_status": {"passed": True}, "ata_smart_attributes": {"table": None}}),
    "negative-capacity": ("negative user_capacity.bytes is decoded (int64), not rejected",
        {"device": {"protocol": "ATA"}, "smart_status": {"passed": True}, "user_capacity": {"bytes": -1}}),
    "protocol-case": ("protocol is matched case-sensitively",
        {"device": {"protocol": "ata"}, "smart_status": {"passed": True},
         "ata_smart_attributes": {"table": [{"id": 5, "raw": {"value": 387}}]}}),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--oracle", required=True)
    args = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    names = list(CASES)
    lines = "".join(json.dumps(CASES[n][1]) + "\n" for n in names).encode()
    res = subprocess.run([args.oracle, "-batch"], input=lines, capture_output=True, check=True)
    results = [json.loads(l) for l in res.stdout.splitlines()]
    for name, g in zip(names, results):
        what, doc = CASES[name]
        expected = {
            "what": what,
            "error": bool(g.get("error")),
            "device_status": g["device_status"],
            "bits": {k: v["status"] & ~8 for k, v in g["attributes"].items() if v["status"] & ~8},
        }
        with open(os.path.join(OUT, name + ".json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump(doc, f, indent=1)
            f.write("\n")
        with open(os.path.join(OUT, name + ".expected.json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump(expected, f, indent=1)
            f.write("\n")
        print(f"{name:28s} device_status={g['device_status']} bits={expected['bits']}")


if __name__ == "__main__":
    main()
