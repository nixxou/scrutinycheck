#!/usr/bin/env python3
"""Differential test: scrutinycheck (Rust) vs scrutiny-oracle (unmodified Scrutiny Go code).

Generates virtual smartctl JSON inputs by mutating real fixtures one field at a
time (bucket edges, +-1, extremes, when_failed, vendor raw strings), runs both
tools, and compares per-attribute status bits.

Comparison level: attribute bits, the device-level "SMART failed" bit and the
device verdict under the default (Scrutiny) policy, which must all be identical.

Usage:
  python oracle/differential.py --oracle PATH/scrutiny-oracle.exe \
      --rust PATH/scrutinycheck.exe --work WORKDIR [--go-src PATH/ata_attribute_metadata.go]
"""
import argparse
import copy
import json
import os
import re
import subprocess
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "..", "tests", "fixtures")

# Rust finding -> fork attribute bit.
def rust_bits(finding):
    st, src = finding["status"], finding["source"]
    if st == "warning":
        return 2
    if st == "fail":
        return 1 if src == "manufacturer" else 4
    if st == "unknown":
        return 8
    return 0


def load(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as f:
        return json.load(f)


def bucket_edges(go_src):
    """All Low/High values that appear in the fork's ATA observed thresholds."""
    edges = set()
    if go_src and os.path.exists(go_src):
        txt = open(go_src, encoding="utf-8").read()
        for m in re.finditer(r"\b(?:Low|High):\s*(-?\d+)", txt):
            edges.add(int(m.group(1)))
    return edges


def probes_from_edges(edges):
    vals = {0, 1, 2, 3, 5, 10, 100, 1000, 65535, 2**32, 2**40, 2**47 + 5}
    for e in edges:
        for d in (-1, 0, 1):
            if e + d >= 0:
                vals.add(e + d)
    return sorted(vals)


def ata_cases(base, tag, probes):
    table = base["ata_smart_attributes"]["table"]
    for idx, attr in enumerate(table):
        aid = attr["id"]
        # raw value sweep
        for v in probes:
            d = copy.deepcopy(base)
            a = d["ata_smart_attributes"]["table"][idx]
            a["raw"]["value"] = v
            a["raw"]["string"] = str(v)
            yield f"{tag}-a{aid}-raw{v}", d
        # normalized value sweep
        for v in (0, 1, 2, 5, 9, 10, 11, 50, 99, 100, 101, 200, 253):
            d = copy.deepcopy(base)
            d["ata_smart_attributes"]["table"][idx]["value"] = v
            yield f"{tag}-a{aid}-norm{v}", d
        # when_failed
        for wf in ("now", "past"):
            d = copy.deepcopy(base)
            d["ata_smart_attributes"]["table"][idx]["when_failed"] = wf
            yield f"{tag}-a{aid}-wf{wf}", d
    # vendor-specific raw strings on 9 / 188 / 194, appended if absent
    special = {
        9: ["1730", "1730h+12m+00.000s", "12345 (0 0)", "0", "70000"],
        188: ["0 0 0", "1 1 1", "0 0 5", "3 2 1", "65537 2 3", "4295032833", "12", "200"],
        194: ["32", "32 (Min/Max 20/45)", "70 (0 15 0 0 0)", "0"],
    }
    for aid, strings in special.items():
        for s in strings:
            d = copy.deepcopy(base)
            t = d["ata_smart_attributes"]["table"]
            a = next((x for x in t if x["id"] == aid), None)
            if a is None:
                a = {"id": aid, "name": {9: "Power_On_Hours", 188: "Command_Timeout", 194: "Temperature_Celsius"}[aid],
                     "value": 100, "worst": 100, "thresh": 0, "when_failed": "",
                     "flags": {"value": 50, "string": "-O--CK ", "prefailure": False},
                     "raw": {"value": 0, "string": "0"}}
                t.append(a)
            nums = [int(x) for x in re.findall(r"\d+", s)]
            a["raw"]["string"] = s
            if aid == 188 and len(nums) == 3:
                a["raw"]["value"] = nums[0] | (nums[1] << 16) | (nums[2] << 32)
            else:
                a["raw"]["value"] = nums[0] if nums else 0
            yield f"{tag}-s{aid}-{re.sub(r'[^0-9a-z]+', '_', s)}", d
    # whole-device: smart failed flag
    d = copy.deepcopy(base)
    d["smart_status"] = {"passed": False}
    yield f"{tag}-smartfailed", d


def nvme_cases(base):
    log = base["nvme_smart_health_information_log"]
    vals = (0, 1, 2, 5, 9, 10, 11, 50, 99, 100, 101, 200, 255)
    for field in sorted(log):
        if not isinstance(log[field], int):
            continue
        for v in vals:
            d = copy.deepcopy(base)
            d["nvme_smart_health_information_log"][field] = v
            yield f"nvme-{field}-{v}", d
    for spare in (0, 5, 9, 10, 11, 100):
        for thr in (0, 10, 50):
            d = copy.deepcopy(base)
            d["nvme_smart_health_information_log"]["available_spare"] = spare
            d["nvme_smart_health_information_log"]["available_spare_threshold"] = thr
            yield f"nvme-spare{spare}-thr{thr}", d


def scsi_cases(base):
    vals = (0, 1, 2, 5, 10, 100, 1000)
    for v in vals:
        d = copy.deepcopy(base)
        d["scsi_grown_defect_list"] = v
        yield f"scsi-grown-{v}", d
    log = base.get("scsi_error_counter_log", {})
    for kind in sorted(log):
        for field in sorted(log[kind]):
            if not isinstance(log[kind][field], int):
                continue
            for v in vals:
                d = copy.deepcopy(base)
                d["scsi_error_counter_log"][kind][field] = v
                yield f"scsi-{kind}-{field}-{v}", d


def run_batches(cmd_prefix, files, batch=120):
    out = []
    for i in range(0, len(files), batch):
        chunk = files[i:i + batch]
        args = list(cmd_prefix)
        for f in chunk:
            args += ["-f", f] if cmd_prefix[-1] == "--json" else [f]
        p = subprocess.run(args, capture_output=True)
        if not p.stdout:
            sys.exit(f"no output from {cmd_prefix[0]}: {p.stderr.decode(errors='replace')[:500]}")
        out.extend(json.loads(p.stdout))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--oracle", required=True)
    ap.add_argument("--rust", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--go-src", default=None)
    ap.add_argument("--show", type=int, default=25, help="max mismatches to print")
    args = ap.parse_args()

    probes = probes_from_edges(bucket_edges(args.go_src))
    hdd = load("smart-ata.json")          # WD 14TB HDD, rotation 5400
    ssd = load("smart-ata-failed-scrutiny.json")  # Samsung SATA SSD
    ssd["ata_smart_attributes"]["table"] = [a for a in ssd["ata_smart_attributes"]["table"] if a["id"] != 199] + \
        [dict(a, raw={"value": 0, "string": "0"}) for a in ssd["ata_smart_attributes"]["table"] if a["id"] == 199]
    nvme = load("smart-nvme.json")
    scsi = load("smart-scsi.json")

    gens = [ata_cases(hdd, "hdd", probes), ata_cases(ssd, "ssd", probes), nvme_cases(nvme), scsi_cases(scsi)]
    os.makedirs(args.work, exist_ok=True)
    files, names = [], []
    for g in gens:
        for name, doc in g:
            path = os.path.join(args.work, f"c{len(files):05d}.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(doc, f)
            files.append(path)
            names.append(name)
    # plus the real fixtures
    for fx in sorted(os.listdir(FIXTURES)):
        if fx.startswith("smart-"):
            files.append(os.path.join(FIXTURES, fx))
            names.append("fixture:" + fx)

    print(f"{len(files)} cases ({len(probes)} probe values per ATA attribute)")
    go = run_batches([args.oracle], files)
    rs = run_batches([args.rust, "--json"], files)
    assert len(go) == len(rs) == len(files)

    mismatches = []
    per_attr = Counter()
    for name, g, r in zip(names, go, rs):
        if g.get("error") or r.get("error"):
            if bool(g.get("error")) != bool(r.get("error")):
                mismatches.append((name, "error", g.get("error"), r.get("error")))
            continue
        gbits = {k: v["status"] for k, v in g["attributes"].items() if v["status"]}
        rbits = defaultdict(int)
        for f in r["findings"]:
            if f["source"] in ("smart_overall", "no_data"):
                continue
            rbits[f["attribute"]] |= rust_bits(f)
        rbits = dict(rbits)
        # INVALID_VALUE (8) comes from devstat, not ported
        gbits = {k: v & ~8 for k, v in gbits.items() if v & ~8}
        if gbits != rbits:
            mismatches.append((name, "attrs", gbits, rbits))
            for k in set(gbits) | set(rbits):
                if gbits.get(k) != rbits.get(k):
                    per_attr[k] += 1
        g_smart = bool(g["device_status"] & 1)
        r_smart = any(f["source"] == "smart_overall" for f in r["findings"])
        if g_smart != r_smart:
            mismatches.append((name, "smart_status", g_smart, r_smart))
        # Device verdict under the default (Scrutiny) policy: must be identical.
        g_fail = g["device_status"] != 0
        r_fail = r["status"] == "fail"
        if g_fail != r_fail:
            mismatches.append((name, "device", g["device_status"], r["status"]))

    print(f"mismatches: {len(mismatches)} / {len(files)}")
    if per_attr:
        print("attributes involved:", dict(per_attr.most_common()))
    for m in mismatches[: args.show]:
        print("  ", m)
    with open(os.path.join(args.work, "mismatches.json"), "w", encoding="utf-8") as f:
        json.dump(mismatches, f, indent=1, default=str)
    sys.exit(1 if mismatches else 0)


if __name__ == "__main__":
    main()
