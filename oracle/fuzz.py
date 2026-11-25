#!/usr/bin/env python3
"""Large-scale differential fuzzing: scrutinycheck (Rust) vs scrutiny-oracle (unmodified
Scrutiny Go code).

Both tools run as long-lived processes in streaming batch mode (one JSON document per
line in, one result per line out), so millions of cases are practical.

Case families (all reproducible from --seed):
  synth-ata / synth-nvme / synth-scsi  whole drives generated from the fork's metadata
  seed-mutate                          real smartctl outputs with several fields mutated
  malformed                            structural damage: missing keys, nulls, wrong
                                       types, out-of-range numbers, duplicates, ...

Each mismatch is minimized (smallest document that still diverges the same way) and
saved with the oracle's verdict under tests/virtual/fuzz/ as a permanent regression
case. --corpus N also saves N diverse non-mismatching cases with their oracle verdicts
(tests/virtual/corpus.jsonl), so that cargo test checks Scrutiny parity without Go.

Usage:
  python oracle/fuzz.py --oracle PATH/scrutiny-oracle.exe --rust PATH/scrutinycheck.exe \
      --go-src PATH/ata_attribute_metadata.go [--cases 200000] [--seed 1] [--corpus 300]
"""
import argparse
import copy
import hashlib
import json
import os
import random
import re
import subprocess
import sys
import threading
import time
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.normpath(os.path.join(HERE, ".."))
FIXTURES = os.path.join(ROOT, "tests", "fixtures")
SEEDS = os.path.join(HERE, "seeds")
OUT_DIR = os.path.join(ROOT, "tests", "virtual", "fuzz")
CORPUS = os.path.join(ROOT, "tests", "virtual", "corpus.jsonl")

I64_MAX = 2**63 - 1

# smartctl's default attribute names (drivedb defaults), plus what the fixtures use.
SMARTCTL_NAMES = {
    1: "Raw_Read_Error_Rate", 2: "Throughput_Performance", 3: "Spin_Up_Time",
    4: "Start_Stop_Count", 5: "Reallocated_Sector_Ct", 7: "Seek_Error_Rate",
    8: "Seek_Time_Performance", 9: "Power_On_Hours", 10: "Spin_Retry_Count",
    11: "Calibration_Retry_Count", 12: "Power_Cycle_Count", 13: "Read_Soft_Error_Rate",
    22: "Helium_Level", 170: "Available_Reservd_Space", 171: "Program_Fail_Count",
    172: "Erase_Fail_Count", 173: "Wear_Leveling_Count", 174: "Unexpect_Power_Loss_Ct",
    175: "Program_Fail_Count_Chip", 177: "Wear_Leveling_Count", 179: "Used_Rsvd_Blk_Cnt_Tot",
    180: "Unused_Rsvd_Blk_Cnt_Tot", 181: "Program_Fail_Cnt_Total", 182: "Erase_Fail_Count_Total",
    183: "Runtime_Bad_Block", 184: "End-to-End_Error", 187: "Reported_Uncorrect",
    188: "Command_Timeout", 189: "High_Fly_Writes", 190: "Airflow_Temperature_Cel",
    191: "G-Sense_Error_Rate", 192: "Power-Off_Retract_Count", 193: "Load_Cycle_Count",
    194: "Temperature_Celsius", 195: "Hardware_ECC_Recovered", 196: "Reallocated_Event_Count",
    197: "Current_Pending_Sector", 198: "Offline_Uncorrectable", 199: "UDMA_CRC_Error_Count",
    200: "Multi_Zone_Error_Rate", 201: "Soft_Read_Error_Rate", 220: "Disk_Shift",
    222: "Loaded_Hours", 223: "Load_Retry_Count", 224: "Load_Friction", 225: "Load_Cycle_Count",
    226: "Load-in_Time", 231: "SSD_Life_Left", 232: "Available_Reservd_Space",
    233: "Media_Wearout_Indicator", 235: "POR_Recovery_Count", 240: "Head_Flying_Hours",
    241: "Total_LBAs_Written", 242: "Total_LBAs_Read", 254: "Free_Fall_Sensor",
}

NVME_FIELDS = [
    "critical_warning", "temperature", "available_spare", "available_spare_threshold",
    "percentage_used", "data_units_read", "data_units_written", "host_reads", "host_writes",
    "controller_busy_time", "power_cycles", "power_on_hours", "unsafe_shutdowns",
    "media_errors", "num_err_log_entries", "warning_temp_time", "critical_comp_time",
]
SCSI_COUNTERS = [
    "errors_corrected_by_eccfast", "errors_corrected_by_eccdelayed",
    "errors_corrected_by_rereads_rewrites", "total_errors_corrected",
    "correction_algorithm_invocations", "gigabytes_processed", "total_uncorrected_errors",
]
SAS_PHY_COUNTERS = [
    "invalid_dword_count", "running_disparity_error_count",
    "loss_of_dword_synchronization_count", "phy_reset_problem_count",
]
MODELS = [
    ("Western Digital Red", "WDC WD40EFRX-68N32N0"), ("Seagate BarraCuda 3.5", "ST2000DM008-2FR102"),
    ("Seagate IronWolf", "ST8000VN004-2M2101"), ("Toshiba N300/MN NAS HDD", "TOSHIBA HDWG480"),
    ("HGST Ultrastar He10", "HGST HUH721010ALE604"), ("Samsung based SSDs", "Samsung SSD 870 EVO 1TB"),
    ("Crucial/Micron Client SSDs", "CT1000MX500SSD1"), ("Intel 53x and Pro 2500 Series SSDs", "INTEL SSDSC2BW240A4"),
    (None, "Generic SSD 256GB"), (None, "VBOX HARDDISK"),
]


# --------------------------------------------------------------------------- metadata

def load_ata_metadata(go_src):
    """id -> dict(name, ideal, critical, display, edges) parsed from the fork's Go table."""
    txt = open(go_src, encoding="utf-8").read()
    body = txt[txt.index("var AtaMetadata"):]
    meta = {}
    for m in re.finditer(r"\n\t(\d+): \{\n(.*?)\n\t\},", body, re.S):
        aid, block = int(m.group(1)), m.group(2)
        name = re.search(r'DisplayName:\s*"([^"]*)"', block)
        ideal = re.search(r"Ideal:\s*ObservedThresholdIdeal(\w+)", block)
        disp = re.search(r"DisplayType:\s*AtaSmartAttributeDisplayType(\w+)", block)
        edges = sorted({int(x) for x in re.findall(r"\b(?:Low|High):\s*(-?\d+)", block)})
        meta[aid] = {
            "name": name.group(1) if name else "",
            "ideal": ideal.group(1) if ideal else "",
            "critical": "Critical:    true" in block or re.search(r"Critical:\s*true", block) is not None,
            "display": disp.group(1) if disp else "Raw",
            "edges": edges,
        }
    if len(meta) < 50:
        sys.exit(f"parsed only {len(meta)} ATA attributes from {go_src}")
    return meta


def load_json_dir(d):
    out = []
    if os.path.isdir(d):
        for f in sorted(os.listdir(d)):
            if f.endswith(".json"):
                with open(os.path.join(d, f), encoding="utf-8") as fh:
                    try:
                        doc = json.load(fh)
                    except ValueError:
                        continue
                if isinstance(doc, dict) and "devices" not in doc:
                    out.append((f, doc))
    return out


# --------------------------------------------------------------------------- generators

class Gen:
    def __init__(self, rng, meta, seeds):
        self.r = rng
        self.meta = meta
        self.seeds = seeds
        names = defaultdict(set)
        for _, d in seeds:
            for a in (d.get("ata_smart_attributes") or {}).get("table") or []:
                if isinstance(a, dict) and isinstance(a.get("name"), str):
                    names[a.get("id")].add(a["name"])
        self.seen_names = names

    # value distributions -------------------------------------------------
    def edge_value(self, edges):
        r = self.r
        p = r.random()
        if edges and p < 0.55:
            return max(0, r.choice(edges) + r.choice((-1, 0, 0, 1)))
        if p < 0.75:
            return r.choice((0, 0, 0, 1, 2, 3, 5, 8, 10, 16, 50, 100, 255, 256, 1000, 65535, 65536))
        if p < 0.95:
            return int(10 ** r.uniform(0, 9))
        return r.choice((2**31 - 1, 2**32, 2**40, 2**47 + 3, 2**48 - 1, I64_MAX))

    def small(self, hi=255):
        r = self.r
        return r.choice((0, 1, 2, 5, 9, 10, 11, 49, 50, 51, 99, 100, 101, hi)) if r.random() < 0.6 else r.randint(0, hi)

    def attr_name(self, aid):
        r = self.r
        opts = list(self.seen_names.get(aid, ()))
        if aid in SMARTCTL_NAMES:
            opts.append(SMARTCTL_NAMES[aid])
        m = self.meta.get(aid)
        p = r.random()
        if opts and p < 0.65:
            return r.choice(opts)
        if m and m["name"] and p < 0.85:
            # fork display name in smartctl style, or verbatim
            return r.choice((m["name"].replace(" ", "_"), m["name"]))
        return r.choice(("Unknown_Attribute", "Unknown_SSD_Attribute", "Vendor_Specific", ""))

    def raw_string(self, aid, raw):
        r = self.r
        if aid == 188 and r.random() < 0.5:
            a, b, c = r.choice(((0, 0, 0), (1, 1, 1), (0, 0, 5), (3, 2, 1), (65537, 2, 3), (2, 1, 0)))
            return f"{a} {b} {c}", a | (b << 16) | (c << 32)
        if aid == 9 and r.random() < 0.4:
            h = r.randint(0, 90000)
            return r.choice((f"{h}h+{r.randint(0,59):02d}m+{r.randint(0,59):02d}.{r.randint(0,999):03d}s", f"{h} ({r.randint(0,9)} {r.randint(0,9)})")), h
        if aid in (190, 194) and r.random() < 0.5:
            t = r.randint(0, 90)
            return r.choice((f"{t} (Min/Max {max(0,t-15)}/{t+10})", f"{t} (0 {r.randint(0,30)} 0 {r.randint(0,60)} 0)")), t
        return str(raw), raw

    # synthetic drives ----------------------------------------------------
    def base_device(self, protocol, name, dtype):
        r = self.r
        fam, model = r.choice(MODELS)
        d = {
            "json_format_version": [1, 0],
            "smartctl": {"version": [7, r.choice((2, 3, 4))], "exit_status": r.choice((0, 0, 0, 4, 8, 32, 64, 128))},
            "device": {"name": name, "info_name": name, "type": dtype, "protocol": protocol},
            "model_name": model,
            "serial_number": "%08X" % r.getrandbits(32),
            "firmware_version": "FW%02d" % r.randint(1, 99),
            "user_capacity": {"blocks": 1953525168, "bytes": r.choice((256, 500, 1000, 4000, 14000)) * 10**9},
            "power_on_time": {"hours": r.randint(0, 80000)},
            "temperature": {"current": r.randint(20, 70)},
        }
        if fam and protocol == "ATA":
            d["model_family"] = fam
        p = r.random()
        if p < 0.85:
            d["smart_status"] = {"passed": True}
        elif p < 0.95:
            d["smart_status"] = {"passed": False}
        return d

    def synth_ata(self):
        r = self.r
        d = self.base_device("ATA", "/dev/sda", r.choice(("sat", "ata", "scsi")))
        rot = r.random()
        if rot < 0.4:
            d["rotation_rate"] = 0
        elif rot < 0.85:
            d["rotation_rate"] = r.choice((5400, 5900, 7200, 10000))
        ids = list(self.meta)
        chosen = r.sample(ids, r.randint(3, min(30, len(ids))))
        if r.random() < 0.3:
            chosen += r.sample(range(1, 256), r.randint(1, 3))
        table = []
        for aid in chosen:
            m = self.meta.get(aid, {"edges": [], "display": "Raw"})
            thresh = r.choice((0, 0, 0, 1, 6, 10, 21, 36, 44, 50, 97, 100))
            value = self.small(253) if r.random() < 0.7 else max(1, thresh + r.choice((-2, -1, 0, 1, 2)))
            worst = min(value, self.small(253)) if r.random() < 0.6 else value
            wf = r.choices(("", "now", "past"), (90, 5, 5))[0]
            raw = self.edge_value(m["edges"])
            raw_str, raw = self.raw_string(aid, raw)
            table.append({
                "id": aid, "name": self.attr_name(aid), "value": value, "worst": worst, "thresh": thresh,
                "when_failed": wf,
                "flags": {"value": r.choice((50, 51, 34, 35, 19)), "string": "PO--CK ", "prefailure": r.random() < 0.4,
                          "updated_online": True, "performance": False, "error_rate": False,
                          "event_count": r.random() < 0.5, "auto_keep": True},
                "raw": {"value": raw, "string": raw_str},
            })
        d["ata_smart_attributes"] = {"revision": 16, "table": table}
        return d

    def synth_nvme(self):
        r = self.r
        d = self.base_device("NVMe", "/dev/nvme0", "nvme")
        log = {}
        for f in NVME_FIELDS:
            if r.random() < 0.08:
                continue  # absent field
            if f == "critical_warning":
                log[f] = r.choice((0, 0, 0, 0, 1, 2, 4, 8, 16, 32, 3, 255))
            elif f in ("available_spare", "available_spare_threshold", "percentage_used"):
                log[f] = self.small(255)
            elif f in ("media_errors", "num_err_log_entries"):
                log[f] = r.choice((0, 0, 0, 1, 2, 10, 1000))
            else:
                log[f] = self.edge_value([])
        d["nvme_smart_health_information_log"] = log
        return d

    def scsi_counters(self):
        r = self.r
        c = {}
        for f in SCSI_COUNTERS:
            if r.random() < 0.1:
                continue
            c[f] = (f"{r.uniform(0, 99999):.3f}" if f == "gigabytes_processed"
                    else r.choice((0, 0, 0, 1, 2, 5, 10, 100, 1000, 10**6)))
        return c

    def synth_scsi(self):
        r = self.r
        d = self.base_device("SCSI", "/dev/sdb", "scsi")
        d["rotation_rate"] = r.choice((0, 7200, 10000, 15000))
        if r.random() < 0.9:
            d["scsi_grown_defect_list"] = r.choice((0, 0, 0, 1, 2, 5, 10, 100, 1000))
        log = {}
        for op in ("read", "write", "verify"):
            if r.random() < 0.85:
                log[op] = self.scsi_counters()
        d["scsi_error_counter_log"] = log
        if r.random() < 0.3:
            d["endurance_used"] = {"current_percent": self.small(255)}
        for port in range(r.choice((0, 0, 1, 2))):
            phys = {}
            for phy in range(r.choice((1, 1, 2))):
                p = {"attached_device_type": "SAS or SATA device",
                     "negotiated_logical_link_rate": r.choice(("phy enabled; 12 Gbps", "phy enabled; 6 Gbps", "phy enabled; unknown", ""))}
                for c in SAS_PHY_COUNTERS:
                    p[c] = r.choice((0, 0, 0, 1, 8, 32, 1000))
                phys[f"phy_{phy}"] = p
            d[f"scsi_sas_port_{port}"] = phys
        return d

    # mutations -----------------------------------------------------------
    def paths(self, node, prefix=()):
        """All (path, value) pairs of scalar leaves."""
        out = []
        if isinstance(node, dict):
            for k, v in node.items():
                out += self.paths(v, prefix + (k,))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                out += self.paths(v, prefix + (i,))
        else:
            out.append((prefix, node))
        return out

    def containers(self, node, prefix=()):
        out = [(prefix, node)] if isinstance(node, (dict, list)) else []
        if isinstance(node, dict):
            for k, v in node.items():
                out += self.containers(v, prefix + (k,))
        elif isinstance(node, list):
            for i, v in enumerate(node):
                out += self.containers(v, prefix + (i,))
        return out

    @staticmethod
    def get(doc, path):
        for p in path:
            doc = doc[p]
        return doc

    def set(self, doc, path, value):
        parent = self.get(doc, path[:-1])
        parent[path[-1]] = value

    def numeric_mutation(self, doc):
        leaves = [(p, v) for p, v in self.paths(doc) if isinstance(v, int) and not isinstance(v, bool)]
        if not leaves:
            return
        path, _ = self.r.choice(leaves)
        aid = None
        if "table" in path:
            try:
                aid = self.get(doc, path[: path.index("table") + 2]).get("id")
            except (TypeError, AttributeError, IndexError, KeyError):
                aid = None
        edges = self.meta.get(aid, {}).get("edges", []) if aid else []
        self.set(doc, path, self.edge_value(edges))

    def seed_mutate(self):
        name, seed = self.r.choice(self.seeds)
        d = copy.deepcopy(seed)
        for _ in range(self.r.randint(1, 6)):
            p = self.r.random()
            if p < 0.7:
                self.numeric_mutation(d)
            elif p < 0.8 and isinstance(d.get("smart_status"), dict):
                d["smart_status"]["passed"] = not d["smart_status"].get("passed", True)
            elif p < 0.9:
                t = (d.get("ata_smart_attributes") or {}).get("table")
                if isinstance(t, list) and t:
                    self.r.choice(t)["when_failed"] = self.r.choice(("", "now", "past"))
            else:
                if "rotation_rate" in d and self.r.random() < 0.5:
                    del d["rotation_rate"]
                else:
                    d["rotation_rate"] = self.r.choice((0, 5400, 7200))
        return d

    def malform(self, d):
        r = self.r
        for _ in range(r.randint(1, 3)):
            kind = r.randrange(10)
            leaves = self.paths(d)
            conts = [c for c in self.containers(d) if c[0]]
            if kind == 0 and conts:  # delete a key / element
                path, _ = r.choice(conts + [(p, v) for p, v in leaves if p])
                parent = self.get(d, path[:-1])
                if isinstance(parent, dict):
                    parent.pop(path[-1], None)
                elif isinstance(parent, list) and path[-1] < len(parent):
                    parent.pop(path[-1])
            elif kind == 1 and leaves:  # null
                path, _ = r.choice(leaves)
                if path:
                    self.set(d, path, None)
            elif kind == 2 and leaves:  # number <-> string
                path, v = r.choice(leaves)
                if path:
                    self.set(d, path, str(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else r.choice((0, 1, -1)))
            elif kind == 3 and leaves:  # float
                ints = [(p, v) for p, v in leaves if isinstance(v, int) and not isinstance(v, bool)]
                if ints:
                    path, v = r.choice(ints)
                    self.set(d, path, v + r.choice((0.5, 0.0001, -0.5)))
            elif kind == 4 and leaves:  # out of range / negative
                ints = [(p, v) for p, v in leaves if isinstance(v, int) and not isinstance(v, bool)]
                if ints:
                    path, _ = r.choice(ints)
                    self.set(d, path, r.choice((-1, -2**31, I64_MAX, I64_MAX + 1, -2**63, -2**63 - 1, 2**64, 2**53 + 1)))
            elif kind == 5:  # duplicate an ATA attribute
                t = (d.get("ata_smart_attributes") or {}).get("table") if isinstance(d.get("ata_smart_attributes"), dict) else None
                if isinstance(t, list) and t:
                    dup = copy.deepcopy(r.choice(t))
                    if isinstance(dup, dict) and isinstance(dup.get("raw"), dict):
                        dup["raw"]["value"] = self.edge_value([])
                    t.insert(r.randrange(len(t) + 1), dup)
            elif kind == 6:  # protocol damage
                dev = d.get("device")
                if isinstance(dev, dict):
                    dev["protocol"] = r.choice(("", "ata", "NVME", "SCSI", "ATA", "NVMe", "SAT", None))
                    if r.random() < 0.3:
                        dev.pop("protocol", None)
            elif kind == 7 and leaves:  # bool flip / bool in number slot
                path, v = r.choice(leaves)
                if path:
                    self.set(d, path, (not v) if isinstance(v, bool) else r.choice((True, False)))
            elif kind == 8 and conts:  # wrong container type
                path, v = r.choice(conts)
                self.set(d, path, [] if isinstance(v, dict) else {})
            elif kind == 9:  # extra unknown keys
                d[r.choice(("unknown_section", "ata_device_statistics", "seagate_farm_log"))] = r.choice(({}, [], 1, "x"))
        return d

    def case(self):
        r = self.r
        p = r.random()
        if p < 0.40:
            fam, d = "synth-ata", self.synth_ata()
        elif p < 0.52:
            fam, d = "synth-nvme", self.synth_nvme()
        elif p < 0.62:
            fam, d = "synth-scsi", self.synth_scsi()
        elif p < 0.85:
            fam, d = "seed-mutate", self.seed_mutate()
        else:
            base = r.choice((self.synth_ata, self.synth_nvme, self.synth_scsi, self.seed_mutate))()
            fam, d = "malformed", self.malform(base)
        return fam, d


# --------------------------------------------------------------------------- processes

class Streamer:
    """A long-lived batch-mode process: write lines on a thread, read results in order."""

    def __init__(self, cmd):
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.DEVNULL, bufsize=1 << 16)

    def run(self, lines):
        def feed():
            try:
                for ln in lines:
                    self.p.stdin.write(ln)
                self.p.stdin.flush()
            except (BrokenPipeError, OSError):
                pass
        t = threading.Thread(target=feed, daemon=True)
        t.start()
        out = []
        for _ in lines:
            res = self.p.stdout.readline()
            if not res:
                raise RuntimeError("batch process died")
            out.append(json.loads(res))
        t.join()
        return out

    def close(self):
        try:
            self.p.stdin.close()
            self.p.wait(timeout=10)
        except Exception:
            self.p.kill()


def encode(doc):
    return (json.dumps(doc, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


# --------------------------------------------------------------------------- compare

# Attribute-id prefixes of Scrutiny layers scrutinycheck does not port yet: mismatches there
# are reported apart as known gaps ("unported:*"). Empty since ATA device statistics
# ("devstat_") and the Seagate FARM log ("farm_") were ported.
UNPORTED_PREFIXES = ()

# Accepted deviation: Go's encoding/json rejects the whole document on any type error in
# any field it knows, even one that plays no part in the evaluation (Scrutiny's API then
# refuses the upload). scrutinycheck evaluates what it can. Real smartctl output is
# well-typed, so this only shows on deliberately malformed input.
KNOWN_KINDS = ("unported:", "error-parity:go-rejects")


def is_known(kind):
    return kind.startswith(KNOWN_KINDS)


def rust_bits(f):
    st, src = f["status"], f["source"]
    if st == "warning":
        return 2
    if st == "fail":
        return 1 if src == "manufacturer" else 4
    return 8 if st == "unknown" else 0


def compare(g, r):
    """List of (kind, detail) mismatches for one case; empty when the tools agree."""
    g_err, r_err = bool(g.get("error")), bool(r.get("error"))
    if g_err or r_err:
        if g.get("error", "").startswith("panic") or r.get("error", "").startswith("panic"):
            return [("panic", {"go": g.get("error"), "rust": r.get("error")})]
        if g_err != r_err:
            side = "go-rejects" if g_err else "rust-rejects"
            return [(f"error-parity:{side}", {"go": g.get("error"), "rust": r.get("error")})]
        return []
    out = []
    # All four bits, InvalidValue (8) included: scrutinycheck reports it as an "unknown" finding.
    gbits = {k: v["status"] for k, v in g["attributes"].items() if v["status"]}
    rbits = defaultdict(int)
    for f in r["findings"]:
        if f["source"] in ("smart_overall", "no_data"):
            continue
        rbits[f["attribute"]] |= rust_bits(f)
    rbits = dict(rbits)
    unported = {k for k in gbits if k.startswith(UNPORTED_PREFIXES)}
    for k in sorted(set(gbits) | set(rbits)):
        if gbits.get(k) != rbits.get(k):
            tag = "unported" if k in unported else "attr"
            out.append((f"{tag}:{k.split('_')[0] if k in unported else k}", {"go": gbits.get(k), "rust": rbits.get(k)}))
    g_smart = bool(g["device_status"] & 1)
    r_smart = any(f["source"] == "smart_overall" for f in r["findings"])
    if g_smart != r_smart:
        out.append(("smart-status", {"go": g_smart, "rust": r_smart}))
    if (g["device_status"] != 0) != (r.get("status") == "fail"):
        # A device verdict driven only by an unported layer is that layer's gap.
        kind = "unported:device" if unported and not any(k.startswith("attr:") for k, _ in out) else "device"
        out.append((kind, {"go": g["device_status"], "rust": r.get("status")}))
    return out


# --------------------------------------------------------------------------- minimize

def simplifications(doc):
    """Candidate smaller documents, biggest cuts first."""
    def walk(node, path):
        if isinstance(node, dict):
            for k in list(node):
                yield ("del", path + (k,))
            for k, v in node.items():
                yield from walk(v, path + (k,))
        elif isinstance(node, list):
            if len(node) > 1:
                half = len(node) // 2
                yield ("keep", path, 0, half)
                yield ("keep", path, half, len(node))
            for i in range(len(node)):
                yield ("del", path + (i,))
            for i, v in enumerate(node):
                yield from walk(v, path + (i,))
        elif isinstance(node, str) and node:
            yield ("set", path, "")
        elif isinstance(node, int) and not isinstance(node, bool) and node not in (0, 1):
            yield ("set", path, 0)
            yield ("set", path, 1)
            yield ("set", path, node // 2)
    for op in walk(doc, ()):
        d = copy.deepcopy(doc)
        try:
            if op[0] == "del":
                parent = Gen.get(d, op[1][:-1])
                del parent[op[1][-1]]
            elif op[0] == "keep":
                lst = Gen.get(d, op[1])
                lst[:] = lst[op[2]:op[3]]
            else:
                parent = Gen.get(d, op[1][:-1])
                parent[op[1][-1]] = op[2]
        except (KeyError, IndexError, TypeError):
            continue
        yield d


def minimize(doc, kind, go, rs, budget=4000):
    def still(d):
        g, r = go.run([encode(d)])[0], rs.run([encode(d)])[0]
        return any(k == kind for k, _ in compare(g, r))
    best, tries, improved = doc, 0, True
    while improved and tries < budget:
        improved = False
        for cand in simplifications(best):
            tries += 1
            if len(encode(cand)) < len(encode(best)) and still(cand):
                best, improved = cand, True
                break
            if tries >= budget:
                break
    return best


# --------------------------------------------------------------------------- main

def signature(g):
    """Diversity key for the regression corpus: which bits fire, on what protocol."""
    if g.get("error"):
        return ("error",)
    bits = tuple(sorted((k, v["status"]) for k, v in g["attributes"].items() if v["status"]))
    return (g.get("protocol"), g["device_status"], bits)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--oracle", required=True)
    ap.add_argument("--rust", required=True)
    ap.add_argument("--go-src", required=True)
    ap.add_argument("--cases", type=int, default=100000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--chunk", type=int, default=2000)
    ap.add_argument("--max-minimize", type=int, default=40, help="distinct mismatch kinds to minimize")
    ap.add_argument("--corpus", type=int, default=0, help="save N diverse agreeing cases as regression corpus")
    ap.add_argument("--no-save", action="store_true")
    args = ap.parse_args()

    meta = load_ata_metadata(args.go_src)
    seeds = load_json_dir(FIXTURES) + load_json_dir(SEEDS)
    gen = Gen(random.Random(args.seed), meta, seeds)
    go = Streamer([args.oracle, "-batch"])
    rs = Streamer([args.rust, "--batch"])

    fam_count, fam_mis, kinds = Counter(), Counter(), Counter()
    examples = {}            # mismatch kind -> first (family, doc, go, rust)
    corpus = {}              # signature -> (doc, go)
    alerts = Counter()
    t0 = time.time()
    done = 0
    while done < args.cases:
        n = min(args.chunk, args.cases - done)
        batch = [gen.case() for _ in range(n)]
        lines = [encode(d) for _, d in batch]
        gres, rres = go.run(lines), rs.run(lines)
        for (fam, doc), g, r in zip(batch, gres, rres):
            fam_count[fam] += 1
            if not g.get("error") and any(v["status"] for v in g["attributes"].values()):
                alerts[fam] += 1
            mis = compare(g, r)
            if mis:
                fam_mis[fam] += 1
                for kind, _ in mis:
                    kinds[kind] += 1
                    examples.setdefault(kind, (fam, doc, g, r))
            elif args.corpus and len(encode(doc)) < 2500:
                corpus.setdefault(signature(g), (doc, g))
        done += n
        rate = done / (time.time() - t0)
        print(f"\r{done}/{args.cases} cases, {sum(fam_mis.values())} mismatching, {rate:.0f} cases/s", end="", flush=True)
    print()

    print("\nper family (cases / with an alert in Scrutiny / mismatching):")
    for fam in sorted(fam_count):
        print(f"  {fam:12s} {fam_count[fam]:8d} {alerts[fam]:8d} {fam_mis[fam]:8d}")
    if kinds:
        print("\nmismatch kinds (* = known, accepted gap):")
        for k, c in kinds.most_common(40):
            print(f"  {'*' if is_known(k) else ' '} {k:40s} {c}")

    saved = []
    examples = {k: v for k, v in examples.items() if not is_known(k)}
    if examples and not args.no_save:
        os.makedirs(OUT_DIR, exist_ok=True)
        for kind, (fam, doc, g, r) in list(examples.items())[: args.max_minimize]:
            small = minimize(doc, kind, go, rs)
            gm, rm = go.run([encode(small)])[0], rs.run([encode(small)])[0]
            h = hashlib.sha1(encode(small)).hexdigest()[:10]
            base = os.path.join(OUT_DIR, f"{re.sub(r'[^a-z0-9]+', '-', kind.lower())}-{h}")
            with open(base + ".json", "w", encoding="utf-8") as f:
                json.dump(small, f, indent=1)
            with open(base + ".expected.json", "w", encoding="utf-8") as f:
                json.dump({"kind": kind, "family": fam, "oracle": gm, "rust_at_discovery": rm}, f, indent=1)
            saved.append((kind, os.path.relpath(base + ".json", ROOT), len(encode(doc)), len(encode(small))))
        print("\nminimized mismatches saved:")
        for kind, path, before, after in saved:
            print(f"  {kind:28s} {path}  ({before} -> {after} bytes)")

    if args.corpus and not args.no_save:
        items = sorted(corpus.items(), key=lambda kv: json.dumps(kv[0], default=str))
        rng = random.Random(args.seed)
        rng.shuffle(items)
        items = items[: args.corpus]
        with open(CORPUS, "w", encoding="utf-8", newline="\n") as f:
            for _, (doc, g) in items:
                exp = {"error": bool(g.get("error")), "device_status": g["device_status"],
                       "bits": {k: v["status"] for k, v in g["attributes"].items() if v["status"]}}
                f.write(json.dumps({"doc": doc, "expected": exp}, separators=(",", ":")) + "\n")
        print(f"\nregression corpus: {len(items)} diverse cases -> {os.path.relpath(CORPUS, ROOT)}")

    go.close()
    rs.close()
    unknown = sum(c for k, c in kinds.items() if not is_known(k))
    print(f"\nunexplained mismatches: {unknown}")
    sys.exit(1 if unknown else 0)


if __name__ == "__main__":
    main()
