#!/usr/bin/env python3
"""Feedback-driven mutation fuzzing: scrutinycheck vs the unmodified Scrutiny Go code.

Unlike oracle/fuzz.py (generators that know smartctl's layout), this engine mutates
*any* value at *any* path of a document, by type, so fields nobody thought of are
exercised too:

  integers  dictionary of limits (0, +-1, 8..64-bit signed/unsigned bounds +-1, powers of
            two +-1, Backblaze bucket bounds +-1, every integer literal of the fork's Go
            code), arithmetic, bit flips, random magnitudes
  strings   empty, numeric, digits changed in place ("0 0 5" -> "0 0 6", "123h+07m"),
            short string literals of the fork's Go code, case swaps, truncation
  bools     flips;  null;  occasional type changes
  structure delete/duplicate/swap list elements, delete keys, transplant a key (with its
            value) from another document of the same drive type, graft a whole subtree

Feedback: a mutant whose *Scrutiny result* has a signature never seen before (protocol,
device status, attribute status bits, magnitude of decoded values) joins the pool the next
mutants are drawn from, so the search follows behaviours, not just values.

Focus: at least 80% of cases are SATA HDD, SATA SSD or NVMe (weights below).

Every case is kept as (base document, list of edit operations), so a 50,000-case corpus
stays small: tests/virtual/corpus/bases.json.gz + cases.jsonl.gz, replayed by
tests/scrutiny_parity.rs without Go. Case line: {"t": drive type, "b": base index,
"ops": [...], then either "e": 1 (Scrutiny rejects the document) or "d": device status
and "x": {attribute: status bits}}.

Usage:
  python oracle/mutfuzz.py --oracle ORACLE.exe --rust scrutinycheck.exe --go-root FORK_SRC \
      [--cases 1000000] [--seed 1] [--corpus 50000]
"""
import argparse
import copy
import glob
import gzip
import hashlib
import json
import os
import random
import re
import sys
import time
import zlib
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fuzz  # noqa: E402  (shared: metadata parsing, generators for bases, processes, compare)

ROOT = fuzz.ROOT
CORPUS_DIR = os.path.join(ROOT, "tests", "virtual", "corpus")

# Share of cases per drive type: >= 80% SATA HDD + SATA SSD + NVMe.
WEIGHTS = {"sata-hdd": 0.30, "sata-ssd": 0.30, "nvme": 0.25, "scsi": 0.15}
I64_MIN, I64_MAX, U64_MAX = -2**63, 2**63 - 1, 2**64 - 1


# --------------------------------------------------------------------------- dictionary

def harvest_go_literals(go_root):
    ints, strs = set(), set()
    pkg = os.path.join(go_root, "webapp", "backend", "pkg")
    files = (glob.glob(os.path.join(pkg, "thresholds", "*.go"))
             + glob.glob(os.path.join(pkg, "models", "measurements", "*.go"))
             + glob.glob(os.path.join(pkg, "models", "collector", "*.go"))
             + glob.glob(os.path.join(pkg, "*.go")))
    for f in files:
        if f.endswith("_test.go"):
            continue
        t = re.sub(r"//[^\n]*", "", open(f, encoding="utf-8").read())
        for m in re.finditer(r"(?<![\w.])(-?\d+)(?![\w.])", t):
            ints.add(int(m.group(1)))
        for m in re.finditer(r'"([^"\\\n]{1,40})"', t):
            s = m.group(1)
            if re.fullmatch(r"[\w ./:%+\-()]+", s):
                strs.add(s)
    return sorted(ints), sorted(strs)


def limit_values(extra):
    vals = {0, 1, -1, 2, -2}
    for bits in (8, 16, 32, 48, 64):
        for v in (2**(bits - 1) - 1, 2**(bits - 1), -2**(bits - 1), 2**bits - 1, 2**bits):
            vals.update((v - 1, v, v + 1))
    for k in range(0, 65):
        vals.update((2**k - 1, 2**k, 2**k + 1))
    for v in extra:
        vals.update((v - 1, v, v + 1))
    return sorted(vals)


# --------------------------------------------------------------------------- ops

def get(doc, path):
    for p in path:
        doc = doc[p]
    return doc


def apply_ops(doc, ops):
    """Apply edit operations in order. Ops: ["set",path,v] ["del",path] ["ins",path,v]."""
    d = copy.deepcopy(doc)
    for op in ops:
        kind, path = op[0], op[1]
        if not path:
            if kind == "set":
                d = copy.deepcopy(op[2])
            continue
        parent = get(d, path[:-1])
        key = path[-1]
        if kind == "set":
            parent[key] = copy.deepcopy(op[2])
        elif kind == "del":
            del parent[key]
        elif kind == "ins":
            parent.insert(key, copy.deepcopy(op[2]))
    return d


class Mutator:
    def __init__(self, rng, limits, go_ints, go_strs, edges):
        self.r = rng
        self.limits = limits
        self.go_ints = go_ints
        self.go_strs = go_strs
        self.edges = edges          # ATA id -> bucket edges

    # value mutations -----------------------------------------------------
    def mut_int(self, v, aid=None):
        r = self.r
        p = r.random()
        if p < 0.25:
            # bucket bounds of the ATA attribute this value belongs to, if any
            edges = self.edges.get(aid) or self.go_ints
            return r.choice(edges) + r.choice((-1, 0, 0, 1))
        if p < 0.45:
            return r.choice(self.limits)
        if p < 0.65:
            return v + r.choice((-1, 1, -2, 2, -10, 10, -100, 100))
        if p < 0.75:
            return r.choice((v * 2, v // 2, -v, v * 10, v // 10, abs(v)))
        if p < 0.85:
            return v ^ (1 << r.randrange(64))
        if p < 0.95:
            return int(10 ** r.uniform(0, 19)) * r.choice((1, 1, 1, -1))
        return r.choice(self.go_ints)

    def mut_str(self, s):
        r = self.r
        p = r.random()
        digits = list(re.finditer(r"\d+", s))
        if digits and p < 0.35:
            m = r.choice(digits)
            new = str(abs(self.mut_int(int(m.group()))))
            return s[: m.start()] + new + s[m.end():]
        if p < 0.50:
            return r.choice(self.go_strs)
        if p < 0.60:
            return ""
        if p < 0.70:
            return str(r.choice(self.limits))
        if p < 0.80:
            return s.swapcase() if s else "X"
        if p < 0.90:
            return s[: r.randrange(len(s) + 1)] if s else " "
        return s + r.choice((" ", "0", " (0 0 0)", "h+00m", "é", "x" * 64))

    def mut_value(self, v, aid=None):
        r = self.r
        if isinstance(v, bool):
            return (not v) if r.random() < 0.9 else None
        if isinstance(v, int):
            return self.mut_int(v, aid) if r.random() < 0.97 else r.choice((None, str(v), v + 0.5))
        if isinstance(v, float):
            return r.choice((int(v), v * 2, -v, 0.0, 1e300))
        if isinstance(v, str):
            return self.mut_str(v) if r.random() < 0.97 else r.choice((None, 0, True))
        if v is None:
            return r.choice((0, 1, "", True, -1))
        return v

    # one mutation as an op ----------------------------------------------
    def one(self, doc, donors):
        r = self.r
        leaves, conts = [], []
        walk(doc, (), leaves, conts)
        p = r.random()
        if p < 0.70 and leaves:                      # change a scalar anywhere
            path, v = r.choice(leaves)
            return ["set", list(path), self.mut_value(v, attr_id_of(doc, path))]
        lists = [(pth, c) for pth, c in conts if isinstance(c, list)]
        dicts = [(pth, c) for pth, c in conts if isinstance(c, dict)]
        if p < 0.78 and lists:                       # list surgery
            path, lst = r.choice(lists)
            if lst and r.random() < 0.5:
                i = r.randrange(len(lst))
                if r.random() < 0.5:
                    return ["del", list(path) + [i]]
                return ["ins", list(path) + [r.randrange(len(lst) + 1)], lst[i]]
            if len(lst) > 1:
                i, j = r.randrange(len(lst)), r.randrange(len(lst))
                return ["set", list(path), [lst[j] if k == i else lst[i] if k == j else x for k, x in enumerate(lst)]]
        if p < 0.86 and dicts:                       # delete a key
            path, d = r.choice(dicts)
            if d:
                return ["del", list(path) + [r.choice(list(d))]]
        if donors:                                   # transplant / graft from a donor
            donor = r.choice(donors)
            dl, dc = [], []
            walk(donor, (), dl, dc)
            dd = [(pth, c) for pth, c in dc if isinstance(c, dict) and c]
            if dd and dicts:
                src_path, src = r.choice(dd)
                key = r.choice(list(src))
                # same place if it exists in this document, else anywhere
                target = tuple(src_path) if is_dict_at(doc, src_path) else r.choice(dicts)[0]
                return ["set", list(target) + [key], src[key]]
        if leaves:
            path, v = r.choice(leaves)
            return ["set", list(path), self.mut_value(v, attr_id_of(doc, path))]
        return None


def walk(node, path, leaves, conts):
    if isinstance(node, dict):
        conts.append((path, node))
        for k, v in node.items():
            walk(v, path + (k,), leaves, conts)
    elif isinstance(node, list):
        conts.append((path, node))
        for i, v in enumerate(node):
            walk(v, path + (i,), leaves, conts)
    elif path:
        leaves.append((path, node))


def is_dict_at(doc, path):
    try:
        return isinstance(get(doc, path), dict)
    except (KeyError, IndexError, TypeError):
        return False


def attr_id_of(doc, path):
    """ATA attribute id when `path` points inside ata_smart_attributes.table[i]."""
    if len(path) >= 3 and path[0] == "ata_smart_attributes" and path[1] == "table":
        try:
            entry = doc["ata_smart_attributes"]["table"][path[2]]
            return entry.get("id") if isinstance(entry, dict) else None
        except (KeyError, IndexError, TypeError):
            return None
    return None


# --------------------------------------------------------------------------- bases

def drive_type(doc):
    dev = doc.get("device") if isinstance(doc.get("device"), dict) else {}
    proto = dev.get("protocol")
    if proto == "NVMe" or "nvme_smart_health_information_log" in doc and proto is None:
        return "nvme"
    if proto == "SCSI":
        return "scsi"
    if proto == "ATA" or "ata_smart_attributes" in doc:
        return "sata-hdd" if (doc.get("rotation_rate") or 0) > 0 else "sata-ssd"
    return "scsi" if "scsi_error_counter_log" in doc else "sata-hdd"


# ATA device statistics (page, offset) and FARM fields the fork evaluates.
DEVSTAT_IDS = [(1, o) for o in (8, 16, 24, 32, 40, 48)] + [(2, 16)] + \
    [(3, o) for o in (8, 16, 24, 32, 40, 48, 56, 64)] + [(4, o) for o in (8, 16, 24)] + \
    [(5, o) for o in range(8, 112, 8)] + [(6, o) for o in (8, 16, 24)] + [(7, 8)] + \
    [(255, o) for o in (8, 16, 24)]
FARM_FIELDS = {
    "page_1_drive_information": ["poh", "spoh", "head_flight_hours", "head_load_events", "power_cycle_count"],
    "page_2_workload_statistics": ["total_read_commands", "total_write_commands",
                                   "logical_sectors_written", "logical_sectors_read"],
    "page_3_error_statistics": ["number_of_unrecoverable_read_errors", "number_of_unrecoverable_write_errors",
                                "number_of_reallocated_sectors", "number_of_reallocated_candidate_sectors",
                                "total_crc_errors", "command_time_out_count_total"],
    "page_4_environment_statistics": ["curent_temp", "highest_temp", "lowest_temp"],
}
# Around the fork's devstat/FARM decision points: > 0, >= 100 (devstat_7_8), > 1,000,000.
LAYER_VALUES = (0, 0, 0, 1, 2, 99, 100, 101, 999999, 1000000, 1000001, 2**31, 2**63 - 1)


def layer_value(r):
    return r.choice(LAYER_VALUES) if r.random() < 0.7 else int(10 ** r.uniform(0, 8))


def synth_devstat(r):
    pages = {}
    for page, offset in r.sample(DEVSTAT_IDS, r.randint(1, 12)):
        flags = {"value": 192, "string": "V--- ", "valid": r.random() < 0.9,
                 "normalized": False, "supports_dsn": False, "monitored_condition_met": r.random() < 0.1}
        pages.setdefault(page, []).append({"offset": offset, "name": f"Stat {page}/{offset}", "size": 4,
                                           "value": layer_value(r), "flags": flags})
    return {"pages": [{"number": p, "name": f"Page {p}", "revision": 1, "table": t} for p, t in pages.items()]}


def synth_farm(r):
    farm = {"supported": r.random() < 0.9,
            "page_0_log_header": {"farm_log_version": [4, 17], "pages_supported": 6}}
    for page, fields in FARM_FIELDS.items():
        if r.random() < 0.9:
            farm[page] = {f: layer_value(r) for f in fields if r.random() < 0.85}
    return farm


def build_bases(gen, n_synth):
    bases = {t: [] for t in WEIGHTS}
    for name, d in fuzz.load_json_dir(fuzz.FIXTURES) + fuzz.load_json_dir(fuzz.SEEDS):
        bases[drive_type(d)].append(d)
    for _ in range(n_synth):
        for make in (gen.synth_ata, gen.synth_ata, gen.synth_nvme, gen.synth_scsi):
            d = make()
            if d.get("device", {}).get("protocol") == "ATA":
                # make both SATA kinds plentiful
                if gen.r.random() < 0.5:
                    d["rotation_rate"] = 0
                else:
                    d["rotation_rate"] = gen.r.choice((5400, 7200))
                # devstat on about 40% of SATA drives, FARM on about 30% of SATA HDDs
                if gen.r.random() < 0.4:
                    d["ata_device_statistics"] = synth_devstat(gen.r)
                if d["rotation_rate"] and gen.r.random() < 0.3:
                    d["seagate_farm_log"] = synth_farm(gen.r)
            bases[drive_type(d)].append(d)
    return bases


# --------------------------------------------------------------------------- signature

def signature(g):
    if g.get("error"):
        return ("error",)
    bits = tuple(sorted((k, v["status"]) for k, v in g["attributes"].items() if v["status"]))
    mags = tuple(sorted((k, len(str(abs(v["transformed"])))) for k, v in g["attributes"].items()
                        if v["status"] or v["transformed"] in (0,)))
    # zlib.crc32, not hash(): Python randomizes str hashing per process, which would make
    # the feedback (and so the whole run) irreproducible for a given --seed.
    return (g.get("protocol"), g["device_status"], bits, zlib.crc32(repr(mags).encode()) % 997)


def ints_in_range(node):
    if isinstance(node, bool) or node is None or isinstance(node, str):
        return True
    if isinstance(node, int):
        return I64_MIN <= node <= U64_MAX
    if isinstance(node, float):
        return abs(node) < 1e15 and node == node
    if isinstance(node, dict):
        return all(ints_in_range(v) for v in node.values())
    if isinstance(node, list):
        return all(ints_in_range(v) for v in node)
    return True


# --------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--oracle", required=True)
    ap.add_argument("--rust", required=True)
    ap.add_argument("--go-root", required=True, help="checkout of the fork (oracle/build.sh WORKDIR/scrutiny-src)")
    ap.add_argument("--cases", type=int, default=200000)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--chunk", type=int, default=2000)
    ap.add_argument("--synth-bases", type=int, default=60, help="synthetic bases per drive kind round")
    ap.add_argument("--max-ops", type=int, default=8)
    ap.add_argument("--pool", type=int, default=400, help="max evolved mutants kept per drive type")
    ap.add_argument("--corpus", type=int, default=0, help="write N agreeing cases as regression corpus")
    ap.add_argument("--max-minimize", type=int, default=30)
    ap.add_argument("--no-save", action="store_true")
    ap.add_argument("--only", choices=list(WEIGHTS), help="restrict to one drive type (targeted hunting)")
    args = ap.parse_args()
    if args.only:
        for t in WEIGHTS:
            WEIGHTS[t] = 1.0 if t == args.only else 0.0

    rng = random.Random(args.seed)
    go_src = os.path.join(args.go_root, "webapp", "backend", "pkg", "thresholds", "ata_attribute_metadata.go")
    meta = fuzz.load_ata_metadata(go_src)
    go_ints, go_strs = harvest_go_literals(args.go_root)
    edges = {aid: m["edges"] for aid, m in meta.items() if m["edges"]}
    all_edges = sorted({e for m in meta.values() for e in m["edges"]})
    limits = limit_values(all_edges + go_ints)
    seeds = fuzz.load_json_dir(fuzz.FIXTURES) + fuzz.load_json_dir(fuzz.SEEDS)
    gen = fuzz.Gen(random.Random(args.seed + 1), meta, seeds)
    bases = build_bases(gen, args.synth_bases)
    base_list, base_index = [], {}
    for t, docs in bases.items():
        for d in docs:
            base_index[id(d)] = len(base_list)
            base_list.append(d)
    mut = Mutator(rng, limits, go_ints, go_strs, edges)
    # pool entries: (drive type, base idx, ops)
    pool = {t: [(t, base_index[id(d)], []) for d in docs] for t, docs in bases.items()}
    evolved = {t: [] for t in WEIGHTS}
    types, weights = zip(*WEIGHTS.items())

    go = fuzz.Streamer([args.oracle, "-batch"])
    rs = fuzz.Streamer([args.rust, "--batch"])
    seen = set()
    per_type, mis_type, kinds, layers = Counter(), Counter(), Counter(), Counter()
    examples = {}
    corpus_novel, corpus_rest = [], []
    t0, done = time.time(), 0
    print(f"bases: {', '.join(f'{t} {len(v)}' for t, v in bases.items())}; "
          f"dictionary: {len(limits)} integers, {len(go_strs)} strings")
    while done < args.cases:
        n = min(args.chunk, args.cases - done)
        batch = []
        for _ in range(n):
            t = rng.choices(types, weights)[0]
            src = evolved[t] if evolved[t] and rng.random() < 0.5 else pool[t]
            _, bidx, ops = rng.choice(src)
            doc = apply_ops(base_list[bidx], ops)
            new_ops = list(ops)
            donors = pool[t] and [base_list[rng.choice(pool[t])[1]] for _ in range(2)]
            for _ in range(rng.randint(1, args.max_ops)):
                op = mut.one(doc, donors)
                if op is None:
                    continue
                try:
                    doc = apply_ops(doc, [op])
                except (KeyError, IndexError, TypeError):
                    continue
                new_ops.append(op)
            if len(new_ops) > 40:          # keep replay cheap
                new_ops = new_ops[-40:]
                try:
                    doc = apply_ops(base_list[bidx], new_ops)
                except (KeyError, IndexError, TypeError):
                    continue
            batch.append((t, bidx, new_ops, doc))
        lines = [fuzz.encode(d) for *_, d in batch]
        gres, rres = go.run(lines), rs.run(lines)
        for (t, bidx, ops, doc), g, r in zip(batch, gres, rres):
            per_type[t] += 1
            layer_hits = {k.split("_")[0] for k, v in g.get("attributes", {}).items()
                          if v["status"] and k.startswith(("devstat_", "farm_"))}
            for lh in layer_hits:
                layers[lh] += 1
            mis = fuzz.compare(g, r)
            sig = signature(g)
            novel = sig not in seen
            if novel:
                seen.add(sig)
                evolved[t].append((t, bidx, ops))
                if len(evolved[t]) > args.pool:
                    evolved[t].pop(rng.randrange(len(evolved[t])))
            if mis:
                mis_type[t] += 1
                for kind, _ in mis:
                    kinds[kind] += 1
                    examples.setdefault(kind, (t, doc))
            elif args.corpus and ints_in_range(ops):
                exp = {"e": 1} if g.get("error") else {
                    "d": g["device_status"],
                    "x": {k: v["status"] for k, v in g["attributes"].items() if v["status"]}}
                entry = (t, bidx, ops, exp)
                (corpus_novel if novel else corpus_rest).append(entry)
                if len(corpus_rest) > 4 * args.corpus:
                    corpus_rest.pop(rng.randrange(len(corpus_rest)))
        done += n
        rate = done / (time.time() - t0)
        print(f"\r{done}/{args.cases} cases, {sum(mis_type.values())} mismatching, "
              f"{len(seen)} distinct Scrutiny results, {rate:.0f} cases/s", end="", flush=True)
    print()

    print("\nper drive type (cases / mismatching):")
    total = sum(per_type.values())
    for t in WEIGHTS:
        print(f"  {t:9s} {per_type[t]:9d} ({100 * per_type[t] / max(total, 1):4.1f}%) {mis_type[t]:8d}")
    focus = sum(per_type[t] for t in ("sata-hdd", "sata-ssd", "nvme")) / max(total, 1)
    print(f"  SATA HDD + SATA SSD + NVMe: {100 * focus:.1f}% of cases")
    print(f"  cases with a devstat alert in Scrutiny: {layers['devstat']}, with a FARM alert: {layers['farm']}")
    if kinds:
        print("\nmismatch kinds (* = known, accepted gap):")
        for k, c in kinds.most_common(40):
            print(f"  {'*' if fuzz.is_known(k) else ' '} {k:40s} {c}")

    if not args.no_save:
        todo = [(k, v) for k, v in examples.items() if not fuzz.is_known(k)][: args.max_minimize]
        if todo:
            os.makedirs(fuzz.OUT_DIR, exist_ok=True)
            print("\nminimized mismatches saved:")
            for kind, (t, doc) in todo:
                small = fuzz.minimize(doc, kind, go, rs)
                gm, rm = go.run([fuzz.encode(small)])[0], rs.run([fuzz.encode(small)])[0]
                h = hashlib.sha1(fuzz.encode(small)).hexdigest()[:10]
                base = os.path.join(fuzz.OUT_DIR, f"mut-{re.sub(r'[^a-z0-9]+', '-', kind.lower())}-{h}")
                with open(base + ".json", "w", encoding="utf-8", newline="\n") as f:
                    json.dump(small, f, indent=1)
                with open(base + ".expected.json", "w", encoding="utf-8", newline="\n") as f:
                    json.dump({"what": f"{kind} found by mutfuzz on {t}", "error": bool(gm.get("error")),
                               "device_status": gm["device_status"],
                               "bits": {k: v["status"] for k, v in gm["attributes"].items() if v["status"]},
                               "rust_at_discovery": rm}, f, indent=1)
                print(f"  {kind:40s} {os.path.relpath(base + '.json', ROOT)}  ({len(fuzz.encode(doc))} -> {len(fuzz.encode(small))} bytes)")

    if args.corpus and not args.no_save:
        # Per drive type quota (same weights as the campaign, so >= 80% SATA/NVMe), filled
        # with cases whose Scrutiny result was novel first, then others; within each group
        # the shortest edit lists first, which keeps the corpus small.
        novel_set = {id(e) for e in corpus_novel}
        rng.shuffle(corpus_novel)
        rng.shuffle(corpus_rest)
        quota = {t: round(args.corpus * w) for t, w in WEIGHTS.items()}
        chosen = []
        for t in WEIGHTS:
            pick = sorted((e for e in corpus_novel if e[0] == t), key=lambda e: len(json.dumps(e[2])))[: quota[t]]
            if len(pick) < quota[t]:
                rest = sorted((e for e in corpus_rest if e[0] == t), key=lambda e: len(json.dumps(e[2])))
                pick += rest[: quota[t] - len(pick)]
            chosen += pick
        rng.shuffle(chosen)
        used = sorted({e[1] for e in chosen})
        remap = {b: i for i, b in enumerate(used)}
        os.makedirs(CORPUS_DIR, exist_ok=True)
        with gzip.open(os.path.join(CORPUS_DIR, "bases.json.gz"), "wt", encoding="utf-8", newline="\n") as f:
            json.dump([base_list[b] for b in used], f, separators=(",", ":"))
        with gzip.open(os.path.join(CORPUS_DIR, "cases.jsonl.gz"), "wt", encoding="utf-8", newline="\n") as f:
            for t, bidx, ops, exp in chosen:
                f.write(json.dumps({"t": t, "b": remap[bidx], "ops": ops, **exp}, separators=(",", ":")) + "\n")
        mix = Counter(e[0] for e in chosen)
        sizes = sum(os.path.getsize(os.path.join(CORPUS_DIR, n)) for n in ("bases.json.gz", "cases.jsonl.gz"))
        n_novel = sum(1 for e in chosen if id(e) in novel_set)
        print(f"\ncorpus: {len(chosen)} cases ({n_novel} with a novel Scrutiny result), "
              f"{len(used)} bases, {sizes / 1e6:.1f} MB compressed; mix: "
              + ", ".join(f"{t} {100 * mix[t] / max(len(chosen), 1):.0f}%" for t in WEIGHTS))

    go.close()
    rs.close()
    unknown = sum(c for k, c in kinds.items() if not fuzz.is_known(k))
    print(f"\nunexplained mismatches: {unknown}")
    sys.exit(1 if unknown else 0)


if __name__ == "__main__":
    main()
