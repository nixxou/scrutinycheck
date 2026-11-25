# scrutinycheck

A command-line tool that rates disk health from `smartctl --json` output, using
the rules of [Scrutiny](https://github.com/AnalogJ/scrutiny) (as maintained in
the [Starosdev/scrutiny](https://github.com/Starosdev/scrutiny) fork). It needs
no server, database or Docker.

This is an independent project and is not affiliated with Scrutiny. The
thresholds and rules ported from Scrutiny are MIT licensed; see
`THIRD_PARTY_NOTICES.md`.

## Requirements

- [smartmontools](https://www.smartmontools.org/) 7.0 or later (`smartctl` on
  the PATH, or `--smartctl PATH`).
- Administrator rights (Windows) or root (Linux/macOS) to read the disks.

## Usage

```
scrutinycheck                 # every disk listed by smartctl --scan
scrutinycheck /dev/sda        # one disk
scrutinycheck -d sat /dev/sdb # force the smartctl device type (USB enclosures, ...)
scrutinycheck -v              # details: serial, power-on hours, temperature
scrutinycheck --strict        # verdict = worst alert (see "Verdict")
scrutinycheck --wake          # also read disks in standby (wakes them up)
scrutinycheck --json          # machine-readable output
scrutinycheck -f saved.json   # evaluate a saved `smartctl -x --json` output
```

To check a disk from another machine:

```
smartctl -x --json /dev/sda > sda.json
scrutinycheck -f sda.json
```

## Sleeping disks are never woken up by default

Waking a hard drive from standby spins it up again: noise, power draw, wear
(start/stop cycles), and on a NAS, disks that never get to sleep if the check is
scheduled. So by default `scrutinycheck` wakes up **no** disk:

- **discovery** uses `smartctl --scan`, which lists disks without opening them
  (`--scan-open`, which opens them, is not used);
- **reading** uses `smartctl -n standby`: smartctl first asks for the power mode
  (the CHECK POWER MODE command, which does not spin the disk up) and reads
  nothing if the disk is in STANDBY or SLEEP.

A skipped disk is shown like this. It is not an error and does not change the
exit code:

```
/dev/sda       ASLEEP           drive in STANDBY: not read so it is not woken up (--wake to force)
```

In JSON: `{"device": "/dev/sda", "skipped": "asleep", "power_mode": "STANDBY"}`.

`--wake` reads these disks anyway. Like the Scrutiny collector, the tool detects
the skip from smartctl's message (`Device is in STANDBY mode`), not from the
exit code, which can be mistaken for a failure to open the device.

Limits: SSDs and NVMe drives have no spin-down standby and are always read.
Some USB enclosures do not pass the power mode through, and their bridge can
wake the disk up by itself when the device is opened.

## Self-tests

`scrutinycheck` does not start S.M.A.R.T. self-tests. Neither does Scrutiny: it
only displays the self-test history already present in the data. To schedule
them, use `smartd` or a scheduled task that runs `smartctl -t short` (weekly)
and `smartctl -t long` (monthly).

## Exit codes

| Code | Meaning |
| ---- | ------- |
| 0 | every disk that was read is OK (disks in standby do not count) |
| 1 | usage or runtime error |
| 2 | a disk could not be read, or its state is unknown (`--strict`) |
| 3 | at least one disk is WARNING (only with `--strict`) |
| 4 | at least one disk is FAILED |

## Verdict: Scrutiny mode (default) and `--strict` mode

The tool always finds the **same alerts** for each attribute. Only the way they
are summed up into one verdict per disk changes.

**By default, the verdict is exactly Scrutiny's** (checked against its Go code,
see "Differential test"). A disk is `FAILED` if and only if:

- its overall SMART health is not "passed" (a **missing** health status counts
  as a failure, because a missing field decodes to `false` in Go), or
- an attribute crosses one of Scrutiny's own thresholds (Backblaze failure
  rates, NVMe/SCSI thresholds, ATA device statistics threshold).

Otherwise it is `OK`, even when it carries alerts: the line then reads
`OK (n alert(s))` and the alerts are listed below it.

Scrutiny mode also reproduces how Scrutiny reads its input, quirks included
(all found by the differential fuzzer, see "Development"):

- without `device.protocol` (exactly `ATA`, `NVMe` or `SCSI`), no attribute is
  evaluated;
- an absent NVMe health field counts as 0 (so a missing `available_spare` fails
  when the drive's spare threshold is above 0);
- when an ATA attribute id (or a device statistic) appears twice, the last
  occurrence is the one reported, but a failure of an earlier occurrence still
  fails the disk;
- a SAS PHY with a wrongly typed field is ignored.

**With `--strict`, the verdict is the worst alert.** This changes three cases
(examples below). Strict mode also reads input more sensibly: it infers the
protocol from the sections present, skips absent NVMe fields and reports every
occurrence of a duplicated attribute.

### Why an option

Scrutiny mode is the reference: it is the logic thousands of users run, and its
choices are sound. A dashboard that watches disks all the time has to avoid
false alarms, or people end up ignoring them.

But `scrutinycheck` is often run **just once**, to decide whether to keep a
disk: a second-hand purchase, a salvaged disk, before putting important data on
it. In that case you would rather hear about everything and check for yourself.
Hence strict mode, as an option.

### Example 1: manufacturer threshold failed in the past only

`tests/virtual/ata-warning-only.json`: attribute 1 (Read Error Rate) once
dropped to 40, below its threshold of 44, then went back to 100.

```
$ scrutinycheck -f ata-warning-only.json
ata-warning-only.json OK (1 alert)     WDC WD140EDFZ-11A0VA0   14.0 TB  HDD
   └ [WARNING]    1 Read Error Rate raw=0: manufacturer threshold failed in the past (worst value 40, threshold 44)

$ scrutinycheck --strict -f ata-warning-only.json
ata-warning-only.json WARNING          WDC WD140EDFZ-11A0VA0   14.0 TB  HDD     (exit code 3)
```

- Scrutiny: it is past history, the disk is fine today.
- Strict: a past episode is a reason to keep an eye on the disk.

### Example 2: manufacturer threshold failing now

`tests/virtual/ata-manufacturer-now.json`: same disk, but attribute 1 is
**currently** at 40 for a threshold of 44, while the disk still reports itself
as "passed" overall.

```
$ scrutinycheck -f ata-manufacturer-now.json
ata-manufacturer-now.json OK (1 alert)     WDC WD140EDFZ-11A0VA0   14.0 TB  HDD
   └ [FAILED]    1 Read Error Rate raw=0: manufacturer threshold failing (value 40, threshold 44)

$ scrutinycheck --strict -f ata-manufacturer-now.json
ata-manufacturer-now.json FAILED           WDC WD140EDFZ-11A0VA0   14.0 TB  HDD     (exit code 4)
```

- Scrutiny: for this criterion, only the disk's overall verdict counts. If it
  says "passed", the disk stays OK.
- Strict: the manufacturer itself considers this attribute failed, so it is a
  failure.

### Example 3: overall SMART health missing

`tests/fixtures/smart-sat.json`: output of `smartctl -A`, which has the
attributes but not the disk's overall verdict.

```
$ scrutinycheck -f smart-sat.json
smart-sat.json FAILED           ?    ?
   └ [FAILED] smart_status SMART overall health: SMART overall health missing: counted as a failure (Scrutiny logic)

$ scrutinycheck --strict -f smart-sat.json
smart-sat.json OK               ?    ?
```

- Scrutiny: no answer means failure (out of caution, and it is also what Go's
  decoding produces).
- Strict: a missing answer is not a failure. The available attributes are
  judged, and the disk is `UNKNOWN` if there are none.

### What does not change

A Scrutiny failure is a failure in both modes. A real example,
`tests/fixtures/smart-ata-failed-scrutiny.json`:

```
smart-ata-failed-scrutiny.json FAILED   Samsung SSD 840 Series   500 GB  SSD
   └ [FAILED]  199 UltraDMA CRC Error Count raw=108: high failure risk (threshold 20%); cumulative counter, may date from an old incident (observed annual failure rate ≈ 22.3%)
```

These 108 CRC errors often come from a faulty SATA cable. In a Scrutiny instance
that runs continuously, the alert clears once the counter stops growing. A
single run cannot know that, hence the "cumulative counter" note.

## Evaluation layers (minimal version)

1. The disk's overall S.M.A.R.T. verdict.
2. ATA: manufacturer thresholds, then observed failure rates (buckets derived
   from Backblaze data, taken as-is from Scrutiny; their source period is not
   documented).
3. ATA device statistics (`ata_device_statistics`, GP log 0x04, part of
   `smartctl -x`). Each valid statistic is the attribute
   `devstat_<page>_<offset>`:
   - `devstat_7_8` (percentage used endurance indicator) at 100 or more is a
     failure, and fails the disk;
   - a non-zero critical error count (reported uncorrectable errors,
     unrecoverable read errors, reallocated sectors, reallocation candidates,
     mechanical start failures) is a warning;
   - a "lower is better" statistic above 1,000,000 is taken for corrupted data:
     it is listed as `UNKNOWN`, not judged, and never changes the verdict, in
     either mode;
   - the other statistics are recorded only.
4. Seagate FARM log (`seagate_farm_log`, from `smartctl -l farm`), on ATA disks
   when the log says `supported`: attributes `farm_*`, judged with the same
   rules as device statistics. None has a failure threshold in Scrutiny, so the
   log can only warn (unrecoverable read/write errors, reallocated sectors,
   reallocation candidates, CRC errors) or flag an implausible value.
   Live collection runs `smartctl -x` only, which does not include the FARM
   log; to have it evaluated, save `smartctl -x -l farm --json` and use `-f`.
5. NVMe and SCSI: Scrutiny's rules.

In strict mode these two layers behave the same; as everywhere, a warning then
makes the disk `WARNING`.

Not implemented yet: consumer drive profiles, risk score, history and trends
(including Scrutiny's power-on-hours rollover check, which uses the FARM hour
counters), user overrides and ignore lists (`failures.ignored.devstat` is
empty by default in Scrutiny, and here), reproducible recomputation of the
Backblaze tables.

## Development

```
cargo test
```

No physical disk and no Go toolchain is needed. The tests use:

- real smartctl outputs (`tests/fixtures/`, taken from Scrutiny's test data);
- a fake `smartctl` script for the collection path (standby, `--wake`, scan);
- **Scrutiny parity cases** (`tests/scrutiny_parity.rs`), each with the verdict
  recorded from Scrutiny's own code:
  - **50,000 mutated drives** (`tests/virtual/corpus/`, 4 MB compressed):
    30% SATA HDD, 30% SATA SSD, 25% NVMe, 15% SCSI/SAS; about 41,000 of them
    each produced a Scrutiny result no other case had produced. They exercise
    all four status bits and every layer (ATA attributes, device statistics,
    FARM, NVMe, SCSI counters, SAS PHYs), healthy drives included;
  - one minimized case per mismatch class the fuzzers ever found and that was
    fixed (`tests/virtual/fuzz/`);
  - 500 drives from the generator fuzzer (`tests/virtual/corpus.jsonl`).

### Differential testing against Scrutiny

`oracle/` builds the **unmodified** Go code of the Scrutiny fork (commit pinned
in `oracle/build.sh`) with a small entry point (`oracle/main.go`). Both tools
have a streaming batch mode (one smartctl document per line). Every comparison
covers the attribute status bits (all four: failed SMART, warning, failed
Scrutiny, invalid value), the SMART-failed bit and each disk's verdict.

```
oracle/build.sh WORKDIR                       # requires Go and git
cargo build --release
python oracle/mutfuzz.py --oracle WORKDIR/scrutiny-oracle.exe \
  --rust target/release/scrutinycheck.exe --go-root WORKDIR/scrutiny-src \
  --cases 1000000 --seed 1 [--corpus 50000] [--only nvme]
```

**`oracle/mutfuzz.py`, feedback-driven mutation fuzzing (main tool).** It
mutates *any* value at *any* path of a document, by type, so fields nobody
anticipated are exercised too:

- integers: a dictionary of limits (0, ±1, 8- to 64-bit signed and unsigned
  bounds ±1, powers of two ±1, Backblaze bucket bounds ±1 of the attribute
  being mutated, and every integer literal found in the fork's Go code),
  arithmetic, bit flips, random magnitudes;
- strings: empty, numeric, digits changed in place (`0 0 5` → `0 0 6`,
  `123h+07m`), short string literals of the fork's Go code, case swaps,
  truncation;
- booleans flipped, `null`, occasional type changes;
- structure: list elements deleted, duplicated or swapped, keys deleted, keys
  transplanted with their value from another drive of the same type.

Starting drives are the real outputs plus synthetic ones (ATA attributes,
device statistics, FARM log, NVMe, SCSI/SAS). A mutant whose Scrutiny result
was never seen before joins the pool the next mutants are drawn from, so the
search follows behaviours, not just values. At least 80% of the cases are SATA
HDD, SATA SSD or NVMe. Runs are reproducible for a given `--seed`, about 1,000
cases per second.

**`oracle/fuzz.py`, generator fuzzing**, about 2,700 cases per second: synthetic
drives built from Scrutiny's metadata, multi-field mutations of real outputs,
and malformed input (missing keys, `null`, wrong types, out-of-range numbers,
duplicates, damaged protocol).

Both fuzzers **minimize** every new kind of mismatch automatically (a 15 KB
document typically shrinks to under 100 bytes) and save it under
`tests/virtual/fuzz/` with both results. `oracle/regressions.py` regenerates
the expected results of those regression cases.

Mismatches found and fixed this way include: a missing `device.protocol`,
absent NVMe fields read as 0, duplicated ATA attribute ids and device
statistics, wrongly typed SAS PHYs, attributes without an id, and an NVMe
spare threshold of `-1` (Scrutiny's "no threshold" sentinel, a rare case: a
handful of hits in over a million mutated cases).

Latest runs: more than 3 million cases across both fuzzers, **0 unexplained
mismatches**. One known gap is reported apart and does not fail a run:
documents Go rejects as a whole because of a type error in any field, even one
unused for the evaluation (Scrutiny's API would refuse the upload);
scrutinycheck evaluates what it can. Real smartctl output is well-typed.

`oracle/differential.py` is the first, single-field sweep over the fixtures.

## License

MIT, see `LICENSE`. The parts taken from Scrutiny remain under their original
MIT license, see `THIRD_PARTY_NOTICES.md`.
