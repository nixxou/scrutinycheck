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
  rates, NVMe/SCSI thresholds).

Otherwise it is `OK`, even when it carries alerts: the line then reads
`OK (n alert(s))` and the alerts are listed below it.

Scrutiny mode also reproduces how Scrutiny reads its input, quirks included
(all found by the differential fuzzer, see "Development"):

- without `device.protocol` (exactly `ATA`, `NVMe` or `SCSI`), no attribute is
  evaluated;
- an absent NVMe health field counts as 0 (so a missing `available_spare` fails
  when the drive's spare threshold is above 0);
- when an ATA attribute id appears twice, the last occurrence is the one
  reported, but a failure of an earlier occurrence still fails the disk;
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
3. NVMe and SCSI: Scrutiny's rules.

Not implemented yet: ATA device statistics (`ata_device_statistics`) and the
Seagate FARM log, which Scrutiny also evaluates; consumer drive profiles, risk
score, history and trends, reproducible recomputation of the Backblaze tables.

## Development

```
cargo test
```

No physical disk and no Go toolchain is needed. The tests use:

- real smartctl outputs (`tests/fixtures/`, taken from Scrutiny's test data);
- a fake `smartctl` script for the collection path (standby, `--wake`, scan);
- **Scrutiny parity cases** (`tests/scrutiny_parity.rs`): 500 diverse generated
  drives (`tests/virtual/corpus.jsonl`) and one minimized case per mismatch
  class the fuzzer ever found (`tests/virtual/fuzz/`), each with the verdict
  recorded from Scrutiny's own code.

### Differential testing against Scrutiny

`oracle/` builds the **unmodified** Go code of the Scrutiny fork (commit pinned
in `oracle/build.sh`) with a small entry point (`oracle/main.go`). Both tools
have a streaming batch mode (one smartctl document per line), so the
comparison runs at about 2,700 cases per second.

```
oracle/build.sh WORKDIR                       # requires Go and git
cargo build --release
python oracle/fuzz.py --oracle WORKDIR/scrutiny-oracle.exe \
  --rust target/release/scrutinycheck.exe --cases 300000 --seed 1 \
  --go-src WORKDIR/scrutiny-src/webapp/backend/pkg/thresholds/ata_attribute_metadata.go
```

`oracle/fuzz.py` generates reproducible cases (same `--seed`, same cases):

- **synthetic drives** (ATA, NVMe, SCSI/SAS) built from Scrutiny's attribute
  metadata: random attribute sets, smartctl-style or alternative attribute
  names, values biased towards bucket bounds ±1, `when_failed`, vendor raw
  strings (Seagate packed values, `12345h+07m`, temperature min/max);
- **mutated real outputs**: several fields changed at once;
- **malformed input**: missing keys, `null`, wrong types, fractional or
  out-of-range numbers, duplicated attributes, damaged protocol.

It compares attribute status bits, the SMART-failed bit and each disk's
verdict. Every new kind of mismatch is **automatically minimized** (a 15 KB
document typically shrinks to under 100 bytes) and saved under
`tests/virtual/fuzz/` with both results. `--corpus N` refreshes the parity
corpus. `oracle/regressions.py` regenerates the expected results of the
regression cases.

Latest run: 300,000 cases, **0 unexplained mismatches**. Two known gaps are
reported apart and do not fail the run:

- documents Go rejects as a whole because of a type error in any field, even
  one unused for the evaluation (Scrutiny's API would refuse the upload);
  scrutinycheck evaluates what it can. Real smartctl output is well-typed;
- the ATA device statistics and FARM layers, not ported yet.

`oracle/differential.py` is the earlier, single-field sweep over the fixtures.

## License

MIT, see `LICENSE`. The parts taken from Scrutiny remain under their original
MIT license, see `THIRD_PARTY_NOTICES.md`.
