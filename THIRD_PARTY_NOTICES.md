# Third-party notices

## Scrutiny

The health rules of scrutinycheck are a port to Rust of parts of
[Scrutiny](https://github.com/AnalogJ/scrutiny), in the version maintained in the
[Starosdev/scrutiny](https://github.com/Starosdev/scrutiny) fork (`master` branch at commit
`de9f016f0987`, release 1.80.2).
scrutinycheck is an independent project and is not affiliated with Scrutiny.

Ported material, all under `webapp/backend/pkg/` in the fork:

| scrutinycheck                  | Scrutiny source                                                              |
| ------------------------------ | ---------------------------------------------------------------------------- |
| `src/rules/ata_thresholds.rs`  | `thresholds/ata_attribute_metadata.go` (attribute table, buckets, transforms) |
| `src/rules/ata.rs`             | `models/measurements/smart_ata_attribute.go`, `models/measurements/smart.go` |
| `src/rules/devstat_thresholds.rs` | `thresholds/ata_attribute_metadata.go` (`AtaDeviceStatsMetadata` table) |
| `src/rules/devstat.rs`         | `models/measurements/smart_ata_devstat_attribute.go`, `models/measurements/smart.go` |
| `src/rules/farm.rs`            | `thresholds/farm_attribute_metadata.go`, `models/measurements/smart_farm_attribute.go`, `models/measurements/smart.go`, `models/collector/farm.go` |
| `src/rules/nvme.rs`            | `thresholds/nvme_attribute_metadata.go`, `models/measurements/smart_nvme_attribute.go`, `models/measurements/smart.go` |
| `src/rules/scsi.rs`            | `thresholds/scsi_attribute_metadata.go`, `models/measurements/smart_scsci_attribute.go`, `models/measurements/smart.go`, `models/collector/smart.go` |
| `src/rules/mod.rs`             | `constants.go` (status bits), `models/measurements/smart.go` (dispatch)      |
| `tests/fixtures/*.json`        | `models/testdata/`, and `collector/pkg/detect/testdata/` at the repository root (smartctl outputs) |

The tests in `src/rules/` and `tests/rules_fixtures.rs` take their expected results from the
fork's own Go tests.

Scrutiny is distributed under the MIT License:

```
MIT License

Copyright (c) 2020 Jason Kulatunga

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
