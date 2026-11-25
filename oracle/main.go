// scrutiny-oracle: runs the UNMODIFIED Scrutiny (Starosdev fork) evaluation code on
// saved `smartctl -x --json` files and prints the per-attribute status bits as JSON.
//
// This file is the only code we add; it must be copied into a checkout of the fork
// (see oracle/build.sh) because it imports the fork's packages. It calls the same
// entry point the web backend uses when a collector uploads SMART data:
// measurements.Smart.FromCollectorSmartInfo, with the fork's default configuration.
//
// Usage: scrutiny-oracle [-profiles] FILE.json...
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/analogj/scrutiny/webapp/backend/pkg/config"
	"github.com/analogj/scrutiny/webapp/backend/pkg/models/collector"
	"github.com/analogj/scrutiny/webapp/backend/pkg/models/measurements"
)

type attrOut struct {
	Status      uint8 `json:"status"`
	Transformed int64 `json:"transformed"`
}

type fileOut struct {
	File         string             `json:"file"`
	Error        string             `json:"error,omitempty"`
	Protocol     string             `json:"protocol,omitempty"`
	DeviceStatus uint8              `json:"device_status"`
	Attributes   map[string]attrOut `json:"attributes"`
	// Ids sorted, convenient for diffing.
	FailingIds []string `json:"failing_ids"`
}

func main() {
	profiles := flag.Bool("profiles", false, "enable consumer drive profiles (fork default: on)")
	flag.Parse()

	cfg, err := config.Create()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}
	// scrutinycheck does not implement consumer drive profiles yet, so compare
	// against the generic rules unless asked otherwise.
	cfg.Set(config.DB_USER_SETTINGS_SUBKEY+".metrics.consumer_drive_profiles_enabled", *profiles)

	var out []fileOut
	for _, path := range flag.Args() {
		res := fileOut{File: path, Attributes: map[string]attrOut{}, FailingIds: []string{}}
		data, err := os.ReadFile(path)
		if err != nil {
			res.Error = err.Error()
			out = append(out, res)
			continue
		}
		var info collector.SmartInfo
		if err := json.Unmarshal(data, &info); err != nil {
			res.Error = "json: " + err.Error()
			out = append(out, res)
			continue
		}
		sm := measurements.Smart{}
		if err := sm.FromCollectorSmartInfo(cfg, "oracle", info); err != nil {
			res.Error = "eval: " + err.Error()
			out = append(out, res)
			continue
		}
		res.Protocol = sm.DeviceProtocol
		res.DeviceStatus = uint8(sm.Status)
		for id, a := range sm.Attributes {
			st := uint8(a.GetStatus())
			res.Attributes[id] = attrOut{Status: st, Transformed: a.GetTransformedValue()}
			if st != 0 {
				res.FailingIds = append(res.FailingIds, id)
			}
		}
		sort.Strings(res.FailingIds)
		out = append(out, res)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
