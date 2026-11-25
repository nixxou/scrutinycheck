// scrutiny-oracle: runs the UNMODIFIED Scrutiny (Starosdev fork) evaluation code on
// `smartctl -x --json` documents and prints the per-attribute status bits as JSON.
//
// This file is the only code we add; it must be copied into a checkout of the fork
// (see oracle/build.sh) because it imports the fork's packages. It calls the same
// entry point the web backend uses when a collector uploads SMART data:
// measurements.Smart.FromCollectorSmartInfo, with the fork's default configuration.
//
// Usage:
//
//	scrutiny-oracle [-profiles] FILE.json...   one JSON array with a result per file
//	scrutiny-oracle [-profiles] -batch         streaming: one smartctl document per
//	                                           stdin line, one result line per input
//	                                           line, flushed after each line
package main

import (
	"bufio"
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

type result struct {
	File         string             `json:"file,omitempty"`
	Error        string             `json:"error,omitempty"`
	Protocol     string             `json:"protocol,omitempty"`
	DeviceStatus uint8              `json:"device_status"`
	Attributes   map[string]attrOut `json:"attributes"`
	// Ids sorted, convenient for diffing.
	FailingIds []string `json:"failing_ids"`
}

// evaluate runs the fork's code on one document. A panic inside the fork is
// reported as an error result instead of killing the process: it is a finding.
func evaluate(cfg config.Interface, data []byte) (res result) {
	res = result{Attributes: map[string]attrOut{}, FailingIds: []string{}}
	defer func() {
		if r := recover(); r != nil {
			res = result{Error: fmt.Sprintf("panic: %v", r), Attributes: map[string]attrOut{}, FailingIds: []string{}}
		}
	}()
	var info collector.SmartInfo
	if err := json.Unmarshal(data, &info); err != nil {
		res.Error = "json: " + err.Error()
		return res
	}
	sm := measurements.Smart{}
	if err := sm.FromCollectorSmartInfo(cfg, "oracle", info); err != nil {
		res.Error = "eval: " + err.Error()
		return res
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
	return res
}

func main() {
	profiles := flag.Bool("profiles", false, "enable consumer drive profiles (fork default: on)")
	batch := flag.Bool("batch", false, "read one JSON document per stdin line, write one result per line")
	flag.Parse()

	cfg, err := config.Create()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}
	// scrutinycheck does not implement consumer drive profiles yet, so compare
	// against the generic rules unless asked otherwise.
	cfg.Set(config.DB_USER_SETTINGS_SUBKEY+".metrics.consumer_drive_profiles_enabled", *profiles)

	if *batch {
		in := bufio.NewReaderSize(os.Stdin, 1<<20)
		out := bufio.NewWriterSize(os.Stdout, 1<<16)
		enc := json.NewEncoder(out)
		for {
			line, err := in.ReadBytes('\n')
			if len(line) > 0 {
				if err := enc.Encode(evaluate(cfg, line)); err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
				out.Flush()
			}
			if err != nil {
				return
			}
		}
	}

	var results []result
	for _, path := range flag.Args() {
		data, err := os.ReadFile(path)
		var res result
		if err != nil {
			res = result{Error: err.Error(), Attributes: map[string]attrOut{}, FailingIds: []string{}}
		} else {
			res = evaluate(cfg, data)
		}
		res.File = path
		results = append(results, res)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(results); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
