/*
 * This file is part of the KubeVirt project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright The KubeVirt Authors.
 *
 */

package e2ecoverage

import (
	"errors"
	"fmt"
	"os"
	"runtime/coverage"
	"sync"
	"syscall"

	"kubevirt.io/client-go/log"
)

// DumpDir is the directory instrumented binaries write covmeta/covcounters
// into when SIGUSR2 is received.
const DumpDir = "/tmp/cov"

var (
	dumpDir = DumpDir
	dumpMu  sync.Mutex
)

// Reset clears in-process coverage counters. The binary must be built with
// -cover and atomic covermode (rules_go does this when collecting coverage).
func Reset() error {
	dumpMu.Lock()
	defer dumpMu.Unlock()
	return coverage.ClearCounters()
}

// Dump writes coverage meta and the current counter snapshot into DumpDir.
func Dump() error {
	dumpMu.Lock()
	defer dumpMu.Unlock()

	if err := os.MkdirAll(dumpDir, 0755); err != nil {
		return fmt.Errorf("create coverage dump dir %q: %w", dumpDir, err)
	}

	var errs []error
	if err := coverage.WriteMetaDir(dumpDir); err != nil {
		errs = append(errs, fmt.Errorf("write coverage meta: %w", err))
	}
	if err := coverage.WriteCountersDir(dumpDir); err != nil {
		errs = append(errs, fmt.Errorf("write coverage counters: %w", err))
	}
	return errors.Join(errs...)
}

func handleCoverageSignals(sigs <-chan os.Signal) {
	for sig := range sigs {
		switch sig {
		case syscall.SIGUSR1:
			log.Log.Info("received SIGUSR1, clearing coverage counters")
			if err := Reset(); err != nil {
				log.Log.Reason(err).Error("failed to clear coverage counters")
			}
		case syscall.SIGUSR2:
			log.Log.Infof("received SIGUSR2, dumping coverage counters to %s", dumpDir)
			if err := Dump(); err != nil {
				log.Log.Reason(err).Error("failed to dump coverage counters")
			}
		}
	}
}
