//go:build coverage_e2e

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
	"os"
	"os/signal"
	"sync"
	"syscall"

	"kubevirt.io/client-go/log"
)

var startOnce sync.Once

// Start registers SIGUSR1 (ClearCounters) and SIGUSR2 (dump to DumpDir).
// Compiled only into binaries built with the coverage_e2e tag.
func Start() {
	startOnce.Do(func() {
		sigs := make(chan os.Signal, 2)
		signal.Notify(sigs, syscall.SIGUSR1, syscall.SIGUSR2)
		go handleCoverageSignals(sigs)
		log.Log.Infof("e2e coverage handlers enabled (SIGUSR1=reset, SIGUSR2=dump to %s)", DumpDir)
	})
}

// ForwardSignals relays SIGUSR1/SIGUSR2 to proc so coverage dumps from
// virt-launcher-monitor (PID 1) also reach virt-launcher.
func ForwardSignals(proc *os.Process) {
	if proc == nil {
		return
	}
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
		for sig := range sigs {
			if err := proc.Signal(sig); err != nil {
				log.Log.Reason(err).Errorf("failed to forward %s to child process", sig.String())
			}
		}
	}()
}
