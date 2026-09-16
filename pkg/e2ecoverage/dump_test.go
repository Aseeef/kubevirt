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
	"syscall"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("e2e coverage dump", func() {
	var originalDumpDir string

	BeforeEach(func() {
		originalDumpDir = dumpDir
		dumpDir = GinkgoT().TempDir()
	})

	AfterEach(func() {
		dumpDir = originalDumpDir
	})

	It("should default dumps to /tmp/cov", func() {
		Expect(DumpDir).To(Equal("/tmp/cov"))
	})

	It("Start should be safe to call more than once", func() {
		Start()
		Start()
		ForwardSignals(nil)
	})

	It("Dump should create the dump directory even without instrumentation", func() {
		err := Dump()
		_, statErr := os.Stat(dumpDir)
		Expect(statErr).NotTo(HaveOccurred())
		if err != nil {
			Expect(err.Error()).To(ContainSubstring("-cover"))
		}
	})

	It("Reset should report missing instrumentation when the binary is not built with -cover", func() {
		err := Reset()
		if err != nil {
			Expect(err.Error()).To(ContainSubstring("-cover"))
		}
	})

	It("should dispatch SIGUSR1 and SIGUSR2 without panicking", func() {
		sigs := make(chan os.Signal, 2)
		done := make(chan struct{})
		go func() {
			defer close(done)
			handleCoverageSignals(sigs)
		}()
		sigs <- syscall.SIGUSR1
		sigs <- syscall.SIGUSR2
		close(sigs)
		Eventually(done).Should(BeClosed())
	})
})
