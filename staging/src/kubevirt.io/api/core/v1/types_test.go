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

package v1_test

import (
	"reflect"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"kubevirt.io/api/apitesting/testutil"
	v1 "kubevirt.io/api/core/v1"
)

var _ = Describe("MigrationConfiguration", func() {
	Describe("AsVMIMConfigurationOptions", func() {
		// Guards against silently dropping cluster defaults due to a missing field
		// assignment in AsVMIMConfigurationOptions. Fields are discovered via
		// reflection so the test catches new fields automatically — no hardcoded list
		// to maintain. Assumes matching fields share the same JSON tag name; update
		// this test to explicitly acknowledge any intentional divergence.
		It("copies every MigrationConfiguration field that has a matching JSON tag in VMIMConfigurationOptions", func() {
			src := testutil.WithAllFieldsSet(reflect.TypeOf(v1.MigrationConfiguration{})).(*v1.MigrationConfiguration)
			oracle := testutil.CopyByJSONTag(src, reflect.TypeOf(v1.VMIMConfigurationOptions{})).(*v1.VMIMConfigurationOptions)
			Expect(src.AsVMIMConfigurationOptions()).To(Equal(oracle))
		})

		It("returns nil when called on a nil receiver", func() {
			var m *v1.MigrationConfiguration
			Expect(m.AsVMIMConfigurationOptions()).To(BeNil())
		})
	})
})
