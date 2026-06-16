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

package v1alpha1

import (
	"reflect"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"k8s.io/utils/ptr"

	"kubevirt.io/api/apitesting/testutil"
	v1 "kubevirt.io/api/core/v1"
)

var _ = Describe("MigrationPolicy", func() {
	Describe("ApplyMigrationPolicy", func() {
		// Guards against silently dropping policy fields due to a missing setIfNotNil
		// call in ApplyMigrationPolicy. Fields are discovered via reflection so the
		// test catches new fields automatically — no hardcoded list to maintain.
		// Assumes matching fields share the same JSON tag name; update this test to
		// explicitly acknowledge any intentional divergence.
		It("applies every MigrationPolicySpec field that has a matching JSON tag in VMIMConfigurationOptions", func() {
			src := testutil.WithAllFieldsSet(reflect.TypeOf(MigrationPolicySpec{})).(*MigrationPolicySpec)
			oracle := testutil.CopyByJSONTag(src, reflect.TypeOf(v1.VMIMConfigurationOptions{})).(*v1.VMIMConfigurationOptions)

			dst := &v1.VMIMConfigurationOptions{}
			policy := &MigrationPolicy{Spec: *src}
			policy.ApplyMigrationPolicy(dst)

			Expect(dst).To(Equal(oracle))
		})

		DescribeTable("backward-compat shim derives AllowWorkloadDisruption from AllowPostCopy when not set",
			func(allowPostCopy bool, expectedWorkloadDisruption bool) {
				policy := &MigrationPolicy{
					Spec: MigrationPolicySpec{
						AllowPostCopy: ptr.To(allowPostCopy),
						// AllowWorkloadDisruption intentionally left nil to trigger shim.
					},
				}
				dst := &v1.VMIMConfigurationOptions{}
				policy.ApplyMigrationPolicy(dst)

				Expect(dst.AllowWorkloadDisruption).NotTo(BeNil())
				Expect(*dst.AllowWorkloadDisruption).To(Equal(expectedWorkloadDisruption))
			},
			Entry("AllowPostCopy true implies AllowWorkloadDisruption true", true, true),
			Entry("AllowPostCopy false implies AllowWorkloadDisruption false", false, false),
		)
	})
})
