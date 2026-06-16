/*
Copyright 2025 The KubeVirt Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package testutil

import (
	"reflect"
	"strings"
)

// WithAllFieldsSet returns a pointer to a new instance of the type described by t
// with every pointer field set to a non-nil zero value. It is intended for use in
// tests that need a fully-populated struct to exercise field-coverage assertions.
func WithAllFieldsSet(t reflect.Type) interface{} {
	v := reflect.New(t).Elem()
	for i := 0; i < t.NumField(); i++ {
		if f := v.Field(i); f.Kind() == reflect.Ptr {
			f.Set(reflect.New(f.Type().Elem()))
		}
	}
	return v.Addr().Interface()
}

// CopyByJSONTag copies fields from src (a pointer to a struct) into a new instance
// of dstType by matching JSON tag names. It is the reflection-based oracle for
// manual mapping functions whose contract is to transfer all fields that share a
// JSON tag name between two types.
func CopyByJSONTag(src interface{}, dstType reflect.Type) interface{} {
	srcVal := reflect.ValueOf(src).Elem()
	srcType := srcVal.Type()
	dstFields := fieldsByJSONTag(dstType)
	dst := reflect.New(dstType)
	for i := 0; i < srcType.NumField(); i++ {
		name, _, _ := strings.Cut(srcType.Field(i).Tag.Get("json"), ",")
		if df, ok := dstFields[name]; ok {
			dst.Elem().FieldByIndex(df.Index).Set(srcVal.Field(i))
		}
	}
	return dst.Interface()
}

func fieldsByJSONTag(t reflect.Type) map[string]reflect.StructField {
	fields := make(map[string]reflect.StructField)
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if name, _, _ := strings.Cut(f.Tag.Get("json"), ","); name != "" && name != "-" {
			fields[name] = f
		}
	}
	return fields
}
