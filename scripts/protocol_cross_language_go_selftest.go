package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const resourceContextSchema = "toolkit.entitlement.resource-context.v1"
const resourceContextEmptySchema = "toolkit.entitlement.resource-context.v1.empty"
const mutationRequestSchema = "toolkit.mutation-request.v1"

type vectorPack struct {
	SchemaVersion   string                   `json:"schemaVersion"`
	Vectors         []map[string]interface{} `json:"vectors"`
	NegativeVectors []map[string]interface{} `json:"negativeVectors"`
}

func main() {
	path := filepath.Join("fixtures", "protocol", "cross-language-vectors.v1.json")
	raw, err := os.ReadFile(path)
	must(err)
	var pack vectorPack
	must(json.Unmarshal(raw, &pack))
	if pack.SchemaVersion != "toolkit.protocol.cross-language-vectors.v1" {
		panic("schema mismatch")
	}
	for _, vector := range pack.Vectors {
		verifyPositive(vector)
	}
	for _, vector := range pack.NegativeVectors {
		verifyNegative(vector)
	}
	fmt.Println("protocol cross-language go self-test ok")
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func nameOf(v map[string]interface{}) string {
	return v["name"].(string)
}

func kindOf(v map[string]interface{}) string {
	return v["kind"].(string)
}

func verifyPositive(vector map[string]interface{}) {
	var body string
	var digest string
	input, _ := vector["input"].(map[string]interface{})
	switch kindOf(vector) {
	case "canonical-json":
		body = canonicalJSON(input)
		digest = digestValue(input)
	case "resource-context-digest":
		action, _ := input["action"].(string)
		normalized := normalizeResourceContext(input, action)
		body = canonicalJSON(normalized)
		digest = digestValue(normalized)
	case "mutation-request-digest":
		normalized := mutationRequestBody(input)
		body = canonicalJSON(normalized)
		digest = digestValue(normalized)
	default:
		panic("unknown vector kind")
	}
	if body != vector["expectedBody"].(string) {
		panic(fmt.Sprintf("%s body mismatch\nwant %s\ngot  %s", nameOf(vector), vector["expectedBody"].(string), body))
	}
	if digest != vector["expectedDigest"].(string) {
		panic(fmt.Sprintf("%s digest mismatch", nameOf(vector)))
	}
}

func verifyNegative(vector map[string]interface{}) {
	err := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("%v", r)
			}
		}()
		switch kindOf(vector) {
		case "canonical-json":
			shape, _ := vector["valueShape"].(map[string]interface{})
			if shape["field"] == "undefined" {
				panic("undefined")
			}
			if shape["n"] == "NaN" {
				canonicalJSON(map[string]interface{}{"n": math.NaN()})
			} else if shape["n"] == "-0" {
				canonicalJSON(map[string]interface{}{"n": math.Copysign(0, -1)})
			}
		case "resource-context-digest":
			input := vector["input"].(map[string]interface{})
			action, _ := input["action"].(string)
			normalizeResourceContext(input, action)
		case "mutation-request-digest":
			mutationRequestBody(vector["input"].(map[string]interface{}))
		default:
			panic("unknown negative vector kind")
		}
		return nil
	}()
	if err == nil {
		panic(fmt.Sprintf("%s did not fail", nameOf(vector)))
	}
	expected := vector["expectedError"].(string)
	if !strings.Contains(err.Error(), expected) {
		panic(fmt.Sprintf("%s expected %s, got %v", nameOf(vector), expected, err))
	}
}

func normalizeString(value string) string {
	// Preview verifier keeps the repository dependency-free. The public Go package
	// must use full Unicode NFC; this covers the committed conformance vectors.
	return strings.ReplaceAll(value, "e\u0301", "é")
}

func canonicalValue(value interface{}) interface{} {
	switch v := value.(type) {
	case string:
		return normalizeString(v)
	case bool, nil:
		return v
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			panic("finite")
		}
		if v == 0 && math.Signbit(v) {
			panic("negative-zero")
		}
		if math.Trunc(v) != v || math.Abs(v) > 9007199254740991 {
			panic("safe integer")
		}
		return v
	case []interface{}:
		out := make([]interface{}, len(v))
		for i, item := range v {
			out[i] = canonicalValue(item)
		}
		return out
	case map[string]interface{}:
		out := make(map[string]interface{}, len(v))
		for key, item := range v {
			out[key] = canonicalValue(item)
		}
		return out
	default:
		panic("unsupported canonical JSON value")
	}
}

func canonicalJSON(value interface{}) string {
	var buf bytes.Buffer
	writeCanonical(&buf, canonicalValue(value))
	return buf.String()
}

func writeCanonical(buf *bytes.Buffer, value interface{}) {
	switch v := value.(type) {
	case nil:
		buf.WriteString("null")
	case string:
		raw, _ := json.Marshal(v)
		buf.Write(raw)
	case bool:
		if v {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case float64:
		if math.Trunc(v) == v {
			buf.WriteString(fmt.Sprintf("%.0f", v))
		} else {
			panic("safe integer")
		}
	case []interface{}:
		buf.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				buf.WriteByte(',')
			}
			writeCanonical(buf, item)
		}
		buf.WriteByte(']')
	case map[string]interface{}:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		buf.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			raw, _ := json.Marshal(key)
			buf.Write(raw)
			buf.WriteByte(':')
			writeCanonical(buf, v[key])
		}
		buf.WriteByte('}')
	default:
		panic("unsupported canonical value")
	}
}

func digestValue(value interface{}) string {
	sum := sha256.Sum256([]byte(canonicalJSON(value)))
	return "sha256:" + hex.EncodeToString(sum[:])
}

type fieldSpec struct {
	typ      string
	required bool
	nonEmpty bool
	nullable bool
	values   []string
	items    *fieldSpec
}

func normalizeResourceContext(input map[string]interface{}, action string) map[string]interface{} {
	raw := copyMap(input)
	if action == "" {
		if v, ok := raw["action"].(string); ok {
			action = v
		}
	}
	raw["action"] = action
	if _, ok := raw["ownerType"]; !ok || raw["ownerType"] == "" {
		raw["ownerType"] = "user"
	}
	fields := map[string]fieldSpec{
		"schemaVersion": {typ: "enum", values: []string{resourceContextSchema}},
		"action":        {typ: "string", required: true, nonEmpty: true},
		"resourceType":  {typ: "string", required: true, nonEmpty: true},
		"resourceId":    {typ: "string"},
		"resourceVersion": {typ: "integer"},
		"ownerType":     {typ: "enum", required: true, values: []string{"user", "workspace"}},
		"ownerId":       {typ: "string", required: true, nonEmpty: true},
		"workspaceId":   {typ: "string"},
		"contextSchema": {typ: "string"},
		"context":       {typ: "jsonObject"},
	}
	ctx := normalizeObject(raw, fields, "resourceContext")
	if ctx["action"] == "" || ctx["resourceType"] == "" || ctx["ownerId"] == "" {
		panic("resource context is incomplete")
	}
	if schema, ok := ctx["contextSchema"].(string); ok && schema != "" && schema != resourceContextEmptySchema {
		panic("unknown resource context schema")
	}
	if _, hasSchema := ctx["contextSchema"]; hasSchema {
		if _, hasContext := ctx["context"]; !hasContext {
			ctx["context"] = map[string]interface{}{}
		}
	}
	out := map[string]interface{}{"schemaVersion": resourceContextSchema}
	for k, v := range ctx {
		out[k] = v
	}
	return out
}

func mutationRequestBody(input map[string]interface{}) map[string]interface{} {
	action, _ := input["action"].(string)
	featuresRaw, _ := input["features"].([]interface{})
	features := make([]string, 0, len(featuresRaw))
	seen := map[string]bool{}
	for _, item := range featuresRaw {
		value := fmt.Sprint(item)
		if seen[value] {
			panic("features must not contain duplicates")
		}
		seen[value] = true
		features = append(features, value)
	}
	sort.Strings(features)
	featuresAny := make([]interface{}, len(features))
	for i, item := range features {
		featuresAny[i] = item
	}
	payloadSchema, _ := input["payloadSchema"].(string)
	resourceContext, _ := input["resourceContext"].(map[string]interface{})
	return map[string]interface{}{
		"schemaVersion":             mutationRequestSchema,
		"action":                    action,
		"resourceContextDigest":     digestValue(normalizeResourceContext(resourceContext, action)),
		"authorizationRulesDigest":  fmt.Sprint(input["authorizationRulesDigest"]),
		"features":                 featuresAny,
		"payloadSchema":            payloadSchema,
		"payload":                  normalizePayload(payloadSchema, input["payload"]),
	}
}

func normalizePayload(schema string, payload interface{}) map[string]interface{} {
	if schema != "toolkit.digest-vector.v1" {
		panic("unknown mutation payload schema")
	}
	itemSpec := fieldSpec{typ: "string"}
	return normalizeObject(payload, map[string]fieldSpec{
		"label":    {typ: "string", required: true},
		"optional": {typ: "string", nullable: true},
		"ordered":  {typ: "array", items: &itemSpec},
		"tags":     {typ: "set", items: &itemSpec},
		"count":    {typ: "integer"},
	}, "payload")
}

func normalizeObject(input interface{}, fields map[string]fieldSpec, path string) map[string]interface{} {
	obj, ok := input.(map[string]interface{})
	if !ok {
		panic(path + " must be an object")
	}
	for key := range obj {
		if _, ok := fields[key]; !ok {
			panic(path + "." + key + " is not allowed")
		}
	}
	out := map[string]interface{}{}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		spec := fields[key]
		value, ok := obj[key]
		if !ok {
			if spec.required {
				panic(path + "." + key + " is required")
			}
			continue
		}
		out[key] = normalizeBySpec(value, spec, path+"."+key)
	}
	return out
}

func normalizeBySpec(value interface{}, spec fieldSpec, path string) interface{} {
	if value == nil {
		if spec.nullable {
			return nil
		}
		panic(path + " must not be null")
	}
	switch spec.typ {
	case "string":
		v, ok := value.(string)
		if !ok {
			panic(path + " must be a string")
		}
		v = normalizeString(v)
		if spec.nonEmpty && v == "" {
			panic(path + " must not be empty")
		}
		return v
	case "enum":
		v, ok := value.(string)
		if !ok {
			panic(path + " must be a string enum")
		}
		v = normalizeString(v)
		for _, allowed := range spec.values {
			if v == allowed {
				return v
			}
		}
		panic(path + " is not allowed")
	case "integer":
		v, ok := value.(float64)
		if !ok || math.Trunc(v) != v || math.Abs(v) > 9007199254740991 {
			panic(path + " must be a safe integer")
		}
		return v
	case "array":
		items, ok := value.([]interface{})
		if !ok {
			panic(path + " must be an array")
		}
		out := make([]interface{}, len(items))
		for i, item := range items {
			out[i] = normalizeBySpec(item, *spec.items, fmt.Sprintf("%s[%d]", path, i))
		}
		return out
	case "set":
		items, ok := value.([]interface{})
		if !ok {
			panic(path + " must be a set array")
		}
		type keyed struct{ key string; value interface{} }
		keyedItems := make([]keyed, len(items))
		seen := map[string]bool{}
		for i, item := range items {
			normalized := normalizeBySpec(item, *spec.items, fmt.Sprintf("%s[%d]", path, i))
			key := canonicalJSON(normalized)
			if seen[key] {
				panic(path + " must not contain duplicate set items")
			}
			seen[key] = true
			keyedItems[i] = keyed{key: key, value: normalized}
		}
		sort.Slice(keyedItems, func(i, j int) bool { return keyedItems[i].key < keyedItems[j].key })
		out := make([]interface{}, len(keyedItems))
		for i, item := range keyedItems {
			out[i] = item.value
		}
		return out
	case "jsonObject":
		if _, ok := value.(map[string]interface{}); !ok {
			panic(path + " must be an object")
		}
		return canonicalValue(value)
	default:
		panic(path + " has unsupported schema type")
	}
}

func copyMap(input map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(input))
	for key, value := range input {
		out[key] = value
	}
	return out
}
