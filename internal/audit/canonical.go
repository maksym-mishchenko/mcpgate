package audit

import (
	"crypto/sha256"
	"encoding/json"
	"sort"
)

// CanonicalHash returns sha256(canonicalJSON(v)).
// The canonical form has sorted keys, no insignificant whitespace,
// and consistent number formatting. It is pinned — never change this function
// without updating the golden tests.
func CanonicalHash(v map[string]any) []byte {
	b := canonicalJSON(v)
	h := sha256.Sum256(b)
	return h[:]
}

// canonicalJSON marshals a map with sorted keys, no extra whitespace.
func canonicalJSON(v map[string]any) []byte {
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := []byte{'{'}
	for i, k := range keys {
		kBytes, _ := json.Marshal(k)
		val, _ := json.Marshal(v[k])
		out = append(out, kBytes...)
		out = append(out, ':')
		out = append(out, val...)
		if i < len(keys)-1 {
			out = append(out, ',')
		}
	}
	out = append(out, '}')
	return out
}
