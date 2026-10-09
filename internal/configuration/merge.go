package configuration

import (
	"encoding/json"
	"slices"

	"github.com/latchway/latchway/internal/jsonsafe"
)

// Merge resolutions name which side wins one conflicting path.
const (
	MergeTakeDraft = "draft"
	MergeTakeLive  = "live"
)

// absentValue marks a key or identified array item missing from one side.
type absentValue struct{}

var absent any = absentValue{}

type mergeState struct {
	resolutions map[string]string
	used        map[string]bool
	conflicts   []string
}

// threeWayMerge merges the changes a draft made since base with the changes
// the live revision made since base. Objects merge by key and arrays of
// uniquely identified objects merge by id; other values, sensitive subtrees
// and reordered arrays are atomic. A path both sides changed differently is a
// conflict unless resolutions names the side that wins. Conflicts and
// resolutions are paths only; values never leave the documents.
func threeWayMerge(base, draft, live json.RawMessage, resolutions map[string]string) (json.RawMessage, []string, error) {
	decode := func(document json.RawMessage) (any, error) {
		if len(document) == 0 {
			return absent, nil
		}
		value, err := jsonsafe.Decode(document)
		if err != nil {
			return nil, ErrInvalid
		}
		return value, nil
	}
	baseValue, err := decode(base)
	if err != nil {
		return nil, nil, err
	}
	draftValue, err := decode(draft)
	if err != nil {
		return nil, nil, err
	}
	liveValue, err := decode(live)
	if err != nil {
		return nil, nil, err
	}
	state := &mergeState{resolutions: resolutions, used: make(map[string]bool, len(resolutions))}
	merged := mergeValue(state, "", baseValue, draftValue, liveValue, false)
	for path := range resolutions {
		if !state.used[path] {
			return nil, nil, ErrInvalid
		}
	}
	slices.Sort(state.conflicts)
	if _, missing := merged.(absentValue); missing {
		return nil, state.conflicts, ErrInvalid
	}
	encoded, err := json.Marshal(merged)
	if err != nil {
		return nil, nil, ErrInvalid
	}
	return encoded, state.conflicts, nil
}

func sameValue(left, right any) bool {
	_, leftAbsent := left.(absentValue)
	_, rightAbsent := right.(absentValue)
	if leftAbsent || rightAbsent {
		return leftAbsent && rightAbsent
	}
	return equalJSONValue(left, right)
}

func mergeValue(state *mergeState, path string, base, draft, live any, sensitive bool) any {
	switch {
	case sameValue(draft, live):
		return draft
	case sameValue(base, draft):
		return live
	case sameValue(base, live):
		return draft
	}
	if !sensitive {
		draftObject, draftIsObject := draft.(map[string]any)
		liveObject, liveIsObject := live.(map[string]any)
		if draftIsObject && liveIsObject {
			baseObject, _ := base.(map[string]any)
			return mergeObject(state, path, baseObject, draftObject, liveObject)
		}
		draftArray, draftIsArray := draft.([]any)
		liveArray, liveIsArray := live.([]any)
		if draftIsArray && liveIsArray {
			if merged, ok := mergeIdentifiedArray(state, path, base, draftArray, liveArray); ok {
				return merged
			}
		}
	}
	return mergeConflict(state, path, draft, live)
}

func mergeConflict(state *mergeState, path string, draft, live any) any {
	key := safePath(path)
	switch state.resolutions[key] {
	case MergeTakeDraft:
		state.used[key] = true
		return draft
	case MergeTakeLive:
		state.used[key] = true
		return live
	}
	state.conflicts = append(state.conflicts, key)
	return draft
}

func objectMember(object map[string]any, key string) any {
	if object == nil {
		return absent
	}
	value, ok := object[key]
	if !ok {
		return absent
	}
	return value
}

func mergeObject(state *mergeState, path string, base, draft, live map[string]any) map[string]any {
	keys := make(map[string]struct{}, len(draft)+len(live))
	for _, object := range []map[string]any{base, draft, live} {
		for key := range object {
			keys[key] = struct{}{}
		}
	}
	result := make(map[string]any, len(keys))
	for _, key := range sortedMapKeys(keys) {
		value := mergeValue(state, path+"/"+pointerToken(key),
			objectMember(base, key), objectMember(draft, key), objectMember(live, key),
			sensitiveConfigurationKey(key))
		if _, missing := value.(absentValue); !missing {
			result[key] = value
		}
	}
	return result
}

func identifierOrder(values []any) []string {
	order := make([]string, 0, len(values))
	for _, value := range values {
		order = append(order, value.(map[string]any)["id"].(string))
	}
	return order
}

// keepsRelativeOrder reports whether the ids in want appear in order within
// order.
func keepsRelativeOrder(want, order []string) bool {
	position := make(map[string]int, len(order))
	for index, item := range order {
		position[item] = index
	}
	last := -1
	for _, item := range want {
		if position[item] < last {
			return false
		}
		last = position[item]
	}
	return true
}

// mergeIdentifiedArray merges arrays whose items are objects with unique ids.
// It refuses (returning false, so the array is atomic) when either side
// reordered items they share with base, or the draft inserted items anywhere
// but the end, because order is meaningful (route fallback order, for one).
func mergeIdentifiedArray(state *mergeState, path string, base any, draft, live []any) ([]any, bool) {
	draftIndex, draftIndexed := identifierIndex(draft)
	liveIndex, liveIndexed := identifierIndex(live)
	if !draftIndexed || !liveIndexed {
		return nil, false
	}
	var baseIndex map[string]any
	var baseOrder []string
	switch value := base.(type) {
	case absentValue:
	case []any:
		index, indexed := identifierIndex(value)
		if !indexed {
			return nil, false
		}
		baseIndex, baseOrder = index, identifierOrder(value)
	default:
		return nil, false
	}
	draftOrder, liveOrder := identifierOrder(draft), identifierOrder(live)
	shared := make([]string, 0, len(baseOrder))
	for _, item := range baseOrder {
		_, inDraft := draftIndex[item]
		_, inLive := liveIndex[item]
		if inDraft && inLive {
			shared = append(shared, item)
		}
	}
	if !keepsRelativeOrder(shared, draftOrder) || !keepsRelativeOrder(shared, liveOrder) {
		return nil, false
	}
	seenAdded := false
	for _, item := range draftOrder {
		_, inBase := baseIndex[item]
		_, inLive := liveIndex[item]
		added := !inBase && !inLive
		if seenAdded && !added {
			return nil, false
		}
		seenAdded = seenAdded || added
	}
	member := func(index map[string]any, key string) any {
		if value, ok := index[key]; ok {
			return value
		}
		return absent
	}
	result := make([]any, 0, len(live)+len(draft))
	for _, item := range liveOrder {
		value := mergeValue(state, path+"/"+pointerToken(item),
			member(baseIndex, item), member(draftIndex, item), liveIndex[item], false)
		if _, missing := value.(absentValue); !missing {
			result = append(result, value)
		}
	}
	for _, item := range draftOrder {
		if _, inLive := liveIndex[item]; inLive {
			continue
		}
		value := mergeValue(state, path+"/"+pointerToken(item),
			member(baseIndex, item), draftIndex[item], absent, false)
		if _, missing := value.(absentValue); !missing {
			result = append(result, value)
		}
	}
	return result, true
}
