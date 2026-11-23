package sessionfields

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
)

const (
	JSON        Type = "json"
	StringArray Type = "string[]"
	NumberArray Type = "number[]"
)

// JSONColumn reports whether the logical value uses JSON storage.
func (f Field) JSONColumn() bool {
	return f.Type == JSON || f.Type == StringArray || f.Type == NumberArray
}

// ElementError points to an invalid element in a typed array.
type ElementError struct {
	Index    int
	Expected string
	Value    any
}

type ElementErrors []ElementError

func (e ElementErrors) Error() string {
	return fmt.Sprintf("array element %d must be a %s", e[0].Index, e[0].Expected)
}

// jsonValue owns the input and checks a single representation for all SQL engines.
func (f Field) jsonValue(raw any) (any, error) {
	data, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if value == nil {
		if f.Required {
			return nil, fmt.Errorf("required field cannot be null")
		}
		return nil, nil
	}
	if f.Type != JSON {
		items, ok := value.([]any)
		if !ok {
			return nil, fmt.Errorf("expected an array")
		}
		var issues ElementErrors
		for i, item := range items {
			if f.Type == StringArray {
				if _, ok := item.(string); !ok {
					issues = append(issues, ElementError{i, "string", item})
				}
			} else if _, ok := item.(json.Number); !ok {
				issues = append(issues, ElementError{i, "number", item})
			}
		}
		if len(issues) > 0 {
			return nil, issues
		}
	}
	if err := portableJSON(value); err != nil {
		return nil, err
	}
	return json.RawMessage(data), nil
}

// PostgreSQL jsonb rejects embedded NUL and JSON clients use finite numbers.
func portableJSON(value any) error {
	switch v := value.(type) {
	case string:
		if strings.ContainsRune(v, 0) {
			return fmt.Errorf("JSON strings cannot contain NUL")
		}
	case json.Number:
		n, err := strconv.ParseFloat(v.String(), 64)
		if err != nil || math.IsInf(n, 0) {
			return fmt.Errorf("JSON number is outside the finite range")
		}
	case []any:
		for _, item := range v {
			if err := portableJSON(item); err != nil {
				return err
			}
		}
	case map[string]any:
		for key, item := range v {
			if strings.ContainsRune(key, 0) {
				return fmt.Errorf("JSON keys cannot contain NUL")
			}
			if err := portableJSON(item); err != nil {
				return err
			}
		}
	}
	return nil
}
