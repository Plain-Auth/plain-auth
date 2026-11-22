// Package sessionfields validates the common configuration used by session
// issuance, public updates and the three relational schema generators.
package sessionfields

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Type string

const (
	String  Type = "string"
	Number  Type = "number"
	Boolean Type = "boolean"
	Date    Type = "date"
)

const MillisecondUTC = "2006-01-02T15:04:05.000Z"

type Field struct {
	Type                         Type
	Column                       string
	Default                      any
	Required, ServerOnly, Hidden bool
}

var identifier = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,62}$`)

// The Go parser alone also admits a comma fraction, one-digit hour and
// overflowed numeric timezone offsets. Accept the date-time shape exposed in OpenAPI.
var dateTimeShape = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?([Zz]|[+-]([01][0-9]|2[0-3]):[0-5][0-9])$`)

var reserved = map[string]bool{"id": true, "userid": true, "token": true, "expiresat": true, "updatedat": true, "createdat": true, "ipaddress": true, "useragent": true, "credentialtype": true, "impersonatedby": true, "activeorganizationid": true, "activeteamid": true, "__proto__": true, "constructor": true, "prototype": true}

func NameOK(name string) bool {
	return identifier.MatchString(name) && !reserved[strings.ToLower(name)]
}

// UserNameOK reserves core profile, authentication input and installed plugin attributes.
func UserNameOK(name string) bool {
	if !NameOK(name) {
		return false
	}
	switch strings.ToLower(name) {
	case "name", "email", "emailverified", "image", "password", "callbackurl", "rememberme", "username", "displayusername", "phonenumber", "phonenumberverified", "lastloginmethod", "isanonymous", "twofactorenabled", "role", "banned", "banreason", "banexpires", "stripecustomerid", "newpassword", "currentpassword", "redirect", "url":
		return false
	}
	return true
}

func Names(fields map[string]Field) []string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// Normalize resolves physical names and freezes static scalar defaults.
func Normalize(fields map[string]Field) (map[string]Field, error) {
	return normalize(fields, "session", NameOK)
}

func NormalizeUser(fields map[string]Field) (map[string]Field, error) {
	return normalize(fields, "user", UserNameOK)
}

func normalize(fields map[string]Field, model string, validName func(string) bool) (map[string]Field, error) {
	if len(fields) == 0 {
		return nil, nil
	}
	result := make(map[string]Field, len(fields))
	used := map[string]string{}
	for _, name := range Names(fields) {
		f := fields[name]
		if f.Column == "" {
			f.Column = name
		}
		for _, key := range []string{name, f.Column} {
			if !validName(key) {
				return nil, fmt.Errorf("invalid additional %s field name %q", model, key)
			}
			lower := strings.ToLower(key)
			if other, ok := used[lower]; ok && other != name {
				return nil, fmt.Errorf("%s field %q collides with %q", model, name, other)
			}
			used[lower] = name
		}
		switch f.Type {
		case String, Number, Boolean, Date:
		default:
			return nil, fmt.Errorf("unsupported type %q for %s field %q", f.Type, model, name)
		}
		if f.Default != nil {
			value, err := f.Value(f.Default)
			if err != nil {
				return nil, fmt.Errorf("invalid default for %s field %q: %w", model, name, err)
			}
			f.Default = value
		}
		result[name] = f
	}
	return result, nil
}

// Value normalizes scalar numbers to the portable signed INTEGER range.
func (f Field) Value(raw any) (any, error) {
	if raw == nil {
		if f.Required {
			return nil, fmt.Errorf("required field cannot be null")
		}
		return nil, nil
	}
	switch f.Type {
	case String:
		if v, ok := raw.(string); ok && !strings.ContainsRune(v, 0) {
			return v, nil
		}
	case Boolean:
		if v, ok := raw.(bool); ok {
			return v, nil
		}
	case Date:
		var instant time.Time
		switch value := raw.(type) {
		case time.Time:
			instant = value
		case string:
			var err error
			if !dateTimeShape.MatchString(value) {
				return nil, fmt.Errorf("expected an RFC 3339 date-time")
			}
			instant, err = time.Parse(time.RFC3339Nano, strings.ToUpper(value))
			if err != nil {
				return nil, fmt.Errorf("expected an RFC 3339 date-time")
			}
		default:
			return nil, fmt.Errorf("expected an RFC 3339 date-time")
		}
		instant = instant.UTC().Truncate(time.Millisecond)
		if instant.Year() >= 1 && instant.Year() <= 9999 {
			return instant, nil
		}
	case Number:
		var n int64
		if number, ok := raw.(json.Number); ok {
			return portableJSONInteger(number)
		}
		v := reflect.ValueOf(raw)
		switch v.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			n = v.Int()
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			if v.Uint() > math.MaxInt32 {
				return nil, fmt.Errorf("integer is out of range")
			}
			n = int64(v.Uint())
		case reflect.Float32, reflect.Float64:
			f := v.Float()
			if f < math.MinInt32 || f > math.MaxInt32 || math.Trunc(f) != f {
				return nil, fmt.Errorf("expected a signed 32-bit integer")
			}
			n = int64(f)
		default:
			return nil, fmt.Errorf("expected a signed 32-bit integer")
		}
		if n >= math.MinInt32 && n <= math.MaxInt32 {
			return n, nil
		}
	}
	return nil, fmt.Errorf("expected %s", f.Type)
}

// PublicValue preserves milliseconds in the JSON representation of a date.
func (f Field) PublicValue(raw any) (any, error) {
	value, err := f.Value(raw)
	if date, ok := value.(time.Time); ok {
		return date.Format(MillisecondUTC), nil
	}
	return value, err
}

// Compare the exact JSON decimal with a signed INTEGER. Trim powers of ten
// before applying the exponent so untrusted exponents never allocate a large number.
func portableJSONInteger(number json.Number) (int64, error) {
	src := number.String()
	invalid := fmt.Errorf("expected a signed 32-bit integer")
	if src == "" || !json.Valid([]byte(src)) {
		return 0, invalid
	}
	unsigned, negative := strings.CutPrefix(src, "-")
	mantissa, exponent := unsigned, "0"
	if split := strings.IndexAny(unsigned, "eE"); split >= 0 {
		mantissa, exponent = unsigned[:split], unsigned[split+1:]
	}
	whole, fraction, _ := strings.Cut(mantissa, ".")
	digits := strings.TrimLeft(whole+fraction, "0")
	if digits == "" {
		return 0, nil
	}
	if strings.IndexFunc(digits, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
		return 0, invalid
	}
	base := strings.TrimRight(digits, "0")
	power, err := strconv.Atoi(exponent)
	if err != nil || power < -len(digits) || power > len(fraction)+10 {
		return 0, invalid
	}
	shift := power - len(fraction) + len(digits) - len(base)
	if shift < 0 || len(base)+shift > 10 {
		return 0, invalid
	}
	canonical := base + strings.Repeat("0", shift)
	if negative {
		canonical = "-" + canonical
	}
	n, err := strconv.ParseInt(canonical, 10, 32)
	if err != nil {
		return 0, invalid
	}
	return n, nil
}

// Definition returns one fresh-schema column after Normalize has validated its name.
func (f Field) Definition(dialect string) string {
	quote := "\""
	if dialect == "mysql" {
		quote = "`"
	}
	sqlType := "text"
	switch f.Type {
	case Boolean:
		sqlType = "boolean"
		if dialect == "sqlite" || dialect == "sqlite3" {
			sqlType = "integer"
		}
	case Number:
		sqlType = "integer"
	case Date:
		switch dialect {
		case "postgres", "postgresql":
			sqlType = "timestamptz"
		case "mysql":
			sqlType = "timestamp(3)"
		default:
			sqlType = "date"
		}
	}
	column := quote + f.Column + quote + " " + sqlType
	if f.Required {
		column += " not null"
	}
	return column
}
