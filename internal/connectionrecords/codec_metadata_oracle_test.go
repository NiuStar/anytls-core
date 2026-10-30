package connectionrecords

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Frozen from codec.go at 9dfff69c4f405261da8d033ae443cdd97bbbf82d.
// Only identifiers are renamed. Validation/error types remain shared, but field
// discovery, encoder growth/escaping/value and token decoder are independent.
// Do not redirect this oracle to candidate metadata or encoding helpers.
func metadataOldEncodeBounded(value any, budget int) ([]byte, error) {
	if budget < 1 {
		return nil, ErrTooLarge
	}
	if err := Validate(value); err != nil {
		return nil, err
	}
	e := metadataOldEncoder{limit: budget}
	if err := e.value(reflect.ValueOf(value), 0); err != nil {
		return nil, err
	}
	return e.b, nil
}

type metadataOldEncoder struct {
	b     []byte
	limit int
}

func (e *metadataOldEncoder) add(s string) error {
	if len(s) > e.limit-len(e.b) {
		return ErrTooLarge
	}
	// Explicit growth avoids append's capacity overshoot beyond the byte budget.
	if len(e.b)+len(s) > cap(e.b) {
		n := cap(e.b) * 2
		if n < 256 {
			n = 256
		}
		if n < len(e.b)+len(s) {
			n = len(e.b) + len(s)
		}
		if n > e.limit {
			n = e.limit
		}
		b := make([]byte, len(e.b), n)
		copy(b, e.b)
		e.b = b
	}
	e.b = append(e.b, s...)
	return nil
}
func (e *metadataOldEncoder) quoted(s string) error {
	if !utf8.ValidString(s) || strings.IndexByte(s, 0) >= 0 {
		return ErrInvalid
	}
	if err := e.add("\""); err != nil {
		return err
	}
	for i := 0; i < len(s); {
		c := s[i]
		var part string
		switch c {
		case '"':
			part = "\\\""
		case '\\':
			part = "\\\\"
		case '\b':
			part = "\\b"
		case '\f':
			part = "\\f"
		case '\n':
			part = "\\n"
		case '\r':
			part = "\\r"
		case '\t':
			part = "\\t"
		default:
			if c < 0x20 {
				const hex = "0123456789abcdef"
				part = "\\u00" + string(hex[c>>4]) + string(hex[c&15])
			} else {
				_, n := utf8.DecodeRuneInString(s[i:])
				part = s[i : i+n]
				i += n
				if err := e.add(part); err != nil {
					return err
				}
				continue
			}
		}
		if err := e.add(part); err != nil {
			return err
		}
		i++
	}
	return e.add("\"")
}

type metadataOldWireField struct {
	name  string
	index []int
}

func metadataOldFields(t reflect.Type, prefix []int) []metadataOldWireField {
	var result []metadataOldWireField
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" {
			continue
		}
		index := append(append([]int(nil), prefix...), i)
		if f.Anonymous {
			result = append(result, metadataOldFields(f.Type, index)...)
			continue
		}
		name := f.Tag.Get("json")
		if name == "-" {
			continue
		}
		if name == "" {
			name = f.Name
		}
		result = append(result, metadataOldWireField{name, index})
	}
	return result
}
func (e *metadataOldEncoder) value(v reflect.Value, depth int) error {
	if depth > 32 {
		return ErrInvalid
	}
	if !v.IsValid() {
		return e.add("null")
	}
	if v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return e.add("null")
		}
		return e.value(v.Elem(), depth+1)
	}
	switch v.Kind() {
	case reflect.String:
		return e.quoted(v.String())
	case reflect.Bool:
		return e.add(strconv.FormatBool(v.Bool()))
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return e.add(strconv.FormatInt(v.Int(), 10))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return e.add(strconv.FormatUint(v.Uint(), 10))
	case reflect.Struct:
		if err := e.add("{"); err != nil {
			return err
		}
		for i, f := range metadataOldFields(v.Type(), nil) {
			if i > 0 {
				if err := e.add(","); err != nil {
					return err
				}
			}
			if err := e.quoted(f.name); err != nil {
				return err
			}
			if err := e.add(":"); err != nil {
				return err
			}
			if err := e.value(v.FieldByIndex(f.index), depth+1); err != nil {
				return err
			}
		}
		return e.add("}")
	case reflect.Slice:
		if v.IsNil() {
			return e.add("null")
		}
		if err := e.add("["); err != nil {
			return err
		}
		for i := 0; i < v.Len(); i++ {
			if i > 0 {
				if err := e.add(","); err != nil {
					return err
				}
			}
			if err := e.value(v.Index(i), depth+1); err != nil {
				return err
			}
		}
		return e.add("]")
	default:
		return ErrInvalid
	}
}

// metadataOldDecodeStrict is transactional and bounded before tokenization. Every declared
// field is required, including explicit nullable keys. Unknown/duplicate keys
// are rejected recursively; no permissive encoding/json struct conversion occurs.
func metadataOldDecodeStrict(data []byte, out any, budget int) error {
	if budget < 1 || len(data) > budget {
		return ErrTooLarge
	}
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return ErrInvalid
	}
	p := reflect.ValueOf(out)
	if p.Kind() != reflect.Pointer || p.IsNil() {
		return ErrInvalid
	}
	temp := reflect.New(p.Elem().Type()).Elem()
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := metadataOldDecodeValue(d, temp, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalid
	}
	if err := Validate(temp.Interface()); err != nil {
		return err
	}
	p.Elem().Set(temp)
	return nil
}
func metadataOldDecodeValue(d *json.Decoder, v reflect.Value, depth int) error {
	if depth > 32 {
		return ErrInvalid
	}
	token, err := d.Token()
	if err != nil {
		return ErrInvalid
	}
	if token == nil {
		if v.Kind() == reflect.Pointer || v.Kind() == reflect.Slice {
			v.SetZero()
			return nil
		}
		return ErrInvalid
	}
	if v.Kind() == reflect.Pointer {
		v.Set(reflect.New(v.Type().Elem()))
		return metadataOldDecodeToken(d, v.Elem(), token, depth)
	}
	return metadataOldDecodeToken(d, v, token, depth)
}
func metadataOldDecodeToken(d *json.Decoder, v reflect.Value, token any, depth int) error {
	switch v.Kind() {
	case reflect.Struct:
		if token != json.Delim('{') {
			return ErrInvalid
		}
		fs := metadataOldFields(v.Type(), nil)
		seen := make(map[string]bool, len(fs))
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return ErrInvalid
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return ErrInvalid
			}
			seen[name] = true
			found := false
			for _, f := range fs {
				if f.name == name {
					found = true
					if err := metadataOldDecodeValue(d, v.FieldByIndex(f.index), depth+1); err != nil {
						return err
					}
					break
				}
			}
			if !found {
				return ErrInvalid
			}
		}
		if len(seen) != len(fs) {
			return ErrInvalid
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return ErrInvalid
		}
		return nil
	case reflect.Slice:
		if token != json.Delim('[') {
			return ErrInvalid
		}
		v.Set(reflect.MakeSlice(v.Type(), 0, 0))
		for d.More() {
			item := reflect.New(v.Type().Elem()).Elem()
			if err := metadataOldDecodeValue(d, item, depth+1); err != nil {
				return err
			}
			v.Set(reflect.Append(v, item))
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return ErrInvalid
		}
		return nil
	case reflect.String:
		s, ok := token.(string)
		if !ok || !utf8.ValidString(s) || strings.IndexByte(s, 0) >= 0 {
			return ErrInvalid
		}
		v.SetString(s)
		return nil
	case reflect.Bool:
		b, ok := token.(bool)
		if !ok {
			return ErrInvalid
		}
		v.SetBool(b)
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		n, ok := token.(json.Number)
		if !ok {
			return ErrInvalid
		}
		i, err := strconv.ParseInt(string(n), 10, v.Type().Bits())
		if err != nil {
			return ErrInvalid
		}
		v.SetInt(i)
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, ok := token.(json.Number)
		if !ok {
			return ErrInvalid
		}
		i, err := strconv.ParseUint(string(n), 10, v.Type().Bits())
		if err != nil {
			return ErrInvalid
		}
		v.SetUint(i)
		return nil
	default:
		return ErrInvalid
	}
}
func metadataOldManifestDigest(m Manifest, budget int) (string, error) {
	m.ManifestID = strings.Repeat("0", 64)
	if err := Validate(m); err != nil {
		return "", err
	}
	view := struct {
		SchemaVersion       int              `json:"schema_version"`
		InstanceID          string           `json:"instance_id"`
		Generation          string           `json:"generation"`
		SelectionGeneration string           `json:"selection_generation"`
		RuntimeSHA256       string           `json:"runtime_sha256"`
		CapturedSources     []CapturedSource `json:"captured_sources"`
		Rules               []RuleOrigin     `json:"rules"`
		FinalOrigin         RouteProjection  `json:"final_origin"`
		Outbounds           []OutboundOrigin `json:"outbounds"`
	}{m.SchemaVersion, m.InstanceID, m.Generation, m.SelectionGeneration, m.RuntimeSHA256, m.CapturedSources, m.Rules, m.FinalOrigin, m.Outbounds}
	// Every projected value was checked by Validate(m) above. Encode the fixed
	// view with the same bounded encoder without validating those values twice.
	// Keep the budget check after manifest validation to preserve error priority.
	if budget < 1 {
		return "", ErrTooLarge
	}
	e := metadataOldEncoder{limit: budget}
	if err := e.value(reflect.ValueOf(view), 0); err != nil {
		return "", err
	}
	sum := sha256.Sum256(e.b)
	return hex.EncodeToString(sum[:]), nil
}
