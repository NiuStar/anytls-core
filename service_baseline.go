package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

// Baselines are restoration authority. Reject duplicate/case-alias fields and
// non-canonical version numbers before encoding/json's permissive struct match.
func decodeBaseline(raw []byte, b *networkBaseline) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return errors.New("baseline object required")
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[strings.ToLower(key)] {
			return errors.New("baseline field ambiguous")
		}
		seen[strings.ToLower(key)] = true
		switch key {
		case "Version", "Scope", "Server", "Servers", "ServerInterface", "PublicInterface", "DNS":
		default:
			return errors.New("baseline field unsupported")
		}
		var value json.RawMessage
		if err = d.Decode(&value); err != nil {
			return err
		}
		if (key == "Scope" || key == "Server" || key == "ServerInterface" || key == "PublicInterface") && string(value) == "null" {
			return errors.New("baseline string required")
		}
		if key == "Version" && string(value) != "0" && string(value) != "1" && string(value) != "2" {
			return errors.New("baseline version unsupported")
		}
	}
	if _, err = d.Token(); err != nil {
		return err
	}
	if _, err = d.Token(); err != io.EOF {
		return errors.New("baseline trailing data")
	}
	if err := json.Unmarshal(raw, b); err != nil {
		return err
	}
	if b.Version == 2 && seen["servers"] {
		return errors.New("local baseline cannot contain server map")
	}
	return nil
}
