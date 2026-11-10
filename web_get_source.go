package main

import "gopkg.in/yaml.v3"

// No state escapes the GET stack. Each independent entry (especially mutation,
// helper and IPC) retains its original source acquisition and validation.
func (w *webConsole) readGETSource(path string, limit int64, follow bool) ([]byte, error) {
	if w.getSourceRead != nil {
		return w.getSourceRead(path, limit, follow)
	}
	return readSnapshotSource(path, limit, follow)
}

func (w *webConsole) getConfigDecode(b []byte) func(any) error {
	var captured *yaml.Node
	return func(v any) error {
		if captured != nil {
			return captured.Decode(v)
		}
		var doc yaml.Node
		var err error
		if w.getYAMLParse != nil {
			err = w.getYAMLParse(b, &doc)
		} else {
			err = yaml.Unmarshal(b, &doc)
		}
		if err != nil {
			return err
		}
		if err := doc.Decode(v); err != nil {
			return err
		}
		// Retain only a successfully parsed and typed-validated document; the
		// second projection still performs its own typed semantic validation.
		captured = &doc
		return nil
	}
}
