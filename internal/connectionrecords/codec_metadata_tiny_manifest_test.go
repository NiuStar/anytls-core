package connectionrecords

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func TestCodecMetadataTinyManifestCacheAdmission(t *testing.T) {
	m := metadataFixture(0)
	budget := ManifestBudget(&m)
	e := boundedEncoder{limit: budget}
	if err := e.value(reflect.ValueOf(m), 0); err != nil {
		t.Fatal(err)
	}
	if e.metadata != nil {
		t.Fatal("two-source zero-rule manifest must not allocate a schema cache")
	}
	d := json.NewDecoder(bytes.NewReader(e.b))
	d.UseNumber()
	var out Manifest
	var metadata fieldMetadata
	if err := decodeValue(d, reflect.ValueOf(&out).Elem(), 0, &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata != nil {
		t.Fatal("two-source zero-rule manifest decode must not allocate a schema cache")
	}
	if !reflect.DeepEqual(out, m) {
		t.Fatal("tiny manifest decode changed values")
	}
}
