package main

import (
 "bytes"
 "encoding/json"
 "os"
 "path/filepath"
 "testing"
 cr "github.com/NiuStar/anytls-core/internal/connectionrecords"
)

func TestFamilySnapshotRealCompilerGeoIPAndRuleSet(t *testing.T) {
 for _,mode:=range []string{"proxy","tun"} {
  for _,rules:=range []string{
   " - GEOIP,CN,DIRECT\n - MATCH,a\n",
   " - GEOIP,CN,DIRECT,no-resolve\n - MATCH,a\n",
   " - RULE-SET,local,DIRECT\n - MATCH,a\n",
   " - RULE-SET,local,REJECT,no-resolve\n - MATCH,a\n",
  } {
   t.Run(mode+rules,func(t *testing.T){
    o,_,_:=recordsCompilerFixture(t,rules);o.Mode=mode
    legacy,err:=prepareRuntime(&o);if err!=nil {t.Fatal(err)}
    want,err:=json.MarshalIndent(legacy,"","  ");if err!=nil {t.Fatal(err)}
    compiled,err:=prepareRuntimeWithRecords(&o);if err!=nil {t.Fatal(err)}
    if !bytes.Equal(want,compiled.JSON) || compiled.familyPolicy==nil || !compiled.familyPolicy.Matches(compiled.JSON) {t.Fatal("actual compiler policy capture changed bytes or missing")}
    if compiled.familyPolicy.Matches(append(append([]byte(nil),compiled.JSON...),' ')) {t.Fatal("runtime drift accepted")}
    // Inline objects, not the original path, are the SDK's actual data source.
    if err:=os.Remove(filepath.Join(filepath.Dir(o.Config),"set.json"));err!=nil {t.Fatal(err)}
    if !compiled.familyPolicy.Matches(compiled.JSON) {t.Fatal("frozen policy still depends on filesystem")}
    for _,r:=range compiled.Manifest.Rules {
     if r.Synthetic==cr.SyntheticNone && r.Route.SourceIndex!=nil {
      if *r.Route.SourceIndex!=0 || r.Route.SourceID==nil || *r.Route.SourceID!=compiled.Manifest.Generation+":rule:0" {t.Fatal("user source identity/order changed")}
     }
    }
   })
  }
 }
}

func TestFamilySnapshotCompilerChangedSourceSHAFailsClosed(t *testing.T) {
 o,_,_:=recordsCompilerFixture(t," - RULE-SET,local,DIRECT\n - MATCH,a\n")
 compiled,err:=prepareRuntimeWithRecords(&o);if err!=nil {t.Fatal(err)}
 path:=filepath.Join(filepath.Dir(o.Config),"set.json")
 if err:=os.WriteFile(path,[]byte(`{"version":3,"rules":[{"ip_cidr":["192.0.2.0/24"]}]}`),0600);err!=nil {t.Fatal(err)}
 if _,err:=prepareRuntimeWithRecords(&o);err==nil {t.Fatal("changed source SHA recompile succeeded")}
 if !compiled.familyPolicy.Matches(compiled.JSON) {t.Fatal("failed recompile mutated active snapshot")}
}
