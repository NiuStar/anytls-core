package main

import (
	"bytes"
	st "github.com/NiuStar/anytls-core/internal/startuptimeline"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestStartupRootPushActualSlotAndFraming(t *testing.T) {
	// UNIT root UID/composite guards injected, real Unix handler and framing.
	s := unitControlServer()
	s.peer = func(net.Conn) (uint32, error) { return 0, nil }
	s.startupRegistration = func() (controlHelperRegistration, error) { return s.registration, nil }
	id := strings.Repeat("a", 32)
	identity,_:=controlHelperConfigIdentity(s.registration.Config)
	o := s.startupBegin(id, "start", identity, "MANUAL_START")
	o.binding = &startupBinding{}
	entered, release := make(chan struct{}), make(chan struct{})
	calls := 0
	s.startupAuthenticate = func(net.Conn, *startupBinding) bool {
		calls++
		if calls == 1 {
			close(entered)
			<-release
		}
		return true
	}
	c, _ := unitControlPair(t, s)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("authentication not entered before body")
	}
	other, _ := unitControlPair(t, s)
	other.SetReadDeadline(time.Now().Add(time.Second))
	b, e := io.ReadAll(other)
	if e != nil || len(b) != 0 {
		close(release)
		t.Fatal("second actual work slot admitted", e)
	}
	if s.startupPushSlot.TryLock() {
		s.startupPushSlot.Unlock()
		close(release)
		t.Fatal("actual authentication slot released while blocked")
	}
	close(release)
	core, _ := st.NewRecorder("CORE", startupProvenance(""))
	q := st.PushRequest{TimelineSchema: 1, Action: "startup.push", OperationID: id, HelperEpoch: *o.trace.HelperEpoch, Snapshot: st.CoreSnapshot{Stream: core.Snapshot(), StartupResult: "IN_PROGRESS"}}
	raw, _ := st.Encode(q)
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, e = c.Write(raw); e != nil {
		t.Fatal(e)
	}
	c.CloseWrite()
	var ack st.PushAck
	if e = st.Decode(c, &ack); e != nil || ack.Code != "OK" {
		t.Fatal("root push fixture", ack, e)
	}
	if calls != 2 || o.core == nil {
		t.Fatal("before/after composite guard or publish absent", calls)
	}
	s.startupFinish(o, controlHelperResponse{OK: true})
}

func TestStartupRootPushBindingAndNoEOF(t *testing.T){
 for _,mode:=range []string{"wrong_operation","wrong_epoch","revoked","no_eof","oversize"}{t.Run(mode,func(t *testing.T){
  s:=unitControlServer();s.peer=func(net.Conn)(uint32,error){return 0,nil};regCalls:=0
  s.startupRegistration=func()(controlHelperRegistration,error){regCalls++;v:=s.registration;if mode=="revoked"&&regCalls>1{v.UID++};return v,nil}
  s.startupAuthenticate=func(net.Conn,*startupBinding)bool{return true}
  identity,_:=controlHelperConfigIdentity(s.registration.Config);id:=strings.Repeat("a",32);o:=s.startupBegin(id,"start",identity,"MANUAL_START");o.binding=&startupBinding{}
  core,_:=st.NewRecorder("CORE",startupProvenance(""));q:=st.PushRequest{TimelineSchema:1,Action:"startup.push",OperationID:id,HelperEpoch:*o.trace.HelperEpoch,Snapshot:st.CoreSnapshot{Stream:core.Snapshot(),StartupResult:"IN_PROGRESS"}}
  if mode=="wrong_operation"{q.OperationID=strings.Repeat("c",32)};if mode=="wrong_epoch"{q.HelperEpoch=strings.Repeat("d",32)}
  raw,_:=st.Encode(q);if mode=="oversize"{raw=append(bytes.Repeat([]byte(" "),st.PushBytes+1-len(raw)),raw...)}
  c,done:=unitControlPair(t,s);c.SetDeadline(time.Now().Add(2*time.Second));if _,e:=c.Write(raw);e!=nil{t.Fatal(e)}
  if mode!="no_eof"{c.CloseWrite()}
  b,e:=io.ReadAll(c);if e!=nil{t.Fatal("bounded handler failed",e)};<-done
  if o.core!=nil{t.Fatal("rejected frame updated cache")}
  if mode=="no_eof"{if len(b)!=0{t.Fatal("missing EOF produced a response")};return}
  if mode=="oversize"{var r controlHelperResponse;if e=controlHelperReadResponse(bytes.NewReader(b),&r);e!=nil||r.Code!="FORBIDDEN"{t.Fatal("unframed/oversize accepted",e)};return}
  var ack st.PushAck;if e=st.Decode(bytes.NewReader(b),&ack);e!=nil{t.Fatal(e)}
  want:="OPERATION_MISMATCH";if mode=="revoked"{want="IDENTITY_MISMATCH"};if ack.Code!=want{t.Fatal(ack.Code,want)}
 })}
}
