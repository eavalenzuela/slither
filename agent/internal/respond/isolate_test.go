//go:build linux

package respond

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// recordedApplier captures argv for assertion.
type recordedApplier struct {
	mu    sync.Mutex
	calls [][]string
	fail  map[int]error // index → error to return on that call
}

func (r *recordedApplier) Run(_ context.Context, argv ...string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	idx := len(r.calls)
	cp := make([]string, len(argv))
	copy(cp, argv)
	r.calls = append(r.calls, cp)
	if r.fail != nil {
		if e, ok := r.fail[idx]; ok {
			return e
		}
	}
	return nil
}

func (r *recordedApplier) snapshot() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]string, len(r.calls))
	for i, c := range r.calls {
		cp := make([]string, len(c))
		copy(cp, c)
		out[i] = cp
	}
	return out
}

// withTestApplier swaps pickApplier for the duration of a test.
func withTestApplier(t *testing.T, ap applier, name string) {
	t.Helper()
	prev := pickApplierForTest
	pickApplierForTest = func() (applier, string, error) { return ap, name, nil }
	t.Cleanup(func() { pickApplierForTest = prev })
}

func withTestAutoderive(t *testing.T, fn func() (string, error)) {
	t.Helper()
	prev := autoderiveMgmtSubnetForTest
	autoderiveMgmtSubnetForTest = fn
	t.Cleanup(func() { autoderiveMgmtSubnetForTest = prev })
}

func TestResolveMgmtSubnet_ExplicitCIDR(t *testing.T) {
	t.Parallel()
	cidr, derived, err := resolveMgmtSubnet("172.31.0.0/16")
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if cidr != "172.31.0.0/16" {
		t.Errorf("cidr = %q, want round-trip", cidr)
	}
	if derived {
		t.Errorf("derived = true, want false for explicit CIDR")
	}
}

func TestResolveMgmtSubnet_BadCIDR(t *testing.T) {
	t.Parallel()
	_, _, err := resolveMgmtSubnet("not-a-cidr")
	if err == nil || !strings.Contains(err.Error(), "not a CIDR") {
		t.Fatalf("err = %v, want CIDR parse error", err)
	}
}

func TestResolveMgmtSubnet_AutoderiveSuccess(t *testing.T) {
	withTestAutoderive(t, func() (string, error) { return "10.0.0.0/24", nil })
	cidr, derived, err := resolveMgmtSubnet("")
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if cidr != "10.0.0.0/24" {
		t.Errorf("cidr = %q, want 10.0.0.0/24", cidr)
	}
	if !derived {
		t.Errorf("derived = false, want true")
	}
}

func TestResolveMgmtSubnet_AutoderiveFailure(t *testing.T) {
	withTestAutoderive(t, func() (string, error) {
		return "", &stubErr{"no default route"}
	})
	_, derived, err := resolveMgmtSubnet("  ")
	if err == nil {
		t.Fatal("err = nil, want autoderive failure")
	}
	if !derived {
		t.Errorf("derived = false on autoderive path, want true")
	}
	if !strings.Contains(err.Error(), "operator must supply explicit CIDR") {
		t.Errorf("err = %v, want operator hint", err)
	}
}

type stubErr struct{ msg string }

func (e *stubErr) Error() string { return e.msg }

func TestDefaultRouteIface_FixturePicksDefault(t *testing.T) {
	t.Parallel()
	// /proc/net/route format: header line then space-separated fields.
	// Default route has Destination "00000000".
	fixture := `Iface	Destination	Gateway	Flags	RefCnt	Use	Metric	Mask	MTU	Window	IRTT
eth0	00000000	0102030A	0003	0	0	100	00000000	0	0	0
eth0	0002000A	00000000	0001	0	0	100	00FFFFFF	0	0	0
`
	dir := t.TempDir()
	path := filepath.Join(dir, "route")
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	iface, err := defaultRouteIface(path)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if iface != "eth0" {
		t.Errorf("iface = %q, want eth0", iface)
	}
}

func TestDefaultRouteIface_NoDefault(t *testing.T) {
	t.Parallel()
	fixture := `Iface	Destination	Gateway	Flags	RefCnt	Use	Metric	Mask	MTU	Window	IRTT
eth0	0002000A	00000000	0001	0	0	100	00FFFFFF	0	0	0
`
	dir := t.TempDir()
	path := filepath.Join(dir, "route")
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := defaultRouteIface(path)
	if err == nil || !strings.Contains(err.Error(), "no default route") {
		t.Errorf("err = %v, want no-default-route error", err)
	}
}

func TestDefaultRouteIface_MissingFile(t *testing.T) {
	t.Parallel()
	_, err := defaultRouteIface("/nonexistent/route")
	if err == nil {
		t.Fatal("err = nil, want open failure")
	}
}

func TestIsolateRuleSet_ContainsExpectedRules(t *testing.T) {
	t.Parallel()
	rs := isolateRuleSet("172.31.0.0/16")
	if len(rs) == 0 {
		t.Fatal("ruleset empty")
	}
	// First call must create the chain.
	if rs[0][1] != "-N" || rs[0][2] != isolationChain {
		t.Errorf("rs[0] = %v, want -N slither-isolation", rs[0])
	}
	// Mgmt subnet must appear as both -s and -d.
	var sawSrc, sawDst, sawDrop bool
	for _, c := range rs {
		joined := strings.Join(c, " ")
		if strings.Contains(joined, "-s 172.31.0.0/16") {
			sawSrc = true
		}
		if strings.Contains(joined, "-d 172.31.0.0/16") {
			sawDst = true
		}
		if strings.Contains(joined, "-j DROP") {
			sawDrop = true
		}
	}
	if !sawSrc {
		t.Error("missing -s mgmt rule")
	}
	if !sawDst {
		t.Error("missing -d mgmt rule")
	}
	if !sawDrop {
		t.Error("missing default DROP rule")
	}
}

func TestIsolateRuleSet_DropAfterAllows(t *testing.T) {
	t.Parallel()
	rs := isolateRuleSet("10.0.0.0/24")
	dropIdx := -1
	lastAllowIdx := -1
	for i, c := range rs {
		joined := strings.Join(c, " ")
		// Look only at chain-build rules, not the INPUT/OUTPUT hooks.
		if !strings.Contains(joined, "-A "+isolationChain) {
			continue
		}
		if strings.HasSuffix(joined, "-j DROP") {
			dropIdx = i
		}
		if strings.HasSuffix(joined, "-j ACCEPT") {
			lastAllowIdx = i
		}
	}
	if dropIdx < 0 || lastAllowIdx < 0 {
		t.Fatalf("dropIdx=%d lastAllowIdx=%d, want both >= 0", dropIdx, lastAllowIdx)
	}
	if dropIdx < lastAllowIdx {
		t.Errorf("DROP rule at %d precedes last ACCEPT at %d — would block mgmt traffic", dropIdx, lastAllowIdx)
	}
}

func TestUnisolateRuleSet_DeletesChain(t *testing.T) {
	t.Parallel()
	rs := unisolateRuleSet()
	last := rs[len(rs)-1]
	if last[1] != "-X" || last[2] != isolationChain {
		t.Errorf("final cmd = %v, want -X slither-isolation", last)
	}
	// -F must run before -X (kernel rejects deletion of non-empty chain).
	flushIdx, deleteIdx := -1, -1
	for i, c := range rs {
		if c[1] == "-F" && c[2] == isolationChain {
			flushIdx = i
		}
		if c[1] == "-X" && c[2] == isolationChain {
			deleteIdx = i
		}
	}
	if flushIdx >= deleteIdx || flushIdx < 0 || deleteIdx < 0 {
		t.Errorf("flushIdx=%d deleteIdx=%d, want flush before delete", flushIdx, deleteIdx)
	}
}

func TestIsolateHostHandler_HappyPath(t *testing.T) {
	rec := &recordedApplier{}
	withTestApplier(t, rec, "iptables")

	h := IsolateHostHandler()
	status, detail, _ := h(context.Background(), &pb.ResponseRequest{Target: "172.31.0.0/16"})
	if status != pb.ResponseStatus_RESPONSE_STATUS_DONE {
		t.Fatalf("status = %s, detail = %q, want DONE", status, detail)
	}
	if !strings.Contains(detail, "172.31.0.0/16") {
		t.Errorf("detail = %q, want mgmt subnet", detail)
	}
	if len(rec.snapshot()) != len(isolateRuleSet("172.31.0.0/16")) {
		t.Errorf("call count = %d, want %d", len(rec.snapshot()), len(isolateRuleSet("172.31.0.0/16")))
	}
}

func TestIsolateHostHandler_BadCIDR(t *testing.T) {
	rec := &recordedApplier{}
	withTestApplier(t, rec, "iptables")
	h := IsolateHostHandler()
	status, detail, _ := h(context.Background(), &pb.ResponseRequest{Target: "garbage"})
	if status != pb.ResponseStatus_RESPONSE_STATUS_FAILED {
		t.Fatalf("status = %s, want FAILED", status)
	}
	if !strings.Contains(detail, "not a CIDR") {
		t.Errorf("detail = %q, want CIDR error", detail)
	}
	if len(rec.snapshot()) != 0 {
		t.Errorf("applier called %d times on bad CIDR, want 0", len(rec.snapshot()))
	}
}

func TestIsolateHostHandler_AutoderiveDetail(t *testing.T) {
	rec := &recordedApplier{}
	withTestApplier(t, rec, "iptables")
	withTestAutoderive(t, func() (string, error) { return "10.0.0.0/24", nil })
	h := IsolateHostHandler()
	status, detail, _ := h(context.Background(), &pb.ResponseRequest{Target: ""})
	if status != pb.ResponseStatus_RESPONSE_STATUS_DONE {
		t.Fatalf("status = %s, detail = %q, want DONE", status, detail)
	}
	if !strings.Contains(detail, "autoderived") {
		t.Errorf("detail = %q, want autoderive marker", detail)
	}
}

func TestIsolateHostHandler_ApplierFailureSurfaces(t *testing.T) {
	rec := &recordedApplier{fail: map[int]error{2: &stubErr{"perm denied"}}}
	withTestApplier(t, rec, "iptables")
	h := IsolateHostHandler()
	status, detail, _ := h(context.Background(), &pb.ResponseRequest{Target: "10.0.0.0/24"})
	if status != pb.ResponseStatus_RESPONSE_STATUS_FAILED {
		t.Fatalf("status = %s, want FAILED", status)
	}
	if !strings.Contains(detail, "perm denied") {
		t.Errorf("detail = %q, want underlying error", detail)
	}
}

func TestUnisolateHostHandler_BestEffortSwallowsErrors(t *testing.T) {
	// Every call fails — handler should still report DONE because
	// unisolate is best-effort (operator may be running it twice or
	// against a never-isolated host).
	rec := &recordedApplier{fail: map[int]error{
		0: &stubErr{"no such rule"},
		1: &stubErr{"no such rule"},
		2: &stubErr{"no such rule"},
		3: &stubErr{"no such rule"},
		4: &stubErr{"no such chain"},
		5: &stubErr{"no such chain"},
	}}
	withTestApplier(t, rec, "iptables")
	h := UnisolateHostHandler()
	status, _, _ := h(context.Background(), &pb.ResponseRequest{})
	if status != pb.ResponseStatus_RESPONSE_STATUS_DONE {
		t.Fatalf("status = %s, want DONE (best-effort)", status)
	}
	if got := len(rec.snapshot()); got != len(unisolateRuleSet()) {
		t.Errorf("call count = %d, want %d", got, len(unisolateRuleSet()))
	}
}
