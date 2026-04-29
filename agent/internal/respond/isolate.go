//go:build linux

package respond

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"

	pb "github.com/t3rmit3/slither/proto/gen/slither/v1"
)

// isolationChain is the netfilter chain the agent installs on
// isolate. Named so manual `iptables -L` / `nft list ruleset` reads
// surface "this is slither's doing" without grep-fu. Phase 4 #80.
const isolationChain = "slither-isolation"

// applier is the iptables/nft seam. Production wires it to
// shellApplier (which exec's the actual binary); tests stub a
// recordedApplier that captures the argv list so the rule shapes
// can be asserted without root or netfilter.
type applier interface {
	Run(ctx context.Context, argv ...string) error
}

// IsolateHostHandler returns the isolate handler. Wired by
// WireIsolationHandlers at startup. Phase 4 #80.
func IsolateHostHandler() Handler {
	return func(ctx context.Context, req *pb.ResponseRequest) (pb.ResponseStatus, string, []byte) {
		mgmt, derived, err := resolveMgmtSubnet(req.GetTarget())
		if err != nil {
			return pb.ResponseStatus_RESPONSE_STATUS_FAILED, err.Error(), nil
		}
		ap, name, err := pickApplier()
		if err != nil {
			return pb.ResponseStatus_RESPONSE_STATUS_FAILED, err.Error(), nil
		}
		if err := isolateApply(ctx, ap, mgmt); err != nil {
			return pb.ResponseStatus_RESPONSE_STATUS_FAILED, err.Error(), nil
		}
		detail := fmt.Sprintf("isolated host: mgmt_subnet=%s applier=%s", mgmt, name)
		if derived {
			detail += " (autoderived from /proc/net/route)"
		}
		return pb.ResponseStatus_RESPONSE_STATUS_DONE, detail, nil
	}
}

// UnisolateHostHandler returns the un-isolate handler. Allowed
// whenever AllowIsolate is — reverse actions inherit per ADR-0034.
func UnisolateHostHandler() Handler {
	return func(ctx context.Context, req *pb.ResponseRequest) (pb.ResponseStatus, string, []byte) {
		_ = req
		ap, name, err := pickApplier()
		if err != nil {
			return pb.ResponseStatus_RESPONSE_STATUS_FAILED, err.Error(), nil
		}
		unisolateApply(ctx, ap)
		return pb.ResponseStatus_RESPONSE_STATUS_DONE,
			fmt.Sprintf("un-isolated host (applier=%s)", name), nil
	}
}

// resolveMgmtSubnet returns (cidr, autoderivedFlag, err). Empty
// target ⇒ derive from /proc/net/route's default route. Explicit
// target must parse as a netip.Prefix.
func resolveMgmtSubnet(target string) (cidr string, autoderived bool, err error) {
	target = strings.TrimSpace(target)
	if target != "" {
		if _, perr := netip.ParsePrefix(target); perr != nil {
			return "", false, fmt.Errorf("mgmt_subnet %q is not a CIDR: %w", target, perr)
		}
		return target, false, nil
	}
	cidr, err = autoderiveMgmtSubnet()
	if err != nil {
		return "", true, fmt.Errorf("mgmt_subnet autoderive: %w (operator must supply explicit CIDR)", err)
	}
	return cidr, true, nil
}

// autoderiveMgmtSubnet reads /proc/net/route, finds the default
// route's interface, and returns the CIDR of that interface's
// primary IPv4 address. Test seam: autoderiveMgmtSubnetForTest
// overrides the whole call so unit tests don't need a real default
// route or interface.
func autoderiveMgmtSubnet() (string, error) {
	if autoderiveMgmtSubnetForTest != nil {
		return autoderiveMgmtSubnetForTest()
	}
	iface, err := defaultRouteIface("/proc/net/route")
	if err != nil {
		return "", err
	}
	cidr, err := primaryIPv4CIDR(iface)
	if err != nil {
		return "", err
	}
	return cidr, nil
}

var autoderiveMgmtSubnetForTest func() (string, error)

// defaultRouteIface parses /proc/net/route. The kernel writes one
// line per route; the default route is the row whose Destination
// column is "00000000". The Iface column is the interface name.
// Path is parameterized so tests can feed a fixture.
func defaultRouteIface(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // path is constant in production; parameterized for unit tests
	if err != nil {
		return "", err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue
		}
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 {
			continue
		}
		if fields[1] == "00000000" {
			return fields[0], nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "", errors.New("no default route in /proc/net/route")
}

// primaryIPv4CIDR returns the first non-link-local IPv4 address +
// prefix on iface, masked to the network ("<network>/<prefix>"). The
// masked form is what iptables -s wants.
func primaryIPv4CIDR(iface string) (string, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return "", fmt.Errorf("lookup iface %q: %w", iface, err)
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return "", fmt.Errorf("addrs for iface %q: %w", iface, err)
	}
	for _, a := range addrs {
		prefix, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}
		if !prefix.Addr().Is4() {
			continue
		}
		if prefix.Addr().IsLinkLocalUnicast() || prefix.Addr().IsLoopback() {
			continue
		}
		return prefix.Masked().String(), nil
	}
	return "", fmt.Errorf("no usable IPv4 on iface %q", iface)
}

// isolateApply pushes the slither-isolation chain via ap.
func isolateApply(ctx context.Context, ap applier, mgmt string) error {
	for _, c := range isolateRuleSet(mgmt) {
		if err := ap.Run(ctx, c...); err != nil {
			return fmt.Errorf("apply %v: %w", c, err)
		}
	}
	return nil
}

// unisolateApply removes the slither-isolation chain. Best-effort —
// errors on intermediate -D calls are swallowed because the operator
// may run unisolate twice or against a never-isolated host.
func unisolateApply(ctx context.Context, ap applier) {
	for _, c := range unisolateRuleSet() {
		_ = ap.Run(ctx, c...)
	}
}

// isolateRuleSet is a pure function so unit tests can pin the exact
// argv set. Order matters: create chain → flush → allow lo →
// allow established/related → allow mgmt subnet (both directions) →
// default DROP → hook from INPUT/OUTPUT.
//
// The hook is installed with -I (insert at position 1) rather than
// -A so the chain runs before any pre-existing accept rules. A
// re-run will produce a duplicate hook; both fire the same chain and
// one DROP is one DROP, so the duplicate is harmless. Phase 5 may
// revisit with -C/-D dedupe if accumulation hurts.
func isolateRuleSet(mgmt string) [][]string {
	return [][]string{
		{"iptables", "-N", isolationChain},
		{"iptables", "-F", isolationChain},
		{"iptables", "-A", isolationChain, "-i", "lo", "-j", "ACCEPT"},
		{"iptables", "-A", isolationChain, "-o", "lo", "-j", "ACCEPT"},
		{"iptables", "-A", isolationChain, "-m", "conntrack",
			"--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},
		{"iptables", "-A", isolationChain, "-s", mgmt, "-j", "ACCEPT"},
		{"iptables", "-A", isolationChain, "-d", mgmt, "-j", "ACCEPT"},
		{"iptables", "-A", isolationChain, "-j", "DROP"},
		{"iptables", "-I", "INPUT", "1", "-j", isolationChain},
		{"iptables", "-I", "OUTPUT", "1", "-j", isolationChain},
	}
}

// unisolateRuleSet reverses isolateRuleSet. Multiple -D calls dedupe
// any doubled hook from re-isolation; trailing -F + -X drop the chain.
func unisolateRuleSet() [][]string {
	return [][]string{
		{"iptables", "-D", "INPUT", "-j", isolationChain},
		{"iptables", "-D", "INPUT", "-j", isolationChain},
		{"iptables", "-D", "OUTPUT", "-j", isolationChain},
		{"iptables", "-D", "OUTPUT", "-j", isolationChain},
		{"iptables", "-F", isolationChain},
		{"iptables", "-X", isolationChain},
	}
}

// pickApplier returns a shellApplier wrapping iptables when present.
// nft-native isolation is deferred to Phase 5; iptables-nft shim
// covers RHEL 10 + Debian 12 + Ubuntu 24 in v1.
//
// Tests override pickApplierForTest to return a recorded mock.
func pickApplier() (applier, string, error) {
	if pickApplierForTest != nil {
		return pickApplierForTest()
	}
	if path, err := exec.LookPath("iptables"); err == nil {
		return &shellApplier{path: path}, "iptables", nil
	}
	if _, err := exec.LookPath("nft"); err == nil {
		return nil, "", errors.New("iptables not found; nft-native isolate rules are deferred to Phase 5")
	}
	return nil, "", errors.New("neither iptables nor nft available — cannot isolate")
}

// pickApplierForTest is the test override for pickApplier. Set in
// _test.go files; production keeps it nil.
var pickApplierForTest func() (applier, string, error)

// shellApplier exec's iptables with the supplied argv. Combined
// stdout+stderr is folded into the returned error so the FAILED
// ResponseResult carries iptables' diagnostic.
type shellApplier struct {
	path string
}

func (s *shellApplier) Run(ctx context.Context, argv ...string) error {
	// gosec G204: argv is constructed from isolateRuleSet/unisolateRuleSet
	// (constants + an operator-validated CIDR). Path is exec.LookPath-resolved.
	cmd := exec.CommandContext(ctx, s.path, argv...) //nolint:gosec // path is exec.LookPath-resolved, argv is from the constant ruleset functions
	out, err := cmd.CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(out))
		if trimmed != "" {
			return fmt.Errorf("%w: %s", err, trimmed)
		}
		return err
	}
	return nil
}
