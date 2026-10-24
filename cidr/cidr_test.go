package cidr_test

import (
	"net/netip"
	"testing"

	"github.com/Subhanmalik138/go-cidr-calculator/cidr"
)

func TestParseNormalisesHostBits(t *testing.T) {
	n, err := cidr.Parse("192.168.1.37/24")
	if err != nil {
		t.Fatal(err)
	}
	if got := n.String(); got != "192.168.1.0/24" {
		t.Fatalf("got %q, want %q", got, "192.168.1.0/24")
	}
}

func TestParseRejectsBadInput(t *testing.T) {
	for _, bad := range []string{"", "192.168.1.0", "192.168.1.0/33", "10.0.0.0/-1", "not-an-ip/24"} {
		if _, err := cidr.Parse(bad); err == nil {
			t.Errorf("Parse(%q): expected error, got nil", bad)
		}
	}
}

func TestNetworkBroadcastAndHosts(t *testing.T) {
	cases := []struct {
		input       string
		network     string
		broadcast   string
		first, last string
		total       string
		usable      string
		mask        string
		wildcard    string
	}{
		{"192.168.1.0/24", "192.168.1.0", "192.168.1.255", "192.168.1.1", "192.168.1.254", "256", "254", "255.255.255.0", "0.0.0.255"},
		{"10.0.0.0/8", "10.0.0.0", "10.255.255.255", "10.0.0.1", "10.255.255.254", "16777216", "16777214", "255.0.0.0", "0.255.255.255"},
		{"192.168.1.0/30", "192.168.1.0", "192.168.1.3", "192.168.1.1", "192.168.1.2", "4", "2", "255.255.255.252", "0.0.0.3"},
		// RFC 3021: both addresses of a /31 are usable.
		{"192.168.1.0/31", "192.168.1.0", "192.168.1.1", "192.168.1.0", "192.168.1.1", "2", "2", "255.255.255.254", "0.0.0.1"},
		{"192.168.1.5/32", "192.168.1.5", "192.168.1.5", "192.168.1.5", "192.168.1.5", "1", "1", "255.255.255.255", "0.0.0.0"},
		{"172.16.5.130/25", "172.16.5.128", "172.16.5.255", "172.16.5.129", "172.16.5.254", "128", "126", "255.255.255.128", "0.0.0.127"},
	}
	for _, c := range cases {
		n := cidr.MustParse(c.input)
		b, err := n.Broadcast()
		if err != nil {
			t.Fatalf("%s: Broadcast: %v", c.input, err)
		}
		if b.String() != c.broadcast {
			t.Errorf("%s: broadcast = %s, want %s", c.input, b, c.broadcast)
		}
		if n.NetworkAddress().String() != c.network {
			t.Errorf("%s: network = %s, want %s", c.input, n.NetworkAddress(), c.network)
		}
		if n.FirstUsable().String() != c.first {
			t.Errorf("%s: first usable = %s, want %s", c.input, n.FirstUsable(), c.first)
		}
		if n.LastUsable().String() != c.last {
			t.Errorf("%s: last usable = %s, want %s", c.input, n.LastUsable(), c.last)
		}
		if n.TotalAddresses().String() != c.total {
			t.Errorf("%s: total = %s, want %s", c.input, n.TotalAddresses(), c.total)
		}
		if n.UsableHostCount().String() != c.usable {
			t.Errorf("%s: usable = %s, want %s", c.input, n.UsableHostCount(), c.usable)
		}
		if n.Mask().String() != c.mask {
			t.Errorf("%s: mask = %s, want %s", c.input, n.Mask(), c.mask)
		}
		if n.WildcardMask().String() != c.wildcard {
			t.Errorf("%s: wildcard = %s, want %s", c.input, n.WildcardMask(), c.wildcard)
		}
	}
}

func TestIPv6(t *testing.T) {
	n := cidr.MustParse("2001:db8::/126")
	if _, err := n.Broadcast(); err == nil {
		t.Error("Broadcast on IPv6: expected error, got nil")
	}
	first, last := n.Range()
	if first.String() != "2001:db8::" || last.String() != "2001:db8::3" {
		t.Errorf("range = %s-%s, want 2001:db8::-2001:db8::3", first, last)
	}
	if n.TotalAddresses().String() != "4" || n.UsableHostCount().String() != "4" {
		t.Errorf("IPv6 /126 counts: total=%s usable=%s, want 4/4", n.TotalAddresses(), n.UsableHostCount())
	}
	if n.Mask().String() != "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffc" {
		t.Errorf("IPv6 mask = %s", n.Mask())
	}
	// A /64 holds 2^64 addresses — big.Int, not a wrapped uint64.
	big := cidr.MustParse("2001:db8::/64")
	if big.TotalAddresses().String() != "18446744073709551616" {
		t.Errorf("/64 total = %s", big.TotalAddresses())
	}
}

func TestContains(t *testing.T) {
	n := cidr.MustParse("10.0.0.0/8")
	for _, ip := range []string{"10.0.0.1", "10.255.255.255"} {
		if !n.Contains(netip.MustParseAddr(ip)) {
			t.Errorf("expected %s to be contained", ip)
		}
	}
	for _, ip := range []string{"11.0.0.1", "9.255.255.255"} {
		if n.Contains(netip.MustParseAddr(ip)) {
			t.Errorf("expected %s NOT to be contained", ip)
		}
	}
	if !n.ContainsNetwork(cidr.MustParse("10.1.2.0/24")) {
		t.Error("expected 10.1.2.0/24 to be contained in 10.0.0.0/8")
	}
	if n.ContainsNetwork(cidr.MustParse("11.0.0.0/8")) {
		t.Error("expected 11.0.0.0/8 NOT to be contained in 10.0.0.0/8")
	}
}

func TestSubnets(t *testing.T) {
	n := cidr.MustParse("192.168.0.0/24")
	subs, err := n.Subnets(26)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"192.168.0.0/26", "192.168.0.64/26", "192.168.0.128/26", "192.168.0.192/26"}
	if len(subs) != len(want) {
		t.Fatalf("got %d subnets, want %d", len(subs), len(want))
	}
	for i, w := range want {
		if subs[i].String() != w {
			t.Errorf("subnet %d = %s, want %s", i, subs[i], w)
		}
	}
	// Non-byte-boundary split.
	subs, err = cidr.MustParse("10.0.0.0/23").Subnets(25)
	if err != nil {
		t.Fatal(err)
	}
	if subs[0].String() != "10.0.0.0/25" || subs[3].String() != "10.0.1.128/25" {
		t.Errorf("unexpected /23 -> /25 split: %v", subs)
	}
	for _, bad := range []int{24, 23, 33} {
		if _, err := n.Subnets(bad); err == nil {
			t.Errorf("Subnets(%d): expected error", bad)
		}
	}
	// The cap must stop absurd splits instead of allocating them.
	if _, err := cidr.MustParse("10.0.0.0/8").Subnets(25); err == nil {
		t.Error("Subnets /8 -> /25: expected cap error")
	}
}

func TestSupernet(t *testing.T) {
	s, err := cidr.MustParse("192.168.1.64/26").Supernet(24)
	if err != nil {
		t.Fatal(err)
	}
	if s.String() != "192.168.1.0/24" {
		t.Errorf("supernet = %s, want 192.168.1.0/24", s)
	}
	if _, err := cidr.MustParse("192.168.1.0/24").Supernet(24); err == nil {
		t.Error("Supernet with equal length: expected error")
	}
	if _, err := cidr.MustParse("192.168.1.0/24").Supernet(25); err == nil {
		t.Error("Supernet with longer length: expected error")
	}
}
