// Package cidr is a dependency-free IPv4/IPv6 subnet calculator.
//
// It wraps the standard library's net/netip package with the operations
// network engineers actually reach for: network and broadcast addresses,
// usable host ranges and counts, subnet splitting, and supernetting.
// All arithmetic is done on masked prefixes, so host bits in the input
// are never silently treated as part of the network address — Parse
// normalises them (see Parse) and the normalised address is what every
// method reports.
//
// IPv6 has no broadcast address, so Broadcast returns an error for IPv6
// networks rather than inventing one. Usable-host counts for IPv6 are
// returned as *big.Int because a /64 alone holds 2^64 addresses.
package cidr

import (
	"errors"
	"fmt"
	"math/big"
	"net/netip"
)

// Network is a single IP network described by a masked prefix.
type Network struct {
	prefix netip.Prefix
}

// Parse parses s as a CIDR prefix such as "192.168.1.37/24" or
// "2001:db8::/32" and returns the network it belongs to. Host bits in
// the address are masked off, so Parse("192.168.1.37/24") and
// Parse("192.168.1.0/24") return the same network. An unmasked,
// unparseable, or non-prefixed input is an error.
func Parse(s string) (Network, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return Network{}, fmt.Errorf("parse CIDR %q: %w", s, err)
	}
	p = p.Masked()
	return Network{prefix: p}, nil
}

// MustParse is Parse, panicking on error. It is for tests and
// package-level examples only; library callers should use Parse.
func MustParse(s string) Network {
	n, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return n
}

// String returns the canonical "address/prefix-length" form.
func (n Network) String() string { return n.prefix.String() }

// Prefix returns the underlying masked netip.Prefix.
func (n Network) Prefix() netip.Prefix { return n.prefix }

// Bits returns the prefix length and the address size in bits
// (32 for IPv4, 128 for IPv6).
func (n Network) Bits() (ones, total int) {
	ones = n.prefix.Bits()
	total = 32
	if n.prefix.Addr().Is6() {
		total = 128
	}
	return ones, total
}

// IsIPv4 reports whether the network is an IPv4 network.
func (n Network) IsIPv4() bool { return n.prefix.Addr().Is4() }

// IsIPv6 reports whether the network is an IPv6 network.
func (n Network) IsIPv6() bool { return n.prefix.Addr().Is6() }

// NetworkAddress returns the first address of the network — the
// address with all host bits zeroed.
func (n Network) NetworkAddress() netip.Addr { return n.prefix.Addr() }

// Mask returns the subnet mask in dotted-decimal (IPv4) or colon
// notation (IPv6).
func (n Network) Mask() netip.Addr {
	ones, total := n.Bits()
	if total == 32 {
		var v4 [4]byte
		full := ones / 8
		for i := 0; i < full; i++ {
			v4[i] = 0xff
		}
		if rem := ones % 8; rem != 0 {
			v4[full] = 0xff << (8 - rem)
		}
		return netip.AddrFrom4(v4)
	}
	var b [16]byte
	full := ones / 8
	for i := 0; i < full; i++ {
		b[i] = 0xff
	}
	if rem := ones % 8; rem != 0 {
		b[full] = 0xff << (8 - rem)
	}
	return netip.AddrFrom16(b)
}

// WildcardMask returns the inverse of the subnet mask: every host bit
// set, every network bit clear.
func (n Network) WildcardMask() netip.Addr {
	ones, total := n.Bits()
	if total == 32 {
		var v4 [4]byte
		for i := 0; i < 4; i++ {
			v4[i] = 0xff
		}
		full := ones / 8
		for i := 0; i < full; i++ {
			v4[i] = 0
		}
		if rem := ones % 8; rem != 0 {
			v4[full] = ^(0xff << (8 - rem))
		}
		return netip.AddrFrom4(v4)
	}
	var b [16]byte
	for i := 0; i < 16; i++ {
		b[i] = 0xff
	}
	full := ones / 8
	for i := 0; i < full; i++ {
		b[i] = 0
	}
	if rem := ones % 8; rem != 0 {
		b[full] = ^(0xff << (8 - rem))
	}
	return netip.AddrFrom16(b)
}

// Broadcast returns the last address of the network (all host bits set).
// It is an IPv4-only concept: for IPv6 it returns an error, because
// IPv6 has no broadcast address.
func (n Network) Broadcast() (netip.Addr, error) {
	if !n.IsIPv4() {
		return netip.Addr{}, errors.New("broadcast address is undefined for IPv6")
	}
	return n.lastAddress(), nil
}

// Range returns the first and last addresses of the network. For IPv4
// the last address is the broadcast address; for IPv6 it is simply the
// highest address in the prefix.
func (n Network) Range() (first, last netip.Addr) {
	return n.prefix.Addr(), n.lastAddress()
}

// FirstUsable returns the first assignable host address. For IPv4 /31
// networks (RFC 3021 point-to-point links) both addresses are usable,
// so it returns the network address; for /32 it returns the single
// address. For IPv6 there is no reserved network/broadcast address, so
// it returns the network address.
func (n Network) FirstUsable() netip.Addr {
	ones, total := n.Bits()
	if n.IsIPv4() && ones < total-1 {
		return n.prefix.Addr().Next()
	}
	return n.prefix.Addr()
}

// LastUsable returns the last assignable host address. For IPv4 /31 it
// returns the broadcast address (both usable per RFC 3021); for /32 the
// single address; otherwise the address before broadcast. For IPv6 it
// returns the last address of the prefix.
func (n Network) LastUsable() netip.Addr {
	ones, total := n.Bits()
	if n.IsIPv4() && ones < total-1 {
		return n.lastAddress().Prev()
	}
	return n.lastAddress()
}

// TotalAddresses returns how many addresses the prefix holds (2^hostBits).
func (n Network) TotalAddresses() *big.Int {
	ones, total := n.Bits()
	return new(big.Int).Lsh(big.NewInt(1), uint(total-ones))
}

// UsableHostCount returns how many addresses can be assigned to hosts.
// IPv4 reserves the network and broadcast addresses except for /31
// (RFC 3021: both usable) and /32 (the single host). IPv6 reserves
// nothing, so the usable count equals the total count.
func (n Network) UsableHostCount() *big.Int {
	total := n.TotalAddresses()
	if !n.IsIPv4() {
		return total
	}
	ones, _ := n.Bits()
	switch {
	case ones >= 31:
		return total // /31: 2 usable, /32: 1 usable
	default:
		return new(big.Int).Sub(total, big.NewInt(2))
	}
}

// Contains reports whether addr lies inside the network.
func (n Network) Contains(addr netip.Addr) bool {
	return n.prefix.Contains(addr)
}

// ContainsNetwork reports whether other is fully contained in n.
func (n Network) ContainsNetwork(other Network) bool {
	ones, _ := n.Bits()
	oOnes, _ := other.Bits()
	return ones <= oOnes && n.prefix.Contains(other.prefix.Addr())
}

// Subnets splits n into subnets of prefix length newBits. newBits must
// be longer than the current prefix length, and the split must produce
// at most maxSubnets (see MaxSubnets) subnets, otherwise an error is
// returned instead of materialising a huge slice.
func (n Network) Subnets(newBits int) ([]Network, error) {
	ones, total := n.Bits()
	if newBits <= ones {
		return nil, fmt.Errorf("subnet prefix /%d must be longer than /%d", newBits, ones)
	}
	if newBits > total {
		return nil, fmt.Errorf("subnet prefix /%d exceeds address size /%d", newBits, total)
	}
	count := 1 << uint(newBits-ones)
	if count > MaxSubnets {
		return nil, fmt.Errorf("splitting /%d into /%d would create %d subnets (max %d)", ones, newBits, count, MaxSubnets)
	}
	out := make([]Network, 0, count)
	base := n.prefix.Addr()
	for i := 0; i < count; i++ {
		addr := addOffset(base, uint64(i)<<uint(total-newBits))
		out = append(out, Network{prefix: netip.PrefixFrom(addr, newBits)})
	}
	return out, nil
}

// MaxSubnets caps Subnets so a careless /0 -> /32 split cannot try to
// allocate billions of entries.
const MaxSubnets = 65536

// Supernet returns the network that contains n with prefix length
// newBits. newBits must be shorter than the current prefix length.
func (n Network) Supernet(newBits int) (Network, error) {
	ones, total := n.Bits()
	if newBits >= ones {
		return Network{}, fmt.Errorf("supernet prefix /%d must be shorter than /%d", newBits, ones)
	}
	if newBits < 0 || newBits > total {
		return Network{}, fmt.Errorf("supernet prefix /%d out of range", newBits)
	}
	return Network{prefix: netip.PrefixFrom(n.prefix.Addr(), newBits).Masked()}, nil
}

// lastAddress returns the highest address in the prefix.
func (n Network) lastAddress() netip.Addr {
	_, total := n.Bits()
	ones, _ := n.Bits()
	hostBits := total - ones
	if n.IsIPv4() {
		a := n.prefix.Addr().As4()
		v := uint64(a[0])<<24 | uint64(a[1])<<16 | uint64(a[2])<<8 | uint64(a[3])
		if hostBits == 32 {
			v = 0xffffffff
		} else {
			v |= (uint64(1) << uint(hostBits)) - 1
		}
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	}
	a := n.prefix.Addr().As16()
	lo, hi := uint64(0), uint64(0)
	for i := 0; i < 8; i++ {
		hi = hi<<8 | uint64(a[i])
	}
	for i := 8; i < 16; i++ {
		lo = lo<<8 | uint64(a[i])
	}
	if hostBits >= 64 {
		if hostBits == 128 {
			hi = ^uint64(0)
		} else {
			hi |= (uint64(1) << uint(hostBits-64)) - 1
		}
		lo = ^uint64(0)
	} else {
		lo |= (1 << uint(hostBits)) - 1
	}
	var out [16]byte
	for i := 7; i >= 0; i-- {
		out[i] = byte(hi)
		hi >>= 8
	}
	for i := 15; i >= 8; i-- {
		out[i] = byte(lo)
		lo >>= 8
	}
	return netip.AddrFrom16(out)
}

// addOffset returns addr advanced by offset addresses. It is used by
// Subnets, where offset always stays inside the parent prefix.
func addOffset(addr netip.Addr, offset uint64) netip.Addr {
	if addr.Is4() {
		a := addr.As4()
		v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
		v += uint32(offset)
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
	}
	a := addr.As16()
	lo, hi := uint64(0), uint64(0)
	for i := 0; i < 8; i++ {
		hi = hi<<8 | uint64(a[i])
	}
	for i := 8; i < 16; i++ {
		lo = lo<<8 | uint64(a[i])
	}
	lo += offset
	if lo < offset { // wrapped past 2^64
		hi++
	}
	var out [16]byte
	h, l := hi, lo
	for i := 7; i >= 0; i-- {
		out[i] = byte(h)
		h >>= 8
	}
	for i := 15; i >= 8; i-- {
		out[i] = byte(l)
		l >>= 8
	}
	return netip.AddrFrom16(out)
}
