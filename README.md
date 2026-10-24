# go-cidr-calculator

A dependency-free IPv4/IPv6 subnet calculator: a Go library plus a small
CLI. Given a CIDR block it reports the network and broadcast addresses,
the usable host range, host counts, and masks — and it can split a block
into subnets or roll it up into a supernet.

## The problem

Subnet math is easy to get subtly wrong: host bits that were never
masked off, the /31 point-to-point exception, broadcast vs. last-usable
confusion, and IPv6 counts that overflow 64 bits. This package puts those
edge cases in one tested place, built on the standard library's
`net/netip` types instead of string hacking.

## Design decisions

1. **netip, not strings.** Addresses and prefixes are `netip.Addr` /
   `netip.Prefix` throughout, so parsing, comparison, and masking are
   the standard library's, not hand-rolled byte code. The only manual
   arithmetic is last-address computation and subnet stepping, both
   covered by table tests.
2. **Parse normalises, never surprises.** `Parse("192.168.1.37/24")`
   returns `192.168.1.0/24` — the network the address belongs to — so a
   caller can never accidentally treat host bits as network bits.
3. **IPv6 is honest, not faked.** There is no broadcast address in IPv6,
   so `Broadcast` returns an error for IPv6 instead of a plausible-
   looking wrong answer. Host counts are `*big.Int` because a /64 alone
   holds 2^64 addresses.
4. **RFC 3021 /31 handling.** A /31 has two usable addresses (no
   network/broadcast reservation on point-to-point links); a /32 has
   one. Every other IPv4 prefix reserves both ends.
5. **A cap on subnet splits.** Splitting /8 into /25 would mean 131,072
   subnets, so `Subnets` refuses anything over 65,536 rather than
   allocating it.

## Library usage

```go
import "github.com/Subhanmalik138/go-cidr-calculator/cidr"

n, err := cidr.Parse("192.168.1.0/24")
if err != nil {
    log.Fatal(err)
}
fmt.Println(n.NetworkAddress())  // 192.168.1.0
b, _ := n.Broadcast()            // 192.168.1.255
fmt.Println(n.FirstUsable())     // 192.168.1.1
fmt.Println(n.LastUsable())      // 192.168.1.254
fmt.Println(n.UsableHostCount()) // 254
fmt.Println(n.Mask())            // 255.255.255.0
fmt.Println(n.WildcardMask())    // 0.0.0.255

subs, _ := n.Subnets(26)         // four /26 networks
super, _ := n.Supernet(16)       // 192.168.0.0/16
fmt.Println(n.Contains(netip.MustParseAddr("192.168.1.200"))) // true
```

## CLI

```sh
go build -o cidr ./cmd/cidr

cidr info 192.168.1.0/24
# Network:        192.168.1.0/24
# Subnet mask:    255.255.255.0
# Wildcard mask:  0.0.0.255
# Broadcast:      192.168.1.255
# First usable:   192.168.1.1
# Last usable:    192.168.1.254
# Total hosts:    256
# Usable hosts:   254

cidr contains 10.0.0.0/8 10.4.2.1   # 10.4.2.1 is inside 10.0.0.0/8
cidr split 192.168.0.0/24 26          # four /26 subnets, one per line
cidr supernet 192.168.1.64/26 24     # 192.168.1.0/24
```

## Running the tests

```sh
go test ./...
go vet ./...
```

## Project layout

```
cidr/          library: parsing, masks, ranges, splits, supernets
cidr/*_test.go table-driven tests (IPv4 edge cases, IPv6, splits)
cmd/cidr/      CLI: info, contains, split, supernet
```

## Tech stack

Go 1.23, standard library only — no third-party dependencies.
