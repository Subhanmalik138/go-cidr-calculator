// Command cidr is a small subnet calculator built on the cidr package.
//
// Usage:
//
//	cidr info <cidr>              show network, broadcast, hosts, masks
//	cidr contains <cidr> <ip>     test whether ip is inside cidr
//	cidr split <cidr> <new-bits>  split cidr into /new-bits subnets
//	cidr supernet <cidr> <new-bits>  show the containing /new-bits network
package main

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"

	"github.com/Subhanmalik138/go-cidr-calculator/cidr"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "info":
		err = runInfo(os.Args[2:])
	case "contains":
		err = runContains(os.Args[2:])
	case "split":
		err = runSplit(os.Args[2:])
	case "supernet":
		err = runSupernet(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `cidr - IPv4/IPv6 subnet calculator

Usage:
  cidr info <cidr>              show network, broadcast, hosts, masks
  cidr contains <cidr> <ip>     test whether ip is inside cidr
  cidr split <cidr> <new-bits>  split cidr into /new-bits subnets
  cidr supernet <cidr> <new-bits>  show the containing /new-bits network
`)
}

func runInfo(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("info needs exactly one argument: cidr info <cidr>")
	}
	n, err := cidr.Parse(args[0])
	if err != nil {
		return err
	}
	ones, total := n.Bits()
	first, last := n.Range()
	fmt.Printf("Network:        %s\n", n)
	fmt.Printf("Address family: IPv%d (%d-bit, /%d)\n", familyBits(total), total, ones)
	fmt.Printf("Subnet mask:    %s\n", n.Mask())
	fmt.Printf("Wildcard mask:  %s\n", n.WildcardMask())
	fmt.Printf("Network:        %s\n", first)
	if b, err := n.Broadcast(); err == nil {
		fmt.Printf("Broadcast:      %s\n", b)
	} else {
		fmt.Printf("Broadcast:      n/a (IPv6 has no broadcast address)\n")
	}
	fmt.Printf("First usable:   %s\n", n.FirstUsable())
	fmt.Printf("Last usable:    %s\n", n.LastUsable())
	fmt.Printf("Last address:   %s\n", last)
	fmt.Printf("Total hosts:    %s\n", n.TotalAddresses())
	fmt.Printf("Usable hosts:   %s\n", n.UsableHostCount())
	return nil
}

func familyBits(total int) int {
	if total == 32 {
		return 4
	}
	return 6
}

func runContains(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("contains needs two arguments: cidr contains <cidr> <ip>")
	}
	n, err := cidr.Parse(args[0])
	if err != nil {
		return err
	}
	addr, err := netip.ParseAddr(args[1])
	if err != nil {
		return fmt.Errorf("parse IP %q: %w", args[1], err)
	}
	if n.Contains(addr) {
		fmt.Printf("%s is inside %s\n", addr, n)
	} else {
		fmt.Printf("%s is NOT inside %s\n", addr, n)
	}
	return nil
}

func runSplit(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("split needs two arguments: cidr split <cidr> <new-bits>")
	}
	n, err := cidr.Parse(args[0])
	if err != nil {
		return err
	}
	bits, err := parseBits(args[1])
	if err != nil {
		return err
	}
	subs, err := n.Subnets(bits)
	if err != nil {
		return err
	}
	for _, s := range subs {
		fmt.Println(s)
	}
	return nil
}

func runSupernet(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("supernet needs two arguments: cidr supernet <cidr> <new-bits>")
	}
	n, err := cidr.Parse(args[0])
	if err != nil {
		return err
	}
	bits, err := parseBits(args[1])
	if err != nil {
		return err
	}
	s, err := n.Supernet(bits)
	if err != nil {
		return err
	}
	fmt.Println(s)
	return nil
}

func parseBits(s string) (int, error) {
	b, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("prefix length %q is not a number: %w", s, err)
	}
	return b, nil
}
