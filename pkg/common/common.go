// Package common contains structs and interfaces used by either ebpf side and ui side
package common

import (
	"fmt"
	"net"
	"unsafe"
)

type Ipv4LpmKey struct {
	PrefixLen uint32
	Data      [4]uint8
}

type LpmVal struct {
	Id      uint16
	Counter uint64
}

type ILpmKeyHolder interface {
	GetPointer() unsafe.Pointer
}

func (k Ipv4LpmKey) GetPointer() unsafe.Pointer {
	return unsafe.Pointer(&k)
}

// RawEvent is a struct that holds data sent from ebpf side to ui side
type RawEvent struct {
	Command string
	IP      net.IP
	Pid     uint32
	Uid     uint32
	Blocked uint8
	LpmVal  LpmVal
}

// CidrResponse is a struct that holds data sent from ebpf side side to ui side
type CidrResponse struct {
	Error   error
	Id      uint16
	Counter uint64
}

// CidrRequestResponse is a struct that holds data sent from ui side to ebpf side
type CidrRequestResponse struct {
	Key    Ipv4LpmKey
	Result chan CidrResponse
}

func ParseCidr(c string) (Ipv4LpmKey, error) {
	var key Ipv4LpmKey
	ip, ipNet, err := net.ParseCIDR(c)
	if err != nil {
		return key, fmt.Errorf("can't parse Cidr %s", c)
	}
	prefix, _ := ipNet.Mask.Size()
	if ipv4 := ip.To4(); ipv4 != nil {
		key.PrefixLen = uint32(prefix)
		key.Data = [4]uint8(ipv4)
		return key, nil
	} else if ipv6 := ip.To16(); ipv6 != nil {
		return key, fmt.Errorf("ipv6 not supported yet %s", c)
	}

	return key, fmt.Errorf("can't converts Cidr to IPv4/IPv6 %s", c)
}
