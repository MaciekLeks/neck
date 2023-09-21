package pty

import (
	"github.com/MaciekLeks/neck/pkg/common"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	"strconv"
)

type view uint

const (
	rawView view = iota
	configView
	cidrView
)

type state uint

const (
	notReady state = iota
	ready    state = iota
)

type model struct {
	width, height int
	ready         state
	active        view
	raw           table.Model     //ring buffer
	config        table.Model     //lpm
	cidr          textinput.Model //cidr
	stop          chan struct{}
	output        chan<- common.CidrRequestResponse
	cidrList      uiPtrCidrList //we need it to manipulate data, we do not need list here for raw data
}

// uiCidr keeps data taken from ebpf side and string representation of cidr
// we need a new struct to compose data taken from ebpf side with string representation of cidr
type uiCidr struct {
	id    uint16
	cidr  string
	count uint64
}

// uiCidrList is a list of uiCidr
type uiCidrList []uiCidr
type uiPtrCidrList []*uiCidr

// RawEventList is a list of common.RawEvent - we use common.RawEvent not local struct
// because RawEvent has all data we need
type RawEventList []common.RawEvent

func (r RawEventList) TeaRows() []table.Row {
	var result []table.Row
	for _, raw := range r {
		result = append(result, []string{raw.Command})
	}

	return result
}

func (c uiCidrList) TeaRows() []table.Row {
	var result []table.Row
	for _, config := range c {
		result = append(result, []string{
			strconv.Itoa(int(config.id)),
			config.cidr,
			strconv.FormatUint(config.count, 10)})
	}

	return result
}

func (c uiPtrCidrList) TeaRows() []table.Row {
	var result []table.Row
	for _, config := range c {
		result = append(result, []string{
			strconv.Itoa(int(config.id)),
			config.cidr,
			strconv.FormatUint(config.count, 10)})
	}

	return result
}
