package bpf

import (
	"encoding/binary"
	"github.com/MaciekLeks/neck/pkg/common"
	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/rs/zerolog/log"
	"net"
	"sync"
	"unsafe"
)

const (
	objFile = "neck.bpf.o"
)

type Bpfy struct {
	bpfModule *bpf.Module
}

func updateACLValueNew(acl *bpf.BPFMap, ikey common.ILpmKeyHolder, val common.LpmVal) error {
	upKey := ikey.GetPointer()
	upVal := unsafe.Pointer(&val)

	err := acl.Update(upKey, upVal)
	if err != nil {
		return err
	}

	return nil
}

func LoadAndAttachProgram() (*Bpfy, error) {
	var err error
	logger := log.Logger
	b := &Bpfy{}

	b.bpfModule, err = bpf.NewModuleFromFile(objFile)
	if err != nil {
		logger.Error().Msg("can't open ebpf object file")
		return nil, err
	}

	logger.Info().Msg("Loading object file")
	b.bpfModule.BPFLoadObject()

	prog, err := b.bpfModule.GetProgram("cgroup_sock_prog")
	if err != nil {
		logger.Error().Msgf("can't get program: %s", err)
		return nil, err
	}

	_, err = prog.AttachCgroup("/sys/fs/cgroup")
	if err != nil {
		logger.Error().Msgf("can't attach kprobe: %s", err)
		defer b.bpfModule.Close()
		return nil, err
	}
	return b, nil
}

func (b *Bpfy) Run(wg *sync.WaitGroup, stop <-chan struct{}, cidrReqRes <-chan common.CidrRequestResponse, rawEvents chan<- common.RawEvent) error {
	wg.Add(1)
	logger := log.Logger

	events := make(chan []byte)
	rb, err := b.bpfModule.InitRingBuf("events", events)
	if err != nil {
		logger.Error().Msgf("can't init ring buffer: %s", err)
		return err
	}

	ipv4LpmMap, err := b.bpfModule.GetMap("ipv4_lpm_map")
	if err != nil {
		logger.Error().Msgf("can't get map: %s", err)
		return err
	}

	rb.Poll(300)

	var lpmId uint16 = 1

	go func() {
		defer wg.Done()

	loop:
		for {
			select {
			case <-stop:
				log.Logger.Info().Msg("Stopping user space eBPF part.")
				return
			case event, ok := <-events:
				if !ok {
					log.Info().Msg("Raw events channel closed.")
					break loop
				}
				val := common.RawEvent{
					Command: string(event[0:16]),
					IP:      net.IP(event[16:20]),
					Pid:     binary.LittleEndian.Uint32(event[20:24]),
					Uid:     binary.LittleEndian.Uint32(event[24:28]),
					Blocked: event[28:29][0],
					LpmVal: common.LpmVal{
						Id:      binary.LittleEndian.Uint16(event[29:31]),
						Counter: binary.LittleEndian.Uint64(event[31:39]),
					},
				}
				rawEvents <- val
			case cidr := <-cidrReqRes:
				err := updateACLValueNew(ipv4LpmMap, cidr.Key, common.LpmVal{Id: lpmId, Counter: 0})
				if err != nil {
					log.Error().Err(err).Msg("Failed to update map.")
					cidr.Result <- common.CidrResponse{Error: err}
				} else {
					log.Info().Msg("Updated map.")
					cidr.Result <- common.CidrResponse{Error: nil, Id: lpmId, Counter: 0}
					lpmId++
				}
			}
		}
	}()
	return nil
}
