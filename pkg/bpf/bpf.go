package bpf

import (
	"encoding/binary"
	"fmt"
	"github.com/MaciekLeks/ebpf-go-template-sock-addr-own-prompt/pkg/common"
	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/rs/zerolog/log"
	"net"
	"sync"
	"unsafe"
)

func updateACLValueNew(acl *bpf.BPFMap, ikey common.ILpmKeyHolder, val common.LpmVal) error {
	upKey := ikey.GetPointer()
	upVal := unsafe.Pointer(&val)

	err := acl.Update(upKey, upVal)
	if err != nil {
		return err
	}

	return nil
}

//func unmarshalValue(bytes []byte) common.LpmVal {
//	return common.LpmVal{
//		Data: binary.LittleEndian.Uint64(bytes[0:8]),
//	}
//}

func Run(wg *sync.WaitGroup, stop chan struct{}, cidrReqRes <-chan common.CidrRequestResponse, rawEvents chan<- common.RawEvent) error {
	wg.Add(1)
	var retErr error
	go func() {
		defer wg.Done()
		logger := log.Logger
		logger.Info().Msg("Starting user and kernel space eBPF parts.")
		bpfModule, err := bpf.NewModuleFromFile("task.bpf.o")
		if err != nil {
			retErr = fmt.Errorf("can't open module from file: %s", err)
			return
		}
		defer bpfModule.Close()

		logger.Info().Msg("Loading object file")
		bpfModule.BPFLoadObject()

		prog, err := bpfModule.GetProgram("cgroup_sock_prog")
		if err != nil {
			retErr = fmt.Errorf("can't get program: %s", err)
			return
		}

		_, err = prog.AttachCgroup("/sys/fs/cgroup")
		if err != nil {
			retErr = fmt.Errorf("can't attach kprobe: %s", err)
			return
		}

		events := make(chan []byte)
		rb, err := bpfModule.InitRingBuf("events", events)
		if err != nil {
			retErr = fmt.Errorf("can't init ring buffer: %s", err)
			return
		}

		ipv4LpmMap, err := bpfModule.GetMap("ipv4_lpm_map")
		if err != nil {
			retErr = fmt.Errorf("can't get map: %s", err)
			return
		}

		rb.Poll(300)

		var lpmId uint16 = 1
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

	return retErr
}
