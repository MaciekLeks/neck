package mediator

import (
	"github.com/MaciekLeks/ebpf-go-template-sock-addr-own-prompt/pkg/common"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/rs/zerolog/log"
	"sync"
)

// Mediator is a struct that mediates between ebpf and ui (ebpf->ui
type Mediator struct {
	pty       *tea.Program
	rawEvents <-chan common.RawEvent
	stop      chan struct{}
}

func NewMediator(stop chan struct{}, p *tea.Program, rawEvents <-chan common.RawEvent) *Mediator {
	return &Mediator{
		pty:       p,
		rawEvents: rawEvents,
		stop:      stop,
	}
}

func (m *Mediator) Run(wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		//wait for stop or iterate over rawEvents
		for {
			select {
			case <-m.stop:
				log.Logger.Info().Msg("Stopping mediator.")
				return
			case msg := <-m.rawEvents:
				m.pty.Send(msg)
			}
		}
	}()
}
