package adapter

import (
	"github.com/MaciekLeks/neck/pkg/common"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/rs/zerolog/log"
	"sync"
)

// PtyAdapter is a struct that can talk to pty in the name of ebpf
type PtyAdapter struct {
	pty       *tea.Program
	rawEvents <-chan common.RawEvent
	stop      <-chan struct{}
}

func NewPtyAdapter(stop <-chan struct{}, p *tea.Program, rawEvents <-chan common.RawEvent) *PtyAdapter {
	return &PtyAdapter{
		pty:       p,
		rawEvents: rawEvents,
		stop:      stop,
	}
}

func (m *PtyAdapter) Run(wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		//wait for stop or iterate over rawEvents
		for {
			select {
			case <-m.stop:
				log.Logger.Info().Msg("Stopping pty-adapter.")
				return
			case msg := <-m.rawEvents:
				m.pty.Send(msg)
			}
		}
	}()
}
