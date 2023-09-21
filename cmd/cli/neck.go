package main

import (
	"fmt"
	"github.com/MaciekLeks/neck/pkg/adapter"
	"github.com/MaciekLeks/neck/pkg/bpf"
	"github.com/MaciekLeks/neck/pkg/common"
	"github.com/MaciekLeks/neck/pkg/pty"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"os"
	"sync"
)

func main() {
	file, err := os.Create("log.txt")
	if err != nil {
		fmt.Println("error creating log file:", err)
		os.Exit(1)
	}
	defer file.Close()
	os.Stderr = file //for libbpf
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: file, NoColor: true})

	wg := sync.WaitGroup{}
	cidrs := make(chan common.CidrRequestResponse)
	defer close(cidrs)

	rawEvents := make(chan common.RawEvent)
	defer close(rawEvents)

	stop := make(chan struct{}) //closing by pty

	pty, err := pty.NewPty(stop, cidrs)
	if err != nil {
		panic(err)
	}

	m := adapter.NewPtyAdapter(stop, pty, rawEvents)
	m.Run(&wg)

	bpfy, err := bpf.LoadAndAttachProgram()
	if err != nil {
		panic(err)
	}
	if err = bpfy.Run(&wg, stop, cidrs, rawEvents); err != nil {
		panic(err)
	}

	if _, err = pty.Run(); err != nil {
		log.Fatal().Err(err).Msg("error running pty")
	}

	log.Logger.Info().Msg("Waiting all goroutines to finish...")
	wg.Wait()
	log.Logger.Info().Msg("All goroutines finished.")
}
