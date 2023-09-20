package main

import (
	"fmt"
	"github.com/MaciekLeks/ebpf-go-template-sock-addr-own-prompt/pkg/bpf"
	"github.com/MaciekLeks/ebpf-go-template-sock-addr-own-prompt/pkg/common"
	"github.com/MaciekLeks/ebpf-go-template-sock-addr-own-prompt/pkg/mediator"
	"github.com/MaciekLeks/ebpf-go-template-sock-addr-own-prompt/pkg/pty"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"os"
	"sync"
)

type argList []string

func (i *argList) String() string {
	return fmt.Sprint(*i)
}

func (i *argList) Set(value string) error {
	*i = append(*i, value)
	return nil
}

func main() {
	//var cidrs argList
	//flag.Var(&cidrs, "cidrs", "CIDR list to block egress traffic")
	//flag.Parse()

	//ctx := utils.SetupSignalHandler()

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

	m := mediator.NewMediator(stop, pty, rawEvents)
	m.Run(&wg)

	err = bpf.Run(&wg, stop, cidrs, rawEvents)
	if err != nil {
		panic(err)
	}

	if _, err = pty.Run(); err != nil {
		log.Fatal().Err(err).Msg("error running pty")
	}

	log.Logger.Info().Msg("Waiting all goroutines to finish...")
	wg.Wait()
	log.Logger.Info().Msg("All goroutines finished.")
}
