package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf ghostgate ../../kernel/ghostgate.bpf.c -- -I../../kernel

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"ghostgate/userspace/engine"
	"ghostgate/userspace/ui"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	ifaceName := flag.String("iface", "eth0", "Network interface to attach XDP filter")
	flag.Parse()

	// 1. Remove Linux memlock limits for eBPF allocations
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	// 2. Load compiled eBPF objects
	objs := ghostgateObjects{}
	if err := loadGhostgateObjects(&objs, nil); err != nil {
		log.Fatalf("Loading eBPF objects failed: %v", err)
	}
	defer objs.Close()

	// 3. Resolve network interface and attach XDP hook
	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("Interface %s not found: %v", *ifaceName, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.GhostgateFilter,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Could not attach XDP to %s: %v", *ifaceName, err)
	}
	defer l.Close()

	// 4. Initialize ring buffer reader
	rd, err := ringbuf.NewReader(objs.FlowEvents)
	if err != nil {
		log.Fatalf("Failed to initialize ring buffer reader: %v", err)
	}
	defer rd.Close()

	anomalyEngine := engine.NewAnomalyEngine(objs.BlockedIps)

	// State tracking for the TUI
	var (
		stateMu      sync.Mutex
		totalPackets uint64
		totalDrops   uint64
		recentBans   []ui.BanRecord
		liveStream   []string
	)

	// Callback to feed the UI with updated metrics
	fetcher := func() ui.TelemetrySnapshot {
		stateMu.Lock()
		defer stateMu.Unlock()

		return ui.TelemetrySnapshot{
			TotalPackets: totalPackets,
			TotalDrops:   totalDrops,
			ActiveFlows:  len(liveStream), // Active sliding windows
			RecentBans:   append([]ui.BanRecord(nil), recentBans...),
			LiveStream:   append([]string(nil), liveStream...),
		}
	}

	// Cancellation context for graceful exit
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Intercept OS interrupts
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		cancel()
	}()

	// 5. Ingestion worker reading from eBPF ring buffer
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				record, err := rd.Read()
				if err != nil {
					return
				}

				stateMu.Lock()
				totalPackets++
				if len(liveStream) >= 8 {
					liveStream = liveStream[1:]
				}
				liveStream = append(liveStream, fmt.Sprintf("[FLOW] %d bytes sampled at %s",
					len(record.RawSample), time.Now().Format("15:04:05.000")))
				stateMu.Unlock()

				if err := anomalyEngine.ProcessPacket(record.RawSample); err != nil {
					stateMu.Lock()
					// Track drop/mitigation actions
					totalDrops++
					recentBans = append(recentBans, ui.BanRecord{
						IP:        "Mitigated IP",
						RiskScore: 85.0,
						Reason:    "Threshold Exceeded",
						BannedAt:  time.Now(),
					})
					stateMu.Unlock()
				}
			}
		}
	}()

	// 6. Launch the interactive Bubble Tea dashboard (blocks until exit)
	if err := ui.LaunchTUI(fetcher); err != nil {
		log.Printf("TUI terminated with error: %v", err)
	}

	cancel()
	fmt.Println("\n[GhostGate] Cleaning up and detaching XDP program...")
}