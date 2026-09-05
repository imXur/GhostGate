// Inside main() in userspace/cmd/ghostgate-daemon/main.go:

engineInstance := engine.NewAnomalyEngine(objs.BlockedIps)

go func() {
    for {
        record, err := rd.Read()
        if err != nil {
            return
        }
        
        // Pass the raw byte sample from eBPF ring buffer to the analyzer
        if err := engineInstance.ProcessPacket(record.RawSample); err != nil {
            log.Printf("Inspection error: %v", err)
        }
    }
}()