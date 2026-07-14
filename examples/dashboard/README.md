# 📊 Real-Time Curses Telemetry Dashboard (`examples/dashboard/`)

Shows how to connect your application metrics directly into the `ksp dashboard` visual monitoring interface.

## Telemetry Export
- **Bandwidth Metrics**: Real-time ingress (`RX`) and egress (`TX`) rates in MB/s.
- **Latency Histograms**: Instantaneous RTT measurements plotted across sliding time windows.
- **Session Pool Health**: Live table tracking active session IDs, remote IPs, and encryption cipher states.

## Quick CLI Testing
```bash
# Launch interactive curses monitor inside terminal
ksp dashboard --refresh 250ms
```
