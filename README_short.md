# Network Intrusion Detection System (IDS)

A production-grade, multi-process network monitoring and intrusion detection system written in C with Prometheus metrics and Grafana dashboards.

## 🚀 Quick Start

```bash
git clone <repository>
cd network-ids
mkdir build && cd build && cmake .. && make
./ids ../ids.conf
curl http://localhost:9101/metrics
```

## ✨ Features

- **Real-time Monitoring**: Network interface statistics via `/proc/net/dev`
- **Multi-Process Architecture**: Separate collector/analyzer processes with IPC
- **Detection Engines**: Rule-based thresholds + statistical anomaly detection
- **Advanced Metrics**: Per-interface rates, alert counters, frequency histograms
- **REST API**: Prometheus metrics, health checks, Grafana dashboard JSON
- **Production Ready**: Docker containerization, graceful shutdown, signal handling

## 🏗️ Architecture

```
Main Process ──┬─ Collector Process ── Network Stats ── Rate Calc ── IPC Pipe
               └─ Analyzer Process ── Detection Engine ── Metrics ── REST API
```

**Components**: `main.c` (orchestration), `rate.c` (calculations), `rule_engine.c` (detection), `http_server.c` (metrics), `anomaly.c` (ML detection)

## 📋 Requirements

- Linux (kernel 3.0+)
- GCC/Clang with C99
- CMake 3.10+, Make
- Optional: Docker, Grafana, Prometheus

## 🛠️ Installation & Usage

### Native Build
```bash
mkdir build && cd build
cmake .. && make
./ids ../ids.conf
```

### Docker
```bash
docker build -t network-ids .
docker run --cap-add=NET_ADMIN --net=host -v $(pwd)/logs:/app/logs network-ids
```

### Configuration (ids.conf)
```json
{
  "settings": {"interval": 2, "log_level": 1, "metrics_port": 9101},
  "rules": [{"name": "HighRxBandwidth", "metric": "RX_BYTES", "threshold": 5000000}]
}
```

## 📊 Monitoring

### Endpoints
- `GET /metrics` - Prometheus metrics
- `GET /healthz` - Health check
- `GET /dashboard` - Grafana JSON

### Key Metrics
```prometheus
ids_total_iterations                    # Processing iterations
ids_total_alerts_total                 # Total alerts
ids_interface_rx_bytes_per_sec{interface="eth0"}  # Per-interface rates
ids_rule_alerts_total{rule="..."}      # Per-rule alerts
ids_alert_frequency_histogram_bucket    # Alert distribution
```

### Grafana Setup
1. `curl http://localhost:9101/dashboard` → Copy JSON
2. Grafana: **Create** → **Import** → Paste JSON
3. Configure Prometheus datasource

## 🚀 Commands

```bash
# Build & Run
cd build && make && ./ids ../ids.conf

# Test (10 seconds)
timeout 10s ./ids ../ids.conf

# Background mode
./ids ../ids.conf &

# Monitor metrics
watch -n 1 curl -s http://localhost:9101/metrics

# Docker operations
docker build -t network-ids .
docker run --cap-add=NET_ADMIN --net=host network-ids

# Stop processes
pkill -f "./ids"
docker stop ids-container
```

## 🔧 Development

### Project Structure
```
network-ids/
├── CMakeLists.txt          # Build config
├── Dockerfile             # Container
├── ids.conf              # Config
├── include/              # Headers
├── src/                  # Sources
└── build/                # Artifacts
```

### Build Options
```bash
# Debug build
cmake -DCMAKE_BUILD_TYPE=Debug .. && make

# Clean rebuild
make clean && make

# Static analysis
cppcheck --enable=all src/
```

## 📄 License

MIT License - see LICENSE file for details.