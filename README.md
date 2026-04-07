# Network Intrusion Detection System (IDS)

A multi-process network monitoring and intrusion detection system written in C.

## Features

- **Real-time Network Monitoring**: Reads network statistics from `/proc/net/dev`
- **Rate Calculation**: Computes bandwidth and packet rates between snapshots
- **Rule-Based Detection**: Configurable threshold-based alerting
- **Anomaly Detection**: Statistical anomaly detection using historical data
- **Multi-Process Architecture**: Separate collector and analyzer processes with IPC
- **Configuration-Driven**: JSON-based configuration system
- **Logging**: Configurable logging levels

## Architecture

### Phase 6: Process Architecture & IPC

The system implements a daemon-like architecture with two main processes:

- **Collector Process**: Reads network snapshots, calculates rates, and sends data via IPC
- **Analyzer Process**: Receives rate data, applies detection algorithms, and outputs alerts

**IPC Mechanism**: Uses UNIX pipes for efficient inter-process communication with custom serialization.

### Components

- `main.c`: Process management and main loop
- `net_reader.c`: Network statistics collection
- `rate.c`: Rate calculation and serialization
- `rule_engine.c`: Rule-based detection engine
- `anomaly.c`: Statistical anomaly detection
- `config.c`: Configuration file parsing
- `common.c`: Shared utilities and logging

## Building

```bash
mkdir build
cd build
cmake ..
make
```

## Usage

```bash
./ids [config_file]
```

Default config file: `../ids.conf`

## Commands

### 🔧 Build Commands

```bash
# Build the project (from build directory)
cd build && make

# Clean and rebuild
cd build && make clean && make

# Build with verbose output
cd build && make VERBOSE=1
```

### 🚀 Run Commands

```bash
# Run with default config
cd build && ./ids

# Run with custom config file
cd build && ./ids ../ids.conf

# Run with specific config file
cd build && ./ids /path/to/custom/config.json
```

### 🧪 Test Commands

```bash
# Run for 10 seconds to test functionality
cd build && timeout 10s ./ids ../ids.conf

# Run in background (daemon mode)
cd build && ./ids ../ids.conf &

# Kill the background process
pkill -f "./ids"

# Test with different log levels (modify config first)
cd build && ./ids ../ids.conf
```

### 🧹 Maintenance Commands

```bash
# Clean build artifacts
cd build && make clean

# Remove entire build directory and recreate
rm -rf build && mkdir build && cd build && cmake ..

# Check for compilation errors without building
cd build && make -n
```

### 📊 Monitoring Commands

```bash
# Run and monitor processes
cd build && ./ids ../ids.conf &
ps aux | grep ids

# Check system resources while running
cd build && ./ids ../ids.conf &
top -p $(pgrep ids | tr '\n' ',' | sed 's/,$//')

# View network interfaces (what IDS monitors)
cat /proc/net/dev
```

### 🔍 Debug Commands

```bash
# Run with debug logging (set log_level to 0 in config)
cd build && ./ids ../ids.conf

# Check for memory issues (if valgrind installed)
cd build && valgrind --leak-check=full ./ids ../ids.conf

# Run with strace to see system calls
cd build && strace -f ./ids ../ids.conf 2>&1 | head -50
```

### 📁 File Operations

```bash
# View project structure
find . -type f -name "*.c" -o -name "*.h" | head -10

# Check config file
cat ids.conf

# View build output
cd build && ls -la
```

### ⚡ Quick Commands

```bash
# One-liner: build and run
cd build && make && ./ids ../ids.conf

# Build and test for 5 seconds
cd build && make && timeout 5s ./ids ../ids.conf

# Full rebuild and run
rm -rf build && mkdir build && cd build && cmake .. && make && ./ids ../ids.conf
```

## Configuration

The system uses a JSON configuration file with the following structure:

```ini
[SETTINGS]
interval=2
log_level=1
metrics_port=9100

[RULES]
# Format: name | description | metric | threshold | severity | enabled
HighRxBandwidth | High receive bandwidth detected | RX_BYTES | 5000000 | 2 | 1
```

## Process Model

```
┌─────────────────┐    ┌─────────────────┐
│  Collector      │    │   Analyzer      │
│  Process        │    │   Process       │
│                 │    │                 │
│ • Read /proc/   │    │ • Rule Engine   │
│   net/dev       │◄──►│ • Anomaly Det.  │
│ • Calculate     │    │ • Alert Output  │
│   rates         │    │                 │
│ • Serialize &   │    │                 │
│   send via pipe │    │                 │
└─────────────────┘    └─────────────────┘
```

## Phase 7: Containerization & Deployment

### Objective

Industry-style deployment with containerization for portability and scalability.

### What to Implement

- **Dockerfile**: Multi-stage build for optimized container images
- **Container Runtime**: Run the IDS system inside Docker containers
- **Log Exposure**: Mount volumes and expose logs for monitoring
- **Network Access**: Grant necessary capabilities for network monitoring

### Tech Stack Addition

- **Docker**: Containerization platform
- **Linux Namespaces**: Process isolation and resource management

### Docker Commands

```bash
# Build the Docker image
docker build -t network-ids .

# Run the container with network access
docker run --cap-add=NET_ADMIN --net=host -v $(pwd)/logs:/app/logs network-ids

# Run with custom config
docker run --cap-add=NET_ADMIN --net=host -v $(pwd)/ids.conf:/app/ids.conf -v $(pwd)/logs:/app/logs network-ids

# Access Prometheus metrics
curl http://localhost:9100/metrics

# Health check
curl http://localhost:9100/healthz

# View container logs
docker logs <container_id>

# Run in detached mode
docker run -d --cap-add=NET_ADMIN --net=host --name ids-container -v $(pwd)/logs:/app/logs network-ids

# Stop the container
docker stop ids-container

# Build for different architectures
docker buildx build --platform linux/amd64,linux/arm64 -t network-ids .
```

### Dockerfile Example

```dockerfile
# Multi-stage build for optimized image
FROM alpine:latest AS builder

RUN apk add --no-cache cmake make build-base

WORKDIR /app
COPY . .

RUN rm -rf build && mkdir build && cd build && cmake .. && make

FROM alpine:latest

RUN apk add --no-cache libgcc

RUN addgroup -g 1000 ids && adduser -D -s /bin/sh -u 1000 -G ids ids

WORKDIR /app

COPY --from=builder /app/build/ids .
COPY ids.conf .

RUN mkdir -p logs && chown ids:ids logs

USER ids

VOLUME ["/app/logs"]

CMD ["./ids", "ids.conf"]
```

### Deployment Scenarios

```bash
# Development deployment
docker-compose up -d

# Production deployment with monitoring
docker stack deploy -c docker-compose.yml ids-stack

# Kubernetes deployment
kubectl apply -f k8s-deployment.yaml
```

### Concepts Learned

- Containerization and Docker fundamentals
- Multi-stage Docker builds for optimization
- Linux capabilities and security contexts
- Volume mounting for persistent logs
- Container networking and host network access
- Industry deployment patterns and DevOps practices

## Phase 8: Industry Polish (ADVANCED)

### Objective

Make the project résumé-ready through refined shutdown, cleanup, and documentation.

### What is Implemented

- **Graceful shutdown** across parent and child processes
- **Signal handling** for `SIGINT` and `SIGTERM`
- **Resource cleanup** for pipes, snapshots, and engine state
- **README polish** with architecture details and deployment guidance

### What this phase proves

- Real-world process lifecycle management
- Clean inter-process shutdown behavior
- OS-level signal and resource handling
- Production-style documentation

### Architecture Diagram

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Main Process   │    │  Collector      │    │   Analyzer      │
│  (PID 1 / Parent)│   │  Process        │    │   Process       │
│                 │    │                 │    │                 │
│ • Setup IPC     │    │ • Read /proc/   │    │ • Read rate data │
│ • Fork child    │    │   net/dev       │    │   from pipe     │
│ • Handle signals│    │ • Compute rates │    │ • Run detection │
│ • Forward TERM  │    │ • Serialize data│    │ • Print alerts  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Graceful shutdown behavior

- `SIGINT` / `SIGTERM` are handled by the parent process
- Signal handler sets `running` flag to 0
- Analyzer uses `select()` with 2-second timeout on pipe reads
  - Checks `running` flag every 2 seconds
  - Exits immediately when shutdown is detected
- Parent sends `SIGTERM` to collector child
- Both processes exit cleanly with proper cleanup
- Open pipes are closed and memory is freed

### Responsiveness

The system responds to `Ctrl+C` within 2 seconds (one timeout interval) due to the `select()` timeout mechanism in the analyzer loop.

### Sample Output

```text
[ANALYZER] Starting analyzer process (PID: 1234)
[COLLECTOR] Starting collector process (PID: 1235)
[Iteration 1]
...
^C[MAIN] Shutdown requested, terminating child process
[COLLECTOR] Collector process exiting
[ANALYZER] Shutting down...
Total iterations: 10
Total alerts: 0
[MAIN] Collector process exited with status 0
```

### Testing approach

- Run locally and send `Ctrl+C` to verify graceful shutdown
- Use `docker run` and stop the container to ensure the same cleanup path
- Confirm no dangling child process remains after exit
- Verify `build/`, `logs/`, and temporary files are excluded by ignore rules

### CMake setup

The existing `CMakeLists.txt` already provides:

- C99 standard
- `include/` directory for headers
- `src/` source file list plus `main.c`
- `-Wall -Wextra -Wpedantic -O2`
- linkage to `-lm` for math support

## Concepts Learned

- Multi-process design patterns
- Inter-process communication (IPC) with pipes
- Process lifecycle management
- Serialization for IPC
- Signal handling in multi-process applications
- OS process model and daemon architecture
- Containerization and Docker fundamentals
- Multi-stage Docker builds for optimization
- Linux capabilities and security contexts
- Volume mounting for persistent logs
- Industry deployment patterns and DevOps practices</content>
<parameter name="filePath">/home/tanishq/Projects/ids/README.md