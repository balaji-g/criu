# ZeroMQ CRIU Plugin

This plugin enables checkpoint/restore of applications using ZeroMQ (libzmq) messaging library.

## Overview

The ZMQ plugin integrates with libzmq's checkpoint/restore API to save and restore ZeroMQ contexts, sockets, endpoints, and message queues.

## Requirements

- **libzmq with checkpoint support** (custom branch: `checkpoint-restore-v1`)
- **CRIU 3.17+** (with plugin support)
- **Linux 5.x+** (for io_uring support if used)

## How It Works

### Checkpoint Flow

1. **PAUSE_DEVICES hook:**
   - Detect if process uses libzmq (scan `/proc/PID/maps`)
   - Load libzmq.so via dlopen
   - Call `zmq_get_all_contexts()` to discover ZMQ contexts
   - Call `zmq_ctx_checkpoint()` for each context
   - Save checkpoint data to image files

2. **CHECKPOINT_DEVICES hook:**
   - Verify checkpoint succeeded
   - Finalize checkpoint data

3. **RESUME_DEVICES_LATE hook:**
   - Load checkpoint data from image files
   - Call `zmq_ctx_restore()` for each context
   - Update application pointers (via ptrace)

### File Format

Checkpoint images are saved as:
- `zmq-ckpt-<PID>-<CTX_INDEX>.img` - Per-context checkpoint data

## Build

```bash
cd /home/balaji/personal/criu/plugins/zmq
make
```

Output: `zmq_plugin.so`

## Usage with CRIU

```bash
# Checkpoint with ZMQ plugin
criu dump --tree <PID> \
    --images-dir /tmp/checkpoint \
    --plugin /path/to/zmq_plugin.so \
    --leave-running

# Restore
criu restore --images-dir /tmp/checkpoint \
    --plugin /path/to/zmq_plugin.so
```

## Usage with GPUCR Agent

The GPUCR agent automatically loads this plugin when checkpointing GPU workloads that use ZMQ (like vLLM).

```bash
# Enable ZMQ plugin in agent
export CRIU_PLUGINS="zmq_plugin.so"

# Checkpoint vLLM (uses ZMQ for IPC)
./scripts/checkpoint.sh create vllm-pod

# Restore
kubectl apply -f vllm-restore.yaml
```

## Supported Workloads

- **vLLM** (DEALER/ROUTER over IPC) ✅
- **PyTorch Distributed** (if using ZMQ)
- **ML inference servers** (using ZMQ for RPC)
- **Custom ZMQ applications**

## Limitations (Phase 1)

- Only supports processes with statically linked libzmq or standard library paths
- Requires libzmq with checkpoint API (custom fork)
- Does not checkpoint messages in-flight (sockets should be idle)

## Development Status

- **Phase 1 (Current):** Basic plugin skeleton, discovery, dlopen integration
- **Phase 2 (TODO):** Ptrace injection to call checkpoint APIs in target process
- **Phase 3 (TODO):** Full message queue serialization

## Testing

```bash
# Test with simple ZMQ application
cd /home/balaji/personal/criu/plugins/zmq
./test_zmq_plugin.sh
```

## See Also

- [ZMQ State Mapping Document](/home/balaji/personal/gpucr/docs/zmq-state-mapping.md)
- [ZMQ Checkpoint API Design](/home/balaji/personal/gpucr/docs/zmq-checkpoint-api.md)
- [CUDA Plugin](../cuda/cuda_plugin.c) (reference implementation)
