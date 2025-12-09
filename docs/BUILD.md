# Building CRIU with io_uring Support

**Date:** December 9, 2025  
**Tested on:** Ubuntu 24.04 (Noble)

## Prerequisites

### Install Build Dependencies

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    pkg-config \
    libprotobuf-dev \
    libprotobuf-c-dev \
    protobuf-c-compiler \
    protobuf-compiler \
    python3-protobuf \
    libnl-3-dev \
    libnl-route-3-dev \
    libcap-dev \
    libnet1-dev \
    libbsd-dev \
    iproute2 \
    libgnutls28-dev
```

### Optional Dependencies

For full functionality (optional):
```bash
# AMD GPU plugin support
sudo apt-get install -y libdrm-dev

# nftables support  
sudo apt-get install -y libnftables-dev

# CUDA plugin (requires CUDA toolkit)
# cuda-checkpoint utility from NVIDIA driver
```

## Building

### Clone the Repository

```bash
git clone https://github.com/balajinvda/criu.git
cd criu
git checkout feat/io-uring-support
```

### Build

```bash
make -j$(nproc)
```

### Verify Build

```bash
# Check binary
ls -la criu/criu

# Check version
./criu/criu --version

# Verify io_uring support
nm criu/criu | grep io_uring
```

Expected output:
```
Version: 4.2
GitID: ...

0000000000083d00 T check_io_uring_support
0000000000083510 T dump_io_uring
0000000000083ca0 T free_io_urings
...
```

## Installation

### Install System-Wide

```bash
sudo make install
```

This installs:
- `/usr/local/sbin/criu` - Main binary
- `/usr/local/lib/criu/` - Plugins directory
- `/usr/local/include/criu/` - Headers

### Install to Custom Location

```bash
make DESTDIR=/opt/criu PREFIX=/ install
```

## Testing

### Run Basic Tests

```bash
# Run io_uring test (requires root)
sudo ./test/zdtm.py run -t zdtm/static/io_uring00
```

### Test io_uring Detection

```bash
# Create a simple test program that uses io_uring
cat > /tmp/test_io_uring.c << 'EOF'
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/io_uring.h>

int main() {
    struct io_uring_params p = {0};
    int fd = syscall(__NR_io_uring_setup, 8, &p);
    if (fd < 0) {
        perror("io_uring_setup");
        return 1;
    }
    printf("io_uring fd: %d\n", fd);
    printf("Sleeping... checkpoint me!\n");
    sleep(60);
    close(fd);
    return 0;
}
EOF

gcc -o /tmp/test_io_uring /tmp/test_io_uring.c
/tmp/test_io_uring &
PID=$!

# Try to checkpoint
sudo ./criu/criu dump --tree $PID --shell-job -D /tmp/ckpt -v4 2>&1 | head -50
```

## Troubleshooting

### Build Errors

**Error: `protoc-gen-c: program not found`**
```bash
sudo apt-get install protobuf-c-compiler
```

**Error: `libnl-3.h: No such file`**
```bash
sudo apt-get install libnl-3-dev libnl-route-3-dev
```

**Error: `cap.h: No such file`**
```bash
sudo apt-get install libcap-dev
```

### Runtime Errors

**Error: `Unknown shit 600 (anon_inode:[io_uring])`**
- You're using old CRIU without io_uring support
- Use this build with io_uring support

**Error: `io_uring has pending I/O`**
- The io_uring has outstanding requests
- Wait for I/O to complete or cancel requests before checkpoint

## Files Modified for io_uring Support

| File | Changes |
|------|---------|
| `criu/io_uring.c` | Core dump/prepare logic |
| `criu/include/io_uring.h` | API headers |
| `criu/pie/restorer.c` | Restore logic in restorer blob |
| `criu/proc_parse.c` | VMA detection for io_uring |
| `criu/cr-dump.c` | Integration |
| `criu/cr-restore.c` | Integration |
| `images/io_uring.proto` | Protobuf definition |
| `images/mm.proto` | mm entry extension |
| `images/Makefile` | Build integration |
| `compel/.../syscall_64.tbl` | io_uring_setup syscall |
| `criu/Makefile.crtools` | Build integration |

## Architecture Support

Currently implemented for:
- ✅ x86_64

Needs syscall table entries for:
- ❌ aarch64
- ❌ ppc64
- ❌ s390
- ❌ mips
- ❌ riscv64
- ❌ loongarch64

