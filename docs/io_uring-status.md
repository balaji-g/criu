# io_uring Implementation Status

**Last Updated:** December 9, 2025

## Current Status: 95% Complete (Ready for testing)

### ✅ Completed

| Component | File | Status |
|-----------|------|--------|
| VMA detection | `criu/proc_parse.c` | ✅ Detects `anon_inode:[io_uring]` |
| VMA flag | `criu/include/image.h` | ✅ `VMA_AREA_IOURING` defined |
| VMA struct | `criu/include/vma.h` | ✅ `vm_iouring_ino`, `nr_iourings` |
| Protobuf | `images/io_uring.proto` | ✅ Full definition |
| mm.proto integration | `images/mm.proto` | ✅ `io_urings` field added |
| Header | `criu/include/io_uring.h` | ✅ Created |
| Dump logic | `criu/io_uring.c` | ✅ `dump_io_uring()` implemented |
| cr-dump integration | `criu/cr-dump.c` | ✅ Calls `dump_io_uring()` |
| **Restore logic** | `criu/io_uring.c` | ✅ `prepare_io_urings()` implemented |
| **Restorer blob** | `criu/pie/restorer.c` | ✅ `restore_io_uring_ring()` implemented |
| **cr-restore integration** | `criu/cr-restore.c` | ✅ Calls `prepare_io_urings()` |
| **Makefile** | `criu/Makefile.crtools` | ✅ `io_uring.o` added |
| **Syscall** | `compel/.../syscall_64.tbl` | ✅ `sys_io_uring_setup` added |
| Design doc | `docs/io_uring-design.md` | ✅ Complete |

### ✅ Tests

| Component | File | Status |
|-----------|------|--------|
| **ZDTM test** | `test/zdtm/static/io_uring00.c` | ✅ Basic io_uring C/R test |

### ❌ Not Yet Implemented

| Component | File | Required Work |
|-----------|------|---------------|
| **Other arch syscalls** | `compel/arch/*/...` | Add io_uring_setup for arm64, s390, ppc64, etc. |

## File Changes Summary

```
Modified:
  criu/proc_parse.c      - Detect io_uring VMAs
  criu/include/image.h   - VMA_AREA_IOURING flag
  criu/include/vma.h     - vm_iouring_ino, nr_iourings
  criu/cr-dump.c         - Call dump_io_uring()
  images/mm.proto        - Add io_urings repeated field

New files:
  criu/io_uring.c        - Dump logic (restore TODO)
  criu/include/io_uring.h - Header
  images/io_uring.proto  - Protobuf definition
  docs/io_uring-design.md - Design document
```

## Next Steps

### 1. Add io_uring.c to Makefile

```makefile
# In criu/Makefile, add to obj-y:
obj-y += io_uring.o
```

### 2. Implement restore_io_uring()

```c
// In criu/io_uring.c
int restore_io_uring(MmEntry *mme, pid_t pid)
{
    int i;
    
    if (!mme->n_io_urings)
        return 0;
        
    for (i = 0; i < mme->n_io_urings; i++) {
        IoUringEntry *e = mme->io_urings[i];
        
        // 1. Call io_uring_setup() with saved params
        // 2. Remap ring memory to original addresses
        // 3. Restore ring state (head/tail)
    }
    
    return 0;
}
```

### 3. Integrate into cr-restore.c

```c
#include "io_uring.h"

// In appropriate restore function:
ret = restore_io_uring(&mme, pid);
if (ret < 0)
    return -1;
```

### 4. Add ZDTM test

Create `test/zdtm/static/io_uring00.c`:
- Create io_uring instance
- Submit/complete some I/O
- Verify state after restore

## Testing

### Build
```bash
make -j$(nproc)
```

### Run ZDTM test
```bash
./test/zdtm.py run -t zdtm/static/io_uring00
```

### Test with vLLM
```bash
# In container with vLLM
criu dump --tree $PID --shell-job -D /tmp/ckpt
criu restore --shell-job -D /tmp/ckpt
```

