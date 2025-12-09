# io_uring Checkpoint/Restore Design Document

**Author:** Balaji Ganesan (bganesan@nvidia.com)  
**Date:** December 9, 2025  
**Status:** Draft

## Background

io_uring is Linux's modern asynchronous I/O interface (kernel 5.1+). It provides high-performance async I/O using shared ring buffers between userspace and kernel.

CRIU currently cannot checkpoint processes using io_uring:
```
Error (criu/proc_parse.c:502): Unknown shit 600 (anon_inode:[io_uring])
```

This blocks checkpointing of:
- vLLM (LLM inference server)
- Modern Python async apps (uvloop-based)
- Any application using liburing

## io_uring Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     User Space                                   │
│  ┌──────────────────┐    ┌──────────────────┐                   │
│  │ Submission Queue │    │ Completion Queue │                   │
│  │  (SQ Ring)       │    │  (CQ Ring)       │                   │
│  │  - head          │    │  - head          │                   │
│  │  - tail          │    │  - tail          │                   │
│  │  - mask          │    │  - mask          │                   │
│  └────────┬─────────┘    └────────┬─────────┘                   │
│           │                       │                              │
│  ┌────────▼─────────┐    ┌────────▼─────────┐                   │
│  │ SQE Array        │    │ CQE Array        │                   │
│  │ (Submission      │    │ (Completion      │                   │
│  │  Queue Entries)  │    │  Queue Entries)  │                   │
│  └──────────────────┘    └──────────────────┘                   │
└─────────────────────────────────────────────────────────────────┘
                    │ mmap'd shared memory │
┌─────────────────────────────────────────────────────────────────┐
│                     Kernel Space                                 │
│  - Processes SQEs                                               │
│  - Posts CQEs                                                    │
│  - Optional: SQ polling thread                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Kernel Information Available

From `/proc/PID/fdinfo/<io_uring_fd>`:
```
SqMask:	0x3f          # SQ ring mask
SqHead:	0             # SQ head position  
SqTail:	0             # SQ tail position
CachedSqHead: 0       # Cached SQ head
CqMask:	0x7f          # CQ ring mask
CqHead:	0             # CQ head position
CqTail:	0             # CQ tail position
CachedCqTail: 0       # Cached CQ tail
SQEs:   0             # Pending SQEs
CQEs:   0             # Pending CQEs
SqThread: 166874      # SQ polling thread TID (-1 if none)
SqThreadCpu: 0        # SQ thread CPU affinity
UserFiles: 0          # Registered file count
UserBufs:  0          # Registered buffer count
```

## Memory Mappings

io_uring creates these mmap regions:
1. **SQ Ring** (offset 0x00000000) - Submission queue header
2. **CQ Ring** (offset 0x08000000) - Completion queue header  
3. **SQE Array** (offset 0x10000000) - Submission queue entries

Example from vLLM:
```
7c37534ef000-7c37534f3000 rw-s 10000000 anon_inode:[io_uring]  # SQEs
7c37534f8000-7c37534fb000 rw-s 00000000 anon_inode:[io_uring]  # SQ/CQ rings
```

## Implementation Plan

### Phase 1: Detection & Basic Dump

1. **Detect io_uring VMAs** (`proc_parse.c`)
   - Check for `anon_inode:[io_uring]` in VMA filename
   - Add `VMA_AREA_IOURING` flag

2. **Parse fdinfo** (`files-reg.c` or new `io_uring.c`)
   - Extract ring configuration from `/proc/PID/fdinfo/<fd>`
   - Store in protobuf

3. **Protobuf definition** (`images/io_uring.proto`)
   ```protobuf
   message io_uring_entry {
     required uint32 id = 1;           // File descriptor
     required uint32 sq_entries = 2;   // SQ size
     required uint32 cq_entries = 3;   // CQ size
     required uint32 flags = 4;        // Setup flags
     optional uint32 sq_thread_cpu = 5;
     optional uint32 sq_thread_idle = 6;
     // Ring state
     required uint32 sq_head = 10;
     required uint32 sq_tail = 11;
     required uint32 cq_head = 12;
     required uint32 cq_tail = 13;
   }
   ```

### Phase 2: Ring Contents Dump

1. **Dump ring memory contents**
   - SQ ring buffer
   - CQ ring buffer
   - SQE array
   - Any pending CQEs

2. **Handle registered resources**
   - Registered file descriptors
   - Registered buffers

### Phase 3: Restore

1. **Recreate io_uring instance**
   - Call `io_uring_setup()` with saved parameters
   - Remap ring memory to original addresses

2. **Restore ring state**
   - Restore head/tail pointers
   - Restore any pending completions

3. **Re-register resources**
   - Re-register file descriptors
   - Re-register buffers

### Phase 4: Testing

1. **ZDTM tests**
   - Basic io_uring create/destroy
   - Submission/completion cycle
   - SQ polling mode
   - Registered files/buffers

2. **Real-world tests**
   - vLLM checkpoint/restore
   - uvloop-based Python apps

## Challenges

### In-flight I/O

**Problem:** I/O submitted but not completed at checkpoint time.

**Solution Options:**
1. **Wait for completion** - Simplest, may hang on slow I/O
2. **Cancel and retry** - Cancel pending, app retries after restore
3. **Drain queue** - Require SQEs == CQEs == 0 before checkpoint

**Recommended:** Start with option 3 (require empty queues), add option 1 later.

### SQ Polling Thread

**Problem:** Kernel-side thread polling the SQ.

**Solution:** 
- Save `SqThread` TID
- On restore, kernel creates new thread
- Map old TID to new TID if needed

### Memory Mapping Addresses

**Problem:** Ring buffers may need to be at specific addresses.

**Solution:**
- Use CRIU's existing VMA remapping infrastructure
- Similar to how AIO rings are handled

## Code Changes Summary

| File | Changes |
|------|---------|
| `criu/proc_parse.c` | Detect io_uring VMAs |
| `criu/include/image.h` | Add `VMA_AREA_IOURING` |
| `images/io_uring.proto` | New protobuf definition |
| `images/mm.proto` | Add io_uring entries to MmEntry |
| `criu/io_uring.c` | New file: dump/restore logic |
| `criu/io_uring.h` | Header for io_uring |
| `criu/cr-dump.c` | Call io_uring dump |
| `criu/cr-restore.c` | Call io_uring restore |
| `criu/Makefile` | Add io_uring.o |
| `test/zdtm/static/` | Add io_uring tests |

## References

- [io_uring man page](https://man7.org/linux/man-pages/man7/io_uring.7.html)
- [liburing](https://github.com/axboe/liburing)
- [Kernel io_uring source](https://github.com/torvalds/linux/blob/master/io_uring/)
- [CRIU AIO implementation](https://github.com/checkpoint-restore/criu/blob/criu-dev/criu/aio.c)

