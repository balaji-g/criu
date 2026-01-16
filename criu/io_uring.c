/*
 * io_uring checkpoint/restore support
 *
 * io_uring is Linux's modern async I/O interface using shared ring buffers.
 * This file handles saving and restoring io_uring state.
 *
 * KEY DESIGN (from code review):
 * 1. io_uring is a proper file type with file_desc support
 * 2. Group io_uring fds by file_desc->id, NOT by fd number
 * 3. Create ONE kernel io_uring object per file_desc
 * 4. dup() that object to all fd numbers sharing the same file_desc
 * 5. NEVER touch fd 0/1/2 (stdin/stdout/stderr)
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include "vma.h"
#include "xmalloc.h"
#include "pstree.h"
#include "io_uring.h"
#include "proc_parse.h"
#include "util.h"
#include "log.h"
#include "cr_options.h"
#include "common/lock.h"
#include "images/mm.pb-c.h"
#include "rst_info.h"
#include "rst-malloc.h"
#include "restorer.h"
#include "imgset.h"
#include "image.h"
#include "files.h"
#include "protobuf.h"
#include "images/io_uring.pb-c.h"
#include "images/fdinfo.pb-c.h"
#include "images/file-lock.pb-c.h"

#undef LOG_PREFIX
#define LOG_PREFIX "io_uring: "

/* io_uring syscall number if not defined */
#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif

/* io_uring setup parameters (from linux/io_uring.h) */
struct io_uring_params {
	__u32 sq_entries;
	__u32 cq_entries;
	__u32 flags;
	__u32 sq_thread_cpu;
	__u32 sq_thread_idle;
	__u32 features;
	__u32 wq_fd;
	__u32 resv[3];
	struct {
		__u32 head;
		__u32 tail;
		__u32 ring_mask;
		__u32 ring_entries;
		__u32 flags;
		__u32 dropped;
		__u32 array;
		__u32 resv1;
		__u64 resv2;
	} sq_off;
	struct {
		__u32 head;
		__u32 tail;
		__u32 ring_mask;
		__u32 ring_entries;
		__u32 overflow;
		__u32 cqes;
		__u32 flags;
		__u32 resv1;
		__u64 resv2;
	} cq_off;
};

/* io_uring mmap offsets */
#ifndef IORING_OFF_SQ_RING
#define IORING_OFF_SQ_RING	0ULL
#endif
#ifndef IORING_OFF_CQ_RING
#define IORING_OFF_CQ_RING	0x8000000ULL
#endif
#ifndef IORING_OFF_SQES
#define IORING_OFF_SQES		0x10000000ULL
#endif

/* Setup flags for element size variants */
#ifndef IORING_SETUP_SQE128
#define IORING_SETUP_SQE128	(1U << 8)  /* 128-byte SQEs (NVMe passthrough) */
#endif
#ifndef IORING_SETUP_CQE32
#define IORING_SETUP_CQE32	(1U << 9)  /* 32-byte CQEs (NVMe passthrough) */
#endif

/* Element sizes */
#define SIZEOF_SQE_NORMAL	64
#define SIZEOF_SQE_128		128
#define SIZEOF_CQE_NORMAL	16
#define SIZEOF_CQE_32		32

static inline uint32_t get_sqe_size_for_flags(uint32_t flags)
{
	return (flags & IORING_SETUP_SQE128) ? SIZEOF_SQE_128 : SIZEOF_SQE_NORMAL;
}

struct io_uring_fdinfo {
	uint32_t sq_mask;
	uint32_t sq_head;
	uint32_t sq_tail;
	uint32_t cached_sq_head;
	uint32_t cq_mask;
	uint32_t cq_head;
	uint32_t cq_tail;
	uint32_t cached_cq_tail;
	uint32_t sqes;
	uint32_t cqes;
	int32_t sq_thread;
	int32_t sq_thread_cpu;
	uint32_t user_files;
	uint32_t user_bufs;
};

/*
 * Deferred epoll registrations for io_uring.
 *
 * Problem: epoll_retore_tfd() runs BEFORE io_uring_setup() in PIE.
 * When epoll tries to add io_uring fd to epoll, the fd doesn't exist yet.
 *
 * Solution:
 * 1. eventpoll_retore_tfd() detects io_uring tfds and stores them here
 * 2. prepare_io_urings() copies them to rst_io_uring_ring structs
 * 3. PIE's restore_io_uring_ring() calls epoll_ctl() after io_uring_setup()
 */
#define MAX_DEFERRED_EPOLL_REGS 64
struct deferred_epoll_reg {
	unsigned int io_uring_fd;	/* The io_uring fd to add to epoll */
	unsigned int epoll_fd;		/* The epoll fd */
	unsigned int events;		/* epoll events mask */
	unsigned long long data;	/* epoll user data */
};

static struct {
	int count;
	struct deferred_epoll_reg regs[MAX_DEFERRED_EPOLL_REGS];
} deferred_epoll_io_uring;

/*
 * Check if a tfd is an io_uring fd (for eventpoll restore).
 * Called during eventpoll_retore_tfd() to decide whether to defer.
 */
int is_io_uring_tfd(struct pstree_item *t, int tfd)
{
	MmEntry *mm = rsti(t)->mm;
	int i;

	if (!mm || !mm->n_io_urings)
		return 0;

	for (i = 0; i < mm->n_io_urings; i++) {
		if (mm->io_urings[i]->id == tfd)
			return 1;
	}
	return 0;
}

/*
 * Defer an epoll registration for an io_uring fd.
 * Called from eventpoll_retore_tfd() when tfd is io_uring.
 */
int defer_epoll_io_uring(int io_uring_fd, int epoll_fd,
			 unsigned int events, unsigned long long data)
{
	struct deferred_epoll_reg *reg;

	if (deferred_epoll_io_uring.count >= MAX_DEFERRED_EPOLL_REGS) {
		pr_err("io_uring: Too many deferred epoll registrations\n");
		return -1;
	}

	reg = &deferred_epoll_io_uring.regs[deferred_epoll_io_uring.count++];
	reg->io_uring_fd = io_uring_fd;
	reg->epoll_fd = epoll_fd;
	reg->events = events;
	reg->data = data;

	pr_info("io_uring: Deferred epoll registration: epoll_fd=%d io_uring_fd=%d events=0x%x\n",
		epoll_fd, io_uring_fd, events);
	return 0;
}

static int parse_io_uring_fdinfo(int proc_fd, int fd, struct io_uring_fdinfo *info)
{
	char path[64];
	char buf[4096];
	FILE *f;
	int fdinfo_fd;

	snprintf(path, sizeof(path), "fdinfo/%d", fd);
	fdinfo_fd = openat(proc_fd, path, O_RDONLY);
	if (fdinfo_fd < 0) {
		pr_perror("Can't open fdinfo for fd %d", fd);
		return -1;
	}

	f = fdopen(fdinfo_fd, "r");
	if (!f) {
		close(fdinfo_fd);
		pr_perror("Can't fdopen fdinfo for fd %d", fd);
		return -1;
	}

	memset(info, 0, sizeof(*info));
	info->sq_thread = -1;
	info->sq_thread_cpu = -1;

	while (fgets(buf, sizeof(buf), f)) {
		char *colon = strchr(buf, ':');
		char *value;
		if (!colon) continue;
		*colon = '\0';
		value = colon + 1;
		while (*value == ' ' || *value == '\t') value++;

		if (!strcmp(buf, "SqMask")) info->sq_mask = strtoul(value, NULL, 0);
		else if (!strcmp(buf, "SqHead")) info->sq_head = strtoul(value, NULL, 0);
		else if (!strcmp(buf, "SqTail")) info->sq_tail = strtoul(value, NULL, 0);
		else if (!strcmp(buf, "CachedSqHead")) info->cached_sq_head = strtoul(value, NULL, 0);
		else if (!strcmp(buf, "CqMask")) info->cq_mask = strtoul(value, NULL, 0);
		else if (!strcmp(buf, "CqHead")) info->cq_head = strtoul(value, NULL, 0);
		else if (!strcmp(buf, "CqTail")) info->cq_tail = strtoul(value, NULL, 0);
		else if (!strcmp(buf, "CachedCqTail")) info->cached_cq_tail = strtoul(value, NULL, 0);
		else if (!strcmp(buf, "SQEs")) info->sqes = strtoul(value, NULL, 0);
		else if (!strcmp(buf, "CQEs")) info->cqes = strtoul(value, NULL, 0);
		else if (!strcmp(buf, "SqThread")) info->sq_thread = strtol(value, NULL, 0);
		else if (!strcmp(buf, "SqThreadCpu")) info->sq_thread_cpu = strtol(value, NULL, 0);
		else if (!strcmp(buf, "UserFiles")) info->user_files = strtoul(value, NULL, 0);
		else if (!strcmp(buf, "UserBufs")) info->user_bufs = strtoul(value, NULL, 0);
	}

	fclose(f);
	return 0;
}

static int find_io_uring_fd(pid_t pid, unsigned long ino, int *found_fd)
{
	char fd_dir[64];
	DIR *dir;
	struct dirent *de;
	int proc_fd;

	proc_fd = open_proc(pid, ".");
	if (proc_fd < 0) return -1;

	snprintf(fd_dir, sizeof(fd_dir), "/proc/%d/fd", pid);
	dir = opendir(fd_dir);
	if (!dir) {
		close(proc_fd);
		pr_perror("Can't open %s", fd_dir);
		return -1;
	}

	*found_fd = -1;

	while ((de = readdir(dir)) != NULL) {
		char link[256];
		char path[64];
		struct stat st;
		int fd;

		if (de->d_name[0] == '.') continue;

		fd = atoi(de->d_name);
		snprintf(path, sizeof(path), "/proc/%d/fd/%d", pid, fd);

		if (readlink(path, link, sizeof(link) - 1) < 0) continue;
		if (!strstr(link, "io_uring")) continue;
		if (fstatat(dirfd(dir), de->d_name, &st, 0) < 0) continue;

		if (st.st_ino == ino) {
			*found_fd = fd;
			break;
		}
	}

	closedir(dir);
	close(proc_fd);

	if (*found_fd < 0) {
		pr_err("Can't find io_uring fd for ino %lu\n", ino);
		return -1;
	}
	return 0;
}

/*
 * Helper to count VMAs for a specific io_uring inode
 */
static int count_vmas_for_ino(struct vm_area_list *vmas, unsigned long ino)
{
	struct vma_area *vma;
	int count = 0;

	list_for_each_entry(vma, &vmas->h, list) {
		if (!vma_entry_is(vma->e, VMA_AREA_IOURING))
			continue;
		if (vma->vm_iouring_ino == ino)
			count++;
	}
	return count;
}

/*
 * Helper to add a VMA to the entry's vmas array
 */
static int add_vma_to_entry(IoUringEntry *entry, struct vma_area *vma, int *vma_idx)
{
	IoUringVma *v;

	if (*vma_idx >= entry->n_vmas) {
		pr_err("VMA index %d exceeds allocated count %zu\n", *vma_idx, entry->n_vmas);
		return -1;
	}

	v = xmalloc(sizeof(*v));
	if (!v)
		return -1;

	io_uring_vma__init(v);
	v->addr = vma->e->start;
	v->size = vma->e->end - vma->e->start;
	v->pgoff = vma->e->pgoff;

	entry->vmas[*vma_idx] = v;
	(*vma_idx)++;

	pr_info("  VMA %d: addr=0x%lx size=%lu pgoff=0x%lx (%s)\n",
		*vma_idx,
		(unsigned long)v->addr,
		(unsigned long)v->size,
		(unsigned long)v->pgoff,
		v->pgoff == IORING_OFF_SQ_RING ? "SQ/CQ ring" :
		v->pgoff == IORING_OFF_CQ_RING ? "CQ ring" :
		v->pgoff == IORING_OFF_SQES ? "SQEs" : "unknown");

	return 0;
}

/*
 * Find existing entry by inode, or return NULL if not found.
 * This replaces the old last_ino assumption with a proper lookup.
 */
static IoUringEntry *find_entry_by_ino(MmEntry *mme, int nr, unsigned long ino)
{
	int i;
	for (i = 0; i < nr; i++) {
		if (mme->io_urings[i] && mme->io_urings[i]->ino == ino)
			return mme->io_urings[i];
	}
	return NULL;
}

int dump_io_uring(MmEntry *mme, struct vm_area_list *vmas, pid_t pid)
{
	struct vma_area *vma;
	struct io_uring_fdinfo fdinfo;
	IoUringEntry *entry = NULL;
	int nr = 0;
	int ret = -1;
	int proc_fd;
	int vma_idx = 0;

	if (!vmas->nr_iourings) {
		pr_debug("No io_uring VMAs to dump\n");
		return 0;
	}

	pr_info("Dumping %u io_uring VMA(s)\n", vmas->nr_iourings);

	proc_fd = open_proc(pid, ".");
	if (proc_fd < 0) return -1;

	/* Allocate space for entries (one per unique inode, not per VMA) */
	mme->io_urings = xmalloc(vmas->nr_iourings * sizeof(IoUringEntry *));
	if (!mme->io_urings) {
		close(proc_fd);
		return -1;
	}
	/* Initialize to NULL for safe lookup */
	memset(mme->io_urings, 0, vmas->nr_iourings * sizeof(IoUringEntry *));

	/*
	 * Process VMAs and collect ALL addresses per io_uring inode.
	 * CRITICAL: uvloop creates MULTIPLE mmap()s on the same ring fd,
	 * so we must capture and restore ALL of them.
	 *
	 * NOTE: We use find_entry_by_ino() to properly group VMAs by inode,
	 * rather than assuming VMAs are sorted by inode (which isn't guaranteed).
	 */
	list_for_each_entry(vma, &vmas->h, list) {
		int fd;

		if (!vma_entry_is(vma->e, VMA_AREA_IOURING))
			continue;

		/* Check if this VMA belongs to an existing entry (by inode lookup) */
		entry = find_entry_by_ino(mme, nr, vma->vm_iouring_ino);
		if (entry != NULL) {
			/* Find the vma_idx for this entry (we need to track per-entry) */
			vma_idx = 0;
			for (size_t k = 0; k < entry->n_vmas; k++) {
				if (entry->vmas[k] != NULL)
					vma_idx++;
			}

			/* Add VMA to existing entry's vmas array */
			if (add_vma_to_entry(entry, vma, &vma_idx) < 0)
				goto err;

			/* Also update legacy single-address fields (keep last of each type) */
			if (vma->e->pgoff == IORING_OFF_SQ_RING) {
				entry->sq_ring_addr = vma->e->start;
				entry->sq_ring_size = vma->e->end - vma->e->start;
			} else if (vma->e->pgoff == IORING_OFF_CQ_RING) {
				entry->cq_ring_addr = vma->e->start;
				entry->cq_ring_size = vma->e->end - vma->e->start;
			} else if (vma->e->pgoff == IORING_OFF_SQES) {
				entry->sqe_addr = vma->e->start;
				entry->sqe_size = vma->e->end - vma->e->start;
			}
			continue;
		}

		/* New io_uring inode - create a new entry */
		if (find_io_uring_fd(pid, vma->vm_iouring_ino, &fd) < 0) {
			pr_err("Can't find fd for io_uring ino %lu\n", vma->vm_iouring_ino);
			goto err;
		}

		if (parse_io_uring_fdinfo(proc_fd, fd, &fdinfo) < 0) {
			pr_err("Can't parse fdinfo for io_uring fd %d\n", fd);
			goto err;
		}

		/*
		 * QUIESCENCE CHECK: Ensure io_uring ring is idle before checkpoint.
		 *
		 * We check TWO things:
		 * 1. SQEs/CQEs count: These are registered files/buffers (less critical)
		 * 2. head != tail: This means pending submissions or completions (CRITICAL)
		 *
		 * If sq_head != sq_tail: there are unprocessed submission entries
		 * If cq_head != cq_tail: there are unprocessed completion entries
		 *
		 * We MUST fail if the ring is not quiescent - restoring with in-flight
		 * I/O will cause corruption or hangs.
		 */
		if (fdinfo.sq_head != fdinfo.sq_tail) {
			pr_err("io_uring fd %d has pending submissions: sq_head=%u sq_tail=%u\n",
			       fd, fdinfo.sq_head, fdinfo.sq_tail);
			pr_err("  Checkpoint while io_uring is busy is not supported.\n");
			pr_err("  Ensure application drains io_uring before checkpoint.\n");
			goto err;
		}
		if (fdinfo.cq_head != fdinfo.cq_tail) {
			pr_err("io_uring fd %d has pending completions: cq_head=%u cq_tail=%u\n",
			       fd, fdinfo.cq_head, fdinfo.cq_tail);
			pr_err("  Checkpoint while io_uring is busy is not supported.\n");
			pr_err("  Ensure application drains io_uring before checkpoint.\n");
			goto err;
		}
		/* Also check registered resources (less critical but log warning) */
		if (fdinfo.user_files > 0 || fdinfo.user_bufs > 0) {
			pr_warn("io_uring fd %d has registered resources: files=%u bufs=%u\n",
			       fd, fdinfo.user_files, fdinfo.user_bufs);
			pr_warn("  Registered files/buffers will NOT be restored.\n");
			/* Continue anyway - registered resources are re-established by app */
		}

		entry = xmalloc(sizeof(*entry));
		if (!entry) goto err;

		io_uring_entry__init(entry);
		entry->id = fd;
		entry->ino = vma->vm_iouring_ino;
		/*
		 * Note: The kernel's io_uring fdinfo doesn't expose SqMask/CqMask.
		 * We compute sq_entries from the SQEs VMA size: size / 64 bytes per SQE.
		 * We'll update these values after processing all VMAs for this io_uring.
		 * For now, set them to 0 as placeholder.
		 */
		entry->sq_entries = 0;
		entry->cq_entries = 0;
		entry->flags = 0;

#define IORING_SETUP_SQPOLL (1U << 1)
		if (fdinfo.sq_thread >= 0) {
			entry->flags |= IORING_SETUP_SQPOLL;
			pr_warn("io_uring fd %d has SQPOLL (thread=%d cpu=%d)\n",
			       fd, fdinfo.sq_thread, fdinfo.sq_thread_cpu);
			pr_warn("  WARNING: SQPOLL kernel thread will be RECREATED on restore.\n");
			pr_warn("  The original thread won't survive. App may need adjustment.\n");
		}

		entry->sq_thread_cpu = fdinfo.sq_thread_cpu;
		entry->has_sq_thread_cpu = true;
		entry->sq_thread_idle = 0;
		entry->has_sq_thread_idle = true;
		entry->sq_mask = fdinfo.sq_mask;
		entry->sq_head = fdinfo.sq_head;
		entry->sq_tail = fdinfo.sq_tail;
		entry->cached_sq_head = fdinfo.cached_sq_head;
		entry->cq_mask = fdinfo.cq_mask;
		entry->cq_head = fdinfo.cq_head;
		entry->cq_tail = fdinfo.cq_tail;
		entry->cached_cq_tail = fdinfo.cached_cq_tail;
		entry->sqes = fdinfo.sqes;
		entry->cqes = fdinfo.cqes;
		entry->user_files = fdinfo.user_files;
		entry->has_user_files = true;
		entry->user_bufs = fdinfo.user_bufs;
		entry->has_user_bufs = true;

		/* Initialize legacy addresses to 0 */
		entry->sq_ring_addr = 0;
		entry->sq_ring_size = 0;
		entry->cq_ring_addr = 0;
		entry->cq_ring_size = 0;
		entry->sqe_addr = 0;
		entry->sqe_size = 0;

		/* Allocate vmas array for ALL VMAs belonging to this inode */
		entry->n_vmas = count_vmas_for_ino(vmas, vma->vm_iouring_ino);
		entry->vmas = xmalloc(entry->n_vmas * sizeof(IoUringVma *));
		if (!entry->vmas) goto err;
		/* CRITICAL: Zero the array so non-NULL check in add_vma_to_entry works */
		memset(entry->vmas, 0, entry->n_vmas * sizeof(IoUringVma *));
		vma_idx = 0;

		pr_info("io_uring fd %d (ino %lu): allocating %zu VMAs\n",
			fd, vma->vm_iouring_ino, entry->n_vmas);

		/* Add this first VMA to the array */
		if (add_vma_to_entry(entry, vma, &vma_idx) < 0)
			goto err;

		/* Set legacy single-address fields from this VMA */
		if (vma->e->pgoff == IORING_OFF_SQ_RING) {
			entry->sq_ring_addr = vma->e->start;
			entry->sq_ring_size = vma->e->end - vma->e->start;
		} else if (vma->e->pgoff == IORING_OFF_CQ_RING) {
			entry->cq_ring_addr = vma->e->start;
			entry->cq_ring_size = vma->e->end - vma->e->start;
		} else if (vma->e->pgoff == IORING_OFF_SQES) {
			entry->sqe_addr = vma->e->start;
			entry->sqe_size = vma->e->end - vma->e->start;
		}

		/* Store new entry in array */
		mme->io_urings[nr++] = entry;
	}

	/*
	 * Second pass: finalize all entries and write file entries.
	 * This is done after all VMAs are collected so we have complete info.
	 */
	for (int i = 0; i < nr; i++) {
		IoUringFileEntry iufe = IO_URING_FILE_ENTRY__INIT;
		FileEntry fe = FILE_ENTRY__INIT;

		entry = mme->io_urings[i];
		if (!entry)
			continue;

		/*
		 * Compute sq_entries and cq_entries.
		 *
		 * Primary source: sq_mask from fdinfo (sq_mask = sq_entries - 1).
		 * This is reliable because kernel exposes it directly.
		 *
		 * Fallback: compute from VMA size / SQE size.
		 * Note: SQE size is normally 64 bytes, but IORING_SETUP_SQE128
		 * uses 128-byte SQEs. We detect this by checking if the VMA
		 * size makes sense with either size.
		 */
		if (entry->sq_mask > 0) {
			/* Use mask from fdinfo (reliable) */
			entry->sq_entries = entry->sq_mask + 1;
		} else if (entry->sqe_size > 0) {
			/*
			 * Infer SQE size from VMA size:
			 * - Standard: VMA = entries * 64
			 * - SQE128:   VMA = entries * 128
			 * Check which one gives a power-of-2 result.
			 */
			uint32_t entries_64 = entry->sqe_size / SIZEOF_SQE_NORMAL;
			uint32_t entries_128 = entry->sqe_size / SIZEOF_SQE_128;
			
			if (entries_128 > 0 && (entries_128 & (entries_128 - 1)) == 0 &&
			    entries_128 * SIZEOF_SQE_128 == entry->sqe_size) {
				/* SQE128 mode - set flag */
				entry->flags |= IORING_SETUP_SQE128;
				entry->sq_entries = entries_128;
				pr_info("  Detected SQE128 mode: %u entries\n", entries_128);
			} else if (entries_64 > 0) {
				entry->sq_entries = entries_64;
			} else {
				entry->sq_entries = 32; /* fallback */
			}
		} else {
			/* Try to find SQEs from vmas array */
			size_t sqe_vma_size = 0;
			size_t k;
			for (k = 0; k < entry->n_vmas; k++) {
				if (entry->vmas[k] && entry->vmas[k]->pgoff == IORING_OFF_SQES &&
				    entry->vmas[k]->size > sqe_vma_size)
					sqe_vma_size = entry->vmas[k]->size;
			}
			entry->sq_entries = sqe_vma_size > 0 ? sqe_vma_size / SIZEOF_SQE_NORMAL : 32;
		}
		
		/* CQ entries: use mask if available, otherwise 2x SQ entries */
		if (entry->cq_mask > 0) {
			entry->cq_entries = entry->cq_mask + 1;
		} else if (entry->cq_entries == 0) {
			entry->cq_entries = entry->sq_entries * 2;
		}
		
		/* Update masks for consistency */
		if (entry->sq_mask == 0)
			entry->sq_mask = entry->sq_entries - 1;
		if (entry->cq_mask == 0)
			entry->cq_mask = entry->cq_entries - 1;

		iufe.id = entry->id;
		iufe.ino = entry->ino;
		fe.type = FD_TYPES__IO_URING;
		fe.id = iufe.id;
		fe.iouring = &iufe;

		if (pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), &fe, PB_FILE)) {
			pr_err("Failed to write io_uring file entry\n");
			goto err;
		}

		pr_info("Dumped io_uring fd %d: SQ=%u CQ=%u n_vmas=%zu (computed from VMA sizes)\n",
			entry->id, entry->sq_entries, entry->cq_entries, entry->n_vmas);
	}

	mme->n_io_urings = nr;
	ret = 0;
err:
	close(proc_fd);
	return ret;
}

void free_io_urings(MmEntry *mme)
{
	int i, j;
	if (mme->io_urings) {
		for (i = 0; i < mme->n_io_urings; i++) {
			IoUringEntry *e = mme->io_urings[i];
			if (e) {
				/* Free the vmas array */
				if (e->vmas) {
					for (j = 0; j < e->n_vmas; j++)
						xfree(e->vmas[j]);
					xfree(e->vmas);
				}
				xfree(e);
			}
		}
		xfree(mme->io_urings);
	}
}

int check_io_uring_support(void)
{
	struct io_uring_params params = { 0 };
	int fd = syscall(__NR_io_uring_setup, 1, &params);
	if (fd < 0) {
		if (errno == ENOSYS) return 0;
	} else {
		close(fd);
	}
	return 1;
}

int prepare_io_urings(struct pstree_item *t, struct task_restore_args *ta)
{
	MmEntry *mm = rsti(t)->mm;
	int i, j;

	if (!mm || !mm->n_io_urings) {
		ta->io_uring_rings = NULL;
		ta->io_uring_rings_n = 0;
		return 0;
	}

	/* Skip io_uring restoration if requested.
	 * This is useful when io_uring state after restore causes issues
	 * with applications like uvloop/libuv that maintain internal state.
	 * The application will either recreate io_uring or fall back to epoll.
	 */
	if (opts.skip_io_uring) {
		pr_warn("Skipping io_uring restoration (--skip-io-uring)\n");
		pr_warn("  %zu io_uring ring(s) will NOT be restored\n", mm->n_io_urings);
		ta->io_uring_rings = NULL;
		ta->io_uring_rings_n = 0;
		return 0;
	}

	/*
	 * Allocate ring info structures for the pie restorer.
	 * The restorer will create fresh io_uring instances and mmap
	 * them at the target addresses (captured during dump).
	 *
	 * Use rst_mem_align_cpos() like aio.c does to get aligned base pointer,
	 * then allocate each ring entry individually.
	 */
	ta->io_uring_rings = (struct rst_io_uring_ring *)rst_mem_align_cpos(RM_PRIVATE);
	ta->io_uring_rings_n = mm->n_io_urings;

	for (i = 0; i < mm->n_io_urings; i++) {
		IoUringEntry *entry = mm->io_urings[i];
		struct rst_io_uring_ring *ring;

		ring = rst_mem_alloc(sizeof(*ring), RM_PRIVATE);
		if (!ring) {
			pr_err("Failed to allocate io_uring ring info\n");
			return -1;
		}

		/* Initialize with defaults */
		ring->sq_ring_addr = 0;
		ring->cq_ring_addr = 0;
		ring->sqe_addr = 0;
		ring->sq_ring_size = 0;
		ring->cq_ring_size = 0;
		ring->sqe_size = 0;
		ring->n_epoll_refs = 0;

		/* Extract addresses from captured VMAs */
		for (j = 0; j < entry->n_vmas; j++) {
			IoUringVma *v = entry->vmas[j];
			if (v->pgoff == IORING_OFF_SQ_RING || v->pgoff == 0) {
				/* Take lowest address for SQ ring (primary) */
				if (!ring->sq_ring_addr || v->addr < ring->sq_ring_addr) {
					ring->sq_ring_addr = v->addr;
					ring->sq_ring_size = v->size;
				}
			} else if (v->pgoff == IORING_OFF_CQ_RING) {
				if (!ring->cq_ring_addr || v->addr < ring->cq_ring_addr) {
					ring->cq_ring_addr = v->addr;
					ring->cq_ring_size = v->size;
				}
			} else if (v->pgoff == IORING_OFF_SQES) {
				if (!ring->sqe_addr || v->addr < ring->sqe_addr) {
					ring->sqe_addr = v->addr;
					ring->sqe_size = v->size;
				}
			}
		}

		ring->sq_entries = entry->sq_entries;
		ring->cq_entries = entry->cq_entries;
		ring->flags = entry->flags;
		ring->sq_thread_cpu = entry->has_sq_thread_cpu ? entry->sq_thread_cpu : -1;
		ring->sq_thread_idle = entry->has_sq_thread_idle ? entry->sq_thread_idle : 0;
		ring->fd = entry->id;

		/*
		 * Copy ring state (head/tail) from checkpoint.
		 * This is CRITICAL: libuv/uvloop cache these values internally.
		 * If we don't restore them, there's a mismatch causing crashes.
		 */
		ring->sq_head = entry->sq_head;
		ring->sq_tail = entry->sq_tail;
		ring->cq_head = entry->cq_head;
		ring->cq_tail = entry->cq_tail;

		/*
		 * Copy deferred epoll registrations from the global array.
		 * These were collected during eventpoll_retore_tfd() when it
		 * detected io_uring tfds and deferred their registration.
		 */
		for (j = 0; j < deferred_epoll_io_uring.count; j++) {
			struct deferred_epoll_reg *reg = &deferred_epoll_io_uring.regs[j];
			if (reg->io_uring_fd == entry->id) {
				if (ring->n_epoll_refs >= MAX_EPOLL_REFS_PER_RING) {
					pr_warn("io_uring fd %u: too many epoll refs\n", entry->id);
					break;
				}
				ring->epoll_refs[ring->n_epoll_refs].epoll_fd = reg->epoll_fd;
				ring->epoll_refs[ring->n_epoll_refs].events = reg->events;
				ring->epoll_refs[ring->n_epoll_refs].data = reg->data;
				ring->n_epoll_refs++;

				pr_info("io_uring fd %u: copied epoll_ref epoll_fd=%u events=0x%x\n",
					entry->id, reg->epoll_fd, reg->events);
			}
		}

		pr_info("Prepared io_uring ring %d: fd=%u sq=%u cq=%u sq_addr=0x%lx sqe_addr=0x%lx n_epoll_refs=%u\n",
			i, ring->fd, ring->sq_entries, ring->cq_entries,
			ring->sq_ring_addr, ring->sqe_addr, ring->n_epoll_refs);
	}

	pr_info("Prepared %u io_uring ring(s) for restorer\n", ta->io_uring_rings_n);
	return 0;
}

/*
 * ============================================================================
 * io_uring FILE TYPE SUPPORT
 * ============================================================================
 */

struct io_uring_file_info {
	IoUringFileEntry *iue;
	struct file_desc d;
	uint32_t sq_entries;
	uint32_t cq_entries;
	uint32_t flags;
	int sq_thread_cpu;
	uint32_t sq_thread_idle;
};

struct io_uring_group {
	u32 file_desc_id;
	int leader_fd;
	int ring_fd;
	int created;
	struct io_uring_file_info *info;
};

#define MAX_IO_URING_GROUPS 16
static struct {
	int count;
	struct io_uring_group groups[MAX_IO_URING_GROUPS];
} io_uring_groups;

int is_io_uring_file_desc(struct file_desc *d)
{
	return d && d->ops && d->ops->type == FD_TYPES__IO_URING;
}

static struct io_uring_group *find_or_create_group(u32 id)
{
	int i;
	for (i = 0; i < io_uring_groups.count; i++) {
		if (io_uring_groups.groups[i].file_desc_id == id)
			return &io_uring_groups.groups[i];
	}
	if (io_uring_groups.count >= MAX_IO_URING_GROUPS) {
		pr_err("Too many io_uring groups\n");
		return NULL;
	}
	i = io_uring_groups.count++;
	io_uring_groups.groups[i].file_desc_id = id;
	io_uring_groups.groups[i].leader_fd = INT_MAX;
	io_uring_groups.groups[i].ring_fd = -1;
	io_uring_groups.groups[i].created = 0;
	io_uring_groups.groups[i].info = NULL;
	return &io_uring_groups.groups[i];
}

static int io_uring_open(struct file_desc *d, int *new_fd)
{
	struct io_uring_file_info *info;
	struct io_uring_group *group;
	struct io_uring_params params = { 0 };
	int ring_fd;

	info = container_of(d, struct io_uring_file_info, d);
	group = find_or_create_group(d->id);
	if (!group) return -1;

	if (group->created) {
		pr_info("Reusing ring fd %d for file_desc %#x\n", group->ring_fd, d->id);
		*new_fd = group->ring_fd;
		return 0;
	}

	params.sq_entries = info->sq_entries;
	params.cq_entries = info->cq_entries;
	params.flags = info->flags & ~(1U << 1); /* No SQPOLL initially */

	if (info->sq_thread_cpu >= 0)
		params.sq_thread_cpu = info->sq_thread_cpu;

	ring_fd = syscall(__NR_io_uring_setup, params.sq_entries, &params);
	if (ring_fd < 0) {
		pr_perror("Failed to create io_uring (sq=%u cq=%u)", info->sq_entries, info->cq_entries);
		return -1;
	}

	group->ring_fd = ring_fd;
	group->created = 1;
	group->info = info;

	pr_info("Created io_uring fd %d for file_desc %#x (sq=%u cq=%u)\n",
		ring_fd, d->id, info->sq_entries, info->cq_entries);

	*new_fd = ring_fd;
	return 0;
}

static struct file_desc_ops io_uring_desc_ops = {
	.type = FD_TYPES__IO_URING,
	.open = io_uring_open,
};

static int collect_one_io_uring(void *obj, ProtobufCMessage *msg, struct cr_img *i)
{
	struct io_uring_file_info *info = obj;
	MmEntry *mm;
	int j;

	info->iue = pb_msg(msg, IoUringFileEntry);

	pr_info("Collected io_uring file_desc id %#x (ino %lu)\n",
		info->iue->id, (unsigned long)info->iue->ino);

	info->sq_entries = 32;
	info->cq_entries = 64;
	info->flags = 0;
	info->sq_thread_cpu = -1;
	info->sq_thread_idle = 0;

	mm = rsti(root_item)->mm;
	if (mm && mm->io_urings) {
		for (j = 0; j < mm->n_io_urings; j++) {
			IoUringEntry *e = mm->io_urings[j];
			if (e->ino == info->iue->ino) {
				info->sq_entries = e->sq_entries;
				info->cq_entries = e->cq_entries;
				info->flags = e->flags;
				info->sq_thread_cpu = e->has_sq_thread_cpu ? e->sq_thread_cpu : -1;
				info->sq_thread_idle = e->has_sq_thread_idle ? e->sq_thread_idle : 0;
				pr_info("Found config for ino %lu: sq=%u cq=%u\n",
					(unsigned long)info->iue->ino, info->sq_entries, info->cq_entries);
				break;
			}
		}
	}

	return file_desc_add(&info->d, info->iue->id, &io_uring_desc_ops);
}

struct collect_image_info io_uring_cinfo = {
	.fd_type = CR_FD_IO_URING_FILE,
	.pb_type = PB_IO_URING_FILE,
	.priv_size = sizeof(struct io_uring_file_info),
	.collect = collect_one_io_uring,
};

static int dump_one_io_uring_fd(int lfd, u32 id, const struct fd_parms *p)
{
	IoUringFileEntry iue = IO_URING_FILE_ENTRY__INIT;
	FileEntry fe = FILE_ENTRY__INIT;

	/* NOTE: We DO NOT skip in portable mode anymore.
	 * io_uring file entries must be written so restore can
	 * create the file_desc and satisfy fdinfo references.
	 */
	iue.id = id;
	iue.ino = p->stat.st_ino;

	fe.type = FD_TYPES__IO_URING;
	fe.id = iue.id;
	fe.iouring = &iue;

	pr_info("Dumping io_uring -> id %#x ino %lu\n", id, (unsigned long)iue.ino);

	return pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), &fe, PB_FILE);
}

const struct fdtype_ops io_uring_dump_ops = {
	.type = FD_TYPES__IO_URING,
	.dump = dump_one_io_uring_fd,
};

int precreate_io_urings(struct pstree_item *t)
{
	MmEntry *mm = rsti(t)->mm;

	io_uring_groups.count = 0;

	if (!mm || !mm->n_io_urings) {
		pr_debug("io_uring: No io_uring entries in MmEntry for pid %d\n", vpid(t));
		return 0;
	}

	/*
	 * io_uring CANNOT be pre-created here. This function runs in CRIU's
	 * address space, not the target process's. Creating io_uring here
	 * would put the fd in CRIU's fd table and the mmaps in CRIU's address
	 * space - neither transfers to the restored process.
	 *
	 * The correct approach:
	 * 1. io_uring is restored by PIE restorer (runs in target process)
	 * 2. epoll registrations for io_uring tfds are deferred
	 * 3. PIE calls epoll_ctl() after io_uring_setup()
	 *
	 * See prepare_io_urings() for how epoll registrations are collected,
	 * and restore_io_uring_ring() in pie/restorer.c for the epoll_ctl.
	 */
	pr_info("io_uring: Found %zu io_uring(s) - will be restored by PIE restorer\n",
		mm->n_io_urings);

	return 0;
}

/* DISABLED: Old precreate code removed - keeping for reference
 * The pie restorer's restore_io_uring_ring() now handles:
 * - io_uring_setup() to create new ring
 * - mmap() with MAP_FIXED to target addresses
 * - dup2() to move fd to target number
 */
#if 0
static void __attribute__((unused)) old_precreate_code(void)
{
	/* This code ran in CRIU's address space, not the restored process.
	 * Memory mappings created here didn't transfer to the restored process,
	 * causing segfaults when uvloop tried to access the unmapped addresses.
	 */

		/*
		 * CRITICAL: Log sq_off and cq_off for layout comparison.
		 * uvloop caches pointers like: sq->array = ring_base + sq_off.array
		 * If offsets differ between dump and restore, uvloop will crash.
		 */
		pr_info("  sq_off: head=%u tail=%u ring_mask=%u ring_entries=%u flags=%u dropped=%u array=%u\n",
			params.sq_off.head, params.sq_off.tail, params.sq_off.ring_mask,
			params.sq_off.ring_entries, params.sq_off.flags, params.sq_off.dropped,
			params.sq_off.array);
		pr_info("  cq_off: head=%u tail=%u ring_mask=%u ring_entries=%u overflow=%u cqes=%u flags=%u\n",
			params.cq_off.head, params.cq_off.tail, params.cq_off.ring_mask,
			params.cq_off.ring_entries, params.cq_off.overflow, params.cq_off.cqes,
			params.cq_off.flags);

		/*
		 * Check if saved offsets exist and compare
		 */
		if (entry->has_sq_off_array) {
			pr_info("  Comparing with saved offsets:\n");
			pr_info("    sq_off.array: saved=%u restored=%u %s\n",
				entry->sq_off_array, params.sq_off.array,
				entry->sq_off_array == params.sq_off.array ? "MATCH" : "MISMATCH!");
			pr_info("    cq_off.cqes: saved=%u restored=%u %s\n",
				entry->cq_off_cqes, params.cq_off.cqes,
				entry->cq_off_cqes == params.cq_off.cqes ? "MATCH" : "MISMATCH!");

			if (entry->sq_off_array != params.sq_off.array ||
			    entry->cq_off_cqes != params.cq_off.cqes) {
				pr_err("LAYOUT MISMATCH! Ring offsets differ - uvloop will crash!\n");
				pr_err("  This usually means kernel version/config differs between checkpoint and restore.\n");
			}
		} else {
			pr_warn("  No saved offsets to compare (checkpoint from older agent version)\n");
		}

		/*
		 * Compute sizes from kernel-returned offsets (for validation)
		 */
		sq_ring_sz = params.sq_off.array + params.sq_entries * sizeof(__u32);
		sq_ring_sz = (sq_ring_sz + 4095) & ~4095UL;

		cq_ring_sz = params.cq_off.cqes + params.cq_entries * 16;
		cq_ring_sz = (cq_ring_sz + 4095) & ~4095UL;

		sqes_sz = params.sq_entries * 64;
		sqes_sz = (sqes_sz + 4095) & ~4095UL;

		/*
		 * Map VMAs from the vmas array using mmap + mremap strategy.
		 *
		 * uvloop creates duplicate VMAs with the same pgoff via mremap(DONTUNMAP).
		 * The kernel rejects multiple mmap() calls for the same io_uring offset.
		 *
		 * Strategy (per friend's guidance):
		 * 1. Group VMAs by pgoff
		 * 2. mmap() only ONCE per pgoff (primary = lowest address)
		 * 3. Use mremap(MREMAP_DONTUNMAP) to create duplicates at other addresses
		 */
		if (entry->n_vmas > 0 && entry->vmas) {
			/* Track which pgoff values we've already mapped */
			int sq_ring_mapped = 0, cq_ring_mapped = 0, sqes_mapped = 0;
			/* Track which pgoff types we've seen (for finding primary) */
			int sq_ring_seen = 0, cq_ring_seen = 0, sqes_seen = 0;
			void *sq_ring_primary = NULL, *cq_ring_primary = NULL, *sqes_primary = NULL;
			size_t sq_ring_primary_sz = 0, cq_ring_primary_sz = 0, sqes_primary_sz = 0;

			pr_info("  Mapping %zu VMAs (mmap + mremap strategy)\n", entry->n_vmas);

			/*
			 * First pass: find primary (lowest addr) for each pgoff group
			 * and determine max size needed
			 */
			for (j = 0; j < entry->n_vmas; j++) {
				IoUringVma *v = entry->vmas[j];

				if (v->pgoff == IORING_OFF_SQ_RING || v->pgoff == 0) {
					if (!sq_ring_seen || v->addr < (uint64_t)sq_ring_primary) {
						sq_ring_primary = (void *)v->addr;
					}
					sq_ring_seen = 1;
					if (v->size > sq_ring_primary_sz)
						sq_ring_primary_sz = v->size;
				} else if (v->pgoff == IORING_OFF_CQ_RING) {
					if (!cq_ring_seen || v->addr < (uint64_t)cq_ring_primary) {
						cq_ring_primary = (void *)v->addr;
					}
					cq_ring_seen = 1;
					if (v->size > cq_ring_primary_sz)
						cq_ring_primary_sz = v->size;
				} else if (v->pgoff == IORING_OFF_SQES) {
					if (!sqes_seen || v->addr < (uint64_t)sqes_primary) {
						sqes_primary = (void *)v->addr;
					}
					sqes_seen = 1;
					if (v->size > sqes_primary_sz)
						sqes_primary_sz = v->size;
				}
			}

			/*
			 * CRITICAL: Use kernel-computed sizes for mmap, not saved VMA sizes.
			 * The kernel will reject mmap requests larger than what it allocated.
			 * If saved sizes are larger (from original process), use kernel sizes.
			 */
			sq_ring_primary_sz = sq_ring_sz;
			cq_ring_primary_sz = cq_ring_sz;
			sqes_primary_sz = sqes_sz;

			pr_info("  Using kernel sizes: sq_ring=%zu cq_ring=%zu sqes=%zu\n",
				sq_ring_sz, cq_ring_sz, sqes_sz);

			/* Log selected primaries */
			if (sq_ring_seen)
				pr_info("  SQ/CQ ring PRIMARY: 0x%lx (size %zu)\n",
					(unsigned long)sq_ring_primary, sq_ring_primary_sz);
			if (cq_ring_seen)
				pr_info("  CQ ring PRIMARY: 0x%lx (size %zu)\n",
					(unsigned long)cq_ring_primary, cq_ring_primary_sz);
			if (sqes_seen)
				pr_info("  SQEs PRIMARY: 0x%lx (size %zu)\n",
					(unsigned long)sqes_primary, sqes_primary_sz);

			/*
			 * Second pass: mmap primary VMAs first, then mremap duplicates
			 */
			for (j = 0; j < entry->n_vmas; j++) {
				IoUringVma *v = entry->vmas[j];
				off_t offset;
				size_t primary_sz;
				void **primary_ptr;
				int *mapped_flag;
				const char *type_str;

				/* Determine offset and type from pgoff */
				if (v->pgoff == IORING_OFF_SQ_RING || v->pgoff == 0) {
					offset = IORING_OFF_SQ_RING;
					primary_sz = sq_ring_primary_sz;
					primary_ptr = &sq_ring_primary;
					mapped_flag = &sq_ring_mapped;
					type_str = "SQ/CQ ring";
				} else if (v->pgoff == IORING_OFF_CQ_RING) {
					offset = IORING_OFF_CQ_RING;
					primary_sz = cq_ring_primary_sz;
					primary_ptr = &cq_ring_primary;
					mapped_flag = &cq_ring_mapped;
					type_str = "CQ ring";
				} else if (v->pgoff == IORING_OFF_SQES) {
					offset = IORING_OFF_SQES;
					primary_sz = sqes_primary_sz;
					primary_ptr = &sqes_primary;
					mapped_flag = &sqes_mapped;
					type_str = "SQEs";
				} else {
					pr_warn("Unknown io_uring pgoff 0x%lx, skipping\n",
						(unsigned long)v->pgoff);
					continue;
				}

				if (!*mapped_flag) {
					/*
					 * Primary mapping strategy:
					 * 1. mmap WITHOUT MAP_FIXED (let kernel choose address)
					 * 2. mremap with MREMAP_FIXED to move to target address
					 *
					 * This is needed because io_uring's mmap handler may reject
					 * MAP_FIXED to arbitrary addresses with EINVAL.
					 */
					void *kernel_ptr;

					pr_info("  VMA %d: %s PRIMARY - step 1: mmap (kernel addr)\n",
						j, type_str);

					kernel_ptr = mmap(NULL, primary_sz,
						   PROT_READ | PROT_WRITE,
						   MAP_SHARED | MAP_POPULATE,
						   ring_fd, offset);

					if (kernel_ptr == MAP_FAILED) {
						pr_perror("Failed to mmap %s (kernel addr)",
							  type_str);
						close(ring_fd);
						return -1;
					}
					pr_info("  %s kernel mapped at %p, now relocating to 0x%lx\n",
						type_str, kernel_ptr, (unsigned long)*primary_ptr);

					/* Now relocate to target address */
					ptr = mremap(kernel_ptr, primary_sz, primary_sz,
						     MREMAP_MAYMOVE | MREMAP_FIXED,
						     *primary_ptr);

					if (ptr == MAP_FAILED) {
						pr_perror("Failed to mremap %s from %p to 0x%lx",
							  type_str, kernel_ptr, (unsigned long)*primary_ptr);
						munmap(kernel_ptr, primary_sz);
						close(ring_fd);
						return -1;
					}
					if (ptr != *primary_ptr) {
						pr_err("%s mremap at wrong address: expected %p, got %p\n",
						       type_str, *primary_ptr, ptr);
						close(ring_fd);
						return -1;
					}
					*mapped_flag = 1;
					pr_info("  %s mapped successfully at %p\n", type_str, ptr);
				}

				/* If this VMA is not the primary, create duplicate mapping */
				if ((void *)v->addr != *primary_ptr) {
					void *dup_kernel_ptr;

					/*
					 * Strategy for duplicate VMAs:
					 * mremap(DONTUNMAP) doesn't work on io_uring mappings.
					 * Instead, we do a fresh mmap() on the same ring_fd
					 * (io_uring allows multiple mmaps) and then mremap
					 * to the target address.
					 */
					pr_info("  VMA %d: %s DUPLICATE - mmap+mremap to 0x%lx\n",
						j, type_str, (unsigned long)v->addr);

					/* Step 1: Fresh mmap to kernel-chosen address */
					dup_kernel_ptr = mmap(NULL, primary_sz,
						   PROT_READ | PROT_WRITE,
						   MAP_SHARED | MAP_POPULATE,
						   ring_fd, offset);

					if (dup_kernel_ptr == MAP_FAILED) {
						pr_warn("Failed to mmap %s for duplicate - skipping\n",
							type_str);
						continue;
					}

					/* Step 2: Relocate to duplicate target address */
					ptr = mremap(dup_kernel_ptr, primary_sz, primary_sz,
						     MREMAP_MAYMOVE | MREMAP_FIXED,
						     (void *)v->addr);

					if (ptr == MAP_FAILED) {
						pr_warn("Failed to mremap %s to 0x%lx - skipping duplicate\n",
							type_str, (unsigned long)v->addr);
						munmap(dup_kernel_ptr, primary_sz);
						continue;
					}
					if (ptr != (void *)v->addr) {
						pr_err("%s mremap at wrong address: expected 0x%lx, got %p\n",
						       type_str, (unsigned long)v->addr, ptr);
						close(ring_fd);
						return -1;
					}
					pr_info("  %s duplicate created at 0x%lx\n",
						type_str, (unsigned long)v->addr);
				}
			}

			/*
			 * CRITICAL: Restore ring head/tail to checkpointed values.
		 *
		 * The app (libuv/uvloop) caches head/tail values internally.
		 * The kernel's new ring is initialized to 0. We MUST restore
		 * the checkpointed head/tail values so the app's internal state
		 * matches the kernel's ring state.
		 *
		 * Ring structure (from params.sq_off / params.cq_off):
		 *   head: kernel-updated (SQ) or app-updated (CQ)
		 *   tail: app-updated (SQ) or kernel-updated (CQ)
		 *
		 * If we set head=tail=0 (old approach), there's a mismatch:
		 *   - App thinks tail is at N, kernel says tail is at 0
		 *   - App tries to submit at index N, kernel expects 0
		 *   - Result: io_uring_enter() fails, libuv calls abort()
		 *
		 * By restoring checkpointed values, the ring state matches
		 * what the app expects, and operations resume correctly.
		 */
		if (sq_ring_primary && sq_ring_mapped) {
			volatile uint32_t *sq_head_ptr, *sq_tail_ptr, *sq_mask, *sq_flags;

			sq_head_ptr = (uint32_t*)((char*)sq_ring_primary + params.sq_off.head);
			sq_tail_ptr = (uint32_t*)((char*)sq_ring_primary + params.sq_off.tail);
			sq_mask = (uint32_t*)((char*)sq_ring_primary + params.sq_off.ring_mask);
			sq_flags = (uint32_t*)((char*)sq_ring_primary + params.sq_off.flags);

			pr_info("  SQ ring state before restore: kernel_head=%u kernel_tail=%u mask=%u flags=%u\n",
				*sq_head_ptr, *sq_tail_ptr, *sq_mask, *sq_flags);
			pr_info("  SQ ring checkpointed state: head=%u tail=%u\n",
				entry->sq_head, entry->sq_tail);

			/* Restore to checkpointed values */
			*sq_head_ptr = entry->sq_head;
			*sq_tail_ptr = entry->sq_tail;

			pr_info("  SQ ring restored: head=%u tail=%u\n", entry->sq_head, entry->sq_tail);

			/* Also restore CQ if it shares the same mapping */
			if (!cq_ring_seen || cq_ring_primary == sq_ring_primary) {
				volatile uint32_t *cq_head_ptr, *cq_tail_ptr;

				cq_head_ptr = (uint32_t*)((char*)sq_ring_primary + params.cq_off.head);
				cq_tail_ptr = (uint32_t*)((char*)sq_ring_primary + params.cq_off.tail);

				pr_info("  CQ ring (shared) state before restore: kernel_head=%u kernel_tail=%u\n",
					*cq_head_ptr, *cq_tail_ptr);
				pr_info("  CQ ring checkpointed state: head=%u tail=%u\n",
					entry->cq_head, entry->cq_tail);

				*cq_head_ptr = entry->cq_head;
				*cq_tail_ptr = entry->cq_tail;

				pr_info("  CQ ring (shared) restored: head=%u tail=%u\n",
					entry->cq_head, entry->cq_tail);
			}
		}

		/* Restore separate CQ ring if it exists */
		if (cq_ring_mapped && cq_ring_primary != sq_ring_primary) {
			volatile uint32_t *cq_head_ptr, *cq_tail_ptr;

			cq_head_ptr = (uint32_t*)((char*)cq_ring_primary + params.cq_off.head);
			cq_tail_ptr = (uint32_t*)((char*)cq_ring_primary + params.cq_off.tail);

			pr_info("  CQ ring (separate) state before restore: kernel_head=%u kernel_tail=%u\n",
				*cq_head_ptr, *cq_tail_ptr);
			pr_info("  CQ ring checkpointed state: head=%u tail=%u\n",
				entry->cq_head, entry->cq_tail);

			*cq_head_ptr = entry->cq_head;
			*cq_tail_ptr = entry->cq_tail;

			pr_info("  CQ ring (separate) restored: head=%u tail=%u\n",
				entry->cq_head, entry->cq_tail);
		}

		pr_info("  io_uring %d ring state restored to checkpointed values\n", entry->id);
	} else {
			/*
			 * Fallback: use legacy single-address fields.
			 * This handles checkpoints made before the multi-VMA support.
			 */
			pr_info("  Using legacy single-address fields\n");

			/* Use saved sizes if available and sufficient, otherwise kernel sizes */
			if (entry->sq_ring_size > 0 && entry->sq_ring_size >= sq_ring_sz)
				sq_ring_sz = entry->sq_ring_size;
			if (entry->cq_ring_size > 0 && entry->cq_ring_size >= cq_ring_sz)
				cq_ring_sz = entry->cq_ring_size;
			if (entry->sqe_size > 0 && entry->sqe_size >= sqes_sz)
				sqes_sz = entry->sqe_size;

			/* Map SQ ring to original address */
			if (entry->sq_ring_addr != 0) {
				pr_info("  Mapping SQ ring: addr=0x%lx size=%zu\n",
					(unsigned long)entry->sq_ring_addr, sq_ring_sz);

				ptr = mmap((void *)entry->sq_ring_addr, sq_ring_sz,
					   PROT_READ | PROT_WRITE,
					   MAP_SHARED | MAP_POPULATE | MAP_FIXED,
					   ring_fd, IORING_OFF_SQ_RING);

				if (ptr == MAP_FAILED) {
					pr_perror("Failed to mmap SQ ring at 0x%lx",
						  (unsigned long)entry->sq_ring_addr);
					close(ring_fd);
					return -1;
				}
				if (ptr != (void *)entry->sq_ring_addr) {
					pr_err("SQ ring mapped at wrong address: expected 0x%lx, got %p\n",
					       (unsigned long)entry->sq_ring_addr, ptr);
					close(ring_fd);
					return -1;
				}
			}

			/* Map CQ ring to original address */
			if (entry->cq_ring_addr != 0) {
				pr_info("  Mapping CQ ring: addr=0x%lx size=%zu\n",
					(unsigned long)entry->cq_ring_addr, cq_ring_sz);

				ptr = mmap((void *)entry->cq_ring_addr, cq_ring_sz,
					   PROT_READ | PROT_WRITE,
					   MAP_SHARED | MAP_POPULATE | MAP_FIXED,
					   ring_fd, IORING_OFF_CQ_RING);

				if (ptr == MAP_FAILED) {
					pr_perror("Failed to mmap CQ ring at 0x%lx",
						  (unsigned long)entry->cq_ring_addr);
					close(ring_fd);
					return -1;
				}
				if (ptr != (void *)entry->cq_ring_addr) {
					pr_err("CQ ring mapped at wrong address: expected 0x%lx, got %p\n",
					       (unsigned long)entry->cq_ring_addr, ptr);
					close(ring_fd);
					return -1;
				}
			}

			/* Map SQEs to original address */
			if (entry->sqe_addr != 0) {
				pr_info("  Mapping SQEs: addr=0x%lx size=%zu\n",
					(unsigned long)entry->sqe_addr, sqes_sz);

				ptr = mmap((void *)entry->sqe_addr, sqes_sz,
					   PROT_READ | PROT_WRITE,
					   MAP_SHARED | MAP_POPULATE | MAP_FIXED,
					   ring_fd, IORING_OFF_SQES);

				if (ptr == MAP_FAILED) {
					pr_perror("Failed to mmap SQEs at 0x%lx",
						  (unsigned long)entry->sqe_addr);
					close(ring_fd);
					return -1;
				}
				if (ptr != (void *)entry->sqe_addr) {
					pr_err("SQEs mapped at wrong address: expected 0x%lx, got %p\n",
					       (unsigned long)entry->sqe_addr, ptr);
					close(ring_fd);
					return -1;
				}
			}
		}

		/* Move to target fd number */
		if (ring_fd != entry->id) {
			if (dup2(ring_fd, entry->id) < 0) {
				pr_perror("Failed to dup2 io_uring %d -> %d", ring_fd, entry->id);
				close(ring_fd);
				return -1;
			}
			close(ring_fd);
			pr_debug("Moved io_uring fd %d -> %d\n", ring_fd, entry->id);
		}
	}

	pr_info("Pre-created %d io_uring(s) with ring mappings\n", (int)mm->n_io_urings);
}
#endif /* disabled old precreate code */

/* Check if fd is a pre-created io_uring fd based on MmEntry data */
int is_io_uring_precreated_fd(struct pstree_item *t, int fd)
{
	MmEntry *mm = rsti(t)->mm;
	int i;

	if (!mm || !mm->n_io_urings)
		return 0;

	for (i = 0; i < mm->n_io_urings; i++) {
		if (mm->io_urings[i]->id == fd)
			return 1;
	}
	return 0;
}