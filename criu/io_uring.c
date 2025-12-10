/*
 * io_uring checkpoint/restore support
 *
 * io_uring is Linux's modern async I/O interface using shared ring buffers.
 * This file handles saving and restoring io_uring state.
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
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
#include "common/lock.h"
#include "images/mm.pb-c.h"
#include "rst_info.h"
#include "rst-malloc.h"
#include "restorer.h"

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

/*
 * Parse io_uring fdinfo to get ring state
 *
 * Format from /proc/PID/fdinfo/<fd>:
 * SqMask:  0x3f
 * SqHead:  0
 * SqTail:  0
 * ...
 */
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

static int parse_io_uring_fdinfo(int proc_fd, int fd, struct io_uring_fdinfo *info)
{
	char path[64];
	char buf[4096];
	FILE *f;
	int ret;

	snprintf(path, sizeof(path), "fdinfo/%d", fd);
	ret = readlinkat(proc_fd, path, buf, sizeof(buf) - 1);
	if (ret < 0) {
		/* Try reading as file instead */
		int fdinfo_fd = openat(proc_fd, path, O_RDONLY);
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
	} else {
		int fdinfo_fd = openat(proc_fd, path, O_RDONLY);
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
	}

	memset(info, 0, sizeof(*info));
	info->sq_thread = -1;
	info->sq_thread_cpu = -1;

	while (fgets(buf, sizeof(buf), f)) {
		char *colon;
		char *value;

		colon = strchr(buf, ':');
		if (!colon)
			continue;

		*colon = '\0';
		value = colon + 1;

		/* Skip whitespace */
		while (*value == ' ' || *value == '\t')
			value++;

		if (!strcmp(buf, "SqMask"))
			info->sq_mask = strtoul(value, NULL, 0);
		else if (!strcmp(buf, "SqHead"))
			info->sq_head = strtoul(value, NULL, 0);
		else if (!strcmp(buf, "SqTail"))
			info->sq_tail = strtoul(value, NULL, 0);
		else if (!strcmp(buf, "CachedSqHead"))
			info->cached_sq_head = strtoul(value, NULL, 0);
		else if (!strcmp(buf, "CqMask"))
			info->cq_mask = strtoul(value, NULL, 0);
		else if (!strcmp(buf, "CqHead"))
			info->cq_head = strtoul(value, NULL, 0);
		else if (!strcmp(buf, "CqTail"))
			info->cq_tail = strtoul(value, NULL, 0);
		else if (!strcmp(buf, "CachedCqTail"))
			info->cached_cq_tail = strtoul(value, NULL, 0);
		else if (!strcmp(buf, "SQEs"))
			info->sqes = strtoul(value, NULL, 0);
		else if (!strcmp(buf, "CQEs"))
			info->cqes = strtoul(value, NULL, 0);
		else if (!strcmp(buf, "SqThread"))
			info->sq_thread = strtol(value, NULL, 0);
		else if (!strcmp(buf, "SqThreadCpu"))
			info->sq_thread_cpu = strtol(value, NULL, 0);
		else if (!strcmp(buf, "UserFiles"))
			info->user_files = strtoul(value, NULL, 0);
		else if (!strcmp(buf, "UserBufs"))
			info->user_bufs = strtoul(value, NULL, 0);
	}

	fclose(f);
	return 0;
}

/*
 * Find io_uring file descriptor for a given inode
 */
static int find_io_uring_fd(pid_t pid, unsigned long ino, int *found_fd)
{
	char fd_dir[64];
	DIR *dir;
	struct dirent *de;
	int proc_fd;

	proc_fd = open_proc(pid, ".");
	if (proc_fd < 0)
		return -1;

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

		if (de->d_name[0] == '.')
			continue;

		fd = atoi(de->d_name);
		snprintf(path, sizeof(path), "/proc/%d/fd/%d", pid, fd);

		if (readlink(path, link, sizeof(link) - 1) < 0)
			continue;

		/* Check if it's an io_uring fd */
		if (!strstr(link, "io_uring"))
			continue;

		/* Get inode */
		if (fstatat(dirfd(dir), de->d_name, &st, 0) < 0)
			continue;

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
 * Collect io_uring VMA information for a memory mapping
 */
struct io_uring_vma_info {
	unsigned long start;
	unsigned long end;
	unsigned long ino;
	unsigned long offset;  /* mmap offset determines type */
};

/*
 * io_uring mmap offsets:
 * IORING_OFF_SQ_RING = 0
 * IORING_OFF_CQ_RING = 0x8000000
 * IORING_OFF_SQES    = 0x10000000
 */
#ifndef IORING_OFF_SQ_RING
#define IORING_OFF_SQ_RING	0ULL
#endif
#ifndef IORING_OFF_CQ_RING
#define IORING_OFF_CQ_RING	0x8000000ULL
#endif
#ifndef IORING_OFF_SQES
#define IORING_OFF_SQES		0x10000000ULL
#endif

/*
 * Dump io_uring state for a process
 */
int dump_io_uring(MmEntry *mme, struct vm_area_list *vmas, pid_t pid)
{
	struct vma_area *vma;
	struct io_uring_fdinfo fdinfo;
	IoUringEntry *entry = NULL;
	unsigned long last_ino = 0;
	int nr = 0;
	int ret = -1;
	int proc_fd;

	if (!vmas->nr_iourings) {
		pr_debug("No io_uring VMAs to dump\n");
		return 0;
	}

	pr_info("Dumping %u io_uring ring(s)\n", vmas->nr_iourings);

	proc_fd = open_proc(pid, ".");
	if (proc_fd < 0)
		return -1;

	/* Allocate array for io_uring entries */
	mme->io_urings = xmalloc(vmas->nr_iourings * sizeof(IoUringEntry *));
	if (!mme->io_urings) {
		close(proc_fd);
		return -1;
	}

	list_for_each_entry(vma, &vmas->h, list) {
		int fd;

		if (!vma_entry_is(vma->e, VMA_AREA_IOURING))
			continue;

		/* Skip if we've already handled this inode */
		if (vma->vm_iouring_ino == last_ino && entry != NULL) {
			/* This is another mapping for the same io_uring instance */
			/* Update the entry with this VMA's info based on offset */
			/* The offset in the VMA tells us which ring this is */
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

		/* New io_uring instance */
		if (find_io_uring_fd(pid, vma->vm_iouring_ino, &fd) < 0) {
			pr_err("Can't find fd for io_uring ino %lu\n", vma->vm_iouring_ino);
			goto err;
		}

		if (parse_io_uring_fdinfo(proc_fd, fd, &fdinfo) < 0) {
			pr_err("Can't parse fdinfo for io_uring fd %d\n", fd);
			goto err;
		}

		/* Check for pending I/O */
		if (fdinfo.sqes > 0 || fdinfo.cqes > 0) {
			pr_err("io_uring fd %d has pending I/O: SQEs=%u CQEs=%u\n",
			       fd, fdinfo.sqes, fdinfo.cqes);
			pr_err("Cannot checkpoint io_uring with pending operations\n");
			goto err;
		}

		/* Check for registered resources (not yet supported) */
		if (fdinfo.user_files > 0 || fdinfo.user_bufs > 0) {
			pr_warn("io_uring fd %d has registered resources: files=%u bufs=%u\n",
				fd, fdinfo.user_files, fdinfo.user_bufs);
			pr_warn("Registered resources are not yet supported in checkpoint\n");
			/* Continue anyway for now */
		}

		entry = xmalloc(sizeof(*entry));
		if (!entry)
			goto err;

		io_uring_entry__init(entry);
		entry->id = fd;
		entry->ino = vma->vm_iouring_ino;

		/* Ring configuration derived from masks */
		entry->sq_entries = fdinfo.sq_mask + 1;
		entry->cq_entries = fdinfo.cq_mask + 1;

		/*
		 * Infer flags from ring state:
		 * - If sq_thread is set (not -1), IORING_SETUP_SQPOLL was used
		 */
		entry->flags = 0;
#define IORING_SETUP_SQPOLL (1U << 1)
		if (fdinfo.sq_thread >= 0) {
			entry->flags |= IORING_SETUP_SQPOLL;
			pr_info("io_uring fd %d has SQPOLL enabled (thread=%d, cpu=%d)\n",
				fd, fdinfo.sq_thread, fdinfo.sq_thread_cpu);
		}

		entry->sq_thread_cpu = fdinfo.sq_thread_cpu;
		entry->has_sq_thread_cpu = true;
		entry->sq_thread_idle = 0;
		entry->has_sq_thread_idle = true;

		/* Ring state */
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

		/* Set first VMA info based on offset */
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

		mme->io_urings[nr++] = entry;
		last_ino = vma->vm_iouring_ino;

		pr_info("Dumped io_uring fd %d: SQ=%u CQ=%u\n",
			fd, entry->sq_entries, entry->cq_entries);
	}

	mme->n_io_urings = nr;
	ret = 0;

err:
	close(proc_fd);
	return ret;
}

/*
 * Free io_uring entries from MmEntry
 */
void free_io_urings(MmEntry *mme)
{
	int i;

	if (mme->io_urings) {
		for (i = 0; i < mme->n_io_urings; i++)
			xfree(mme->io_urings[i]);
		xfree(mme->io_urings);
	}
}

/*
 * Check if io_uring is supported on this kernel
 */
int check_io_uring_support(void)
{
	/* Just try to create a minimal io_uring */
	struct io_uring_params params = { 0 };
	int fd;

	fd = syscall(__NR_io_uring_setup, 1, &params);
	if (fd < 0) {
		if (errno == ENOSYS)
			return 0; /* Not supported */
		/* Other errors are okay, io_uring exists */
	} else {
		close(fd);
	}

	return 1;
}

/*
 * Prepare io_uring rings for restore
 *
 * This sets up the rst_io_uring_ring structures that will be
 * passed to the restorer blob, which will recreate the io_uring
 * instances and remap them to the original addresses.
 */
int prepare_io_urings(struct pstree_item *t, struct task_restore_args *ta)
{
	int i;
	MmEntry *mm = rsti(t)->mm;

	if (!mm || !mm->n_io_urings) {
		ta->io_uring_rings = NULL;
		ta->io_uring_rings_n = 0;
		return 0;
	}

	pr_info("Preparing %zu io_uring ring(s) for restore\n", mm->n_io_urings);

	/*
	 * Allocate the io_uring restore info in rst memory
	 * This memory is shared with the restorer blob
	 */
	ta->io_uring_rings = (struct rst_io_uring_ring *)rst_mem_align_cpos(RM_PRIVATE);
	ta->io_uring_rings_n = mm->n_io_urings;

	for (i = 0; i < mm->n_io_urings; i++) {
		struct rst_io_uring_ring *ring;
		IoUringEntry *e = mm->io_urings[i];

		ring = rst_mem_alloc(sizeof(*ring), RM_PRIVATE);
		if (!ring)
			return -1;

		ring->sq_ring_addr = e->sq_ring_addr;
		ring->cq_ring_addr = e->cq_ring_addr;
		ring->sqe_addr = e->sqe_addr;
		ring->sq_ring_size = e->sq_ring_size;
		ring->cq_ring_size = e->cq_ring_size;
		ring->sqe_size = e->sqe_size;
		ring->sq_entries = e->sq_entries;
		ring->cq_entries = e->cq_entries;
		ring->flags = e->flags;
		ring->sq_thread_cpu = e->has_sq_thread_cpu ? e->sq_thread_cpu : -1;
		ring->sq_thread_idle = e->has_sq_thread_idle ? e->sq_thread_idle : 0;
		ring->fd = e->id;

		pr_info("  Ring %d: fd=%u sq=%u cq=%u flags=0x%x sq_addr=0x%lx cq_addr=0x%lx sqe_addr=0x%lx\n",
			i, ring->fd, ring->sq_entries, ring->cq_entries, ring->flags,
			ring->sq_ring_addr, ring->cq_ring_addr, ring->sqe_addr);
	}

	return 0;
}

