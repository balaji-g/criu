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
	if (proc_fd < 0) return -1;

	mme->io_urings = xmalloc(vmas->nr_iourings * sizeof(IoUringEntry *));
	if (!mme->io_urings) {
		close(proc_fd);
		return -1;
	}

	/*
	 * First pass: collect all VMA addresses per io_uring inode.
	 * Multiple VMAs share the same inode (SQ ring, CQ ring, SQEs).
	 */
	list_for_each_entry(vma, &vmas->h, list) {
		int fd;

		if (!vma_entry_is(vma->e, VMA_AREA_IOURING)) continue;

		/* Check if this VMA belongs to an existing entry */
		if (vma->vm_iouring_ino == last_ino && entry != NULL) {
			/* Update existing entry with this VMA's address */
			if (vma->e->pgoff == IORING_OFF_SQ_RING) {
				entry->sq_ring_addr = vma->e->start;
				entry->sq_ring_size = vma->e->end - vma->e->start;
				pr_debug("  VMA SQ ring: 0x%lx size %lu\n",
					(unsigned long)entry->sq_ring_addr, (unsigned long)entry->sq_ring_size);
			} else if (vma->e->pgoff == IORING_OFF_CQ_RING) {
				entry->cq_ring_addr = vma->e->start;
				entry->cq_ring_size = vma->e->end - vma->e->start;
				pr_debug("  VMA CQ ring: 0x%lx size %lu\n",
					(unsigned long)entry->cq_ring_addr, (unsigned long)entry->cq_ring_size);
			} else if (vma->e->pgoff == IORING_OFF_SQES) {
				entry->sqe_addr = vma->e->start;
				entry->sqe_size = vma->e->end - vma->e->start;
				pr_debug("  VMA SQEs: 0x%lx size %lu\n",
					(unsigned long)entry->sqe_addr, (unsigned long)entry->sqe_size);
			}
			continue;
		}

		/* New io_uring inode - first finalize previous entry if exists */
		if (entry != NULL) {
			IoUringFileEntry iufe = IO_URING_FILE_ENTRY__INIT;
			FileEntry fe = FILE_ENTRY__INIT;

			mme->io_urings[nr++] = entry;

			iufe.id = entry->id;
			iufe.ino = entry->ino;
			fe.type = FD_TYPES__IO_URING;
			fe.id = iufe.id;
			fe.iouring = &iufe;

			if (pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), &fe, PB_FILE)) {
				pr_err("Failed to write io_uring file entry\n");
				goto err;
			}

			pr_info("Dumped io_uring fd %d: SQ=%u CQ=%u sq_addr=0x%lx cq_addr=0x%lx sqe_addr=0x%lx\n",
				entry->id, entry->sq_entries, entry->cq_entries,
				(unsigned long)entry->sq_ring_addr,
				(unsigned long)entry->cq_ring_addr,
				(unsigned long)entry->sqe_addr);
		}

		/* Create new entry for this io_uring */
		if (find_io_uring_fd(pid, vma->vm_iouring_ino, &fd) < 0) {
			pr_err("Can't find fd for io_uring ino %lu\n", vma->vm_iouring_ino);
			goto err;
		}

		if (parse_io_uring_fdinfo(proc_fd, fd, &fdinfo) < 0) {
			pr_err("Can't parse fdinfo for io_uring fd %d\n", fd);
			goto err;
		}

		if (fdinfo.sqes > 0 || fdinfo.cqes > 0) {
			pr_err("io_uring fd %d has pending I/O: SQEs=%u CQEs=%u\n",
			       fd, fdinfo.sqes, fdinfo.cqes);
			goto err;
		}

		entry = xmalloc(sizeof(*entry));
		if (!entry) goto err;

		io_uring_entry__init(entry);
		entry->id = fd;
		entry->ino = vma->vm_iouring_ino;
		entry->sq_entries = fdinfo.sq_mask + 1;
		entry->cq_entries = fdinfo.cq_mask + 1;
		entry->flags = 0;

#define IORING_SETUP_SQPOLL (1U << 1)
		if (fdinfo.sq_thread >= 0) {
			entry->flags |= IORING_SETUP_SQPOLL;
			pr_info("io_uring fd %d has SQPOLL (thread=%d)\n", fd, fdinfo.sq_thread);
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

		/* Initialize addresses to 0, they'll be filled by this and subsequent VMAs */
		entry->sq_ring_addr = 0;
		entry->sq_ring_size = 0;
		entry->cq_ring_addr = 0;
		entry->cq_ring_size = 0;
		entry->sqe_addr = 0;
		entry->sqe_size = 0;

		/* Set address from this VMA */
		if (vma->e->pgoff == IORING_OFF_SQ_RING) {
			entry->sq_ring_addr = vma->e->start;
			entry->sq_ring_size = vma->e->end - vma->e->start;
			pr_debug("  VMA SQ ring: 0x%lx size %lu\n",
				(unsigned long)entry->sq_ring_addr, (unsigned long)entry->sq_ring_size);
		} else if (vma->e->pgoff == IORING_OFF_CQ_RING) {
			entry->cq_ring_addr = vma->e->start;
			entry->cq_ring_size = vma->e->end - vma->e->start;
			pr_debug("  VMA CQ ring: 0x%lx size %lu\n",
				(unsigned long)entry->cq_ring_addr, (unsigned long)entry->cq_ring_size);
		} else if (vma->e->pgoff == IORING_OFF_SQES) {
			entry->sqe_addr = vma->e->start;
			entry->sqe_size = vma->e->end - vma->e->start;
			pr_debug("  VMA SQEs: 0x%lx size %lu\n",
				(unsigned long)entry->sqe_addr, (unsigned long)entry->sqe_size);
		}

		last_ino = vma->vm_iouring_ino;
	}

	/* Finalize the last entry */
	if (entry != NULL) {
		IoUringFileEntry iufe = IO_URING_FILE_ENTRY__INIT;
		FileEntry fe = FILE_ENTRY__INIT;

		mme->io_urings[nr++] = entry;

		iufe.id = entry->id;
		iufe.ino = entry->ino;
		fe.type = FD_TYPES__IO_URING;
		fe.id = iufe.id;
		fe.iouring = &iufe;

		if (pb_write_one(img_from_set(glob_imgset, CR_FD_FILES), &fe, PB_FILE)) {
			pr_err("Failed to write io_uring file entry\n");
			goto err;
		}

		pr_info("Dumped io_uring fd %d: SQ=%u CQ=%u sq_addr=0x%lx cq_addr=0x%lx sqe_addr=0x%lx\n",
			entry->id, entry->sq_entries, entry->cq_entries,
			(unsigned long)entry->sq_ring_addr,
			(unsigned long)entry->cq_ring_addr,
			(unsigned long)entry->sqe_addr);
	}

	mme->n_io_urings = nr;
	ret = 0;
err:
	close(proc_fd);
	return ret;
}

void free_io_urings(MmEntry *mme)
{
	int i;
	if (mme->io_urings) {
		for (i = 0; i < mme->n_io_urings; i++)
			xfree(mme->io_urings[i]);
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
	int i;
	MmEntry *mm = rsti(t)->mm;

	if (!mm || !mm->n_io_urings) {
		ta->io_uring_rings = NULL;
		ta->io_uring_rings_n = 0;
		return 0;
	}

	pr_info("Preparing %zu io_uring ring(s) for restore\n", mm->n_io_urings);

	ta->io_uring_rings = (struct rst_io_uring_ring *)rst_mem_align_cpos(RM_PRIVATE);
	ta->io_uring_rings_n = mm->n_io_urings;

	for (i = 0; i < mm->n_io_urings; i++) {
		struct rst_io_uring_ring *ring;
		IoUringEntry *e = mm->io_urings[i];

		ring = rst_mem_alloc(sizeof(*ring), RM_PRIVATE);
		if (!ring) return -1;

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

		pr_info("  Ring %d: fd=%u sq=%u cq=%u\n", i, ring->fd, ring->sq_entries, ring->cq_entries);
	}
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
	int i;

	io_uring_groups.count = 0;

	if (!mm || !mm->n_io_urings) {
		pr_debug("No io_uring entries in MmEntry for pid %d\n", vpid(t));
		return 0;
	}

	pr_info("Pre-creating %d io_uring(s) from MmEntry\n", (int)mm->n_io_urings);

	for (i = 0; i < mm->n_io_urings; i++) {
		IoUringEntry *entry = mm->io_urings[i];
		struct io_uring_params params = { 0 };
		int ring_fd;
		void *ptr;
		size_t sq_ring_sz, cq_ring_sz, sqes_sz;

		/* CRITICAL: Never touch fd 0/1/2 */
		if (entry->id < 3) {
			pr_err("BUG: io_uring fd %d < 3!\n", entry->id);
			BUG();
		}

		params.sq_entries = entry->sq_entries;
		params.cq_entries = entry->cq_entries;
		params.flags = entry->flags;

		if (entry->has_sq_thread_cpu && entry->sq_thread_cpu >= 0)
			params.sq_thread_cpu = entry->sq_thread_cpu;
		if (entry->has_sq_thread_idle)
			params.sq_thread_idle = entry->sq_thread_idle;

		/* Create the io_uring with identical parameters */
		ring_fd = syscall(__NR_io_uring_setup, params.sq_entries, &params);
		if (ring_fd < 0) {
			pr_perror("Failed to create io_uring for fd %d", entry->id);
			return -1;
		}

		pr_info("Created io_uring fd %d (target fd %d, ino %lu)\n",
			ring_fd, entry->id, (unsigned long)entry->ino);
		pr_info("  Kernel returned: sq_entries=%u cq_entries=%u features=0x%x\n",
			params.sq_entries, params.cq_entries, params.features);

		/*
		 * CRITICAL: Map ring memory to the EXACT original addresses!
		 * uvloop/liburing have cached pointers to these addresses.
		 * Without MAP_FIXED to original addresses, uvloop will segfault.
		 *
		 * Compute sizes from kernel-returned offsets (more robust than saved sizes)
		 */

		/* SQ ring size: includes sq_off.array + sq_entries * sizeof(u32) */
		sq_ring_sz = params.sq_off.array + params.sq_entries * sizeof(__u32);
		/* Round up to page size */
		sq_ring_sz = (sq_ring_sz + 4095) & ~4095UL;

		/* CQ ring size: cq_off.cqes + cq_entries * sizeof(struct io_uring_cqe) */
		cq_ring_sz = params.cq_off.cqes + params.cq_entries * 16; /* cqe is 16 bytes */
		cq_ring_sz = (cq_ring_sz + 4095) & ~4095UL;

		/* SQEs size */
		sqes_sz = params.sq_entries * 64; /* sqe is 64 bytes */
		sqes_sz = (sqes_sz + 4095) & ~4095UL;

		/* Validate against saved sizes */
		if (entry->sq_ring_size > 0 && sq_ring_sz > entry->sq_ring_size) {
			pr_warn("SQ ring size mismatch: kernel needs %zu, saved %lu\n",
				sq_ring_sz, (unsigned long)entry->sq_ring_size);
		}
		if (entry->cq_ring_size > 0 && cq_ring_sz > entry->cq_ring_size) {
			pr_warn("CQ ring size mismatch: kernel needs %zu, saved %lu\n",
				cq_ring_sz, (unsigned long)entry->cq_ring_size);
		}
		if (entry->sqe_size > 0 && sqes_sz > entry->sqe_size) {
			pr_warn("SQEs size mismatch: kernel needs %zu, saved %lu\n",
				sqes_sz, (unsigned long)entry->sqe_size);
		}

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
			pr_info("  SQ ring mapped successfully at 0x%lx\n",
				(unsigned long)entry->sq_ring_addr);
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
			pr_info("  CQ ring mapped successfully at 0x%lx\n",
				(unsigned long)entry->cq_ring_addr);
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
			pr_info("  SQEs mapped successfully at 0x%lx\n",
				(unsigned long)entry->sqe_addr);
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
	return 0;
}

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