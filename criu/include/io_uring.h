#ifndef __CR_IO_URING_H__
#define __CR_IO_URING_H__

#include "vma.h"
#include "images/mm.pb-c.h"

struct pstree_item;
struct task_restore_args;
struct file_desc;

/* Dump functions */
int dump_io_uring(MmEntry *mme, struct vm_area_list *vmas, pid_t pid);
void free_io_urings(MmEntry *mme);

/* Restore functions */
int prepare_io_urings(struct pstree_item *t, struct task_restore_args *ta);

/*
 * Pre-create io_uring groups before normal FD restore.
 * Groups io_uring fds by file_desc->id and prepares for restore.
 * Must be called BEFORE open_fdinfos().
 */
int precreate_io_urings(struct pstree_item *t);

/*
 * Check if a file_desc is io_uring type.
 * This checks file_desc->ops->type, NOT fd number!
 */
int is_io_uring_file_desc(struct file_desc *d);

/*
 * Check if an fd belongs to an io_uring file_desc.
 * This looks up the fd's file_desc and checks its type.
 * IMPORTANT: Does NOT decide by fd number alone!
 */
int is_io_uring_precreated_fd(struct pstree_item *t, int fd);

/*
 * Check if a tfd is an io_uring fd (for eventpoll restore).
 * Uses MmEntry to check if tfd matches an io_uring fd.
 */
int is_io_uring_tfd(struct pstree_item *t, int tfd);

/*
 * Defer an epoll registration for an io_uring fd.
 * Called from eventpoll_retore_tfd() when tfd is io_uring.
 * The registration is replayed by PIE after io_uring_setup().
 */
int defer_epoll_io_uring(int io_uring_fd, int epoll_fd,
			 unsigned int events, unsigned long long data);

/* Utility */
int check_io_uring_support(void);

/* Dump operations for io_uring file type */
extern const struct fdtype_ops io_uring_dump_ops;

/* Collect image info for io_uring file type */
extern struct collect_image_info io_uring_cinfo;

/*
 * Deferred epoll registration for io_uring
 * Epoll tries to add io_uring fds BEFORE they exist (restored in PIE).
 * We collect these registrations and replay them after io_uring_setup().
 */
#define MAX_EPOLL_REFS_PER_RING 8
struct rst_io_uring_epoll_ref {
	unsigned int epoll_fd;		/* The epoll fd that should monitor this io_uring */
	unsigned int events;		/* epoll events mask */
	unsigned long long data;	/* epoll user data */
};

/*
 * io_uring ring info for restore
 * This is passed to the restorer blob
 */
struct rst_io_uring_ring {
	unsigned long sq_ring_addr;
	unsigned long cq_ring_addr;
	unsigned long sqe_addr;
	unsigned long sq_ring_size;
	unsigned long cq_ring_size;
	unsigned long sqe_size;
	unsigned int sq_entries;
	unsigned int cq_entries;
	unsigned int flags;
	int sq_thread_cpu;
	unsigned int sq_thread_idle;
	unsigned int fd;

	/*
	 * Ring state from checkpoint - must be restored to match app's internal state.
	 * libuv/uvloop cache these values internally; if we don't restore them,
	 * there's a mismatch between kernel ring state and app state, causing crashes.
	 */
	unsigned int sq_head;
	unsigned int sq_tail;
	unsigned int cq_head;
	unsigned int cq_tail;

	/*
	 * Deferred epoll registrations.
	 * These are collected during prepare_io_urings() by scanning
	 * eventpoll images for tfds matching this io_uring's fd.
	 * PIE calls epoll_ctl() after io_uring_setup() to complete them.
	 */
	unsigned int n_epoll_refs;
	struct rst_io_uring_epoll_ref epoll_refs[MAX_EPOLL_REFS_PER_RING];
};

#endif /* __CR_IO_URING_H__ */
