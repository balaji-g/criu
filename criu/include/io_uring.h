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

/* Utility */
int check_io_uring_support(void);

/* Dump operations for io_uring file type */
extern const struct fdtype_ops io_uring_dump_ops;

/* Collect image info for io_uring file type */
extern struct collect_image_info io_uring_cinfo;

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
};

#endif /* __CR_IO_URING_H__ */
