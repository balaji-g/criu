#ifndef __CR_IO_URING_H__
#define __CR_IO_URING_H__

#include "vma.h"
#include "images/mm.pb-c.h"

struct pstree_item;
struct task_restore_args;

/* Dump functions */
int dump_io_uring(MmEntry *mme, struct vm_area_list *vmas, pid_t pid);
void free_io_urings(MmEntry *mme);

/* Restore functions */
int prepare_io_urings(struct pstree_item *t, struct task_restore_args *ta);

/* Utility */
int check_io_uring_support(void);

/*
 * io_uring ring info for restore
 * This is passed to the restorer blob
 */
struct rst_io_uring_ring {
	/* Target addresses (where app expects the rings) */
	unsigned long sq_ring_addr;
	unsigned long cq_ring_addr;
	unsigned long sqe_addr;
	
	/* Sizes */
	unsigned long sq_ring_size;
	unsigned long cq_ring_size;
	unsigned long sqe_size;
	
	/* Ring configuration */
	unsigned int sq_entries;
	unsigned int cq_entries;
	unsigned int flags;
	
	/* SQPOLL configuration */
	int sq_thread_cpu;  /* CPU for SQPOLL thread (-1 for any) */
	unsigned int sq_thread_idle; /* Idle timeout in ms */
	
	/* Target fd (what the app expects) */
	unsigned int fd;
};

#endif /* __CR_IO_URING_H__ */

