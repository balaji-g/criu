/*
 * io_uring basic checkpoint/restore test
 *
 * This test creates an io_uring instance, checkpoints it,
 * and verifies it's still functional after restore.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <linux/io_uring.h>

#include "zdtmtst.h"

const char *test_doc = "Check that io_uring checkpoint/restore works";
const char *test_author = "Balaji Ganesan <bganesan@nvidia.com>";

/* io_uring syscall wrappers */
static int io_uring_setup(unsigned entries, struct io_uring_params *p)
{
	return syscall(__NR_io_uring_setup, entries, p);
}

static int io_uring_enter(int fd, unsigned to_submit, unsigned min_complete,
			  unsigned flags, sigset_t *sig)
{
	return syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags, sig, _NSIG/8);
}

/* io_uring mmap offsets */
#define IORING_OFF_SQ_RING	0ULL
#define IORING_OFF_CQ_RING	0x8000000ULL
#define IORING_OFF_SQES		0x10000000ULL

struct io_uring_ctx {
	int fd;
	
	/* Submission queue */
	unsigned *sq_head;
	unsigned *sq_tail;
	unsigned *sq_ring_mask;
	unsigned *sq_ring_entries;
	unsigned *sq_flags;
	unsigned *sq_dropped;
	unsigned *sq_array;
	struct io_uring_sqe *sqes;
	
	/* Completion queue */
	unsigned *cq_head;
	unsigned *cq_tail;
	unsigned *cq_ring_mask;
	unsigned *cq_ring_entries;
	unsigned *cq_overflow;
	struct io_uring_cqe *cqes;
	
	/* Mapped memory */
	void *sq_ring_ptr;
	void *cq_ring_ptr;
	size_t sq_ring_sz;
	size_t cq_ring_sz;
	size_t sqes_sz;
};

static int io_uring_init(struct io_uring_ctx *ctx, unsigned entries)
{
	struct io_uring_params p;
	int fd;
	void *ptr;
	
	memset(&p, 0, sizeof(p));
	
	fd = io_uring_setup(entries, &p);
	if (fd < 0) {
		pr_perror("io_uring_setup failed");
		return -1;
	}
	
	ctx->fd = fd;
	
	/* Map the SQ ring */
	ctx->sq_ring_sz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
	ptr = mmap(NULL, ctx->sq_ring_sz, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQ_RING);
	if (ptr == MAP_FAILED) {
		pr_perror("mmap SQ ring failed");
		close(fd);
		return -1;
	}
	ctx->sq_ring_ptr = ptr;
	
	ctx->sq_head = ptr + p.sq_off.head;
	ctx->sq_tail = ptr + p.sq_off.tail;
	ctx->sq_ring_mask = ptr + p.sq_off.ring_mask;
	ctx->sq_ring_entries = ptr + p.sq_off.ring_entries;
	ctx->sq_flags = ptr + p.sq_off.flags;
	ctx->sq_dropped = ptr + p.sq_off.dropped;
	ctx->sq_array = ptr + p.sq_off.array;
	
	/* Map the CQ ring (usually same mapping as SQ with IORING_FEAT_SINGLE_MMAP) */
	if (p.features & IORING_FEAT_SINGLE_MMAP) {
		ctx->cq_ring_ptr = ctx->sq_ring_ptr;
	} else {
		ctx->cq_ring_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
		ptr = mmap(NULL, ctx->cq_ring_sz, PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_CQ_RING);
		if (ptr == MAP_FAILED) {
			pr_perror("mmap CQ ring failed");
			munmap(ctx->sq_ring_ptr, ctx->sq_ring_sz);
			close(fd);
			return -1;
		}
		ctx->cq_ring_ptr = ptr;
	}
	
	ptr = ctx->cq_ring_ptr;
	ctx->cq_head = ptr + p.cq_off.head;
	ctx->cq_tail = ptr + p.cq_off.tail;
	ctx->cq_ring_mask = ptr + p.cq_off.ring_mask;
	ctx->cq_ring_entries = ptr + p.cq_off.ring_entries;
	ctx->cq_overflow = ptr + p.cq_off.overflow;
	ctx->cqes = ptr + p.cq_off.cqes;
	
	/* Map SQEs */
	ctx->sqes_sz = p.sq_entries * sizeof(struct io_uring_sqe);
	ptr = mmap(NULL, ctx->sqes_sz, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQES);
	if (ptr == MAP_FAILED) {
		pr_perror("mmap SQEs failed");
		if (ctx->cq_ring_ptr != ctx->sq_ring_ptr)
			munmap(ctx->cq_ring_ptr, ctx->cq_ring_sz);
		munmap(ctx->sq_ring_ptr, ctx->sq_ring_sz);
		close(fd);
		return -1;
	}
	ctx->sqes = ptr;
	
	return 0;
}

static void io_uring_cleanup(struct io_uring_ctx *ctx)
{
	munmap(ctx->sqes, ctx->sqes_sz);
	if (ctx->cq_ring_ptr != ctx->sq_ring_ptr)
		munmap(ctx->cq_ring_ptr, ctx->cq_ring_sz);
	munmap(ctx->sq_ring_ptr, ctx->sq_ring_sz);
	close(ctx->fd);
}

int main(int argc, char **argv)
{
	struct io_uring_ctx ctx;
	int ret;
	
	test_init(argc, argv);
	
	/* Create io_uring instance */
	if (io_uring_init(&ctx, 8) < 0) {
		pr_perror("Failed to init io_uring");
		return 1;
	}
	
	/* Verify initial state */
	if (*ctx.sq_head != 0 || *ctx.sq_tail != 0) {
		fail("Initial SQ state wrong: head=%u tail=%u",
		     *ctx.sq_head, *ctx.sq_tail);
		io_uring_cleanup(&ctx);
		return 1;
	}
	
	test_daemon();
	test_waitsig();
	
	/* Verify state after restore */
	if (*ctx.sq_head != 0 || *ctx.sq_tail != 0) {
		fail("SQ state wrong after restore: head=%u tail=%u",
		     *ctx.sq_head, *ctx.sq_tail);
		io_uring_cleanup(&ctx);
		return 1;
	}
	
	/* Try to submit a NOP to verify the ring is still functional */
	{
		struct io_uring_sqe *sqe;
		unsigned tail = *ctx.sq_tail;
		unsigned index = tail & *ctx.sq_ring_mask;
		
		sqe = &ctx.sqes[index];
		memset(sqe, 0, sizeof(*sqe));
		sqe->opcode = IORING_OP_NOP;
		sqe->user_data = 0x1234;
		
		ctx.sq_array[index] = index;
		
		/* Memory barrier before updating tail */
		__sync_synchronize();
		*ctx.sq_tail = tail + 1;
		__sync_synchronize();
		
		/* Submit and wait for completion */
		ret = io_uring_enter(ctx.fd, 1, 1, IORING_ENTER_GETEVENTS, NULL);
		if (ret < 0) {
			fail("io_uring_enter failed: %d", ret);
			io_uring_cleanup(&ctx);
			return 1;
		}
		
		/* Check completion */
		if (*ctx.cq_tail == *ctx.cq_head) {
			fail("No completion received");
			io_uring_cleanup(&ctx);
			return 1;
		}
		
		struct io_uring_cqe *cqe = &ctx.cqes[*ctx.cq_head & *ctx.cq_ring_mask];
		if (cqe->user_data != 0x1234) {
			fail("Wrong user_data: expected 0x1234, got 0x%llx",
			     (unsigned long long)cqe->user_data);
			io_uring_cleanup(&ctx);
			return 1;
		}
		
		if (cqe->res != 0) {
			fail("NOP returned error: %d", cqe->res);
			io_uring_cleanup(&ctx);
			return 1;
		}
		
		/* Consume the completion */
		*ctx.cq_head = *ctx.cq_head + 1;
	}
	
	io_uring_cleanup(&ctx);
	
	pass();
	return 0;
}

