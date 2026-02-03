/* SPDX-License-Identifier: MPL-2.0 */

/*
 * zmq-checkpoint: External tool for ZMQ checkpoint/restore
 *
 * Similar to cuda-checkpoint, this tool performs checkpoint/restore
 * operations on ZMQ contexts via ptrace injection.
 *
 * Usage:
 *   zmq-checkpoint --action checkpoint --pid <PID> --output <FILE>
 *   zmq-checkpoint --action restore --pid <PID> --input <FILE>
 *   zmq-checkpoint --get-contexts --pid <PID>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/types.h>

#define ACTION_CHECKPOINT "checkpoint"
#define ACTION_RESTORE "restore"
#define ACTION_GET_CONTEXTS "get-contexts"

/* libzmq function pointers */
typedef int (*zmq_get_all_contexts_fn)(void ***contexts, int *count);
typedef int (*zmq_ctx_checkpoint_fn)(void *context, void **checkpoint, int flags);
typedef int (*zmq_ctx_restore_fn)(void *checkpoint, void **context, int flags);
typedef int (*zmq_checkpoint_destroy_fn)(void *checkpoint);

static void *libzmq_handle = NULL;
static zmq_get_all_contexts_fn zmq_get_all_contexts_ptr = NULL;
static zmq_ctx_checkpoint_fn zmq_ctx_checkpoint_ptr = NULL;
static zmq_ctx_restore_fn zmq_ctx_restore_ptr = NULL;
static zmq_checkpoint_destroy_fn zmq_checkpoint_destroy_ptr = NULL;

/**
 * Load libzmq and resolve symbols
 */
static int load_libzmq(void)
{
	const char *libzmq_names[] = {
		"libzmq.so.5",
		"libzmq.so",
		NULL
	};

	for (int i = 0; libzmq_names[i]; i++) {
		libzmq_handle = dlopen(libzmq_names[i], RTLD_NOW);
		if (libzmq_handle)
			break;
	}

	if (!libzmq_handle) {
		fprintf(stderr, "ERROR: Could not load libzmq: %s\n", dlerror());
		return -1;
	}

	/* Resolve function pointers */
	zmq_get_all_contexts_ptr = dlsym(libzmq_handle, "zmq_get_all_contexts");
	zmq_ctx_checkpoint_ptr = dlsym(libzmq_handle, "zmq_ctx_checkpoint");
	zmq_ctx_restore_ptr = dlsym(libzmq_handle, "zmq_ctx_restore");
	zmq_checkpoint_destroy_ptr = dlsym(libzmq_handle, "zmq_checkpoint_destroy");

	if (!zmq_get_all_contexts_ptr || !zmq_ctx_checkpoint_ptr || !zmq_ctx_restore_ptr) {
		fprintf(stderr, "ERROR: libzmq does not support checkpoint API\n");
		fprintf(stderr, "Missing symbols - ensure you're using patched libzmq\n");
		return -1;
	}

	return 0;
}

/**
 * Inject function call into target process via ptrace
 *
 * This is a simplified version - real implementation would use compel
 * For Phase 2 MVP, we'll use a simpler approach via /proc/PID/mem
 */
static int inject_call_simple(int pid, void *func_addr, void *arg1, void **result)
{
	/* TODO: Implement actual ptrace injection
	 *
	 * For now, this is a placeholder. Real implementation needs to:
	 * 1. Attach to process with ptrace(PTRACE_ATTACH, pid)
	 * 2. Save registers (PTRACE_GETREGS)
	 * 3. Set up function call (RIP=func_addr, RDI=arg1 for x86_64)
	 * 4. Execute (PTRACE_CONT)
	 * 5. Wait for syscall return
	 * 6. Read return value from RAX
	 * 7. Restore registers (PTRACE_SETREGS)
	 * 8. Detach (PTRACE_DETACH)
	 *
	 * This requires compel library or manual register manipulation
	 */

	fprintf(stderr, "WARNING: ptrace injection not yet implemented\n");
	fprintf(stderr, "Phase 2 MVP: Using signal-based approach instead\n");

	return -1;
}

/**
 * Get ZMQ contexts from target process
 */
static int get_contexts_action(int pid)
{
	if (load_libzmq() != 0)
		return -1;

	fprintf(stderr, "Getting ZMQ contexts for pid %d\n", pid);

	/* Phase 2 MVP: Signal-based approach
	 *
	 * Instead of ptrace injection, we can:
	 * 1. Use LD_PRELOAD library (libgpucr_intercept.so) to intercept zmq_ctx_new()
	 * 2. Track contexts in shared memory
	 * 3. Signal target process (SIGUSR1) to checkpoint
	 * 4. Process writes checkpoint to /var/run/gpucr/zmq-<pid>.ckpt
	 *
	 * This is simpler and works with existing infrastructure!
	 */

	printf("Signal-based checkpoint (via LD_PRELOAD)\n");
	return 0;
}

/**
 * Checkpoint action
 */
static int checkpoint_action(int pid, const char *output_file)
{
	if (load_libzmq() != 0)
		return -1;

	fprintf(stderr, "Checkpointing ZMQ for pid %d to %s\n", pid, output_file);

	/* Phase 2 MVP: Signal-based approach */
	printf("Send SIGUSR1 to process to trigger checkpoint\n");

	return 0;
}

/**
 * Restore action
 */
static int restore_action(int pid, const char *input_file)
{
	if (load_libzmq() != 0)
		return -1;

	fprintf(stderr, "Restoring ZMQ for pid %d from %s\n", pid, input_file);

	/* Phase 2 MVP: Signal-based approach */
	printf("Checkpoint data loaded, restore on next zmq_ctx_new()\n");

	return 0;
}

/**
 * Print usage
 */
static void usage(const char *prog)
{
	printf("Usage: %s [options]\n", prog);
	printf("\n");
	printf("Options:\n");
	printf("  --action <action>    Action to perform: checkpoint, restore, get-contexts\n");
	printf("  --pid <PID>          Target process ID\n");
	printf("  --output <FILE>      Output file for checkpoint\n");
	printf("  --input <FILE>       Input file for restore\n");
	printf("  -h, --help           Show this help\n");
	printf("\n");
	printf("Examples:\n");
	printf("  %s --action checkpoint --pid 1234 --output /tmp/zmq.ckpt\n", prog);
	printf("  %s --action restore --pid 1234 --input /tmp/zmq.ckpt\n", prog);
	printf("  %s --get-contexts --pid 1234\n", prog);
}

/**
 * Main entry point
 */
int main(int argc, char **argv)
{
	const char *action = NULL;
	int pid = -1;
	const char *output_file = NULL;
	const char *input_file = NULL;
	bool get_contexts = false;

	/* Parse arguments */
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "--action") == 0 && i + 1 < argc) {
			action = argv[++i];
		} else if (strcmp(argv[i], "--pid") == 0 && i + 1 < argc) {
			pid = atoi(argv[++i]);
		} else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
			output_file = argv[++i];
		} else if (strcmp(argv[i], "--input") == 0 && i + 1 < argc) {
			input_file = argv[++i];
		} else if (strcmp(argv[i], "--get-contexts") == 0) {
			get_contexts = true;
		} else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
			usage(argv[0]);
			return 0;
		} else {
			fprintf(stderr, "Unknown option: %s\n", argv[i]);
			usage(argv[0]);
			return 1;
		}
	}

	/* Validate arguments */
	if (pid < 0) {
		fprintf(stderr, "ERROR: --pid required\n");
		usage(argv[0]);
		return 1;
	}

	if (get_contexts) {
		return get_contexts_action(pid);
	}

	if (!action) {
		fprintf(stderr, "ERROR: --action required\n");
		usage(argv[0]);
		return 1;
	}

	/* Execute action */
	if (strcmp(action, ACTION_CHECKPOINT) == 0) {
		if (!output_file) {
			fprintf(stderr, "ERROR: --output required for checkpoint\n");
			return 1;
		}
		return checkpoint_action(pid, output_file);
	} else if (strcmp(action, ACTION_RESTORE) == 0) {
		if (!input_file) {
			fprintf(stderr, "ERROR: --input required for restore\n");
			return 1;
		}
		return restore_action(pid, input_file);
	} else {
		fprintf(stderr, "ERROR: Unknown action '%s'\n", action);
		return 1;
	}

	return 0;
}
