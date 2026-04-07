#include "criu-log.h"
#include "plugin.h"
#include "util.h"
#include "cr_options.h"
#include "pid.h"
#include "proc_parse.h"
#include "seize.h"
#include "fault-injection.h"

#include <common/list.h>
#include <compel/infect.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/sysmacros.h>
#include <sys/stat.h>

/* cuda-checkpoint binary should live in your PATH */
#define CUDA_CHECKPOINT "cuda-checkpoint"

/* cuda-checkpoint --action flags */
#define ACTION_LOCK	  "lock"
#define ACTION_CHECKPOINT "checkpoint"
#define ACTION_RESTORE	  "restore"
#define ACTION_UNLOCK	  "unlock"

typedef enum {
	CUDA_TASK_RUNNING = 0,
	CUDA_TASK_LOCKED,
	CUDA_TASK_CHECKPOINTED,
	CUDA_TASK_UNKNOWN = -1
} cuda_task_state_t;

#define CUDA_CKPT_BUF_SIZE (128)

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "cuda_plugin: "

/* Disable plugin functionality if cuda-checkpoint is not in $PATH or driver
 * version doesn't support --action flag
 */
bool plugin_disabled = false;

bool plugin_added_to_inventory = false;

/* Forward declarations */
static int scan_and_save_nvidia_fds(int pid);

struct pid_info {
	int pid;
	char checkpointed;
	cuda_task_state_t initial_task_state;
	struct list_head list;
};

/* Used to track which PID's we've paused CUDA operations on so far so we can
 * release them after we're done with the DUMP
 */
static LIST_HEAD(cuda_pids);

static void dealloc_pid_buffer(struct list_head *pid_buf)
{
	struct pid_info *info;
	struct pid_info *n;

	list_for_each_entry_safe(info, n, pid_buf, list) {
		list_del(&info->list);
		xfree(info);
	}
}

static int add_pid_to_buf(struct list_head *pid_buf, int pid, cuda_task_state_t state)
{
	struct pid_info *new = xmalloc(sizeof(*new));

	if (new == NULL) {
		return -1;
	}

	new->pid = pid;
	new->checkpointed = 0;
	new->initial_task_state = state;
	list_add_tail(&new->list, pid_buf);

	return 0;
}

static int launch_cuda_checkpoint(const char **args, char *buf, int buf_size)
{
#define READ  0
#define WRITE 1
	int fd[2], buf_off;

	if (pipe(fd) != 0) {
		pr_perror("Couldn't create pipes for reading cuda-checkpoint output");
		return -1;
	}

	buf[0] = '\0';

	int child_pid = fork();
	if (child_pid == -1) {
		pr_perror("Failed to fork to exec cuda-checkpoint");
		close(fd[READ]);
		close(fd[WRITE]);
		return -1;
	}

	if (child_pid == 0) { // child
		if (dup2(fd[WRITE], STDOUT_FILENO) == -1) {
			pr_perror("unable to clone fd %d->%d", fd[WRITE], STDOUT_FILENO);
			_exit(EXIT_FAILURE);
		}
		if (dup2(fd[WRITE], STDERR_FILENO) == -1) {
			pr_perror("unable to clone fd %d->%d", fd[WRITE], STDERR_FILENO);
			_exit(EXIT_FAILURE);
		}
		close(fd[READ]);

		close_fds(STDERR_FILENO + 1);

		execvp(args[0], (char **)args);

		/* We can't use pr_error() as log file fd is closed. */
		fprintf(stderr, "execvp(\"%s\") failed: %s\n", args[0], strerror(errno));

		_exit(EXIT_FAILURE);
	}

	close(fd[WRITE]);
	buf_off = 0;
	/* Reserve one byte for the null charracter. */
	buf_size--;
	while (buf_off < buf_size) {
		int bytes_read;
		bytes_read = read(fd[READ], buf + buf_off, buf_size - buf_off);
		if (bytes_read == -1) {
			pr_perror("Unable to read output of cuda-checkpoint");
			goto err;
		}
		if (bytes_read == 0)
			break;
		buf_off += bytes_read;
	}
	buf[buf_off] = '\0';

	/* Clear out any of the remaining output in the pipe in case the buffer wasn't large enough */
	while (true) {
		char scratch[1024];
		int bytes_read;
		bytes_read = read(fd[READ], scratch, sizeof(scratch));
		if (bytes_read == -1) {
			pr_perror("Unable to read output of cuda-checkpoint");
			goto err;
		}
		if (bytes_read == 0)
			break;
	}
	close(fd[READ]);

	int status, exit_code = -1;
	if (waitpid(child_pid, &status, 0) == -1) {
		pr_perror("Unable to wait for the cuda-checkpoint process %d", child_pid);
		goto err;
	}
	if (WIFSIGNALED(status)) {
		int sig = WTERMSIG(status);
		pr_err("cuda-checkpoint unexpectedly signaled with %d: %s\n", sig, strsignal(sig));
	} else if (WIFEXITED(status)) {
		exit_code = WEXITSTATUS(status);
	} else {
		pr_err("cuda-checkpoint exited improperly: %u\n", status);
	}

	if (exit_code != EXIT_SUCCESS)
		pr_debug("cuda-checkpoint output ===>\n%s\n"
			 "<=== cuda-checkpoint output\n",
			 buf);

	return exit_code;
err:
	kill(child_pid, SIGKILL);
	waitpid(child_pid, NULL, 0);
	return -1;
}

/**
 * Checks if a given flag is supported by the cuda-checkpoint utility
 *
 * Returns:
 *  1 if the flag is supported,
 *  0 if the flag is not supported,
 *  -1 if there was an error launching the cuda-checkpoint utility.
 */
static int cuda_checkpoint_supports_flag(const char *flag)
{
	char msg_buf[2048];
	const char *args[] = { CUDA_CHECKPOINT, "-h", NULL };

	if (launch_cuda_checkpoint(args, msg_buf, sizeof(msg_buf)) != 0)
		return -1;

	if (strstr(msg_buf, flag) == NULL)
		return 0;

	return 1;
}

/* Retrieve the cuda restore thread TID from the root pid.
 * Returns -1 if the process has no CUDA context (not an error condition).
 */
/* Dump thread list and kernel stacks for pid (diagnostic when restore thread not found) */
static void dump_threads_and_stacks(int pid)
{
	DIR *dir;
	struct dirent *de;
	char stack_buf[512];
	FILE *stack_f;

	dir = opendir_proc(pid, "task");
	if (!dir) {
		pr_warn("cuda_plugin: could not opendir /proc/%d/task: %s\n", pid, strerror(errno));
		return;
	}

	pr_warn("cuda_plugin: pid %d threads and stacks (when restore thread not found):\n", pid);
	while ((de = readdir(dir))) {
		if (de->d_name[0] == '.')
			continue;
		pr_warn("  TID %s:\n", de->d_name);
		stack_f = fopen_proc(pid, "task/%s/stack", de->d_name);
		if (stack_f) {
			while (fgets(stack_buf, sizeof(stack_buf), stack_f))
				pr_warn("    %s", stack_buf);
			fclose(stack_f);
		} else {
			pr_warn("    (could not read stack: %s)\n", strerror(errno));
		}
	}
	closedir(dir);
}

/* Retrieve the cuda restore thread TID from the root pid */
static int get_cuda_restore_tid(int root_pid)
{
	char pid_buf[16];
	char pid_out[CUDA_CKPT_BUF_SIZE];

	snprintf(pid_buf, sizeof(pid_buf), "%d", root_pid);

	const char *args[] = { CUDA_CHECKPOINT, "--get-restore-tid", "--pid", pid_buf, NULL };
	int ret = launch_cuda_checkpoint(args, pid_out, sizeof(pid_out));
	if (ret != 0) {
		/* "Could not find restore thread" means no CUDA context - this is OK, not an error.
		 * This commonly happens for helper processes like Python's multiprocessing.resource_tracker
		 * which are part of the process tree but have no GPU context.
		 */
		if (strstr(pid_out, "Could not find restore thread") != NULL ||
		    strstr(pid_out, "not supported") != NULL ||
		    strstr(pid_out, "no CUDA") != NULL) {
			pr_debug("pid %d has no CUDA context (restore tid not found), skipping\n", root_pid);
			return -1;
		}
		pr_err("Failed to launch cuda-checkpoint to retrieve restore tid: %s\n", pid_out);
		if (strstr(pid_out, "Could not find restore thread") != NULL)
			dump_threads_and_stacks(root_pid);
		return -1;
	}

	return atoi(pid_out);
}

static cuda_task_state_t get_task_state_enum(const char *state_str)
{
	if (strncmp(state_str, "running", 7) == 0)
		return CUDA_TASK_RUNNING;

	if (strncmp(state_str, "locked", 6) == 0)
		return CUDA_TASK_LOCKED;

	if (strncmp(state_str, "checkpointed", 12) == 0)
		return CUDA_TASK_CHECKPOINTED;

	pr_err("Unknown CUDA state: %s\n", state_str);
	return CUDA_TASK_UNKNOWN;
}

static cuda_task_state_t get_cuda_state(pid_t pid)
{
	char pid_buf[16];
	char state_str[CUDA_CKPT_BUF_SIZE];
	const char *args[] = { CUDA_CHECKPOINT, "--get-state", "--pid", pid_buf, NULL };

	snprintf(pid_buf, sizeof(pid_buf), "%d", pid);

	if (launch_cuda_checkpoint(args, state_str, sizeof(state_str))) {
		/* Non-CUDA processes will fail here - treat as "no context" not error */
		if (strstr(state_str, "not supported") != NULL ||
		    strstr(state_str, "Could not") != NULL ||
		    strstr(state_str, "no CUDA") != NULL) {
			pr_debug("pid %d has no CUDA context (get-state failed), skipping\n", pid);
			return CUDA_TASK_UNKNOWN;
		}
		pr_err("Failed to launch cuda-checkpoint to retrieve state: %s\n", state_str);
		return CUDA_TASK_UNKNOWN;
	}

	return get_task_state_enum(state_str);
}

static int cuda_process_checkpoint_action(int pid, const char *action, unsigned int timeout, char *msg_buf,
					  int buf_size)
{
	char pid_buf[16];
	char timeout_buf[16];

	snprintf(pid_buf, sizeof(pid_buf), "%d", pid);

	const char *args[] = { CUDA_CHECKPOINT, "--action", action, "--pid", pid_buf, NULL /* --timeout */,
			       NULL /* timeout_val */, NULL };
	if (timeout > 0) {
		snprintf(timeout_buf, sizeof(timeout_buf), "%d", timeout);
		args[5] = "--timeout";
		args[6] = timeout_buf;
	}

	return launch_cuda_checkpoint(args, msg_buf, buf_size);
}

static int interrupt_restore_thread(int restore_tid, k_rtsigset_t *restore_sigset)
{
	/* Since we resumed a thread that CRIU previously already froze we need to
	 * INTERRUPT it once again, task was already SEIZE'd so we don't need to do
	 * a compel_interrupt_task()
	 */
	if (ptrace(PTRACE_INTERRUPT, restore_tid, NULL, 0)) {
		pr_perror("Could not interrupt cuda restore tid %d after checkpoint, process may be in strange state",
			  restore_tid);
		return -1;
	}

	struct proc_status_creds creds;
	if (compel_wait_task(restore_tid, -1, parse_pid_status, NULL, &creds.s, NULL) != COMPEL_TASK_ALIVE) {
		pr_err("compel_wait_task failed after interrupt\n");
		return -1;
	}

	if (ptrace(PTRACE_SETOPTIONS, restore_tid, NULL, PTRACE_O_SUSPEND_SECCOMP | PTRACE_O_TRACESYSGOOD)) {
		pr_perror("Failed to set ptrace options on interrupt for restore tid %d", restore_tid);
		return -1;
	}

	if (ptrace(PTRACE_SETSIGMASK, restore_tid, sizeof(*restore_sigset), restore_sigset)) {
		pr_perror("Unable to restore original sigmask to restore tid %d", restore_tid);
		return -1;
	}

	return 0;
}

static int resume_restore_thread(int restore_tid, k_rtsigset_t *save_sigset)
{
	k_rtsigset_t block;

	if (ptrace(PTRACE_GETSIGMASK, restore_tid, sizeof(*save_sigset), save_sigset)) {
		pr_perror("Failed to get current sigmask for restore tid %d", restore_tid);
		return -1;
	}

	ksigfillset(&block);
	ksigdelset(&block, SIGTRAP);

	if (ptrace(PTRACE_SETSIGMASK, restore_tid, sizeof(block), &block)) {
		pr_perror("Failed to block signals on restore tid %d", restore_tid);
		return -1;
	}

	// Clear out PTRACE_O_SUSPEND_SECCOMP when we resume the restore thread
	if (ptrace(PTRACE_SETOPTIONS, restore_tid, NULL, 0)) {
		pr_perror("Could not clear ptrace options on restore tid %d", restore_tid);
		return -1;
	}

	if (ptrace(PTRACE_CONT, restore_tid, NULL, 0)) {
		pr_perror("Could not resume cuda restore tid %d", restore_tid);
		return -1;
	}

	return 0;
}

int cuda_plugin_checkpoint_devices(int pid)
{
	int restore_tid;
	char msg_buf[CUDA_CKPT_BUF_SIZE];
	int int_ret;
	int status;
	k_rtsigset_t save_sigset;
	struct pid_info *task_info;
	bool pid_found = false;

	if (plugin_disabled) {
		return -ENOTSUP;
	}

	if (getenv("CRYO_SKIP_CUDA_CHECKPOINT")) {
		pr_info("skipping cuda-checkpoint checkpoint for pid %d (CRYO_SKIP_CUDA_CHECKPOINT)\n", pid);
		return 0;
	}

	restore_tid = get_cuda_restore_tid(pid);

	/* We can possibly hit a race with cuInit() where we are past the point of
	 * locking the process but at lock time cuInit() hadn't completed in which
	 * case cuda-checkpoint will report that we're in an invalid state to
	 * checkpoint
	 */
	if (restore_tid == -1) {
		pr_info("No need to checkpoint devices on pid %d\n", pid);
		return 0;
	}

	/* Check if the process is already in a checkpointed state */
	list_for_each_entry(task_info, &cuda_pids, list) {
		if (task_info->pid == pid) {
			if (task_info->initial_task_state == CUDA_TASK_CHECKPOINTED) {
				pr_info("pid %d already in a checkpointed state\n", pid);
				return 0;
			}
			pid_found = true;
			break;
		}
	}

	if (pid_found == false) {
		/* We return an error here. The task should be restored
		 * to its original state at cuda_plugin_fini().
		 */
		pr_err("Failed to track pid %d\n", pid);
		return -1;
	}

	pr_info("Checkpointing CUDA devices on pid %d restore_tid %d\n", pid, restore_tid);
	/* We need to resume the checkpoint thread to prepare the mappings for
	 * checkpointing
	 */
	if (resume_restore_thread(restore_tid, &save_sigset)) {
		return -1;
	}

	task_info->checkpointed = 1;
	status = cuda_process_checkpoint_action(pid, ACTION_CHECKPOINT, 0, msg_buf, sizeof(msg_buf));
	if (status) {
		pr_err("CHECKPOINT_DEVICES failed with %s\n", msg_buf);
	}

	int_ret = interrupt_restore_thread(restore_tid, &save_sigset);
	return status != 0 ? -1 : int_ret;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__CHECKPOINT_DEVICES, cuda_plugin_checkpoint_devices);

int cuda_plugin_pause_devices(int pid)
{
	int restore_tid;
	char msg_buf[CUDA_CKPT_BUF_SIZE];
	cuda_task_state_t task_state;

	if (plugin_disabled) {
		return -ENOTSUP;
	}

	if (getenv("CRYO_SKIP_CUDA_CHECKPOINT")) {
		pr_info("skipping cuda-checkpoint pause for pid %d (CRYO_SKIP_CUDA_CHECKPOINT)\n", pid);
		return 0;
	}

	restore_tid = get_cuda_restore_tid(pid);

	if (restore_tid == -1) {
		pr_debug("no need to pause devices on pid %d (no CUDA context)\n", pid);
		return 0;
	}

	task_state = get_cuda_state(restore_tid);
	if (task_state == CUDA_TASK_UNKNOWN) {
		/* Process has no valid CUDA state - skip it (not an error) */
		pr_debug("skipping pid %d: no valid CUDA state\n", pid);
		return 0;
	}

	if (!plugin_added_to_inventory) {
		if (add_inventory_plugin(CR_PLUGIN_DESC.name)) {
			pr_err("Failed to add CUDA plugin to inventory image\n");
			return -1;
		}
		plugin_added_to_inventory = true;
	}

	/*
	 * Scan and save NVIDIA device FDs BEFORE cuda-checkpoint runs.
	 * This is critical because cuda-checkpoint will close/modify these FDs,
	 * and CRIU won't see them during its later FD collection phase.
	 */
	scan_and_save_nvidia_fds(pid);

	if (task_state == CUDA_TASK_LOCKED) {
		pr_info("pid %d already in a locked state\n", pid);
		/* Leave this PID in a "locked" state at resume_device() */
		add_pid_to_buf(&cuda_pids, pid, CUDA_TASK_LOCKED);
		return 0;
	}

	if (task_state == CUDA_TASK_CHECKPOINTED) {
		/* We need to skip this PID in cuda_plugin_checkpoint_devices(),
		 * and leave it in a "checkpoined" state at resume_device(). */
		add_pid_to_buf(&cuda_pids, pid, CUDA_TASK_CHECKPOINTED);
		return 0;
	}

	pr_info("pausing devices on pid %d\n", pid);
	int status = cuda_process_checkpoint_action(pid, ACTION_LOCK, opts.timeout * 1000, msg_buf, sizeof(msg_buf));
	if (status) {
		pr_err("PAUSE_DEVICES failed with %s\n", msg_buf);
		if (alarm_timeouted())
			goto unlock;
		return -1;
	}

	if (add_pid_to_buf(&cuda_pids, pid, CUDA_TASK_RUNNING)) {
		pr_err("unable to track paused pid %d\n", pid);
		goto unlock;
	}

	return 0;
unlock:
	status = cuda_process_checkpoint_action(pid, ACTION_UNLOCK, 0, msg_buf, sizeof(msg_buf));
	if (status) {
		pr_err("Failed to unlock process status %s, pid %d may hang\n", msg_buf, pid);
	}
	return -1;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__PAUSE_DEVICES, cuda_plugin_pause_devices)

int resume_device(int pid, int checkpointed, cuda_task_state_t initial_task_state)
{
	char msg_buf[CUDA_CKPT_BUF_SIZE];
	int status;
	int ret = 0;
	int int_ret;
	k_rtsigset_t save_sigset;

	if (initial_task_state == CUDA_TASK_UNKNOWN) {
		pr_info("skip resume for PID %d (unknown state)\n", pid);
		return 0;
	}

	int restore_tid = get_cuda_restore_tid(pid);
	if (restore_tid == -1) {
		pr_info("No need to resume devices on pid %d\n", pid);
		return 0;
	}

	pr_info("resuming devices on pid %d\n", pid);
	/* The resuming process has to stay frozen during this time otherwise
	 * attempting to access a UVM pointer will crash if we haven't restored the
	 * underlying mappings yet
	 */
	pr_debug("Restore thread pid %d found for real pid %d\n", restore_tid, pid);
	/* wakeup the restore thread so we can handle the restore for this pid,
	 * rseq_cs has to be restored before execution
	 */
	if (resume_restore_thread(restore_tid, &save_sigset)) {
		return -1;
	}

	if (checkpointed && (initial_task_state == CUDA_TASK_RUNNING || initial_task_state == CUDA_TASK_LOCKED)) {
		/* If the process was "locked" or "running" before checkpointing it, we need to restore it */
		status = cuda_process_checkpoint_action(pid, ACTION_RESTORE, 0, msg_buf, sizeof(msg_buf));
		if (status) {
			pr_err("RESUME_DEVICES RESTORE failed with %s\n", msg_buf);
			ret = -1;
			goto interrupt;
		}
	}

	if (initial_task_state == CUDA_TASK_RUNNING) {
		/* If the process was "running" before we paused it, we need to unlock it */
		status = cuda_process_checkpoint_action(pid, ACTION_UNLOCK, 0, msg_buf, sizeof(msg_buf));
		if (status) {
			pr_err("RESUME_DEVICES UNLOCK failed with %s\n", msg_buf);
			ret = -1;
		}
	}

interrupt:
	int_ret = interrupt_restore_thread(restore_tid, &save_sigset);

	return ret != 0 ? ret : int_ret;
}

int cuda_plugin_resume_devices_late(int pid)
{
	int ret;

	if (plugin_disabled) {
		return -ENOTSUP;
	}

	if (getenv("CRYO_SKIP_CUDA_CHECKPOINT")) {
		pr_info("skipping cuda-checkpoint resume for pid %d (CRYO_SKIP_CUDA_CHECKPOINT)\n", pid);
		return 0;
	}

	/* RESUME_DEVICES_LATE is used during `criu restore`.
	 * Here, we assume that users expect the target process
	 * to be in a "running" state after restore, even if it was
	 * in a "locked" or "checkpointed" state during `criu dump`.
	 *
	 * If cuda-checkpoint is not available or fails, we continue anyway.
	 * The application may be using external GPU checkpoint/restore
	 * (e.g., via GPUCR library and SIGUSR1/SIGUSR2 signals).
	 */
	ret = resume_device(pid, 1, CUDA_TASK_RUNNING);
	if (ret != 0) {
		pr_warn("CUDA plugin: resume_device failed for PID %d (ret=%d), "
			"continuing anyway (external GPU restore may be used)\n", pid, ret);
		/* Return 0 to not fail the restore - let external restore handle it */
		return 0;
	}
	return 0;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESUME_DEVICES_LATE, cuda_plugin_resume_devices_late)

/* Forward declaration - checks if a device major number is an NVIDIA device */
static bool is_nvidia_device_major(unsigned int maj);

/**
 * Handle NVIDIA device VMAs during dump.
 * This hook is called when CRIU encounters a device file mmap.
 * Returning 0 tells CRIU that this plugin will handle the VMA.
 */
int cuda_plugin_handle_device_vma(int fd, const struct stat *st_buf)
{
	unsigned int major_num = major(st_buf->st_rdev);

	if (is_nvidia_device_major(major_num)) {
		pr_info("CUDA plugin handling NVIDIA device VMA (major %d, minor %d)\n",
			major_num, minor(st_buf->st_rdev));

		if (!plugin_added_to_inventory) {
			if (add_inventory_plugin(CR_PLUGIN_DESC.name)) {
				pr_err("Failed to add CUDA plugin to inventory\n");
				return -1;
			}
			plugin_added_to_inventory = true;
		}

		return 0; /* Plugin will handle this VMA */
	}

	return -ENOTSUP; /* Not our device, let other plugins try */
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__HANDLE_DEVICE_VMA, cuda_plugin_handle_device_vma)

/**
 * Update VMA mapping during restore.
 * For NVIDIA device VMAs, we return a /dev/zero mapping instead of the real device.
 * cuda-checkpoint will restore the actual GPU state after CRIU restore completes.
 */
int cuda_plugin_update_vma_map(const char *path, const uint64_t addr,
			       const uint64_t old_pgoff, uint64_t *new_pgoff, int *plugin_fd)
{
	static int devzero_fd = -1;
	int dup_fd;

	/* Check if this is an NVIDIA device by major number.
	 * The path comes from CRIU's VMA info — stat it to verify. */
	{
		struct stat vma_st;
		if (stat(path, &vma_st) < 0 || !S_ISCHR(vma_st.st_mode) ||
		    !is_nvidia_device_major(major(vma_st.st_rdev))) {
			return -ENOTSUP; /* Not our device */
		}
	}

	pr_debug("CUDA plugin: mapping NVIDIA VMA at 0x%lx (%s) to /dev/zero\n",
		(unsigned long)addr, path);

	/* Open /dev/zero once and keep it */
	if (devzero_fd < 0) {
		devzero_fd = open("/dev/zero", O_RDWR);
		if (devzero_fd < 0) {
			pr_perror("CUDA plugin: failed to open /dev/zero");
			return -1;
		}
	}

	/*
	 * CRIU will dup and close the returned fd, so we must return a dup'd copy.
	 * We keep devzero_fd for ourselves, and return a fresh dup each time.
	 */
	dup_fd = dup(devzero_fd);
	if (dup_fd < 0) {
		pr_perror("CUDA plugin: failed to dup /dev/zero fd");
		return -1;
	}

	*plugin_fd = dup_fd;
	*new_pgoff = 0;

	return 1; /* Tell CRIU to use our fd */
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__UPDATE_VMA_MAP, cuda_plugin_update_vma_map)

/**
 * Handle NVIDIA device file descriptors during dump.
 * NVIDIA device FDs cannot be dumped normally - they are kernel resources
 * tied to GPU context. We tell CRIU to skip them.
 * cuda-checkpoint will restore the GPU context on restore.
 */
/*
 * NVIDIA device major numbers are dynamically allocated and can change
 * between systems, kernel versions, and driver versions.
 * We detect them at runtime by reading /proc/devices.
 *
 * Known NVIDIA device types:
 * - nvidia, nvidiactl, nvidia-modeset (usually 195)
 * - nvidia-uvm (dynamic, e.g., 507)
 * - nvidia-nvswitch (dynamic, e.g., 508)
 * - nvidia-nvlink (dynamic, e.g., 509)
 * - nvidia-caps (dynamic, e.g., 510)
 * - nvidia-caps-imex-channels (dynamic, e.g., 511)
 */
#define MAX_NVIDIA_MAJORS 16
static int nvidia_majors[MAX_NVIDIA_MAJORS];
static int nvidia_major_count = 0;
static bool majors_initialized = false;

static void add_nvidia_major(int major)
{
	/* Check if already added */
	for (int i = 0; i < nvidia_major_count; i++) {
		if (nvidia_majors[i] == major)
			return;
	}
	if (nvidia_major_count < MAX_NVIDIA_MAJORS) {
		nvidia_majors[nvidia_major_count++] = major;
	}
}

static void init_nvidia_majors(void)
{
	FILE *f;
	char line[256];

	if (majors_initialized)
		return;

	majors_initialized = true;

	f = fopen("/proc/devices", "r");
	if (!f)
		return;

	while (fgets(line, sizeof(line), f)) {
		int major;
		char name[64];

		if (sscanf(line, "%d %63s", &major, name) != 2)
			continue;

		/* Match any device name containing "nvidia" */
		if (strstr(name, "nvidia") != NULL) {
			add_nvidia_major(major);
			pr_debug("CUDA plugin: detected NVIDIA device '%s' at major %d\n", name, major);
		}
	}

	fclose(f);

	pr_info("CUDA plugin: detected %d NVIDIA device majors\n", nvidia_major_count);
}

static bool is_nvidia_device_major(unsigned int maj)
{
	init_nvidia_majors();

	for (int i = 0; i < nvidia_major_count; i++) {
		if ((int)maj == nvidia_majors[i])
			return true;
	}

	/* Fallback to common known values if detection failed */
	if (maj == 195)  /* nvidia - usually static */
		return true;

	return false;
}

/*
 * Save NVIDIA device file mappings to a file during dump.
 * Format: one line per file "id path\n"
 */
#define NVIDIA_FILES_IMG "nvidia-files.img"
static FILE *nvidia_files_fp = NULL;

static void save_nvidia_file_mapping(int id, unsigned int maj, unsigned int min, const char *path)
{
	if (!nvidia_files_fp) {
		int img_dir_fd = criu_get_image_dir();
		int fd = openat(img_dir_fd, NVIDIA_FILES_IMG, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd < 0) {
			pr_perror("Failed to create %s via openat(img_dir_fd=%d)", NVIDIA_FILES_IMG, img_dir_fd);
			return;
		}
		nvidia_files_fp = fdopen(fd, "w");
		if (!nvidia_files_fp) {
			pr_perror("Failed to fdopen %s", NVIDIA_FILES_IMG);
			close(fd);
			return;
		}
		pr_info("CUDA plugin: saving NVIDIA mappings via openat(img_dir_fd=%d, %s)\n",
			img_dir_fd, NVIDIA_FILES_IMG);
	}
	fprintf(nvidia_files_fp, "%d %u %u %s\n", id, maj, min, path);
	fflush(nvidia_files_fp);
	pr_debug("CUDA plugin: saved mapping id=0x%x -> %s (dev %u:%u)\n", id, path, maj, min);
}

/*
 * Scan a process's file descriptors for NVIDIA devices and save mappings.
 * This MUST be called BEFORE cuda-checkpoint closes the device FDs.
 *
 * The id format uses FD number + device info to create a unique identifier
 * that can be matched during restore.
 */
static int scan_and_save_nvidia_fds(int pid)
{
	char fd_dir[64];
	DIR *dir;
	struct dirent *entry;
	int count = 0;

	snprintf(fd_dir, sizeof(fd_dir), "/proc/%d/fd", pid);
	dir = opendir(fd_dir);
	if (!dir) {
		pr_perror("CUDA plugin: failed to open %s", fd_dir);
		return -1;
	}

	while ((entry = readdir(dir)) != NULL) {
		char fd_path[PATH_MAX];
		char link_target[256];
		struct stat st;
		ssize_t len;
		int fd_num;

		if (entry->d_name[0] == '.')
			continue;

		fd_num = atoi(entry->d_name);
		snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd/%d", pid, fd_num);

		/* Stat the FD directly to get device type and major/minor.
		 * Uses fstatat on the /proc/pid/fd/N symlink — no need to
		 * resolve the link target first. This catches ALL nvidia
		 * devices regardless of path or naming. */
		if (stat(fd_path, &st) < 0)
			continue;

		if (!S_ISCHR(st.st_mode))
			continue;

		if (!is_nvidia_device_major(major(st.st_rdev)))
			continue;

		/* Read the symlink for the device path (for mapping file) */
		len = readlink(fd_path, link_target, sizeof(link_target) - 1);
		if (len <= 0)
			continue;
		link_target[len] = '\0';

		/* Create a unique ID from major:minor:fd */
		unsigned int maj = major(st.st_rdev);
		unsigned int min = minor(st.st_rdev);
		int id = (maj << 20) | (min << 8) | (fd_num & 0xFF);

		save_nvidia_file_mapping(id, maj, min, link_target);
		count++;

		pr_debug("CUDA plugin: found NVIDIA fd %d -> %s (id=0x%x)\n",
			fd_num, link_target, id);
	}

	closedir(dir);

	if (count > 0) {
		pr_info("CUDA plugin: saved %d NVIDIA device mappings for pid %d\n", count, pid);
	}

	return count;
}

int cuda_plugin_dump_file(int fd, int id)
{
	struct stat st;
	char path[PATH_MAX];
	char fd_link[64];
	ssize_t len;

	if (fstat(fd, &st) == -1) {
		return -ENOTSUP; /* Can't stat, not our file */
	}

	/* Check if this is a character device with an NVIDIA major */
	if (!S_ISCHR(st.st_mode) || !is_nvidia_device_major(major(st.st_rdev))) {
		return -ENOTSUP; /* Not an NVIDIA device */
	}

	/*
	 * Register this plugin in the inventory so CRIU knows to load it
	 * during restore. This is critical - without it, the plugin will
	 * be disabled during restore and external files won't be restored.
	 */
	if (!plugin_added_to_inventory) {
		if (add_inventory_plugin(CR_PLUGIN_DESC.name))
			return -1;
		plugin_added_to_inventory = true;
		pr_info("CUDA plugin: added to inventory for DUMP_EXT_FILE\n");
	}

	/* Get the actual device path */
	unsigned int dmaj = major(st.st_rdev);
	unsigned int dmin = minor(st.st_rdev);
	snprintf(fd_link, sizeof(fd_link), "/proc/self/fd/%d", fd);
	len = readlink(fd_link, path, sizeof(path) - 1);
	if (len > 0) {
		path[len] = '\0';
		save_nvidia_file_mapping(id, dmaj, dmin, path);
	} else {
		/* Readlink failed — scan /dev for matching major:minor */
		DIR *devdir = opendir("/dev");
		bool found = false;
		if (devdir) {
			struct dirent *de;
			while ((de = readdir(devdir)) != NULL) {
				struct stat devst;
				snprintf(path, sizeof(path), "/dev/%s", de->d_name);
				if (stat(path, &devst) == 0 && S_ISCHR(devst.st_mode) &&
				    major(devst.st_rdev) == dmaj && minor(devst.st_rdev) == dmin) {
					save_nvidia_file_mapping(id, dmaj, dmin, path);
					found = true;
					break;
				}
			}
			closedir(devdir);
		}
		if (!found) {
			snprintf(path, sizeof(path), "/dev/nvidia-unknown-%u-%u", dmaj, dmin);
			save_nvidia_file_mapping(id, dmaj, dmin, path);
			pr_warn("CUDA plugin: couldn't find device for major %u minor %u, "
				"using placeholder path\n", dmaj, dmin);
		}
	}

	pr_info("CUDA plugin: marking NVIDIA device fd %d id 0x%x (%s) as external\n",
		fd, id, path);

	/* Return 0 to tell CRIU we handled this file (skip dumping it) */
	return 0;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__DUMP_EXT_FILE, cuda_plugin_dump_file)

/**
 * Restore an external NVIDIA device file.
 * CRIU calls this during restore for each ext file we claimed during dump.
 */
/*
 * Load NVIDIA device file mappings saved during dump.
 */
#define MAX_NVIDIA_FILES 512
static struct {
	int id;
	unsigned int maj;
	unsigned int min;
	char path[PATH_MAX];
} nvidia_file_map[MAX_NVIDIA_FILES];
static int nvidia_file_map_count = 0;
static bool nvidia_file_map_loaded = false;

static void load_nvidia_file_mappings(void)
{
	FILE *fp;
	int id, fd;
	char path[PATH_MAX];
	int img_dir_fd;

	if (nvidia_file_map_loaded)
		return;
	nvidia_file_map_loaded = true;

	img_dir_fd = criu_get_image_dir();
	fd = openat(img_dir_fd, NVIDIA_FILES_IMG, O_RDONLY);
	if (fd < 0) {
		pr_warn("CUDA plugin: no %s found via openat(img_dir_fd=%d) (errno=%d: %s), using fallback\n",
			NVIDIA_FILES_IMG, img_dir_fd, errno, strerror(errno));
		return;
	}
	fp = fdopen(fd, "r");
	if (!fp) {
		pr_warn("CUDA plugin: fdopen failed for %s (errno=%d: %s)\n",
			NVIDIA_FILES_IMG, errno, strerror(errno));
		close(fd);
		return;
	}
	pr_info("CUDA plugin: loading NVIDIA mappings via openat(img_dir_fd=%d, %s)\n",
		img_dir_fd, NVIDIA_FILES_IMG);

	{
		unsigned int fmaj, fmin;
		while (fscanf(fp, "%d %u %u %255s", &id, &fmaj, &fmin, path) == 4) {
			if (nvidia_file_map_count >= MAX_NVIDIA_FILES) {
				pr_warn("CUDA plugin: too many NVIDIA files, truncating\n");
				break;
			}
			nvidia_file_map[nvidia_file_map_count].id = id;
			nvidia_file_map[nvidia_file_map_count].maj = fmaj;
			nvidia_file_map[nvidia_file_map_count].min = fmin;
			strncpy(nvidia_file_map[nvidia_file_map_count].path, path, sizeof(nvidia_file_map[0].path) - 1);
			nvidia_file_map[nvidia_file_map_count].path[sizeof(nvidia_file_map[0].path) - 1] = '\0';
			nvidia_file_map_count++;
		}
	}
	fclose(fp);
	pr_info("CUDA plugin: loaded %d NVIDIA file mappings\n", nvidia_file_map_count);
}

static int find_nvidia_entry_for_id(int id, const char **out_path,
				    unsigned int *out_maj, unsigned int *out_min)
{
	load_nvidia_file_mappings();
	for (int i = 0; i < nvidia_file_map_count; i++) {
		if (nvidia_file_map[i].id == id) {
			*out_path = nvidia_file_map[i].path;
			*out_maj = nvidia_file_map[i].maj;
			*out_min = nvidia_file_map[i].min;
			return 0;
		}
	}
	return -1;
}

int cuda_plugin_restore_file(int id, bool *retry_needed)
{
	int fd;
	const char *path;

	*retry_needed = false;

	if (plugin_disabled) {
		pr_debug("CUDA plugin: plugin disabled, returning ENOTSUP\n");
		return -ENOTSUP;
	}

	/* Look up the original path and device major:minor for this file ID */
	{
		unsigned int dmaj, dmin;
		if (find_nvidia_entry_for_id(id, &path, &dmaj, &dmin) == 0) {
			fd = open(path, O_RDWR);
			if (fd >= 0) {
				pr_debug("CUDA plugin: restored id 0x%x as %s (fd=%d)\n", id, path, fd);
				return fd;
			}
			/* Device doesn't exist in container — create it via mknod */
			if (errno == ENOENT && dmaj > 0) {
				char parent[PATH_MAX];
				strncpy(parent, path, sizeof(parent) - 1);
				parent[sizeof(parent) - 1] = '\0';
				char *slash = strrchr(parent, '/');
				if (slash && slash != parent) {
					*slash = '\0';
					mkdir(parent, 0755);
				}
				if (mknod(path, S_IFCHR | 0666, makedev(dmaj, dmin)) == 0 ||
				    errno == EEXIST) {
					fd = open(path, O_RDWR);
					if (fd >= 0) {
						pr_info("CUDA plugin: restored id 0x%x as %s "
							"(created via mknod %u:%u, fd=%d)\n",
							id, path, dmaj, dmin, fd);
						return fd;
					}
				}
				pr_warn("CUDA plugin: mknod %s (%u:%u) failed: %s\n",
					path, dmaj, dmin, strerror(errno));
			} else {
				pr_warn("CUDA plugin: can't open %s for id 0x%x: %s\n",
					path, id, strerror(errno));
			}
		}
	}

	/* Fallback: try to reconstruct device path from the ID.
	 * ID format: (major << 20) | (minor << 8) | (fd_num & 0xFF)
	 * We can extract major/minor and scan /dev for a matching device. */
	{
		unsigned int id_major = (id >> 20) & 0xFFF;
		unsigned int id_minor = (id >> 8) & 0xFFF;
		DIR *devdir = opendir("/dev");
		if (devdir) {
			struct dirent *de;
			while ((de = readdir(devdir)) != NULL) {
				char devpath[PATH_MAX];
				struct stat devst;
				snprintf(devpath, sizeof(devpath), "/dev/%s", de->d_name);
				if (stat(devpath, &devst) < 0)
					continue;
				if (!S_ISCHR(devst.st_mode))
					continue;
				if (major(devst.st_rdev) == id_major &&
				    minor(devst.st_rdev) == id_minor) {
					fd = open(devpath, O_RDWR);
					if (fd >= 0) {
						pr_info("CUDA plugin: restored id 0x%x as %s "
							"(fallback by major:minor %u:%u, fd=%d)\n",
							id, devpath, id_major, id_minor, fd);
						closedir(devdir);
						return fd;
					}
				}
			}
			closedir(devdir);
		}
	}

	/* Return -ENOTSUP (not -ENOENT) so CRIU knows this plugin can't handle
	 * this file and tries other restore methods. -ENOENT means "file doesn't
	 * exist" which causes CRIU to abort. -ENOTSUP means "not my file." */
	pr_debug("CUDA plugin: id 0x%x (major=%u minor=%u) not an NVIDIA device, returning ENOTSUP\n",
		id, (id >> 20) & 0xFFF, (id >> 8) & 0xFFF);
	return -ENOTSUP;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESTORE_EXT_FILE, cuda_plugin_restore_file)

/**
 * Check if a CUDA device is available on the system
 */
static bool is_cuda_device_available(void)
{
	const char *gpu_path = "/proc/driver/nvidia/gpus/";
	struct stat sb;

	if (stat(gpu_path, &sb) != 0)
		return false;

	return S_ISDIR(sb.st_mode);
}

int cuda_plugin_init(int stage)
{
	int ret;

	/* Disable CUDA checkpointing with pre-dump */
	if (stage == CR_PLUGIN_STAGE__PRE_DUMP) {
		plugin_disabled = true;
		return 0;
	}

	if (stage == CR_PLUGIN_STAGE__RESTORE) {
		if (!check_and_remove_inventory_plugin(CR_PLUGIN_DESC.name, strlen(CR_PLUGIN_DESC.name))) {
			plugin_disabled = true;
			return 0;
		}
	}

	if (!fault_injected(FI_PLUGIN_CUDA_FORCE_ENABLE) && !is_cuda_device_available()) {
		pr_info("No GPU device found; CUDA plugin is disabled\n");
		plugin_disabled = true;
		return 0;
	}

	ret = cuda_checkpoint_supports_flag("--action");
	if (ret == -1) {
		/* cuda-checkpoint not found - this is OK if using external GPU checkpoint (gpucr) */
		pr_warn("check that %s is present in $PATH\n", CUDA_CHECKPOINT);
		pr_info("CUDA plugin will use fallback mode (external GPU checkpoint via signals)\n");
		/* Don't disable - allow the plugin to handle device FDs */
	} else if (ret == 0) {
		pr_warn("cuda-checkpoint --action flag not supported, an r555 or higher version driver is required\n");
		/* Still continue - allow device FD handling */
	}

	pr_info("initialized: %s stage %d\n", CR_PLUGIN_DESC.name, stage);

	/* In the DUMP stage track all the PID's we've paused CUDA operations on to
	 * release them when we're done if the user requested the leave-running option
	 */
	if (stage == CR_PLUGIN_STAGE__DUMP) {
		INIT_LIST_HEAD(&cuda_pids);
	}

	set_compel_interrupt_only_mode();

	return 0;
}

void cuda_plugin_fini(int stage, int ret)
{
	if (plugin_disabled) {
		return;
	}

	pr_info("finished %s stage %d err %d\n", CR_PLUGIN_DESC.name, stage, ret);

	/* Release all the paused PID's at the end of the DUMP stage in case the
	 * user provides the -R (leave-running) flag or an error occurred
	 */
	if (stage == CR_PLUGIN_STAGE__DUMP && (opts.final_state == TASK_ALIVE || ret != 0)) {
		struct pid_info *info;
		list_for_each_entry(info, &cuda_pids, list) {
			resume_device(info->pid, info->checkpointed, info->initial_task_state);
		}
	}
	if (stage == CR_PLUGIN_STAGE__DUMP) {
		dealloc_pid_buffer(&cuda_pids);
	}
}
CR_PLUGIN_REGISTER("cuda_plugin", cuda_plugin_init, cuda_plugin_fini)
