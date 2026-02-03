/* SPDX-License-Identifier: MPL-2.0 */

#include "criu-log.h"
#include "criu-plugin.h"

#include <common/list.h>

#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <linux/limits.h>

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "zmq_plugin: "

/* Plugin state */
static bool plugin_disabled = false;
static bool plugin_added_to_inventory = false;

/* libzmq function pointers (loaded via dlopen) */
static void *libzmq_handle = NULL;

typedef int (*zmq_get_all_contexts_fn)(void ***contexts, int *count);
typedef int (*zmq_ctx_checkpoint_fn)(void *context, void **checkpoint, int flags);
typedef int (*zmq_ctx_restore_fn)(void *checkpoint, void **context, int flags);
typedef int (*zmq_ctx_checkpoint_resume_fn)(void *context);
typedef int (*zmq_checkpoint_destroy_fn)(void *checkpoint);

static zmq_get_all_contexts_fn zmq_get_all_contexts_ptr = NULL;
static zmq_ctx_checkpoint_fn zmq_ctx_checkpoint_ptr = NULL;
static zmq_ctx_restore_fn zmq_ctx_restore_ptr = NULL;
static zmq_ctx_checkpoint_resume_fn zmq_ctx_checkpoint_resume_ptr = NULL;
static zmq_checkpoint_destroy_fn zmq_checkpoint_destroy_ptr = NULL;

/* Checkpoint data per PID */
struct zmq_pid_checkpoint {
	int pid;
	int num_contexts;
	void **checkpoints;	   /* Array of checkpoint handles */
	struct list_head list;
};

static LIST_HEAD(zmq_checkpoints);

/* Image file path format */
#define ZMQ_CKPT_IMG_FMT "zmq-ckpt-%d.img"

/**
 * Check if a process uses libzmq by scanning /proc/PID/maps
 */
static bool process_uses_libzmq(int pid)
{
	char maps_path[64];
	char line[512];
	FILE *fp;
	bool found = false;

	snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
	fp = fopen(maps_path, "r");
	if (!fp) {
		pr_debug("can't open %s\n", maps_path);
		return false;
	}

	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "libzmq.so")) {
			found = true;
			break;
		}
	}

	fclose(fp);
	return found;
}

/**
 * Load libzmq and resolve checkpoint/restore function pointers
 */
static int load_libzmq_symbols(void)
{
	if (libzmq_handle)
		return 0; /* Already loaded */

	/* Try common libzmq names */
	const char *libzmq_names[] = {
		"libzmq.so.5",	  /* Most common */
		"libzmq.so",	  /* Symlink */
		"/usr/lib/x86_64-linux-gnu/libzmq.so.5",
		"/usr/local/lib/libzmq.so.5",
		NULL
	};

	for (int i = 0; libzmq_names[i]; i++) {
		libzmq_handle = dlopen(libzmq_names[i], RTLD_NOW | RTLD_GLOBAL);
		if (libzmq_handle) {
			pr_info("loaded libzmq from %s\n", libzmq_names[i]);
			break;
		}
	}

	if (!libzmq_handle) {
		pr_warn("could not load libzmq: %s\n", dlerror());
		return -1;
	}

	/* Resolve function pointers */
	zmq_get_all_contexts_ptr = dlsym(libzmq_handle, "zmq_get_all_contexts");
	zmq_ctx_checkpoint_ptr = dlsym(libzmq_handle, "zmq_ctx_checkpoint");
	zmq_ctx_restore_ptr = dlsym(libzmq_handle, "zmq_ctx_restore");
	zmq_ctx_checkpoint_resume_ptr = dlsym(libzmq_handle, "zmq_ctx_checkpoint_resume");
	zmq_checkpoint_destroy_ptr = dlsym(libzmq_handle, "zmq_checkpoint_destroy");

	if (!zmq_ctx_checkpoint_ptr || !zmq_ctx_restore_ptr) {
		pr_warn("libzmq does not support checkpoint/restore API\n");
		pr_warn("missing symbols: %s\n", dlerror());
		return -1;
	}

	pr_info("successfully loaded ZMQ checkpoint/restore API\n");
	return 0;
}

/**
 * Save a checkpoint to an image file
 */
static int save_checkpoint_to_file(void *checkpoint, int pid, int ctx_index, const char *img_dir)
{
	char img_path[PATH_MAX];

	if (!img_dir)
		img_dir = ".";

	snprintf(img_path, sizeof(img_path), "%s/zmq-ckpt-%d-%d.img", img_dir, pid, ctx_index);

	/* For Phase 1: Just save a marker file
	 * Phase 2: Will implement proper serialization via zmq_checkpoint_serialize()
	 */
	FILE *fp = fopen(img_path, "w");
	if (!fp) {
		pr_perror("failed to create %s", img_path);
		return -1;
	}

	fprintf(fp, "ZMQ_CHECKPOINT pid=%d ctx_index=%d checkpoint=%p\n", pid, ctx_index, checkpoint);
	fclose(fp);

	pr_info("saved checkpoint for pid %d ctx %d to %s\n", pid, ctx_index, img_path);
	return 0;
}

/**
 * Load a checkpoint from an image file
 */
static void *load_checkpoint_from_file(int pid, int ctx_index, const char *img_dir)
{
	char img_path[PATH_MAX];

	if (!img_dir)
		img_dir = ".";

	snprintf(img_path, sizeof(img_path), "%s/zmq-ckpt-%d-%d.img", img_dir, pid, ctx_index);

	/* For Phase 1: Just check file exists
	 * Phase 2: Will implement proper deserialization via zmq_checkpoint_deserialize()
	 */
	struct stat st;
	if (stat(img_path, &st) != 0) {
		pr_debug("no checkpoint file %s\n", img_path);
		return NULL;
	}

	pr_info("found checkpoint file %s\n", img_path);

	/* For now, return a dummy pointer
	 * Real implementation will deserialize checkpoint data
	 */
	return (void *)0x1; /* Non-NULL marker */
}

/**
 * PAUSE_DEVICES hook - called before checkpoint
 * Quiesce ZMQ operations and create checkpoints
 */
int zmq_plugin_pause_devices(int pid)
{

	if (plugin_disabled)
		return -ENOTSUP;

	/* Check if this process uses ZMQ */
	if (!process_uses_libzmq(pid)) {
		pr_debug("pid %d does not use libzmq, skipping\n", pid);
		return 0;
	}

	/* Load libzmq symbols */
	if (load_libzmq_symbols() != 0) {
		pr_warn("could not load libzmq for pid %d\n", pid);
		return 0; /* Not an error - process may not use ZMQ checkpoint API */
	}

	/* Add plugin to inventory */
	if (!plugin_added_to_inventory) {
		/* TODO: Implement inventory tracking for ZMQ plugin */
		plugin_added_to_inventory = true;
	}

	pr_info("checkpointing ZMQ contexts for pid %d\n", pid);

	/* Get all ZMQ contexts in the process
	 * NOTE: This requires ptrace injection to call zmq_get_all_contexts()
	 * in the target process. For Phase 1, we'll implement a simpler approach.
	 */

	/* Phase 1 Simple Approach: Assume process has 1 context
	 * Phase 2: Will use ptrace to inject zmq_get_all_contexts() call
	 */

	struct zmq_pid_checkpoint *pid_ckpt = malloc(sizeof(*pid_ckpt));
	pid_ckpt->pid = pid;
	pid_ckpt->num_contexts = 0; /* Will be filled during actual checkpoint */
	pid_ckpt->checkpoints = NULL;
	list_add_tail(&pid_ckpt->list, &zmq_checkpoints);

	pr_info("ZMQ checkpoint prepared for pid %d\n", pid);

	return 0;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__PAUSE_DEVICES, zmq_plugin_pause_devices)

/**
 * CHECKPOINT_DEVICES hook - called during checkpoint freeze
 * Perform actual checkpoint serialization
 */
int zmq_plugin_checkpoint_devices(int pid)
{
	if (plugin_disabled)
		return -ENOTSUP;

	struct zmq_pid_checkpoint *pid_ckpt;
	bool found = false;

	/* Find this PID in our tracking list */
	list_for_each_entry(pid_ckpt, &zmq_checkpoints, list) {
		if (pid_ckpt->pid == pid) {
			found = true;
			break;
		}
	}

	if (!found) {
		pr_debug("no ZMQ checkpoint for pid %d (process doesn't use ZMQ)\n", pid);
		return 0;
	}

	pr_info("checkpoint_devices for pid %d\n", pid);

	/* Phase 1: Just mark as checkpointed
	 * Phase 2: Will call zmq_ctx_checkpoint() via ptrace injection
	 */

	return 0;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__CHECKPOINT_DEVICES, zmq_plugin_checkpoint_devices)

/**
 * RESUME_DEVICES_LATE hook - called after restore
 * Restore ZMQ contexts from checkpoint
 */
int zmq_plugin_resume_devices_late(int pid)
{
	if (plugin_disabled)
		return -ENOTSUP;

	struct zmq_pid_checkpoint *pid_ckpt;
	bool found = false;

	/* Find checkpoint for this PID */
	list_for_each_entry(pid_ckpt, &zmq_checkpoints, list) {
		if (pid_ckpt->pid == pid) {
			found = true;
			break;
		}
	}

	if (!found) {
		pr_debug("no ZMQ checkpoint to restore for pid %d\n", pid);
		return 0;
	}

	pr_info("restoring ZMQ contexts for pid %d\n", pid);

	/* Phase 1: Just verify checkpoint exists
	 * Phase 2: Will call zmq_ctx_restore() via ptrace injection
	 */

	for (int i = 0; i < pid_ckpt->num_contexts; i++) {
		void *checkpoint = load_checkpoint_from_file(pid, i, ".");
		if (checkpoint) {
			pr_info("loaded checkpoint for pid %d context %d\n", pid, i);
			/* Phase 2: zmq_ctx_restore(checkpoint, &new_ctx, 0) */
		}
	}

	return 0;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESUME_DEVICES_LATE, zmq_plugin_resume_devices_late)

/**
 * Plugin initialization
 */
int zmq_plugin_init(int stage)
{
	if (stage == CR_PLUGIN_STAGE__PRE_DUMP) {
		/* ZMQ checkpoint not supported with pre-dump */
		plugin_disabled = true;
		return 0;
	}

	if (stage == CR_PLUGIN_STAGE__RESTORE) {
		/* TODO: Implement inventory check for restore */
	}

	pr_info("initialized: %s stage %d\n", CR_PLUGIN_DESC.name, stage);

	if (stage == CR_PLUGIN_STAGE__DUMP) {
		INIT_LIST_HEAD(&zmq_checkpoints);
	}

	return 0;
}

/**
 * Plugin cleanup
 */
void zmq_plugin_fini(int stage, int ret)
{
	struct zmq_pid_checkpoint *pid_ckpt, *n;

	if (plugin_disabled)
		return;

	pr_info("finished %s stage %d err %d\n", CR_PLUGIN_DESC.name, stage, ret);

	/* Cleanup checkpoint tracking */
	if (stage == CR_PLUGIN_STAGE__DUMP) {
		list_for_each_entry_safe(pid_ckpt, n, &zmq_checkpoints, list) {
			if (pid_ckpt->checkpoints) {
				/* Destroy checkpoint handles */
				for (int i = 0; i < pid_ckpt->num_contexts; i++) {
					if (zmq_checkpoint_destroy_ptr) {
						zmq_checkpoint_destroy_ptr(pid_ckpt->checkpoints[i]);
					}
				}
				free(pid_ckpt->checkpoints);
			}
			list_del(&pid_ckpt->list);
			free(pid_ckpt);
		}
	}

	/* Close libzmq handle */
	if (libzmq_handle) {
		dlclose(libzmq_handle);
		libzmq_handle = NULL;
	}
}

CR_PLUGIN_REGISTER("zmq_plugin", zmq_plugin_init, zmq_plugin_fini)
