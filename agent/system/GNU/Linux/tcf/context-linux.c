/*******************************************************************************
 * Copyright (c) 2007, 2013 Wind River Systems, Inc. and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 * You may elect to redistribute this code under either of these licenses.
 *
 * Contributors:
 *     Wind River Systems - initial API and implementation
 *******************************************************************************/

/*
 * This module handles process/thread OS contexts and their state machine.
 */

#include <tcf/config.h>

#if defined(__linux__)

#if ENABLE_DebugContext && !ENABLE_ContextProxy

#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <sched.h>
#include <dirent.h>
#include <ctype.h>
#include <asm/unistd.h>
#include <sys/ptrace.h>
#include <sys/utsname.h>
#include <linux/kdev_t.h>
#include <tcf/framework/context.h>
#include <tcf/framework/events.h>
#include <tcf/framework/errors.h>
#include <tcf/framework/trace.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/waitpid.h>
#include <tcf/framework/signames.h>
#include <tcf/services/symbols.h>
#include <tcf/services/contextquery.h>
#include <tcf/services/breakpoints.h>
#include <tcf/services/expressions.h>
#include <tcf/services/memorymap.h>
#include <tcf/services/runctrl.h>
#include <tcf/services/elf-loader.h>
#include <tcf/services/tcf_elf.h>
#include <system/GNU/Linux/tcf/regset.h>

#if !defined(TRAP_OFFSET)
#define TRAP_OFFSET -1
#endif

#if !defined(PTRACE_SETOPTIONS)
#define PTRACE_SETOPTIONS       0x4200
#define PTRACE_GETEVENTMSG      0x4201
#define PTRACE_GETSIGINFO       0x4202
#define PTRACE_SETSIGINFO       0x4203

#define PTRACE_O_TRACESYSGOOD   0x00000001
#define PTRACE_O_TRACEFORK      0x00000002
#define PTRACE_O_TRACEVFORK     0x00000004
#define PTRACE_O_TRACECLONE     0x00000008
#define PTRACE_O_TRACEEXEC      0x00000010
#define PTRACE_O_TRACEVFORKDONE 0x00000020
#define PTRACE_O_TRACEEXIT      0x00000040

#define PTRACE_EVENT_FORK       1
#define PTRACE_EVENT_VFORK      2
#define PTRACE_EVENT_CLONE      3
#define PTRACE_EVENT_EXEC       4
#define PTRACE_EVENT_VFORK_DONE 5
#define PTRACE_EVENT_EXIT       6
#endif

#define USE_PTRACE_SYSCALL      0

static const int PTRACE_FLAGS =
#if USE_PTRACE_SYSCALL
      PTRACE_O_TRACESYSGOOD |
#endif
      PTRACE_O_TRACECLONE |
      PTRACE_O_TRACEEXEC |
      PTRACE_O_TRACEFORK |
      PTRACE_O_TRACEVFORK |
      PTRACE_O_TRACEVFORKDONE |
      PTRACE_O_TRACEEXIT;

typedef struct ContextExtensionLinux {
    pid_t                   pid;
    ContextAttachCallBack * attach_callback;
    void *                  attach_data;
    int                     attach_mode;
    int                     ptrace_flags;
    int                     ptrace_event;
    int                     syscall_enter;
    int                     syscall_exit;
    int                     syscall_id;
    ContextAddress          syscall_pc;
    ContextAddress          loader_state;
    int                     end_of_step;
    REG_SET *               regs;               /* copy of context registers, updated on request */
    uint8_t *               regs_valid;
    uint8_t *               regs_dirty;
    int                     pending_step;
    int                     stop_cnt;
    int                     sigstop_posted;
    int                     waitpid_posted;
    int                     detach_req;
} ContextExtensionLinux;

static size_t context_extension_offset = 0;

#define EXT(ctx) ((ContextExtensionLinux *)((char *)(ctx) + context_extension_offset))

#include <tcf/framework/pid-hash.h>

static LINK attach_list = TCF_LIST_INIT(attach_list);
static LINK detach_list = TCF_LIST_INIT(detach_list);

static MemoryErrorInfo mem_err_info;

static const char * event_name(int event) {
    switch (event) {
    case 0: return "none";
    case PTRACE_EVENT_FORK: return "fork";
    case PTRACE_EVENT_VFORK: return "vfork";
    case PTRACE_EVENT_CLONE: return "clone";
    case PTRACE_EVENT_EXEC: return "exec";
    case PTRACE_EVENT_VFORK_DONE: return "vfork-done";
    case PTRACE_EVENT_EXIT: return "exit";
    }
    trace(LOG_ALWAYS, "event_name(): unexpected event code %d", event);
    return "unknown";
}

const char * context_suspend_reason(Context * ctx) {
    static char reason[128];

    if (EXT(ctx)->end_of_step) return REASON_STEP;
    if (EXT(ctx)->ptrace_event != 0) {
        assert(ctx->signal == SIGTRAP);
        snprintf(reason, sizeof(reason), "Event: %s", event_name(EXT(ctx)->ptrace_event));
        return reason;
    }
    if (EXT(ctx)->syscall_enter) return "System Call";
    if (EXT(ctx)->syscall_exit) return "System Return";
    if (ctx->signal == SIGSTOP || ctx->signal == SIGTRAP) return REASON_USER_REQUEST;
    snprintf(reason, sizeof(reason), "Signal %d", ctx->signal);
    return reason;
}

int context_attach_self(void) {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) < 0) {
        int err = errno;
        trace(LOG_ALWAYS, "error: ptrace(PTRACE_TRACEME) failed: pid %d, error %d %s",
              getpid(), err, errno_to_str(err));
        errno = err;
        return -1;
    }
    return 0;
}

static void proc_get_children(pid_t pid, int * cnt, pid_t ** pids) {
    char dir[FILE_PATH_SIZE];
    DIR * proc;
    static int max_threads_cnt = 0;
    int threads_cnt = 0;
    static pid_t * thread_pid = NULL;

    *cnt = 0;

    snprintf(dir, sizeof(dir), "/proc/%d/task", pid);
    proc = opendir(dir);
    if (proc == NULL) return;
    for (;;) {
        struct dirent * ent = readdir(proc);
        if (ent == NULL) break;
        if (ent->d_name[0] >= '1' && ent->d_name[0] <= '9') {
            pid_t pid = atol(ent->d_name);
            if (threads_cnt >= max_threads_cnt) {
                max_threads_cnt += 10;
                thread_pid = (pid_t *)loc_realloc(thread_pid, max_threads_cnt * sizeof(pid_t));
            }
            thread_pid[threads_cnt++] = pid;
        }
    }
    closedir(proc);
    *cnt = threads_cnt;
    *pids = thread_pid;
}

int context_attach(pid_t pid, ContextAttachCallBack * done, void * data, int mode) {
    Context * ctx = NULL;
    ContextExtensionLinux * ext = NULL;

    assert(done != NULL);
    trace(LOG_CONTEXT, "context: attaching pid %d", pid);
    if ((mode & CONTEXT_ATTACH_SELF) == 0 && ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) {
        int err = errno;
        trace(LOG_ALWAYS, "error: ptrace(PTRACE_ATTACH) failed: pid %d, error %d %s",
            pid, err, errno_to_str(err));
        errno = err;
        return -1;
    }
    add_waitpid_process(pid);
    ctx = create_context(pid2id(pid, 0));
    ctx->mem = ctx;
    ctx->mem_access |= MEM_ACCESS_INSTRUCTION;
    ctx->mem_access |= MEM_ACCESS_DATA;
    ctx->mem_access |= MEM_ACCESS_USER;
    ctx->big_endian = big_endian_host();
    ext = EXT(ctx);
    ext->pid = pid;
    ext->attach_callback = done;
    ext->attach_data = data;
    ext->attach_mode = mode;
    list_add_first(&ctx->ctxl, &attach_list);
    /* TODO: context_attach works only for main task in a process */
    return 0;
}

static int context_detach(Context * ctx) {
    ContextExtensionLinux * ext = EXT(ctx);

    assert(is_dispatch_thread());
    assert(ctx->parent == NULL);
    assert(!ctx->exited);

    trace(LOG_CONTEXT, "context: detach ctx %#lx, id %s", ctx, ctx->id);

    unplant_breakpoints(ctx);
    ctx->exiting = 1;
    ext->detach_req = 1;
    if (!list_is_empty(&ctx->children)) {
        LINK * l = ctx->children.next;
        while (l != &ctx->children) {
            Context * c = cldl2ctxp(l);
            if (!c->exited) {
                ContextExtensionLinux * e = EXT(c);
                c->exiting = 1;
                e->detach_req = 1;
            }
            l = l->next;
        }
    }
    return 0;
}

int context_has_state(Context * ctx) {
    return ctx != NULL && ctx->parent != NULL;
}

static int get_process_state(pid_t pid) {
    int ch = 0;
    FILE * file = NULL;
    char file_name[FILE_PATH_SIZE];
    snprintf(file_name, sizeof(file_name), "/proc/%d/stat", pid);
    if ((file = fopen(file_name, "r")) == NULL) return EOF;
    while (ch != EOF && ch != ')') ch = fgetc(file);
    if (ch != EOF) {
        ch = fgetc(file);
        if (ch == ' ') ch = fgetc(file);
    }
    fclose(file);
    return ch;
}

int context_stop(Context * ctx) {
    ContextExtensionLinux * ext = EXT(ctx);
    trace(LOG_CONTEXT, "context:%s suspending ctx %#lx id %s",
        ctx->pending_intercept ? "" : " temporary", ctx, ctx->id);
    assert(is_dispatch_thread());
    assert(context_has_state(ctx));
    assert(!ctx->exited);
    assert(!ctx->exiting);
    assert(!ctx->stopped);
    assert(ext->waitpid_posted);
    if (ext->stop_cnt > 4) {
        /* Waiting too long, check for zombies */
        int ch = get_process_state(ext->pid);
        if (ch == EOF || ch == 'Z') {
            /* Already exited or zombie */
            ctx->exiting = 1;
            return 0;
        }
        ext->stop_cnt = 0;
        ext->sigstop_posted = 0;
    }
    if (!ext->sigstop_posted) {
        if (tkill(ext->pid, SIGSTOP) < 0) {
            int err = errno;
            if (err == ESRCH) {
                ctx->exiting = 1;
                return 0;
            }
            trace(LOG_ALWAYS, "error: tkill(SIGSTOP) failed: ctx %#lx, id %s, error %d %s",
                ctx, ctx->id, err, errno_to_str(err));
            errno = err;
            return -1;
        }
        ext->sigstop_posted = 1;
    }
    ext->stop_cnt++;
    return 0;
}

static int syscall_never_returns(Context * ctx) {
    if (EXT(ctx)->syscall_enter) {
        switch (EXT(ctx)->syscall_id) {
#ifdef __NR_sigreturn
        case __NR_sigreturn:
            return 1;
#endif
        }
    }
    return 0;
}

static void alloc_regs(Context * ctx) {
    ContextExtensionLinux * ext = EXT(ctx);
    assert(ext->regs == NULL);
    ext->regs = (REG_SET *)loc_alloc_zero(sizeof(REG_SET));
    ext->regs_valid = (uint8_t *)loc_alloc_zero(sizeof(REG_SET));
    ext->regs_dirty = (uint8_t *)loc_alloc_zero(sizeof(REG_SET));
}

static int flush_regs(Context * ctx) {
    ContextExtensionLinux * ext = EXT(ctx);
    size_t i = 0;
    int err = 0;

    for (i = 0; i < sizeof(REG_SET); i++) {
        if (!ext->regs_dirty[i]) continue;
        if (i >= offsetof(REG_SET, fp) && i < offsetof(REG_SET, fp) + sizeof(ext->regs->fp)) {
            if (ptrace(PTRACE_SETFPREGS, ext->pid, 0, &ext->regs->fp) < 0) {
                err = errno;
                break;
            }
            memset(ext->regs_dirty + offsetof(REG_SET, fp), 0, sizeof(ext->regs->fp));
        }
#ifdef MDEP_OtherRegisters
        else if (i >= offsetof(REG_SET, other) && i < offsetof(REG_SET, other) + sizeof(ext->regs->other)) {
            size_t offs = 0;
            size_t size = 0;
            size_t j = i + 1;
            while (j < offsetof(REG_SET, other) + sizeof(ext->regs->other) && ext->regs_dirty[j]) j++;
            if (mdep_set_other_regs(ext->pid, ext->regs, i, j - i, &offs, &size) < 0) {
                err = errno;
                break;
            }
            assert(i >= offs);
            assert(j <= offs + size);
            memset(ext->regs_dirty + offs, 0, size);
        }
#endif
        else {
            size_t j = i - (i - offsetof(REG_SET, user)) % sizeof(ContextAddress);
            assert(*(ContextAddress *)(ext->regs_valid + j) == ~(ContextAddress)0);
            if (ptrace(PTRACE_POKEUSER, ext->pid, (void *)j, (void *)*(ContextAddress *)((uint8_t *)&ext->regs->user + j)) < 0) {
                err = errno;
                break;
            }
            *(ContextAddress *)(ext->regs_dirty + j) = 0;
        }
    }

    if (!err) return 0;

    if (err == ESRCH) {
        ctx->exiting = 1;
        memset(ext->regs_dirty, 0, sizeof(REG_SET));
        return 0;
    }

    {
        RegisterDefinition * def = get_reg_definitions(ctx);
        while (def->name != NULL && (def->offset > i || def->offset + def->size <= i)) def++;
        trace(LOG_ALWAYS, "error: writing register %s failed: ctx %#lx, id %s, error %d %s",
            def->name ? def->name : "?", ctx, ctx->id, err, errno_to_str(err));
        if (def->name) err = set_fmt_errno(err, "Cannot write register %s", def->name);
    }
    errno = err;
    return -1;
}

static void free_regs(Context * ctx) {
    ContextExtensionLinux * ext = EXT(ctx);
    loc_free(ext->regs);
    loc_free(ext->regs_valid);
    loc_free(ext->regs_dirty);
    ext->regs = NULL;
    ext->regs_valid = NULL;
    ext->regs_dirty = NULL;
}

static void send_process_exited_event(Context * prs) {
    LINK * l = prs->children.next;
    assert(prs->parent == NULL);
    assert(prs->exited == 0);
    assert(prs->stopped == 0);
    assert(EXT(prs)->regs == NULL);
    while (l != &prs->children) {
        Context * c = cldl2ctxp(l);
        if (!c->exited) return;
        l = l->next;
    }
    prs->exiting = 1;
    send_context_exited_event(prs);
}

static int do_single_step(Context * ctx) {
    ContextExtensionLinux * ext = EXT(ctx);

    assert(!ext->pending_step);

    if (skip_breakpoint(ctx, 1)) return 0;

    trace(LOG_CONTEXT, "context: single step ctx %#lx, id %s", ctx, ctx->id);
    if (flush_regs(ctx) < 0) return -1;
    if (!ctx->stopped) return 0;
    if (ptrace(PTRACE_SINGLESTEP, ext->pid, 0, 0) < 0) {
        int err = errno;
        if (err == ESRCH) {
            ctx->exiting = 1;
            send_context_started_event(ctx);
            return 0;
        }
        trace(LOG_ALWAYS, "error: ptrace(PTRACE_SINGLESTEP, ...) failed: ctx %#lx, id %s, error %d %s",
            ctx, ctx->id, err, errno_to_str(err));
        errno = err;
        return -1;
    }
    ext->pending_step = 1;
    send_context_started_event(ctx);
    return 0;
}

int context_continue(Context * ctx) {
    int cpu_bp_step = 0;
    int signal = 0;
    ContextExtensionLinux * ext = EXT(ctx);
#if USE_PTRACE_SYSCALL
    int cmd = PTRACE_SYSCALL;
#else
    int cmd = PTRACE_CONT;
#endif

    assert(is_dispatch_thread());
    assert(ctx->stopped);
    assert(!is_intercepted(ctx));
    assert(!ctx->pending_intercept);
    assert(!ext->pending_step);
    assert(!ctx->exited);

    if (cpu_bp_on_resume(ctx, &cpu_bp_step) < 0) return -1;
    if (cpu_bp_step) return do_single_step(ctx);
    if (skip_breakpoint(ctx, 0)) return 0;

    if (!ext->syscall_enter && !ext->ptrace_event) {
        while (ctx->pending_signals != 0) {
            while ((ctx->pending_signals & (1 << signal)) == 0) signal++;
            if (ctx->sig_dont_pass & (1 << signal)) {
                ctx->pending_signals &= ~(1 << signal);
                signal = 0;
            }
            else {
                break;
            }
        }
        assert(signal != SIGSTOP);
        assert(signal != SIGTRAP);
    }

    trace(LOG_CONTEXT, "context: resuming ctx %#lx, id %s, with signal %d", ctx, ctx->id, signal);
#if defined(__i386__) || defined(__x86_64__)
    if (ext->regs->user.regs.eflags & 0x100) {
        ext->regs->user.regs.eflags &= ~0x100;
        memset(ext->regs_dirty + offsetof(REG_SET, user.regs.eflags), 0xff, 4);
    }
#endif
    if (flush_regs(ctx) < 0) return -1;
    if (ext->detach_req && !ext->waitpid_posted) cmd = PTRACE_DETACH;
    if (ptrace((enum __ptrace_request)cmd, ext->pid, 0, signal) < 0) {
        int err = errno;
        if (err == ESRCH) {
            ctx->exiting = 1;
            send_context_started_event(ctx);
            return 0;
        }
        trace(LOG_ALWAYS, "error: ptrace(%d, ...) failed: ctx %#lx, id %s, error %d %s",
            cmd, ctx, ctx->id, err, errno_to_str(err));
        errno = err;
        return -1;
    }
    ctx->pending_signals &= ~(1 << signal);
    if (syscall_never_returns(ctx)) {
        ext->syscall_enter = 0;
        ext->syscall_exit = 0;
        ext->syscall_id = 0;
    }
    send_context_started_event(ctx);
    if (cmd == PTRACE_DETACH) {
        Context * prs = ctx->parent;
        assert(ctx->exiting);
        assert(ext->waitpid_posted == 0);
        if (ext->pid == EXT(prs)->pid && (EXT(prs)->attach_mode & CONTEXT_ATTACH_SELF) != 0) {
            /* The inferior process was started by the agent, post waitpid to wait until the inferior exits */
            add_waitpid_process(ext->pid);
        }
        free_regs(ctx);
        send_context_exited_event(ctx);
        send_process_exited_event(prs);
    }
    else {
        assert(ext->waitpid_posted);
        if (ext->detach_req && !ext->sigstop_posted) {
            assert(ctx->exiting);
            if (tkill(ext->pid, SIGSTOP) >= 0) ext->sigstop_posted = 1;
        }
    }
    return 0;
}

int context_single_step(Context * ctx) {
    ContextExtensionLinux * ext = EXT(ctx);
    int cpu_bp_step = 0;

    assert(is_dispatch_thread());
    assert(context_has_state(ctx));
    assert(ctx->stopped);
    assert(!is_intercepted(ctx));
    assert(!ctx->exited);

    if (ext->detach_req || syscall_never_returns(ctx)) return context_continue(ctx);
    if (cpu_bp_on_resume(ctx, &cpu_bp_step) < 0) return -1;
    return do_single_step(ctx);
}

int context_resume(Context * ctx, int mode, ContextAddress range_start, ContextAddress range_end) {
    switch (mode) {
    case RM_RESUME:
        return context_continue(ctx);
    case RM_STEP_INTO:
        return context_single_step(ctx);
    case RM_TERMINATE:
        ctx->pending_signals |= 1 << SIGKILL;
        return context_continue(ctx);
    case RM_DETACH:
        return context_detach(ctx);
    }
    errno = ERR_UNSUPPORTED;
    return -1;
}

int context_can_resume(Context * ctx, int mode) {
    switch (mode) {
    case RM_RESUME:
        return 1;
    case RM_STEP_INTO:
    case RM_TERMINATE:
        return context_has_state(ctx);
    case RM_DETACH:
        return ctx != NULL && ctx->parent == NULL;
    }
    return 0;
}

int context_write_mem(Context * ctx, ContextAddress address, void * buf, size_t size) {
    ContextAddress word_addr;
    unsigned word_size = context_word_size(ctx);
    ContextExtensionLinux * ext = EXT(ctx);
    int error = 0;

    assert(word_size <= sizeof(unsigned long));
    assert(is_dispatch_thread());
    assert(!ctx->exited);
    trace(LOG_CONTEXT,
        "context: write memory ctx %#lx, id %s, address %#lx, size %zu",
        ctx, ctx->id, address, size);
    mem_err_info.error = 0;
    if (size == 0) return 0;
    if (check_breakpoints_on_memory_write(ctx, address, buf, size) < 0) return -1;
    for (word_addr = address & ~((ContextAddress)word_size - 1); word_addr < address + size; word_addr += word_size) {
        unsigned long word = 0;
        if (word_addr < address || word_addr + word_size > address + size) {
            unsigned i = 0;
            errno = 0;
            word = ptrace(PTRACE_PEEKDATA, ext->pid, (void *)word_addr, 0);
            if (errno != 0) {
                error = errno;
                trace(LOG_CONTEXT,
                    "error: ptrace(PTRACE_PEEKDATA, ...) failed: ctx %#lx, id %s, addr %#lx, error %d %s",
                    ctx, ctx->id, word_addr, error, errno_to_str(error));
                break;
            }
            for (i = 0; i < word_size; i++) {
                if (word_addr + i >= address && word_addr + i < address + size) {
                    ((char *)&word)[i] = ((char *)buf)[word_addr + i - address];
                }
            }
        }
        else {
            memcpy(&word, (char *)buf + (word_addr - address), word_size);
        }
        if (ptrace(PTRACE_POKEDATA, ext->pid, (void *)word_addr, word) < 0) {
            error = errno;
            trace(LOG_ALWAYS,
                "error: ptrace(PTRACE_POKEDATA, ...) failed: ctx %#lx, id %s, addr %#lx, error %d %s",
                ctx, ctx->id, word_addr, error, errno_to_str(error));
            break;
        }
    }
    if (error) {
#if ENABLE_ExtendedMemoryErrorReports
        size_t size_valid = 0;
        size_t size_error = word_size;
        if (word_addr > address) size_valid = (size_t)(word_addr - address);
        /* Find number of invalid bytes */
        /* Note: cannot write memory here, read instead */
        while (size_error < 0x1000 && size_valid + size_error < size) {
            errno = 0;
            ptrace(PTRACE_PEEKDATA, ext->pid, (void *)(word_addr + size_error), 0);
            if (errno != error) break;
            size_error += word_size;
        }
        mem_err_info.error = error;
        mem_err_info.size_valid = size_valid;
        mem_err_info.size_error = size_error;
#endif
        errno = error;
        return -1;
    }
    return 0;
}

int context_read_mem(Context * ctx, ContextAddress address, void * buf, size_t size) {
    ContextAddress word_addr;
    unsigned word_size = context_word_size(ctx);
    ContextExtensionLinux * ext = EXT(ctx);
    size_t size_valid = 0;
    int error = 0;

    assert(word_size <= sizeof(unsigned long));
    assert(is_dispatch_thread());
    assert(!ctx->exited);
    trace(LOG_CONTEXT,
        "context: read memory ctx %#lx, id %s, address %#lx, size %zu",
        ctx, ctx->id, address, size);
    mem_err_info.error = 0;
    if (size == 0) return 0;
    for (word_addr = address & ~((ContextAddress)word_size - 1); word_addr < address + size; word_addr += word_size) {
        unsigned long word = 0;
        errno = 0;
        word = ptrace(PTRACE_PEEKDATA, ext->pid, (void *)word_addr, 0);
        if (errno != 0) {
            error = errno;
            trace(LOG_CONTEXT,
                "error: ptrace(PTRACE_PEEKDATA, ...) failed: ctx %#lx, id %s, addr %#lx, error %d %s",
                ctx, ctx->id, word_addr, error, errno_to_str(error));
            break;
        }
        if (word_addr < address || word_addr + word_size > address + size) {
            unsigned i = 0;
            for (i = 0; i < word_size; i++) {
                if (word_addr + i >= address && word_addr + i < address + size) {
                    ((char *)buf)[word_addr + i - address] = ((char *)&word)[i];
                }
            }
        }
        else {
            memcpy((char *)buf + (word_addr - address), &word, word_size);
        }
    }
    if (word_addr > address) size_valid = (size_t)(word_addr - address);
    if (size_valid > size) size_valid = size;
    if (check_breakpoints_on_memory_read(ctx, address, buf, size_valid) < 0) return -1;
    if (error) {
#if ENABLE_ExtendedMemoryErrorReports
        size_t size_error = word_size;
        /* Find number of unreadable bytes */
        while (size_error < 0x1000 && size_valid + size_error < size) {
            errno = 0;
            ptrace(PTRACE_PEEKDATA, ext->pid, (void *)(word_addr + size_error), 0);
            if (errno != error) break;
            size_error += word_size;
        }
        mem_err_info.error = error;
        mem_err_info.size_valid = size_valid;
        mem_err_info.size_error = size_error;
#endif
        errno = error;
        return -1;
    }
    return 0;
}

#if ENABLE_ExtendedMemoryErrorReports
int context_get_mem_error_info(MemoryErrorInfo * info) {
    if (mem_err_info.error == 0) {
        set_errno(ERR_OTHER, "Extended memory error info not available");
        return -1;
    }
    *info = mem_err_info;
    return 0;
}
#endif

int context_write_reg(Context * ctx, RegisterDefinition * def, unsigned offs, unsigned size, void * buf) {
    int valid = 1;
    size_t i = 0;
    ContextExtensionLinux * ext = EXT(ctx);

    assert(is_dispatch_thread());
    assert(context_has_state(ctx));
    assert(ctx->stopped);
    assert(!ctx->exited);
    assert(offs + size <= def->size);

    for (i = def->offset + offs; i < def->offset + offs + size; i++) {
        if (ext->regs_valid[i] == 0) valid = 0;
    }
    if (!valid && context_read_reg(ctx, def, offs, size, NULL) < 0) return -1;
    if (memcmp((uint8_t *)ext->regs + def->offset + offs, buf, size) == 0) return 0;
    memcpy((uint8_t *)ext->regs + def->offset + offs, buf, size);
    memset(ext->regs_dirty + def->offset + offs, 0xff, size);
    return 0;
}

int context_read_reg(Context * ctx, RegisterDefinition * def, unsigned offs, unsigned size, void * buf) {
    ContextExtensionLinux * ext = EXT(ctx);
    size_t i = 0;
    int err = 0;

    assert(is_dispatch_thread());
    assert(context_has_state(ctx));
    assert(ctx->stopped);
    assert(!ctx->exited);
    assert(offs + size <= def->size);

    for (i = def->offset + offs; i < def->offset + offs + size; i++) {
        if (ext->regs_valid[i]) continue;
        if (i >= offsetof(REG_SET, user.regs) && i < offsetof(REG_SET, user.regs) + sizeof(ext->regs->user.regs)) {
            if (ptrace(PTRACE_GETREGS, ext->pid, 0, &ext->regs->user.regs) < 0 && errno != ESRCH) {
                err = errno;
                break;
            }
            memset(ext->regs_valid + offsetof(REG_SET, user.regs), 0xff, sizeof(ext->regs->user.regs));
        }
        else if (i >= offsetof(REG_SET, fp) && i < offsetof(REG_SET, fp) + sizeof(ext->regs->fp)) {
            if (ptrace(PTRACE_GETFPREGS, ext->pid, 0, &ext->regs->fp) < 0 && errno != ESRCH) {
                err = errno;
                break;
            }
            memset(ext->regs_valid + offsetof(REG_SET, fp), 0xff, sizeof(ext->regs->fp));
        }
#ifdef MDEP_OtherRegisters
        else if (i >= offsetof(REG_SET, other) && i < offsetof(REG_SET, other) + sizeof(ext->regs->other)) {
            size_t offs = 0;
            size_t size = 0;
            size_t j = i + 1;
            while (j < def->offset + offs + size && !ext->regs_valid[j]) j++;
            if (mdep_get_other_regs(ext->pid, ext->regs, i, j - i, &offs, &size) < 0) {
                err = errno;
                break;
            }
            assert(i >= offs);
            assert(j <= offs + size);
            memset(ext->regs_valid + offs, 0xff, size);
        }
#endif
        else if (i >= offsetof(REG_SET, user) && i < offsetof(REG_SET, user) + sizeof(ext->regs->user)) {
            size_t j = i - (i - offsetof(REG_SET, user)) % sizeof(ContextAddress);
            *(ContextAddress *)((uint8_t *)ext->regs + j) = (ContextAddress)ptrace(PTRACE_PEEKUSER,
                ext->pid, (void *)(j - offsetof(REG_SET, user)), 0);
            memset(ext->regs_valid + j, 0xff, sizeof(ContextAddress));
        }
    }

    if (err) {
        trace(LOG_ALWAYS, "error: reading registers failed: ctx %#lx, id %s, error %d %s",
            ctx, ctx->id, err, errno_to_str(err));
        errno = err;
        return -1;
    }

    if (buf != NULL) memcpy(buf, (uint8_t *)ext->regs + def->offset + offs, size);
    return 0;
}

unsigned context_word_size(Context * ctx) {
    return sizeof(void *);
}

int context_get_canonical_addr(Context * ctx, ContextAddress addr,
        Context ** canonical_ctx, ContextAddress * canonical_addr,
        ContextAddress * block_addr, ContextAddress * block_size) {
    /* Direct mapping, page size is irrelevant */
    ContextAddress page_size = 0x100000;
    assert(is_dispatch_thread());
    *canonical_ctx = ctx->mem;
    if (canonical_addr != NULL) *canonical_addr = addr;
    if (block_addr != NULL) *block_addr = addr & ~(page_size - 1);
    if (block_size != NULL) *block_size = page_size;
    return 0;
}

Context * context_get_group(Context * ctx, int group) {
    static Context * cpu_group = NULL;
    switch (group) {
    case CONTEXT_GROUP_INTERCEPT:
        return ctx;
    case CONTEXT_GROUP_CPU:
        if (cpu_group == NULL) {
            cpu_group = create_context("CPU");
            ini_cpu_disassembler(cpu_group);
        }
        return cpu_group;
    }
    return ctx->mem;
}

int context_get_supported_bp_access_types(Context * ctx) {
    return cpu_bp_get_capabilities(ctx);
}

int context_plant_breakpoint(ContextBreakpoint * bp) {
    assert(!EXT(bp->ctx->mem)->detach_req);
    return cpu_bp_plant(bp);
}

int context_unplant_breakpoint(ContextBreakpoint * bp) {
    return cpu_bp_remove(bp);
}

int context_get_memory_map(Context * ctx, MemoryMap * map) {
    char maps_file_name[FILE_PATH_SIZE];
    FILE * file = NULL;

    ctx = ctx->mem;
    assert(!ctx->exited);
    assert(map->region_cnt == 0);

    snprintf(maps_file_name, sizeof(maps_file_name), "/proc/%d/maps", EXT(ctx)->pid);
    if ((file = fopen(maps_file_name, "r")) == NULL) return -1;
    for (;;) {
        MemoryRegion * prev = NULL;
        unsigned long addr0 = 0;
        unsigned long addr1 = 0;
        unsigned long offset = 0;
        unsigned long dev_ma = 0;
        unsigned long dev_mi = 0;
        unsigned long inode = 0;
        char permissions[16];
        char file_name[FILE_PATH_SIZE];
        unsigned i = 0;
        int flags = 0;

        int cnt = fscanf(file, "%lx-%lx %s %lx %lx:%lx %ld",
            &addr0, &addr1, permissions, &offset, &dev_ma, &dev_mi, &inode);
        if (cnt == 0 || cnt == EOF) break;

        for (;;) {
            int ch = fgetc(file);
            if (ch == '\n' || ch == EOF) break;
            if (i < FILE_PATH_SIZE - 1 && (ch != ' ' || i > 0)) {
                file_name[i++] = ch;
            }
        }
        file_name[i++] = 0;

        if (map->region_cnt >= map->region_max) {
            map->region_max = map->region_max < 8 ? 8 : map->region_max * 2;
            map->regions = (MemoryRegion *)loc_realloc(map->regions, sizeof(MemoryRegion) * map->region_max);
        }

        for (i = 0; permissions[i]; i++) {
            switch (permissions[i]) {
            case 'r': flags |= MM_FLAG_R; break;
            case 'w': flags |= MM_FLAG_W; break;
            case 'x': flags |= MM_FLAG_X; break;
            }
        }
        if (flags == 0) continue;

        if (map->region_cnt > 0) prev = map->regions + (map->region_cnt - 1);

        if (inode != 0 && file_name[0] && file_name[0] != '[') {
            MemoryRegion * r = map->regions + map->region_cnt++;
            memset(r, 0, sizeof(MemoryRegion));
            r->addr = addr0;
            r->size = addr1 - addr0;
            r->flags = flags;
            r->file_offs = offset;
            r->dev = MKDEV(dev_ma, dev_mi);
            r->ino = (ino_t)inode;
            r->file_name = loc_strdup(file_name);
        }
        else if (file_name[0] == 0 && prev != NULL && prev->addr + prev->size == addr0) {
            MemoryRegion * r = map->regions + map->region_cnt++;
            memset(r, 0, sizeof(MemoryRegion));
            r->bss = 1;
            r->addr = addr0;
            r->size = addr1 - addr0;
            r->flags = flags;
            r->file_offs = prev->file_offs + prev->size;
            r->dev = prev->dev;
            r->ino = prev->ino;
            r->file_name = loc_strdup(prev->file_name);
        }
    }
    fclose(file);
    return 0;
}

#if ENABLE_ContextISA
int context_get_isa(Context * ctx, ContextAddress addr, ContextISA * isa) {
    memset(isa, 0, sizeof(ContextISA));
#if defined(__i386__)
    isa->def = "386";
#elif defined(__x86_64__)
    isa->def = "X86_64";
#elif defined(__arm__)
    isa->def = "ARM";
#else
    isa->def = NULL;
#endif
#if SERVICE_Symbols
    if (get_context_isa(ctx, addr, &isa->isa, &isa->addr, &isa->size) < 0) return -1;
#endif
    return 0;
}
#endif

static Context * find_pending_attach(pid_t pid) {
    LINK * l = attach_list.next;
    while (l != &attach_list) {
        Context * c = ctxl2ctxp(l);
        if (EXT(c)->pid == pid) {
            list_remove(&c->ctxl);
            return c;
        }
        l = l->next;
    }
    return NULL;
}

static Context * find_pending_detach(pid_t pid) {
    LINK * l = detach_list.next;
    while (l != &detach_list) {
        Context * c = ctxl2ctxp(l);
        if (EXT(c)->pid == pid) {
            list_remove(&c->ctxl);
            return c;
        }
        l = l->next;
    }
    return NULL;
}

static void event_pid_exited(pid_t pid, int status, int signal) {
    Context * ctx;

    ctx = context_find_from_pid(pid, 1);
    if (ctx == NULL) {
        ctx = find_pending_attach(pid);
        if (ctx == NULL) {
            trace(LOG_EVENTS, "event: ctx not found, pid %d, exit status %d, term signal %d", pid, status, signal);
        }
        else {
            assert(ctx->ref_count == 0);
            if (EXT(ctx)->attach_callback != NULL) {
                if (status == 0) status = EINVAL;
                EXT(ctx)->attach_callback(status, ctx, EXT(ctx)->attach_data);
            }
            assert(list_is_empty(&ctx->children));
            assert(ctx->parent == NULL);
            ctx->exited = 1;
            ctx->ref_count = 1;
            context_unlock(ctx);
        }
    }
    else {
        /* Note: ctx->exiting should be 1 here. However, PTRACE_EVENT_EXIT can be lost by PTRACE because of racing
         * between PTRACE_CONT (or PTRACE_SYSCALL) and SIGTRAP/PTRACE_EVENT_EXIT. So, ctx->exiting can be 0.
         */
        Context * prs = ctx->parent;
        EXT(ctx)->waitpid_posted = 0;
        trace(LOG_EVENTS, "event: ctx %#lx, pid %d, exit status %d, term signal %d", ctx, pid, status, signal);
        assert(EXT(prs)->attach_callback == NULL);
        assert(!prs->exited);
        assert(!ctx->exited);
        ctx->exiting = 1;
        if (ctx->stopped) send_context_started_event(ctx);
        free_regs(ctx);
        send_context_exited_event(ctx);
        send_process_exited_event(prs);
    }
    assert(context_find_from_pid(pid, 1) == NULL);
    assert(find_pending_attach(pid) == NULL);
    assert(find_pending_detach(pid) == NULL);
}

#if !USE_PTRACE_SYSCALL
#   define get_syscall_id(ctx) 0
#elif defined(__x86_64__)
#   define get_syscall_id(ctx) (EXT(ctx)->regs->gp.orig_rax)
#elif defined(__i386__)
#   define get_syscall_id(ctx) (EXT(ctx)->regs->gp.orig_eax)
#else
#   error "get_syscall_id() is not implemented for CPU other then X86"
#endif

static unsigned long get_child_pid(pid_t parent_pid) {
    unsigned long child_pid = 0;
    DIR * dir = NULL;
    char task_file_name[FILE_PATH_SIZE];
    snprintf(task_file_name, sizeof(task_file_name), "/proc/%d/task", parent_pid);
    dir = opendir(task_file_name);
    if (dir == NULL) {
        trace(LOG_ALWAYS, "error: opendir(%s) failed; error %d %s",
            task_file_name, errno, errno_to_str(errno));
    }
    else {
        struct dirent * e;
        for (;;) {
            int n = 0;
            e = readdir(dir);
            if (e == NULL) break;
            n = atoi(e->d_name);
            if (n != 0 && context_find_from_pid(n, 1) == NULL) {
                child_pid = n;
                break;
            }
        }
        closedir(dir);
    }
    return child_pid;
}

static pid_t get_thread_group_id(pid_t pid) {
    pid_t res = pid;
    FILE * file = NULL;
    char file_name[FILE_PATH_SIZE];
    snprintf(file_name, sizeof(file_name), "/proc/%d/status", pid);
    if ((file = fopen(file_name, "r")) != NULL) {
        for (;;) {
            char s[256];
            if (fgets(s, sizeof(s), file) == NULL) break;
            if (strncmp(s, "Tgid:", 5) == 0) {
                char * p = s + 5;
                while (isspace(*p)) p++;
                res = atoi(p);
                break;
            }
        }
        fclose(file);
    }
    return res;
}

static Context * add_thread(Context * parent, Context * creator, pid_t pid) {
    Context * ctx;
    assert (parent != NULL);
    ctx = create_context(pid2id(pid, EXT(parent)->pid));
    EXT(ctx)->pid = pid;
    EXT(ctx)->attach_mode = EXT(parent)->attach_mode;
    EXT(ctx)->sigstop_posted = (EXT(ctx)->attach_mode & CONTEXT_ATTACH_SELF) == 0;
    EXT(ctx)->waitpid_posted = 1;
    alloc_regs(ctx);
    ctx->mem = parent;
    ctx->big_endian = parent->big_endian;
    ctx->creator = creator;
    if (creator) {
        ctx->sig_dont_stop = creator->sig_dont_stop;
        ctx->sig_dont_pass = creator->sig_dont_pass;
        creator->ref_count++;
    }
    (ctx->parent = parent)->ref_count++;
    if (EXT(parent)->detach_req) {
        ctx->exiting = 1;
        EXT(ctx)->detach_req = 1;
    }
    else if ((creator == NULL || parent != creator->parent) && (EXT(parent)->attach_mode & CONTEXT_ATTACH_NO_STOP) == 0) {
        ctx->pending_intercept = 1;
    }
    list_add_last(&ctx->cldl, &parent->children);
    link_context(ctx);
    trace(LOG_EVENTS, "event: new context 0x%x, id %s", ctx, ctx->id);
    send_context_created_event(ctx);
    return ctx;
}

static void event_pid_stopped(pid_t pid, int signal, int event, int syscall) {
    int stopped_by_exception = 0;
    unsigned long msg = 0;
    Context * ctx = NULL;
    ContextExtensionLinux * ext = NULL;

    trace(LOG_EVENTS, "event: pid %d stopped, signal %d, event %s", pid, signal, event_name(event));

    ctx = context_find_from_pid(pid, 1);

    if (ctx == NULL) {
        Context * prs = find_pending_attach(pid);
        if (prs != NULL) {
            int n;
            int cnt = 0;
            int * pids = NULL;
            assert(prs->ref_count == 0);
            assert(!EXT(prs)->detach_req);
            link_context(prs);
            send_context_created_event(prs);
            ctx = add_thread(prs, NULL, pid);
            proc_get_children(pid, &cnt, &pids);
            for (n = 0; n < cnt; n++) {
                if (pids[n] == pid) continue;
                if (ptrace(PTRACE_ATTACH, pids[n],0,0) != 0) {
                    trace(LOG_ALWAYS, "error: ptrace(PTRACE_ATTACH) failed: pid %d, error %d %s",
                    pids[n], errno, errno_to_str(errno));
                }
                add_waitpid_process(pids[n]);
            }
            if (EXT(prs)->attach_callback) {
                EXT(prs)->attach_callback(0, prs, EXT(prs)->attach_data);
                EXT(prs)->attach_callback = NULL;
                EXT(prs)->attach_data = NULL;
            }
        }
        else {
            pid_t ppid = get_thread_group_id(pid);
            Context * parent = context_find_from_pid(ppid, 0);
            if (parent != NULL) ctx = add_thread(parent, NULL, pid);
        }
    }

    if (ctx == NULL) {
        Context * prs = find_pending_detach(pid);
        if (prs != NULL) {
            /* Fork child that we don't want to attach */
            unplant_breakpoints(prs);
            assert(prs->ref_count == 1);
            prs->exited = 1;
            if (ptrace((enum __ptrace_request)PTRACE_DETACH, pid, 0, 0) < 0) {
                trace(LOG_ALWAYS, "error: ptrace(PTRACE_DETACH) failed: pid %d, error %d %s",
                    pid, errno, errno_to_str(errno));
            }
            context_unlock(prs);
        }
        detach_waitpid_process();
        return;
    }

    ext = EXT(ctx);
    assert(!ext->attach_callback);
    if (event == PTRACE_EVENT_EXIT && !ctx->stopped) {
        int ch = get_process_state(ext->pid);
        if (ch != 't' && ch != 'T') {
            /* Lost PTRACE_EVENT_EXIT event - we alredy have resumed the process */
            /* This happens when the agent resumes a process right after the process receives SIGKILL */
            ctx->exiting = 1;
            return;
        }
    }
    assert(!ctx->exited);
    assert(ext->waitpid_posted);
    if (signal == SIGSTOP) ext->sigstop_posted = 0;
    ext->stop_cnt = 0;

    if (ext->ptrace_flags == 0) {
        if (ptrace((enum __ptrace_request)PTRACE_SETOPTIONS, ext->pid, 0, PTRACE_FLAGS) < 0 && errno != ESRCH) {
            int err = errno;
            trace(LOG_ALWAYS, "error: ptrace(PTRACE_SETOPTIONS) failed: pid %d, error %d %s",
                ext->pid, err, errno_to_str(err));
        }
        else {
            ext->ptrace_flags = PTRACE_FLAGS;
        }
    }

    switch (event) {
    case PTRACE_EVENT_FORK:
    case PTRACE_EVENT_VFORK:
    case PTRACE_EVENT_CLONE:
        if (ptrace((enum __ptrace_request)PTRACE_GETEVENTMSG, pid, 0, &msg) < 0) {
            if (errno == ESRCH) {
                msg = SIGKILL;
            }
            else {
                trace(LOG_ALWAYS, "error: ptrace(PTRACE_GETEVENTMSG) failed; pid %d, error %d %s",
                    pid, errno, errno_to_str(errno));
                break;
            }
        }
        {
            Context * prs2 = NULL;
            /* Check the thread is not killed already by SIGKILL */
            if (msg == SIGKILL) {
                unsigned long child_pid = get_child_pid(EXT(ctx->parent)->pid);
                if (child_pid) {
                    msg = child_pid;
                }
                else {
                    trace(LOG_ALWAYS, "cannot trace %s - aborted by SIGKILL", event_name(event));
                    break;
                }
            }
            assert(msg != 0);
            add_waitpid_process(msg);
            if (get_thread_group_id(msg) != (pid_t)msg) {
                prs2 = ctx->parent;
            }
            else {
                prs2 = create_context(pid2id(msg, 0));
                EXT(prs2)->pid = msg;
                EXT(prs2)->attach_mode = ext->attach_mode & ~CONTEXT_ATTACH_SELF;
                prs2->mem = prs2;
                prs2->mem_access |= MEM_ACCESS_INSTRUCTION;
                prs2->mem_access |= MEM_ACCESS_DATA;
                prs2->mem_access |= MEM_ACCESS_USER;
                prs2->big_endian = ctx->parent->big_endian;
                (prs2->creator = ctx)->ref_count++;
                prs2->sig_dont_stop = ctx->sig_dont_stop;
                prs2->sig_dont_pass = ctx->sig_dont_pass;
                prs2->ref_count = 1;
                clone_breakpoints_on_process_fork(ctx, prs2);
                if ((ext->attach_mode & CONTEXT_ATTACH_CHILDREN) == 0) {
                    list_add_first(&prs2->ctxl, &detach_list);
                    break;
                }
                prs2->ref_count--;
                link_context(prs2);
                send_context_created_event(prs2);
            }
            add_thread(prs2, ctx, msg);
        }
        break;
    case PTRACE_EVENT_EXEC:
        send_context_changed_event(ctx);
        memory_map_event_mapping_changed(ctx->mem);
        break;
    case PTRACE_EVENT_EXIT:
        {
            /* SIGKILL can override PTRACE_EVENT_CLONE event with PTRACE_EVENT_EXIT */
            unsigned long child_pid = get_child_pid(EXT(ctx->parent)->pid);
            if (child_pid) {
                int state = get_process_state(child_pid);
                if (state != EOF) {
                    Context * prs = ctx->parent;
                    Context * ctx2 = create_context(pid2id(child_pid, EXT(prs)->pid));
                    EXT(ctx2)->pid = child_pid;
                    EXT(ctx2)->attach_mode = EXT(prs)->attach_mode;
                    EXT(ctx2)->detach_req = EXT(prs)->detach_req;
                    EXT(ctx2)->sigstop_posted = 1;
                    EXT(ctx2)->waitpid_posted = 1;
                    alloc_regs(ctx2);
                    ctx2->mem = prs;
                    ctx2->big_endian = prs->big_endian;
                    ctx2->sig_dont_stop = ctx->sig_dont_stop;
                    ctx2->sig_dont_pass = ctx->sig_dont_pass;
                    ctx2->exiting = 1;
                    (ctx2->creator = ctx)->ref_count++;
                    (ctx2->parent = prs)->ref_count++;
                    list_add_last(&ctx2->cldl, &prs->children);
                    link_context(ctx2);
                    trace(LOG_EVENTS, "event: new context 0x%x, id %s", ctx2, ctx2->id);
                    send_context_created_event(ctx2);
                    if (state == 't' || state == 'T') {
                        event_pid_stopped(child_pid, SIGSTOP, 0, 0);
                    }
                    add_waitpid_process(child_pid);
                }
            }
        }
        ctx->exiting = 1;
        memset(ext->regs_dirty, 0, sizeof(REG_SET));
        break;
    }

    if (signal != SIGSTOP && signal != SIGTRAP) {
        assert(signal < 32);
        ctx->pending_signals |= 1 << signal;
        if ((ctx->sig_dont_stop & (1 << signal)) == 0) {
            if (!is_intercepted(ctx)) ctx->pending_intercept = 1;
            stopped_by_exception = 1;
        }
    }

    if (ctx->stopped) {
        if (event != PTRACE_EVENT_EXEC) send_context_changed_event(ctx);
    }
    else {
        int cb_found = 0;
        ContextAddress pc0 = 0;
        ContextAddress pc1 = 0;

        ext->end_of_step = 0;
        ext->ptrace_event = event;
        ctx->signal = signal;
        ctx->stopped_by_bp = 0;
        ctx->stopped_by_cb = NULL;
        ctx->stopped_by_exception = stopped_by_exception;
        ctx->stopped = 1;

        pc0 = get_regs_PC(ctx);

#if defined(__powerpc__) || defined(__powerpc64__)
    /* Don't retrieve registers from an exiting process,
        causes kernel critical messages */
    if (event != PTRACE_EVENT_EXIT)
#endif
        memset(ext->regs_valid, 0, sizeof(REG_SET));
        pc1 = get_regs_PC(ctx);

        if (syscall) {
            if (!ext->syscall_enter) {
                ext->syscall_id = get_syscall_id(ctx);
                ext->syscall_pc = pc1;
                ext->syscall_enter = 1;
                ext->syscall_exit = 0;
                trace(LOG_EVENTS, "event: pid %d enter sys call %d, PC = %#lx",
                    pid, ext->syscall_id, ext->syscall_pc);
            }
            else {
                if (ext->syscall_pc != pc1) {
                    trace(LOG_ALWAYS, "Invalid PC at sys call exit: pid %d, sys call %d, PC %#lx, expected PC %#lx",
                        ext->pid, ext->syscall_id, pc1, ext->syscall_pc);
                }
                trace(LOG_EVENTS, "event: pid %d exit sys call %d, PC = %#lx",
                    pid, ext->syscall_id, pc1);
                switch (ext->syscall_id) {
#ifdef __NR_mmap
                case __NR_mmap:
#endif
                case __NR_munmap:
#ifdef __NR_mmap2
                case __NR_mmap2:
#endif
                case __NR_mremap:
                case __NR_remap_file_pages:
                    memory_map_event_mapping_changed(ctx->mem);
                    break;
                }
                ext->syscall_enter = 0;
                ext->syscall_exit = 1;
            }
        }
        else {
            if (!ext->syscall_enter || pc0 != pc1) {
                ext->syscall_enter = 0;
                ext->syscall_exit = 0;
                ext->syscall_id = 0;
                ext->syscall_pc = 0;
            }
            trace(LOG_EVENTS, "event: pid %d stopped at PC = %#lx", pid, pc1);
        }

        cpu_bp_on_suspend(ctx, &cb_found);
        if (signal == SIGTRAP && event == 0 && !syscall) {
            ctx->stopped_by_bp = is_breakpoint_address(ctx, pc1 + TRAP_OFFSET);
            if (ctx->stopped_by_bp) set_regs_PC(ctx, pc1 + TRAP_OFFSET);
            else ctx->stopped_by_bp = is_breakpoint_address(ctx, pc1);
            ext->end_of_step = !ctx->stopped_by_cb && !ctx->stopped_by_bp && ext->pending_step;
        }
        ext->pending_step = 0;
        send_context_stopped_event(ctx);
    }

    if (ext->detach_req && !ext->sigstop_posted && !ctx->pending_signals) {
        ext->waitpid_posted = 0;
        detach_waitpid_process();
    }
}

static void waitpid_listener(int pid, int exited, int exit_code, int signal, int event_code, int syscall, void * args) {
    if (exited) {
        event_pid_exited(pid, exit_code, signal);
    }
    else {
        event_pid_stopped(pid, signal, event_code, syscall);
    }
}

#if SERVICE_Expressions && ENABLE_ELF

static int expression_identifier_callback(Context * ctx, int frame, char * name, Value * v) {
    if (ctx == NULL) return 0;
    if (strcmp(name, "$loader_brk") == 0) {
        v->address = elf_get_debug_structure_address(ctx, NULL);
        v->type_class = TYPE_CLASS_POINTER;
        v->size = context_word_size(ctx);
        if (v->address != 0) {
            v->big_endian = ctx->big_endian;
            switch (v->size) {
            case 4: v->address += 8; break;
            case 8: v->address += 16; break;
            default: assert(0);
            }
            v->remote = 1;
        }
        else {
            set_value(v, NULL, v->size, 0);
        }
        return 1;
    }
    if (strcmp(name, "$loader_state") == 0) {
        v->address = elf_get_debug_structure_address(ctx, NULL);
        v->type_class = TYPE_CLASS_CARDINAL;
        v->size = context_word_size(ctx);
        if (v->address != 0) {
            switch (v->size) {
            case 4: v->address += 12; break;
            case 8: v->address += 24; break;
            default: assert(0);
            }
        }
        v->remote = 1;
        return 1;
    }
    return 0;
}

static void eventpoint_at_loader(Context * ctx, void * args) {
    typedef enum { RT_CONSISTENT, RT_ADD, RT_DELETE } r_state;
    ELF_File * file = NULL;
    ContextAddress addr = elf_get_debug_structure_address(ctx, &file);
    unsigned size = context_word_size(ctx);
    ContextAddress state = 0;
    ContextExtensionLinux * ext = NULL;


    assert(!is_intercepted(ctx));
    if (ctx->parent != NULL) ctx = ctx->parent;
    ext = EXT(ctx);

    if (addr != 0) {
        switch (size) {
        case 4: addr += 12; break;
        case 8: addr += 24; break;
        default: assert(0);
        }
        if (elf_read_memory_word(ctx, file, addr, &state) < 0) {
            int error = errno;
            trace(LOG_ALWAYS, "Can't read loader state flag: %d %s", error, errno_to_str(error));
            ctx->pending_intercept = 1;
            ext->loader_state = 0;
            return;
        }
    }

    switch (state) {
    case RT_CONSISTENT:
        if (ext->loader_state == RT_ADD) {
            memory_map_event_module_loaded(ctx);
        }
        else if (ext->loader_state == RT_DELETE) {
            memory_map_event_module_unloaded(ctx);
        }
        break;
    case RT_ADD:
        break;
    case RT_DELETE:
        /* TODO: need to call memory_map_event_code_section_ummapped() */
        break;
    }
    ext->loader_state = state;
}

#endif /* SERVICE_Expressions && ENABLE_ELF */

static void eventpoint_at_main(Context * ctx, void * args) {
    send_context_changed_event(ctx->mem);
    memory_map_event_mapping_changed(ctx->mem);
    if ((EXT(ctx)->attach_mode & CONTEXT_ATTACH_NO_MAIN) == 0) {
        suspend_debug_context(ctx);
    }
}

static int cmp_linux_pid(Context * ctx, const char * v) {
    ctx = context_get_group(ctx, CONTEXT_GROUP_PROCESS);
    return ctx != NULL && EXT(ctx)->pid == atoi(v);
}

static int cmp_linux_tid(Context * ctx, const char * v) {
    return ctx->parent != NULL && EXT(ctx)->pid == atoi(v);
}

static int cmp_linux_kernel_name(Context * ctx, const char * v) {
    struct utsname un;
    if (uname(&un) != 0) {
        return 0;
    }
    return (strcmp(un.sysname, v)== 0);
}

void init_contexts_sys_dep(void) {
    context_extension_offset = context_extension(sizeof(ContextExtensionLinux));
    add_waitpid_listener(waitpid_listener, NULL);
    ini_context_pid_hash();
#if SERVICE_Expressions && ENABLE_ELF
    add_identifier_callback(expression_identifier_callback);
    create_eventpoint("$loader_brk", NULL, eventpoint_at_loader, NULL);
#endif /* SERVICE_Expressions && ENABLE_ELF */
    create_eventpoint("main", NULL, eventpoint_at_main, NULL);
    add_context_query_comparator("pid", cmp_linux_pid);
    add_context_query_comparator("tid", cmp_linux_tid);
    add_context_query_comparator("KernelName", cmp_linux_kernel_name);
}

#endif  /* if ENABLE_DebugContext */
#endif /* __linux__ */
