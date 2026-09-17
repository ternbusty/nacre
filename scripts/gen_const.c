/*
 * gen_const.c — Extract kernel/libc constants for Nacre::Const.
 *
 * Compile natively or cross-compile, run, and feed the output to
 * gen_const.sh which assembles lib/Nacre/Const.pm.
 *
 *   cc -o gen_const gen_const.c && ./gen_const
 *   aarch64-linux-gnu-gcc -static -o gen_const_arm gen_const.c && qemu-aarch64 ./gen_const_arm
 */
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/sched.h>
#include <linux/prctl.h>
#include <linux/bpf.h>
#include <linux/seccomp.h>
#include <linux/capability.h>
#include <linux/close_range.h>
#include <linux/mount.h>
#include <linux/fcntl.h>
#include <signal.h>

#define P(name)  printf(#name "=%d\n", (int)(name))
#define PU(name) printf(#name "=%u\n", (unsigned)(name))
#define PX(name) printf(#name "=0x%08x\n", (unsigned)(name))

int main(void) {
    /* ── Syscall numbers ────────────────────────────────────────── */
    P(__NR_mount);
    P(__NR_umount2);
    P(__NR_pivot_root);
    P(__NR_unshare);
    P(__NR_setns);
    P(__NR_clone);
    P(__NR_clone3);
    P(__NR_prctl);
    P(__NR_capget);
    P(__NR_capset);
#ifdef __NR_mknod
    P(__NR_mknod);
#else
    printf("__NR_mknod=-1\n");
#endif
    P(__NR_mknodat);
    P(__NR_seccomp);
    P(__NR_bpf);
    P(__NR_pidfd_open);
    P(__NR_close_range);
    P(__NR_sethostname);
    P(__NR_setdomainname);
    P(__NR_setgroups);
    P(__NR_prlimit64);
    P(__NR_ioprio_set);
    P(__NR_sched_setattr);
    P(__NR_sched_setaffinity);
    P(__NR_set_mempolicy);
    P(__NR_keyctl);
    P(__NR_add_key);
    P(__NR_memfd_create);
    P(__NR_open_tree);
    P(__NR_move_mount);
    P(__NR_mount_setattr);
    P(__NR_fsopen);
    P(__NR_fsconfig);
    P(__NR_fsmount);
    P(__NR_fchown);
    P(__NR_sendmsg);
    P(__NR_recvmsg);
    P(__NR_epoll_create1);
    P(__NR_epoll_ctl);
#ifdef __NR_epoll_wait
    P(__NR_epoll_wait);
#else
    printf("__NR_epoll_wait=-1\n");
#endif
    P(__NR_inotify_init1);
    P(__NR_inotify_add_watch);
    P(__NR_waitid);

    /* ── Clone / namespace flags ────────────────────────────────── */
    PX(CLONE_NEWNS);
    PX(CLONE_NEWUTS);
    PX(CLONE_NEWIPC);
    PX(CLONE_NEWUSER);
    PX(CLONE_NEWPID);
    PX(CLONE_NEWNET);
    PX(CLONE_NEWCGROUP);
    PX(CLONE_NEWTIME);
    P(SIGCHLD);

    /* ── Mount flags (traditional) ──────────────────────────────── */
    /* MS_* are not in <linux/mount.h>; define from well-known values. */
    printf("MS_RDONLY=%d\n", 1);
    printf("MS_NOSUID=%d\n", 2);
    printf("MS_NODEV=%d\n", 4);
    printf("MS_NOEXEC=%d\n", 8);
    printf("MS_REMOUNT=%d\n", 32);
    printf("MS_NOATIME=%d\n", 1024);
    printf("MS_NODIRATIME=%d\n", 2048);
    printf("MS_BIND=%d\n", 4096);
    printf("MS_MOVE=%d\n", 8192);
    printf("MS_REC=%d\n", 16384);
    printf("MS_SILENT=%d\n", 32768);
    printf("MS_RELATIME=%u\n", 1u << 21);
    printf("MS_STRICTATIME=%u\n", 1u << 24);
    printf("MS_SLAVE=%u\n", 1u << 19);
    printf("MS_SHARED=%u\n", 1u << 20);
    printf("MS_PRIVATE=%u\n", 1u << 18);
    printf("MS_UNBINDABLE=%u\n", 1u << 17);
    printf("MNT_DETACH=%d\n", 2);
    printf("MNT_FORCE=%d\n", 1);

    /* ── prctl ──────────────────────────────────────────────────── */
    P(PR_SET_NO_NEW_PRIVS);
    P(PR_CAPBSET_READ);
    P(PR_CAPBSET_DROP);
    P(PR_SET_KEEPCAPS);
    P(PR_CAP_AMBIENT);
    P(PR_CAP_AMBIENT_RAISE);
    P(PR_CAP_AMBIENT_LOWER);
    P(PR_CAP_AMBIENT_CLEAR_ALL);
    P(PR_SET_CHILD_SUBREAPER);
    P(PR_SET_PDEATHSIG);
    P(PR_SET_DUMPABLE);
    P(PR_SET_NAME);

    /* ── Capabilities ───────────────────────────────────────────── */
    PX(_LINUX_CAPABILITY_VERSION_3);
    P(_LINUX_CAPABILITY_U32S_3);
    PX(VFS_CAP_REVISION_2);

    P(CAP_CHOWN);
    P(CAP_DAC_OVERRIDE);
    P(CAP_DAC_READ_SEARCH);
    P(CAP_FOWNER);
    P(CAP_FSETID);
    P(CAP_KILL);
    P(CAP_SETGID);
    P(CAP_SETUID);
    P(CAP_SETPCAP);
    P(CAP_LINUX_IMMUTABLE);
    P(CAP_NET_BIND_SERVICE);
    P(CAP_NET_BROADCAST);
    P(CAP_NET_ADMIN);
    P(CAP_NET_RAW);
    P(CAP_IPC_LOCK);
    P(CAP_IPC_OWNER);
    P(CAP_SYS_MODULE);
    P(CAP_SYS_RAWIO);
    P(CAP_SYS_CHROOT);
    P(CAP_SYS_PTRACE);
    P(CAP_SYS_PACCT);
    P(CAP_SYS_ADMIN);
    P(CAP_SYS_BOOT);
    P(CAP_SYS_NICE);
    P(CAP_SYS_RESOURCE);
    P(CAP_SYS_TIME);
    P(CAP_SYS_TTY_CONFIG);
    P(CAP_MKNOD);
    P(CAP_LEASE);
    P(CAP_AUDIT_WRITE);
    P(CAP_AUDIT_CONTROL);
    P(CAP_SETFCAP);
    P(CAP_MAC_OVERRIDE);
    P(CAP_MAC_ADMIN);
    P(CAP_SYSLOG);
    P(CAP_WAKE_ALARM);
    P(CAP_BLOCK_SUSPEND);
    P(CAP_AUDIT_READ);
    P(CAP_PERFMON);
    P(CAP_BPF);
    P(CAP_CHECKPOINT_RESTORE);

    /* ── seccomp ────────────────────────────────────────────────── */
    P(SECCOMP_SET_MODE_FILTER);
    PX(SECCOMP_FILTER_FLAG_TSYNC);
    PX(SECCOMP_FILTER_FLAG_LOG);
    PX(SECCOMP_FILTER_FLAG_NEW_LISTENER);
    PX(SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV);

    /* ── BPF (cgroup device) ────────────────────────────────────── */
    P(BPF_PROG_LOAD);
    P(BPF_PROG_ATTACH);
    P(BPF_PROG_DETACH);
    P(BPF_PROG_QUERY);
    P(BPF_CGROUP_DEVICE);
    PX(BPF_F_ALLOW_MULTI);
    P(BPF_PROG_TYPE_CGROUP_DEVICE);

    /* ── close_range ────────────────────────────────────────────── */
    PX(CLOSE_RANGE_CLOEXEC);

    /* ── New mount API (kernel 5.2+) ────────────────────────────── */
    PX(AT_RECURSIVE);
    PX(AT_EMPTY_PATH);
    PX(MOUNT_ATTR_RDONLY);
    PX(MOUNT_ATTR_NOSUID);
    PX(MOUNT_ATTR_NODEV);
    PX(MOUNT_ATTR_NOEXEC);
    PX(MOUNT_ATTR_NOATIME);
    PX(MOUNT_ATTR_STRICTATIME);
    PX(MOUNT_ATTR_NODIRATIME);
    PX(MOUNT_ATTR__ATIME);
    PX(MOUNT_ATTR_NOSYMFOLLOW);
    PX(MOUNT_ATTR_IDMAP);
    PX(OPEN_TREE_CLONE);
    PX(OPEN_TREE_CLOEXEC);
    PX(MOVE_MOUNT_F_EMPTY_PATH);

    /* ── PTY / terminal ioctls ──────────────────────────────────── */
    PX(TIOCGPTN);
    PX(TIOCSPTLCK);
    PX(TIOCSCTTY);
    PX(TIOCSWINSZ);
    PX(TIOCGWINSZ);

    /* ── fcntl extras ───────────────────────────────────────────── */
    PX(O_CLOEXEC);
    PX(O_PATH);

    return 0;
}
