package Nacre::Const;
use strict;
use warnings;
use Exporter 'import';

# ═══════════════════════════════════════════════════════════════════════
# Fcntl extras (may not be available on all systems)
# ═══════════════════════════════════════════════════════════════════════
use constant O_CLOEXEC => 0o2000000;
use constant O_PATH    => 0o10000000;

# ═══════════════════════════════════════════════════════════════════════
# Syscall numbers (architecture-dependent)
# ═══════════════════════════════════════════════════════════════════════
BEGIN {
    require Config;
    my $a = $Config::Config{archname} // '';
    my $x86 = ($a =~ /x86_64|amd64/i) ? 1 : 0;

    if ($x86) {
        eval 'package Nacre::Const; use constant {
            SYS_mount             => 165,
            SYS_umount2           => 166,
            SYS_pivot_root        => 155,
            SYS_unshare           => 272,
            SYS_setns             => 308,
            SYS_clone             => 56,
            SYS_clone3            => 435,
            SYS_prctl             => 157,
            SYS_capget            => 125,
            SYS_capset            => 126,
            SYS_mknod             => 133,
            SYS_mknodat           => 259,
            SYS_seccomp           => 317,
            SYS_bpf               => 321,
            SYS_pidfd_open        => 434,
            SYS_close_range       => 436,
            SYS_sethostname       => 170,
            SYS_setdomainname     => 171,
            SYS_setgroups         => 116,
            SYS_prlimit64         => 302,
            SYS_ioprio_set        => 251,
            SYS_sched_setattr     => 314,
            SYS_sched_setaffinity => 203,
            SYS_set_mempolicy     => 238,
            SYS_keyctl            => 250,
            SYS_add_key           => 248,
            SYS_memfd_create      => 319,
            SYS_open_tree         => 428,
            SYS_move_mount        => 429,
            SYS_mount_setattr     => 442,
            SYS_fsopen            => 430,
            SYS_fsconfig          => 431,
            SYS_fsmount           => 432,
            SYS_fchown            => 93,
            SYS_sendmsg           => 46,
            SYS_recvmsg           => 47,
            SYS_epoll_create1     => 291,
            SYS_epoll_ctl         => 233,
            SYS_epoll_wait        => 232,
            SYS_inotify_init1     => 294,
            SYS_inotify_add_watch => 254,
            SYS_waitid            => 247,
        }; 1' or die $@;
    } else {
        eval 'package Nacre::Const; use constant {
            SYS_mount             => 40,
            SYS_umount2           => 39,
            SYS_pivot_root        => 41,
            SYS_unshare           => 97,
            SYS_setns             => 268,
            SYS_clone             => 220,
            SYS_clone3            => 435,
            SYS_prctl             => 167,
            SYS_capget            => 90,
            SYS_capset            => 91,
            SYS_mknod             => -1,
            SYS_mknodat           => 33,
            SYS_seccomp           => 277,
            SYS_bpf               => 280,
            SYS_pidfd_open        => 434,
            SYS_close_range       => 436,
            SYS_sethostname       => 161,
            SYS_setdomainname     => 162,
            SYS_setgroups         => 159,
            SYS_prlimit64         => 261,
            SYS_ioprio_set        => 30,
            SYS_sched_setattr     => 274,
            SYS_sched_setaffinity => 122,
            SYS_set_mempolicy     => 237,
            SYS_keyctl            => 219,
            SYS_add_key           => 217,
            SYS_memfd_create      => 279,
            SYS_open_tree         => 428,
            SYS_move_mount        => 429,
            SYS_mount_setattr     => 442,
            SYS_fsopen            => 430,
            SYS_fsconfig          => 431,
            SYS_fsmount           => 432,
            SYS_fchown            => 55,
            SYS_sendmsg           => 211,
            SYS_recvmsg           => 212,
            SYS_epoll_create1     => 20,
            SYS_epoll_ctl         => 21,
            SYS_epoll_wait        => -1,
            SYS_inotify_init1     => 26,
            SYS_inotify_add_watch => 27,
            SYS_waitid            => 95,
        }; 1' or die $@;
    }
}

# ═══════════════════════════════════════════════════════════════════════
# Clone / Namespace flags
# ═══════════════════════════════════════════════════════════════════════
use constant {
    CLONE_NEWNS     => 0x00020000,
    CLONE_NEWUTS    => 0x04000000,
    CLONE_NEWIPC    => 0x08000000,
    CLONE_NEWUSER   => 0x10000000,
    CLONE_NEWPID    => 0x20000000,
    CLONE_NEWNET    => 0x40000000,
    CLONE_NEWCGROUP => 0x02000000,
    CLONE_NEWTIME   => 0x00000080,
    SIGCHLD         => 17,
};

# ═══════════════════════════════════════════════════════════════════════
# Mount flags
# ═══════════════════════════════════════════════════════════════════════
use constant {
    MS_RDONLY       => 1,
    MS_NOSUID      => 2,
    MS_NODEV        => 4,
    MS_NOEXEC      => 8,
    MS_REMOUNT     => 32,
    MS_NOATIME     => 1024,
    MS_NODIRATIME  => 2048,
    MS_BIND        => 4096,
    MS_MOVE        => 8192,
    MS_REC         => 16384,
    MS_SILENT      => 32768,
    MS_RELATIME    => (1 << 21),
    MS_STRICTATIME => (1 << 24),
    MS_SLAVE       => (1 << 19),
    MS_SHARED      => (1 << 20),
    MS_PRIVATE     => (1 << 18),
    MS_UNBINDABLE  => (1 << 17),
    MNT_DETACH     => 2,
    MNT_FORCE      => 1,
};

# ═══════════════════════════════════════════════════════════════════════
# prctl constants
# ═══════════════════════════════════════════════════════════════════════
use constant {
    PR_SET_NO_NEW_PRIVS => 38,
    PR_CAPBSET_READ     => 23,
    PR_CAPBSET_DROP     => 24,
    PR_SET_KEEPCAPS     => 8,
    PR_CAP_AMBIENT      => 47,
    PR_CAP_AMBIENT_RAISE   => 2,
    PR_CAP_AMBIENT_LOWER   => 3,
    PR_CAP_AMBIENT_CLEAR_ALL => 4,
    PR_SET_CHILD_SUBREAPER  => 36,
    PR_SET_PDEATHSIG        => 1,
    PR_SET_DUMPABLE         => 4,
    PR_SET_NAME             => 15,
};

# ═══════════════════════════════════════════════════════════════════════
# Capabilities
# ═══════════════════════════════════════════════════════════════════════
our @CAP_NAMES = qw(
    CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER CAP_FSETID
    CAP_KILL CAP_SETGID CAP_SETUID CAP_SETPCAP CAP_LINUX_IMMUTABLE
    CAP_NET_BIND_SERVICE CAP_NET_BROADCAST CAP_NET_ADMIN CAP_NET_RAW
    CAP_IPC_LOCK CAP_IPC_OWNER CAP_SYS_MODULE CAP_SYS_RAWIO CAP_SYS_CHROOT
    CAP_SYS_PTRACE CAP_SYS_PACCT CAP_SYS_ADMIN CAP_SYS_BOOT CAP_SYS_NICE
    CAP_SYS_RESOURCE CAP_SYS_TIME CAP_SYS_TTY_CONFIG CAP_MKNOD CAP_LEASE
    CAP_AUDIT_WRITE CAP_AUDIT_CONTROL CAP_SETFCAP CAP_MAC_OVERRIDE
    CAP_MAC_ADMIN CAP_SYSLOG CAP_WAKE_ALARM CAP_BLOCK_SUSPEND
    CAP_AUDIT_READ CAP_PERFMON CAP_BPF CAP_CHECKPOINT_RESTORE
);
our %CAP_NUM;
for my $i (0..$#CAP_NAMES) { $CAP_NUM{$CAP_NAMES[$i]} = $i; }

use constant {
    _LINUX_CAPABILITY_VERSION_3 => 0x20080522,
    _LINUX_CAPABILITY_U32S_3   => 2,
    VFS_CAP_REVISION_2         => 0x02000000,
};

# ═══════════════════════════════════════════════════════════════════════
# seccomp
# ═══════════════════════════════════════════════════════════════════════
use constant {
    SECCOMP_SET_MODE_FILTER => 1,
    SECCOMP_FILTER_FLAG_TSYNC     => (1 << 0),
    SECCOMP_FILTER_FLAG_LOG       => (1 << 1),
    SECCOMP_FILTER_FLAG_NEW_LISTENER => (1 << 3),
    SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV => (1 << 5),
};

# ═══════════════════════════════════════════════════════════════════════
# BPF (cgroup device)
# ═══════════════════════════════════════════════════════════════════════
use constant {
    BPF_PROG_LOAD   => 5,
    BPF_PROG_ATTACH => 8,
    BPF_CGROUP_DEVICE => 9,
    BPF_F_ALLOW_MULTI => (1 << 1),
    BPF_PROG_TYPE_CGROUP_DEVICE => 15,
};

# ═══════════════════════════════════════════════════════════════════════
# close_range
# ═══════════════════════════════════════════════════════════════════════
use constant {
    CLOSE_RANGE_CLOEXEC => (1 << 2),
};

# ═══════════════════════════════════════════════════════════════════════
# mount_setattr flags (kernel 5.12+)
# ═══════════════════════════════════════════════════════════════════════
use constant {
    AT_RECURSIVE        => 0x8000,
    AT_EMPTY_PATH       => 0x1000,
    MOUNT_ATTR_RDONLY   => 0x00000001,
    MOUNT_ATTR_NOSUID   => 0x00000002,
    MOUNT_ATTR_NODEV    => 0x00000004,
    MOUNT_ATTR_NOEXEC   => 0x00000008,
    MOUNT_ATTR_NOATIME     => 0x00000010,
    MOUNT_ATTR_STRICTATIME => 0x00000020,
    MOUNT_ATTR_NODIRATIME  => 0x00000080,
    MOUNT_ATTR__ATIME      => 0x00000070,
    MOUNT_ATTR_NOSYMFOLLOW => 0x00200000,
    MOUNT_ATTR_IDMAP       => 0x00100000,
    OPEN_TREE_CLONE     => 1,
    OPEN_TREE_CLOEXEC   => 0x80000,
    MOVE_MOUNT_F_EMPTY_PATH => 0x00000004,
};

# ═══════════════════════════════════════════════════════════════════════
# PTY / terminal ioctls
# ═══════════════════════════════════════════════════════════════════════
use constant {
    TIOCGPTN   => 0x80045430,
    TIOCSPTLCK => 0x40045431,
    TIOCSCTTY  => 0x5480,
    TIOCSWINSZ => 0x5414,
    TIOCGWINSZ => 0x5413,
};

# ═══════════════════════════════════════════════════════════════════════
# Signals (name -> number)
# ═══════════════════════════════════════════════════════════════════════
use Config;
our %SIG_NUM;
{
    my @names = split ' ', $Config{sig_name} // '';
    my @nums  = split ' ', $Config{sig_num}  // '';
    if (!@names) {
        %SIG_NUM = (
            HUP => 1, INT => 2, QUIT => 3, ILL => 4, TRAP => 5, ABRT => 6,
            BUS => 7, FPE => 8, KILL => 9, USR1 => 10, SEGV => 11, USR2 => 12,
            PIPE => 13, ALRM => 14, TERM => 15, STKFLT => 16, CHLD => 17,
            CONT => 18, STOP => 19, TSTP => 20, TTIN => 21, TTOU => 22,
            URG => 23, XCPU => 24, XFSZ => 25, VTALRM => 26, PROF => 27,
            WINCH => 28, IO => 29, PWR => 30, SYS => 31,
        );
    } else {
        for my $i (0..$#names) {
            $SIG_NUM{$names[$i]} = $nums[$i] if $names[$i] && $nums[$i];
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════
# OCI namespace type -> clone flag & proc name
# ═══════════════════════════════════════════════════════════════════════
our %NS_MAP = (
    pid     => { flag => CLONE_NEWPID,    proc => 'pid'     },
    network => { flag => CLONE_NEWNET,    proc => 'net'     },
    mount   => { flag => CLONE_NEWNS,     proc => 'mnt'     },
    ipc     => { flag => CLONE_NEWIPC,    proc => 'ipc'     },
    uts     => { flag => CLONE_NEWUTS,    proc => 'uts'     },
    user    => { flag => CLONE_NEWUSER,   proc => 'user'    },
    cgroup  => { flag => CLONE_NEWCGROUP, proc => 'cgroup'  },
    time    => { flag => CLONE_NEWTIME,   proc => 'time_for_children' },
);

# ═══════════════════════════════════════════════════════════════════════
# Exports
# ═══════════════════════════════════════════════════════════════════════
our @EXPORT = qw(
    O_CLOEXEC O_PATH

    SYS_mount SYS_umount2 SYS_pivot_root SYS_unshare SYS_setns
    SYS_clone SYS_clone3 SYS_prctl SYS_capget SYS_capset
    SYS_mknod SYS_mknodat SYS_seccomp SYS_bpf SYS_pidfd_open
    SYS_close_range SYS_sethostname SYS_setdomainname SYS_setgroups
    SYS_prlimit64 SYS_ioprio_set SYS_sched_setattr SYS_sched_setaffinity
    SYS_set_mempolicy SYS_keyctl SYS_add_key SYS_memfd_create
    SYS_open_tree SYS_move_mount SYS_mount_setattr
    SYS_fsopen SYS_fsconfig SYS_fsmount SYS_fchown
    SYS_sendmsg SYS_recvmsg SYS_epoll_create1 SYS_epoll_ctl
    SYS_epoll_wait SYS_inotify_init1 SYS_inotify_add_watch SYS_waitid

    CLONE_NEWNS CLONE_NEWUTS CLONE_NEWIPC CLONE_NEWUSER CLONE_NEWPID
    CLONE_NEWNET CLONE_NEWCGROUP CLONE_NEWTIME SIGCHLD

    MS_RDONLY MS_NOSUID MS_NODEV MS_NOEXEC MS_REMOUNT
    MS_NOATIME MS_NODIRATIME MS_BIND MS_MOVE MS_REC MS_SILENT
    MS_RELATIME MS_STRICTATIME MS_SLAVE MS_SHARED MS_PRIVATE
    MS_UNBINDABLE MNT_DETACH MNT_FORCE

    PR_SET_NO_NEW_PRIVS PR_CAPBSET_READ PR_CAPBSET_DROP PR_SET_KEEPCAPS
    PR_CAP_AMBIENT PR_CAP_AMBIENT_RAISE PR_CAP_AMBIENT_LOWER
    PR_CAP_AMBIENT_CLEAR_ALL PR_SET_CHILD_SUBREAPER PR_SET_PDEATHSIG
    PR_SET_DUMPABLE PR_SET_NAME

    @CAP_NAMES %CAP_NUM
    _LINUX_CAPABILITY_VERSION_3 _LINUX_CAPABILITY_U32S_3 VFS_CAP_REVISION_2

    SECCOMP_SET_MODE_FILTER SECCOMP_FILTER_FLAG_TSYNC
    SECCOMP_FILTER_FLAG_LOG SECCOMP_FILTER_FLAG_NEW_LISTENER
    SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV

    BPF_PROG_LOAD BPF_PROG_ATTACH BPF_CGROUP_DEVICE
    BPF_F_ALLOW_MULTI BPF_PROG_TYPE_CGROUP_DEVICE

    CLOSE_RANGE_CLOEXEC

    AT_RECURSIVE AT_EMPTY_PATH
    MOUNT_ATTR_RDONLY MOUNT_ATTR_NOSUID MOUNT_ATTR_NODEV MOUNT_ATTR_NOEXEC
    MOUNT_ATTR_NOATIME MOUNT_ATTR_STRICTATIME MOUNT_ATTR_NODIRATIME
    MOUNT_ATTR__ATIME MOUNT_ATTR_NOSYMFOLLOW MOUNT_ATTR_IDMAP
    OPEN_TREE_CLONE OPEN_TREE_CLOEXEC MOVE_MOUNT_F_EMPTY_PATH

    TIOCGPTN TIOCSPTLCK TIOCSCTTY TIOCSWINSZ TIOCGWINSZ

    %SIG_NUM %NS_MAP
);

1;
