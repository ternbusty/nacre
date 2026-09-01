package Nacre::Seccomp;
use strict;
use warnings;
use Exporter 'import';
use Nacre::Const;
use Nacre::Util;

# ═══════════════════════════════════════════════════════════════════════
# Seccomp (via dlopen/dlsym of libseccomp, with BPF fallback)
# ═══════════════════════════════════════════════════════════════════════

my $SECCOMP_AVAILABLE = 0;
my $LIBSECCOMP;

sub init_libseccomp {
    eval {
        require DynaLoader;
        $LIBSECCOMP = DynaLoader::dl_load_file('/usr/lib/x86_64-linux-gnu/libseccomp.so.2', 0);
        $SECCOMP_AVAILABLE = 1 if $LIBSECCOMP;
    };
}

# Seccomp actions
use constant {
    SCMP_ACT_KILL         => 0x00000000,
    SCMP_ACT_KILL_PROCESS => 0x80000000,
    SCMP_ACT_TRAP         => 0x00030000,
    SCMP_ACT_NOTIFY       => 0x7fc00000,
    SCMP_ACT_LOG          => 0x7ffc0000,
    SCMP_ACT_ALLOW        => 0x7fff0000,
    SCMP_ACT_ERRNO_BASE   => 0x00050000,
};

sub apply_seccomp_raw {
    my ($spec) = @_;
    my $seccomp = $spec->{linux}{seccomp} // return undef;

    # If FFI::Platypus is available, use it
    if (eval { require FFI::Platypus; 1 }) {
        return _apply_seccomp_ffi($spec);
    }

    # Fallback: build and load BPF program directly via seccomp(2)
    return _apply_seccomp_minimal($seccomp);
}

sub _apply_seccomp_ffi {
    my ($spec) = @_;
    my $seccomp = $spec->{linux}{seccomp} // return;

    require FFI::Platypus;
    my $ffi = FFI::Platypus->new(api => 2);
    $ffi->lib('/usr/lib/x86_64-linux-gnu/libseccomp.so.2');

    $ffi->attach('seccomp_init'           => ['uint32'] => 'opaque');
    $ffi->attach('seccomp_arch_add'       => ['opaque', 'uint32'] => 'int');
    $ffi->attach('seccomp_rule_add'       => ['opaque', 'uint32', 'int', 'uint'] => 'int', sub {
        my ($xsub, @args) = @_;
        return $xsub->(@args);
    });
    $ffi->attach('seccomp_syscall_resolve_name' => ['string'] => 'int');
    $ffi->attach('seccomp_load'           => ['opaque'] => 'int');
    $ffi->attach('seccomp_release'        => ['opaque'] => 'void');
    $ffi->attach('seccomp_export_bpf'     => ['opaque', 'int'] => 'int');
    $ffi->attach('seccomp_attr_set'       => ['opaque', 'uint32', 'uint32'] => 'int');

    my %action_map = (
        SCMP_ACT_KILL         => SCMP_ACT_KILL,
        SCMP_ACT_KILL_PROCESS => SCMP_ACT_KILL_PROCESS,
        SCMP_ACT_TRAP         => SCMP_ACT_TRAP,
        SCMP_ACT_NOTIFY       => SCMP_ACT_NOTIFY,
        SCMP_ACT_LOG          => SCMP_ACT_LOG,
        SCMP_ACT_ALLOW        => SCMP_ACT_ALLOW,
    );

    my $default_action_str = $seccomp->{defaultAction} // 'SCMP_ACT_ALLOW';
    my $default_errno_ret_ffi = $seccomp->{defaultErrnoRet};
    my $default_action;
    if ($default_action_str =~ /^SCMP_ACT_ERRNO\((\d+)\)$/) {
        $default_action = SCMP_ACT_ERRNO_BASE | ($1 & 0xffff);
    } elsif ($default_action_str eq 'SCMP_ACT_ERRNO') {
        my $ev = $default_errno_ret_ffi // 1;
        $default_action = SCMP_ACT_ERRNO_BASE | ($ev & 0xffff);
    } else {
        $default_action = $action_map{$default_action_str}
            // fatal("unknown seccomp action: $default_action_str");
    }

    my $ctx = seccomp_init($default_action)
        or fatal("seccomp_init failed");

    seccomp_attr_set($ctx, 2, 0);  # SCMP_FLTATR_CTL_NNP = 2

    my %arch_map = (
        SCMP_ARCH_X86_64  => 0xc000003e,
        SCMP_ARCH_X86     => 0x40000003,
        SCMP_ARCH_AARCH64 => 0xc00000b7,
        SCMP_ARCH_ARM     => 0x40000028,
    );

    for my $arch (@{$seccomp->{architectures} // []}) {
        my $arch_val = $arch_map{$arch} // next;
        seccomp_arch_add($ctx, $arch_val);
    }

    my $ffi_default_errno_ret = $seccomp->{defaultErrnoRet};

    for my $rule (@{$seccomp->{syscalls} // []}) {
        my $action_str = $rule->{action} // $default_action_str;
        my $action;
        if ($action_str eq 'SCMP_ACT_ERRNO') {
            my $ev = $rule->{errnoRet} // $ffi_default_errno_ret // 1;
            $action = SCMP_ACT_ERRNO_BASE | ($ev & 0xffff);
        } elsif ($action_str =~ /^SCMP_ACT_ERRNO\((\d+)\)$/) {
            $action = SCMP_ACT_ERRNO_BASE | ($1 & 0xffff);
        } else {
            $action = $action_map{$action_str} // next;
        }

        for my $name (@{$rule->{names} // []}) {
            my $nr = seccomp_syscall_resolve_name($name);
            next if $nr < 0;
            seccomp_rule_add($ctx, $action, $nr, 0);
        }
    }

    pipe(my $rd, my $wr) or fatal("pipe for seccomp export: $!");
    my $fd = fileno($wr);
    my $ret = seccomp_export_bpf($ctx, $fd);
    close $wr;

    if ($ret == 0) {
        local $/;
        my $bpf_prog = <$rd>;
        close $rd;

        if (defined $bpf_prog && length $bpf_prog >= 8) {
            my $filter_count = length($bpf_prog) / 8;
            my $sock_fprog = pack('S x![P] P', $filter_count, unpack('Q', pack('P', $bpf_prog)));

            my $nr_sec = SYS_seccomp + 0;
            my $op     = SECCOMP_SET_MODE_FILTER + 0;
            my %ffi_flag_map = (
                SECCOMP_FILTER_FLAG_TSYNC     => SECCOMP_FILTER_FLAG_TSYNC,
                SECCOMP_FILTER_FLAG_LOG       => SECCOMP_FILTER_FLAG_LOG,
                SECCOMP_FILTER_FLAG_SPEC_ALLOW => (1 << 2),
                SECCOMP_FILTER_FLAG_NEW_LISTENER => SECCOMP_FILTER_FLAG_NEW_LISTENER,
                SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV => SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV,
            );
            my $fl = 0;
            my $ffi_has_flags_field = exists $seccomp->{flags};
            for my $fn (@{$seccomp->{flags} // []}) {
                $fl |= ($ffi_flag_map{$fn} // 0);
            }
            if (!$ffi_has_flags_field) {
                $fl |= (1 << 2);  # SECCOMP_FILTER_FLAG_SPEC_ALLOW
            }
            log_debug("seccomp filter flags: $fl");
            $fl += 0;
            my $sec_ret = syscall($nr_sec, $op, $fl, $sock_fprog);
            if ($sec_ret != 0) {
                seccomp_release($ctx);
                fatal("seccomp: BPF load failed via FFI (errno=$!)");
            }
        }
    } else {
        close $rd;
        my $lr = seccomp_load($ctx);
        if ($lr != 0) {
            seccomp_release($ctx);
            fatal("seccomp: seccomp_load failed (ret=$lr)");
        }
    }

    seccomp_release($ctx);
}

my %_SYSCALL_NR;

sub _init_syscall_table {
    return if %_SYSCALL_NR;
    require Config;
    my $arch = $Config::Config{archname} // '';

    my @hdrs;
    if ($arch =~ /x86_64|amd64/i) {
        @hdrs = (
            '/usr/include/x86_64-linux-gnu/asm/unistd_64.h',
            '/usr/include/asm/unistd_64.h',
        );
    } elsif ($arch =~ /aarch64|arm64/i) {
        @hdrs = (
            '/usr/include/aarch64-linux-gnu/asm/unistd.h',
            '/usr/include/asm-generic/unistd.h',
        );
    } else {
        @hdrs = ('/usr/include/asm/unistd.h');
    }

    for my $hdr (@hdrs) {
        open my $fh, '<', $hdr or next;
        while (<$fh>) {
            $_SYSCALL_NR{$1} = $2 + 0
                if /^\s*#\s*define\s+__NR(?:3264)?_(\w+)\s+(\d+)/;
        }
        close $fh;
        last if %_SYSCALL_NR;
    }

    # Builtin fallback for x86_64
    if (!%_SYSCALL_NR && $arch =~ /x86_64|amd64/i) {
        %_SYSCALL_NR = (
            read=>0,write=>1,open=>2,close=>3,stat=>4,fstat=>5,lstat=>6,poll=>7,
            lseek=>8,mmap=>9,mprotect=>10,munmap=>11,brk=>12,rt_sigaction=>13,
            rt_sigprocmask=>14,rt_sigreturn=>15,ioctl=>16,pread64=>17,pwrite64=>18,
            readv=>19,writev=>20,access=>21,pipe=>22,select=>23,sched_yield=>24,
            mremap=>25,msync=>26,mincore=>27,madvise=>28,shmget=>29,shmat=>30,
            shmctl=>31,dup=>32,dup2=>33,pause=>34,nanosleep=>35,getitimer=>36,
            alarm=>37,setitimer=>38,getpid=>39,sendfile=>40,socket=>41,connect=>42,
            accept=>43,sendto=>44,recvfrom=>45,sendmsg=>46,recvmsg=>47,shutdown=>48,
            bind=>49,listen=>50,getsockname=>51,getpeername=>52,socketpair=>53,
            setsockopt=>54,getsockopt=>55,clone=>56,fork=>57,vfork=>58,execve=>59,
            exit=>60,wait4=>61,kill=>62,uname=>63,semget=>64,semop=>65,semctl=>66,
            shmdt=>67,msgget=>68,msgsnd=>69,msgrcv=>70,msgctl=>71,fcntl=>72,
            flock=>73,fsync=>74,fdatasync=>75,truncate=>76,ftruncate=>77,
            getdents=>78,getcwd=>79,chdir=>80,fchdir=>81,rename=>82,mkdir=>83,
            rmdir=>84,creat=>85,link=>86,unlink=>87,symlink=>88,readlink=>89,
            chmod=>90,fchmod=>91,chown=>92,fchown=>93,lchown=>94,umask=>95,
            gettimeofday=>96,getrlimit=>97,getrusage=>98,sysinfo=>99,times=>100,
            ptrace=>101,getuid=>102,syslog=>103,getgid=>104,setuid=>105,setgid=>106,
            geteuid=>107,getegid=>108,setpgid=>109,getppid=>110,getpgrp=>111,
            setsid=>112,setreuid=>113,setregid=>114,getgroups=>115,setgroups=>116,
            setresuid=>117,getresuid=>118,setresgid=>119,getresgid=>120,getpgid=>121,
            setfsuid=>122,setfsgid=>123,getsid=>124,capget=>125,capset=>126,
            rt_sigpending=>127,rt_sigtimedwait=>128,rt_sigqueueinfo=>129,
            rt_sigsuspend=>130,sigaltstack=>131,utime=>132,mknod=>133,uselib=>134,
            personality=>135,ustat=>136,statfs=>137,fstatfs=>138,sysfs=>139,
            getpriority=>140,setpriority=>141,sched_setparam=>142,sched_getparam=>143,
            sched_setscheduler=>144,sched_getscheduler=>145,sched_get_priority_max=>146,
            sched_get_priority_min=>147,sched_rr_get_interval=>148,mlock=>149,
            munlock=>150,mlockall=>151,munlockall=>152,vhangup=>153,modify_ldt=>154,
            pivot_root=>155,_sysctl=>156,prctl=>157,arch_prctl=>158,adjtimex=>159,
            setrlimit=>160,chroot=>161,sync=>162,acct=>163,settimeofday=>164,
            mount=>165,umount2=>166,swapon=>167,swapoff=>168,reboot=>169,
            sethostname=>170,setdomainname=>171,iopl=>172,ioperm=>173,
            create_module=>174,init_module=>175,delete_module=>176,
            get_kernel_syms=>177,query_module=>178,quotactl=>179,nfsservctl=>180,
            getpmsg=>181,putpmsg=>182,afs_syscall=>183,tuxcall=>184,security=>185,
            gettid=>186,readahead=>187,setxattr=>188,lsetxattr=>189,fsetxattr=>190,
            getxattr=>191,lgetxattr=>192,fgetxattr=>193,listxattr=>194,
            llistxattr=>195,flistxattr=>196,removexattr=>197,lremovexattr=>198,
            fremovexattr=>199,tkill=>200,time=>201,futex=>202,
            sched_setaffinity=>203,sched_getaffinity=>204,set_thread_area=>205,
            io_setup=>206,io_destroy=>207,io_getevents=>208,io_submit=>209,
            io_cancel=>210,get_thread_area=>211,lookup_dcookie=>212,
            epoll_create=>213,epoll_ctl_old=>214,epoll_wait_old=>215,
            remap_file_pages=>216,getdents64=>217,set_tid_address=>218,
            restart_syscall=>219,semtimedop=>220,fadvise64=>221,timer_create=>222,
            timer_settime=>223,timer_gettime=>224,timer_getoverrun=>225,
            timer_delete=>226,clock_settime=>227,clock_gettime=>228,clock_getres=>229,
            clock_nanosleep=>230,exit_group=>231,epoll_wait=>232,epoll_ctl=>233,
            tgkill=>234,utimes=>235,vserver=>236,mbind=>237,set_mempolicy=>238,
            get_mempolicy=>239,mq_open=>240,mq_unlink=>241,mq_timedsend=>242,
            mq_timedreceive=>243,mq_notify=>244,mq_getsetattr=>245,kexec_load=>246,
            waitid=>247,add_key=>248,request_key=>249,keyctl=>250,ioprio_set=>251,
            ioprio_get=>252,inotify_init=>253,inotify_add_watch=>254,
            inotify_rm_watch=>255,migrate_pages=>256,openat=>257,mkdirat=>258,
            mknodat=>259,fchownat=>260,futimesat=>261,newfstatat=>262,unlinkat=>263,
            renameat=>264,linkat=>265,symlinkat=>266,readlinkat=>267,fchmodat=>268,
            faccessat=>269,pselect6=>270,ppoll=>271,unshare=>272,
            set_robust_list=>273,get_robust_list=>274,splice=>275,tee=>276,
            sync_file_range=>277,vmsplice=>278,move_pages=>279,utimensat=>280,
            epoll_pwait=>281,signalfd=>282,timerfd_create=>283,eventfd=>284,
            fallocate=>285,timerfd_settime=>286,timerfd_gettime=>287,accept4=>288,
            signalfd4=>289,eventfd2=>290,epoll_create1=>291,dup3=>292,pipe2=>293,
            inotify_init1=>294,preadv=>295,pwritev=>296,rt_tgsigqueueinfo=>297,
            perf_event_open=>298,recvmmsg=>299,fanotify_init=>300,fanotify_mark=>301,
            prlimit64=>302,name_to_handle_at=>303,open_by_handle_at=>304,
            clock_adjtime=>305,syncfs=>306,sendmmsg=>307,setns=>308,getcpu=>309,
            process_vm_readv=>310,process_vm_writev=>311,kcmp=>312,finit_module=>313,
            sched_setattr=>314,sched_getattr=>315,renameat2=>316,seccomp=>317,
            getrandom=>318,memfd_create=>319,kexec_file_load=>320,bpf=>321,
            execveat=>322,userfaultfd=>323,membarrier=>324,mlock2=>325,
            copy_file_range=>326,preadv2=>327,pwritev2=>328,pkey_mprotect=>329,
            pkey_alloc=>330,pkey_free=>331,statx=>332,io_pgetevents=>333,rseq=>334,
            pidfd_send_signal=>424,io_uring_setup=>425,io_uring_enter=>426,
            io_uring_register=>427,open_tree=>428,move_mount=>429,fsopen=>430,
            fsconfig=>431,fsmount=>432,fspick=>433,pidfd_open=>434,clone3=>435,
            close_range=>436,openat2=>437,pidfd_getfd=>438,faccessat2=>439,
            process_madvise=>440,epoll_pwait2=>441,mount_setattr=>442,
            quotactl_fd=>443,landlock_create_ruleset=>444,landlock_add_rule=>445,
            landlock_restrict_self=>446,memfd_secret=>447,process_mrelease=>448,
            futex_waitv=>449,set_mempolicy_home_node=>450,cachestat=>451,
            fchmodat2=>452,map_shadow_stack=>453,futex_wake=>454,futex_wait=>455,
            futex_requeue=>456,statmount=>457,listmount=>458,
            lsm_get_self_attr=>459,lsm_set_self_attr=>460,lsm_list_modules=>461,
        );
    }
}

sub _resolve_seccomp_syscall {
    my ($name) = @_;
    _init_syscall_table();
    return $_SYSCALL_NR{$name};
}

my %_SECCOMP_RET = (
    SCMP_ACT_KILL         => 0x00000000,
    SCMP_ACT_KILL_PROCESS => 0x80000000,
    SCMP_ACT_TRAP         => 0x00030000,
    SCMP_ACT_NOTIFY       => 0x7fc00000,
    SCMP_ACT_LOG          => 0x7ffc0000,
    SCMP_ACT_ALLOW        => 0x7fff0000,
);

sub _seccomp_action_val {
    my ($str, $errno_override) = @_;
    return $_SECCOMP_RET{$str} if exists $_SECCOMP_RET{$str};
    if ($str =~ /^SCMP_ACT_ERRNO\((\d+)\)$/) {
        return 0x00050000 | ($1 & 0xffff);
    }
    if ($str eq 'SCMP_ACT_ERRNO') {
        my $ev = $errno_override // 1;
        return 0x00050000 | ($ev & 0xffff);
    }
    if ($str =~ /^SCMP_ACT_TRACE\((\d+)\)$/) {
        return 0x7ff00000 | ($1 & 0xffff);
    }
    return undef;
}

# BPF opcodes (classic BPF for seccomp)
use constant {
    _BPF_LD_W_ABS  => 0x20,
    _BPF_ALU_AND_K => 0x54,
    _BPF_JMP_JEQ_K => 0x15,
    _BPF_JMP_JGT_K => 0x25,
    _BPF_JMP_JGE_K => 0x35,
    _BPF_JMP_JA    => 0x05,
    _BPF_RET_K     => 0x06,
};

use constant {
    _AUDIT_ARCH_X86_64  => 0xc000003e,
    _AUDIT_ARCH_AARCH64 => 0xc00000b7,
};

sub _gen_seccomp_rule_bpf {
    my ($nr, $ret, $args) = @_;

    unless (@$args) {
        return (
            pack('SCCL', _BPF_JMP_JEQ_K, 0, 1, $nr),
            pack('SCCL', _BPF_RET_K,     0, 0, $ret),
        );
    }

    my %by_idx;
    push @{$by_idx{$_->{index}}}, $_ for @$args;
    my @group_idxs = sort { $a <=> $b } keys %by_idx;

    my @body;
    my @group_starts;

    for my $gi (0..$#group_idxs) {
        my $idx = $group_idxs[$gi];
        my @conds = @{$by_idx{$idx}};
        my $arg_off = 16 + $idx * 8;
        my $gp = "gp:$gi";

        $group_starts[$gi] = scalar @body;

        push @body, { code => _BPF_LD_W_ABS, k => $arg_off, jt => 0, jf => 0 };

        for my $ci (0..$#conds) {
            my $c     = $conds[$ci];
            my $op    = $c->{op} // 'SCMP_CMP_EQ';
            my $val   = $c->{value}    // 0;
            my $val2  = $c->{valueTwo} // 0;
            my $is_last = ($ci == $#conds);

            if ($op eq 'SCMP_CMP_MASKED_EQ') {
                push @body, { code => _BPF_ALU_AND_K, k => $val, jt => 0, jf => 0 };
                if ($is_last) {
                    push @body, { code => _BPF_JMP_JEQ_K, k => $val2, jt => 'pass', jf => 'fail' };
                } else {
                    push @body, { code => _BPF_JMP_JEQ_K, k => $val2, jt => $gp, jf => 'next' };
                    push @body, { code => _BPF_LD_W_ABS, k => $arg_off, jt => 0, jf => 0 };
                }
            } else {
                my ($opcode, $swap) = _seccomp_cmp_opcode($op);
                my ($jt_sym, $jf_sym);
                if ($is_last) {
                    $jt_sym = $swap ? 'fail' : 'pass';
                    $jf_sym = $swap ? 'pass' : 'fail';
                } else {
                    $jt_sym = $swap ? 'next' : $gp;
                    $jf_sym = $swap ? $gp    : 'next';
                }
                push @body, { code => $opcode, k => $val, jt => $jt_sym, jf => $jf_sym };
            }
        }
    }

    my $ret_pos  = scalar @body;
    push @body, { code => _BPF_RET_K,     k => $ret, jt => 0, jf => 0 };
    my $fail_pos = scalar @body;
    push @body, { code => _BPF_LD_W_ABS,  k => 0,    jt => 0, jf => 0 };

    my %gp_pos;
    for my $gi (0..$#group_idxs) {
        $gp_pos{"gp:$gi"} = ($gi < $#group_idxs) ? $group_starts[$gi + 1] : $ret_pos;
    }

    my @insns;
    my $body_len = scalar @body;
    push @insns, pack('SCCL', _BPF_JMP_JEQ_K, 0, $body_len, $nr);

    for my $i (0..$#body) {
        my $e = $body[$i];
        my $jt = $e->{jt};
        my $jf = $e->{jf};

        for my $ref (\$jt, \$jf) {
            if    (!defined $$ref || $$ref eq '0' || $$ref eq 'next' || $$ref eq 'pass') { $$ref = 0; }
            elsif ($$ref eq 'fail')                  { $$ref = $fail_pos - $i - 1; }
            elsif (exists $gp_pos{$$ref})             { $$ref = $gp_pos{$$ref} - $i - 1; }
        }

        push @insns, pack('SCCL', $e->{code}, $jt + 0, $jf + 0, $e->{k} // 0);
    }

    return @insns;
}

sub _seccomp_cmp_opcode {
    my ($op) = @_;
    return (_BPF_JMP_JEQ_K, 0) if $op eq 'SCMP_CMP_EQ';
    return (_BPF_JMP_JEQ_K, 1) if $op eq 'SCMP_CMP_NE';
    return (_BPF_JMP_JGE_K, 0) if $op eq 'SCMP_CMP_GE';
    return (_BPF_JMP_JGT_K, 0) if $op eq 'SCMP_CMP_GT';
    return (_BPF_JMP_JGT_K, 1) if $op eq 'SCMP_CMP_LE';
    return (_BPF_JMP_JGE_K, 1) if $op eq 'SCMP_CMP_LT';
    return (_BPF_JMP_JEQ_K, 0);
}

sub _apply_seccomp_minimal {
    my ($seccomp) = @_;

    my $default_str = $seccomp->{defaultAction} // 'SCMP_ACT_ALLOW';
    my $default_errno_ret = $seccomp->{defaultErrnoRet};

    my $default_ret = _seccomp_action_val($default_str, $default_errno_ret)
        // do { warn "nacre: seccomp: unknown default action $default_str\n"; return };

    my @rules;
    for my $rule (@{$seccomp->{syscalls} // []}) {
        my $act = $rule->{action} // $default_str;
        my $errno_val = $rule->{errnoRet} // $default_errno_ret;
        my $ret = _seccomp_action_val($act, $errno_val);
        next unless defined $ret;
        next if $ret == $default_ret;

        my @rule_args;
        for my $a (@{$rule->{args} // []}) {
            push @rule_args, {
                index    => $a->{index}    // 0,
                value    => $a->{value}    // 0,
                valueTwo => $a->{valueTwo} // 0,
                op       => $a->{op}       // 'SCMP_CMP_EQ',
            };
        }

        for my $name (@{$rule->{names} // []}) {
            my $nr = _resolve_seccomp_syscall($name);
            unless (defined $nr) {
                warn "nacre: seccomp: unknown syscall '$name', skipping\n";
                next;
            }
            push @rules, { nr => $nr, ret => $ret, args => \@rule_args };
        }
    }

    my @insns;

    require Config;
    my $arch_val = ($Config::Config{archname} // '') =~ /aarch64|arm64/i
        ? _AUDIT_ARCH_AARCH64 : _AUDIT_ARCH_X86_64;
    push @insns, pack('SCCL', _BPF_LD_W_ABS,  0, 0, 4);
    push @insns, pack('SCCL', _BPF_JMP_JEQ_K, 1, 0, $arch_val);
    push @insns, pack('SCCL', _BPF_RET_K,     0, 0, 0x00000000);

    push @insns, pack('SCCL', _BPF_LD_W_ABS, 0, 0, 0);

    my $enosys_val = 0x00050000 | 38;
    if ($default_ret != $enosys_val) {
        my $max_nr = $arch_val == _AUDIT_ARCH_AARCH64 ? 294 : 463;
        push @insns, pack('SCCL', _BPF_JMP_JGE_K, 0, 1, $max_nr);
        push @insns, pack('SCCL', _BPF_RET_K,     0, 0, $enosys_val);
    }

    for my $r (@rules) {
        push @insns, _gen_seccomp_rule_bpf($r->{nr}, $r->{ret}, $r->{args});
    }

    push @insns, pack('SCCL', _BPF_RET_K, 0, 0, $default_ret);

    my $filter = join('', @insns);
    my $ninsns = scalar @insns;
    my $fprog = pack('S x![Q] P', $ninsns, $filter);

    my $has_notify = 0;
    for my $r (@rules) {
        $has_notify = 1 if $r->{ret} == 0x7fc00000;
    }
    $has_notify = 1 if $default_ret == 0x7fc00000;

    my %flag_map = (
        SECCOMP_FILTER_FLAG_TSYNC     => 0,
        SECCOMP_FILTER_FLAG_LOG       => SECCOMP_FILTER_FLAG_LOG,
        SECCOMP_FILTER_FLAG_SPEC_ALLOW => (1 << 2),
        SECCOMP_FILTER_FLAG_NEW_LISTENER => SECCOMP_FILTER_FLAG_NEW_LISTENER,
        SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV => SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV,
    );
    my $fl = 0;
    my $has_flags_field = exists $seccomp->{flags};
    for my $flag_name (@{$seccomp->{flags} // []}) {
        my $fv = $flag_map{$flag_name};
        if (defined $fv) {
            $fl |= $fv;
        } else {
            warn "nacre: seccomp: unknown flag '$flag_name'\n";
        }
    }

    if ($has_notify) {
        $fl |= SECCOMP_FILTER_FLAG_NEW_LISTENER;
    }

    if (!$has_flags_field) {
        $fl |= (1 << 2);
    }

    log_debug("seccomp filter flags: $fl");

    my $nr = SYS_seccomp + 0;
    my $op = SECCOMP_SET_MODE_FILTER + 0;
    $fl += 0;
    my $ret = syscall($nr, $op, $fl, $fprog);

    if ($has_notify || ($fl & SECCOMP_FILTER_FLAG_NEW_LISTENER)) {
        if ($ret < 0) {
            fatal("seccomp: BPF load failed (errno=$!), filter has $ninsns insns");
        }
        return $ret;
    } else {
        if ($ret != 0) {
            fatal("seccomp: BPF load failed (errno=$!), filter has $ninsns insns");
        }
        return undef;
    }
}

our @EXPORT = qw(init_libseccomp apply_seccomp_raw);

1;
