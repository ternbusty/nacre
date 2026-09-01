package Nacre::Process;
use strict;
use warnings;
use Exporter 'import';
use POSIX qw(setgid setuid);
use Nacre::Const;
use Nacre::Util;
use Nacre::Seccomp;
use Nacre::Caps;

# ═══════════════════════════════════════════════════════════════════════
# Process Security
# ═══════════════════════════════════════════════════════════════════════

sub apply_process_security {
    my ($spec) = @_;
    my $proc = $spec->{process} // {};

    # 1. OOM score adj
    if (defined $proc->{oomScoreAdj}) {
        eval { write_file('/proc/self/oom_score_adj', $proc->{oomScoreAdj}); };
    }

    # 2. Umask
    if (defined $proc->{user}{umask}) {
        umask($proc->{user}{umask});
    }

    # 3. No new privileges
    if ($proc->{noNewPrivileges}) {
        do_syscall(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    }

    # 3b. Rlimits — must be applied BEFORE dropping caps, because
    #     raising hard limits beyond the current value requires
    #     CAP_SYS_RESOURCE (which may not be in the target cap sets).
    apply_rlimits($spec);

    # 3c. Scheduler — must be applied BEFORE dropping caps, because
    #     SCHED_DEADLINE and SCHED_FIFO require CAP_SYS_NICE.
    apply_scheduler($spec);

    # 4. Seccomp (must be applied before dropping caps)
    my $seccomp_notify_fd = apply_seccomp_raw($spec);

    # 5. Capabilities phase 1: drop bounding set + set KEEPCAPS.
    #    KEEPCAPS must be on BEFORE setuid so the kernel preserves the
    #    permitted set across the uid-0 → uid-N transition.
    apply_capabilities_bounding($spec);

    # 6. Set supplementary groups, then gid, then uid.
    #    Must happen AFTER KEEPCAPS is set and BEFORE the final capset.
    if (my $groups = $proc->{user}{additionalGids}) {
        my $nr = SYS_setgroups + 0;
        my $n  = scalar(@$groups) + 0;
        my $pk = pack('L*', @$groups);
        syscall($nr, $n, $pk);
    } else {
        my $nr = SYS_setgroups + 0;
        my $pk = '';
        syscall($nr, 0, $pk);
    }

    my $gid = $proc->{user}{gid} // 0;
    my $uid = $proc->{user}{uid} // 0;
    POSIX::setgid($gid + 0);
    POSIX::setuid($uid + 0);

    # 7. Capabilities phase 2: capset + clear KEEPCAPS + ambient caps.
    #    Now running as the target uid/gid, restore the desired capability
    #    sets.  The kernel cleared effective on setuid but kept permitted
    #    (KEEPCAPS was on); capset re-establishes the spec's desired sets.
    apply_capabilities_final($spec);

    return $seccomp_notify_fd;
}

# ═══════════════════════════════════════════════════════════════════════
# rlimits
# ═══════════════════════════════════════════════════════════════════════

my %RLIMIT_MAP = (
    RLIMIT_AS         => 9,
    RLIMIT_CORE       => 4,
    RLIMIT_CPU        => 0,
    RLIMIT_DATA       => 2,
    RLIMIT_FSIZE      => 1,
    RLIMIT_LOCKS      => 10,
    RLIMIT_MEMLOCK    => 8,
    RLIMIT_MSGQUEUE   => 12,
    RLIMIT_NICE       => 13,
    RLIMIT_NOFILE     => 7,
    RLIMIT_NPROC      => 6,
    RLIMIT_RSS        => 5,
    RLIMIT_RTPRIO     => 14,
    RLIMIT_RTTIME     => 15,
    RLIMIT_SIGPENDING => 11,
    RLIMIT_STACK      => 3,
);

sub validate_rlimits {
    # OCI spec: "The runtime MUST generate an error for any values
    # which cannot be mapped to a relevant kernel interface."
    my ($spec) = @_;
    return unless $spec->{process};  # avoid auto-vivifying {process}
    my $rlimits = $spec->{process}{rlimits} // return;
    for my $rl (@$rlimits) {
        exists $RLIMIT_MAP{$rl->{type}}
            or fatal("unknown rlimit type '$rl->{type}'");
    }
}

sub apply_rlimits {
    my ($spec) = @_;
    my $rlimits = $spec->{process}{rlimits} // return;
    for my $rl (@$rlimits) {
        my $type = $RLIMIT_MAP{$rl->{type}} // next;
        my $soft = $rl->{soft} // 0;
        my $hard = $rl->{hard} // 0;
        # prlimit64(pid=0, resource, new_rlim, old_rlim=NULL)
        my $nr = SYS_prlimit64 + 0;
        my $t  = $type + 0;
        my $new_rlim = pack('QQ', $soft, $hard);
        syscall($nr, 0, $t, $new_rlim, 0);
    }
}

# ═══════════════════════════════════════════════════════════════════════
# IO Priority
# ═══════════════════════════════════════════════════════════════════════

my %IOPRIO_CLASS_MAP = (
    IOPRIO_CLASS_RT   => 1,
    IOPRIO_CLASS_BE   => 2,
    IOPRIO_CLASS_IDLE => 3,
);

sub apply_iopriority {
    my ($spec) = @_;
    my $iop = $spec->{process}{ioPriority} // return;
    my $class = $IOPRIO_CLASS_MAP{$iop->{class} // ''} // return;
    my $prio  = $iop->{priority} // 0;
    # ioprio_set(IOPRIO_WHO_PROCESS=1, pid=0, ioprio)
    # ioprio = (class << 13) | prio
    my $ioprio = ($class << 13) | ($prio & 0x1fff);
    my $nr = SYS_ioprio_set + 0;
    my $who  = 1 + 0;  # IOPRIO_WHO_PROCESS
    my $pid  = 0 + 0;  # self
    my $val  = $ioprio + 0;
    syscall($nr, $who, $pid, $val);
}

# ═══════════════════════════════════════════════════════════════════════
# Scheduler
# ═══════════════════════════════════════════════════════════════════════

my %SCHED_POLICY_MAP = (
    SCHED_OTHER    => 0,
    SCHED_FIFO     => 1,
    SCHED_RR       => 2,
    SCHED_BATCH    => 3,
    SCHED_IDLE     => 5,
    SCHED_DEADLINE => 6,
);

my %SCHED_FLAG_MAP = (
    SCHED_FLAG_RESET_ON_FORK  => 0x01,
    SCHED_FLAG_RECLAIM        => 0x02,
    SCHED_FLAG_DL_OVERRUN     => 0x04,
    SCHED_FLAG_KEEP_POLICY    => 0x08,
    SCHED_FLAG_KEEP_PARAMS    => 0x10,
    SCHED_FLAG_UTIL_CLAMP_MIN => 0x20,
    SCHED_FLAG_UTIL_CLAMP_MAX => 0x40,
);

sub apply_scheduler {
    my ($spec) = @_;
    my $sched = $spec->{process}{scheduler} // return;

    # If CPU affinity is set AND scheduler is DEADLINE, conflict
    my $cpus = $spec->{linux}{resources}{cpu}{cpus} // '';
    if ($cpus ne '' && ($sched->{policy} // '') eq 'SCHED_DEADLINE') {
        fatal("process scheduler can't be used together with AllowedCPUs");
    }

    my $policy = $SCHED_POLICY_MAP{$sched->{policy} // 'SCHED_OTHER'} // 0;
    my $flags = 0;
    for my $f (@{$sched->{flags} // []}) {
        $flags |= ($SCHED_FLAG_MAP{$f} // 0);
    }
    my $nice      = $sched->{nice}     // 0;
    my $priority  = $sched->{priority} // 0;
    my $runtime   = $sched->{runtime}  // 0;
    my $deadline  = $sched->{deadline} // 0;
    my $period    = $sched->{period}   // 0;

    # struct sched_attr (48 bytes):
    #   u32 size, u32 sched_policy, u64 sched_flags, s32 sched_nice,
    #   u32 sched_priority, u64 sched_runtime, u64 sched_deadline, u64 sched_period
    my $attr = pack('LLQlLQQQ',
        48,        # size
        $policy,
        $flags,
        $nice,
        $priority,
        $runtime,
        $deadline,
        $period,
    );
    my $nr = SYS_sched_setattr + 0;
    my $pid_val = 0 + 0;  # self
    my $fl = 0 + 0;
    my $r = syscall($nr, $pid_val, $attr, $fl);
    if ($r == -1) {
        fatal("sched_setattr: $!");
    }
}

# ═══════════════════════════════════════════════════════════════════════
# Memory Policy (set_mempolicy)
# ═══════════════════════════════════════════════════════════════════════

my %MPOL_MODE_MAP = (
    MPOL_DEFAULT    => 0,
    MPOL_PREFERRED  => 1,
    MPOL_BIND       => 2,
    MPOL_INTERLEAVE => 3,
    MPOL_LOCAL      => 4,
);

my %MPOL_FLAG_MAP = (
    MPOL_F_STATIC_NODES   => (1 << 15),
    MPOL_F_RELATIVE_NODES => (1 << 14),
    MPOL_F_NUMA_BALANCING => (1 << 13),
);

sub parse_node_list {
    my ($nodes_str) = @_;
    my @nodes;
    for my $part (split /,/, $nodes_str) {
        $part =~ s/^\s+|\s+$//g;
        next if $part eq '';
        if ($part =~ /^(\d+)-(\d+)$/) {
            my ($lo, $hi) = ($1 + 0, $2 + 0);
            fatal("invalid memory policy node: $part") if $hi > 1024 * 1024;
            push @nodes, $lo .. $hi;
        } elsif ($part =~ /^(\d+)$/) {
            push @nodes, $1 + 0;
        } else {
            fatal("invalid memory policy node: $part");
        }
    }
    return @nodes;
}

sub validate_memory_policy {
    my ($spec) = @_;
    my $mp = $spec->{linux}{memoryPolicy} // return;

    my $mode_str = $mp->{mode} // '';
    if (!defined $mp->{mode} && !keys %{$mp}) {
        fatal("invalid memory policy");
    }
    if (!defined $mp->{mode} || $mode_str eq '') {
        fatal("invalid memory policy mode: (empty)");
    }
    if (!exists $MPOL_MODE_MAP{$mode_str}) {
        fatal("invalid memory policy mode: $mode_str");
    }
    for my $f (@{$mp->{flags} // []}) {
        fatal("invalid memory policy flag: $f")
            unless exists $MPOL_FLAG_MAP{$f};
    }
    my $nodes_str = $mp->{nodes} // '';
    my @nodes = $nodes_str ne '' ? parse_node_list($nodes_str) : ();
    if ($mode_str eq 'MPOL_DEFAULT' && @nodes > 0) {
        fatal("set_mempolicy: mode requires 0 nodes but got " . scalar(@nodes));
    }
}

sub apply_memory_policy {
    my ($spec) = @_;
    my $mp = $spec->{linux}{memoryPolicy} // return;

    my $mode_str = $mp->{mode} // '';
    if ($mode_str eq '' || !exists $MPOL_MODE_MAP{$mode_str}) {
        return;  # validation already done
    }
    my $mode = $MPOL_MODE_MAP{$mode_str};

    # Parse flags
    my $flags = 0;
    for my $f (@{$mp->{flags} // []}) {
        $flags |= ($MPOL_FLAG_MAP{$f} // 0);
    }
    $mode |= $flags;

    # Parse nodes
    my $nodes_str = $mp->{nodes} // '';
    my @nodes = $nodes_str ne '' ? parse_node_list($nodes_str) : ();

    # Build nodemask bitmask
    my $maxnode = 0;
    my @mask;
    if (@nodes) {
        $maxnode = (sort { $b <=> $a } @nodes)[0] + 1;
        # Round maxnode up to multiple of 64 for kernel alignment
        my $mask_longs = int(($maxnode + 63) / 64);
        @mask = (0) x $mask_longs;
        for my $n (@nodes) {
            my $idx = int($n / 64);
            my $bit = $n % 64;
            $mask[$idx] |= (1 << $bit);
        }
        $maxnode = $mask_longs * 64 + 1;
    }

    my $nodemask = @mask ? pack('Q*', @mask) : 0;  # 0 = NULL pointer
    my $nr = SYS_set_mempolicy + 0;
    my $m  = $mode + 0;
    my $mn = $maxnode + 0;
    my $r = syscall($nr, $m, $nodemask, $mn);
    if ($r == -1) {
        fatal("set_mempolicy: $!");
    }
}

# ═══════════════════════════════════════════════════════════════════════
# Time Namespace Offsets
# ═══════════════════════════════════════════════════════════════════════

sub apply_timens_offsets {
    my ($spec) = @_;
    my $offsets = $spec->{linux}{timeOffsets} // return;
    # Only write if there are actual offsets to set
    return unless ref $offsets eq 'HASH' && %$offsets;

    # Collect the lines first so we don't open the file needlessly
    my @lines;
    for my $clock (qw(monotonic boottime)) {
        my $entry = $offsets->{$clock} // next;
        my $secs  = $entry->{secs}     // 0;
        my $nsecs = $entry->{nanosecs} // 0;
        push @lines, "$clock $secs $nsecs\n";
    }
    return unless @lines;

    my $path = '/proc/self/timens_offsets';
    if (open(my $fh, '>', $path)) {
        print $fh @lines;
        close $fh;
    } else {
        warn "nacre: open $path: $! (ignoring)\n";
    }
}

# ═══════════════════════════════════════════════════════════════════════
# CPU Affinity
# ═══════════════════════════════════════════════════════════════════════

sub parse_cpu_list {
    # Parse a CPU list string like "0", "0-3", "0,2,4-7" into a list of
    # individual CPU numbers.
    my ($str) = @_;
    my @cpus;
    for my $part (split /,/, $str) {
        if ($part =~ /^(\d+)-(\d+)$/) {
            push @cpus, $1 .. $2;
        } elsif ($part =~ /^(\d+)$/) {
            push @cpus, $1;
        }
    }
    return @cpus;
}

sub cpu_list_to_mask {
    # Convert a list of CPU numbers to a bitmask for sched_setaffinity.
    # Returns ($mask_bytes, $mask_len).  The mask is a packed byte string
    # suitable for the syscall.
    my @cpus = @_;
    return ('', 0) unless @cpus;
    my $max = 0;
    for my $c (@cpus) { $max = $c if $c > $max; }
    # Kernel expects mask size in bytes, aligned to sizeof(unsigned long)=8
    my $longs = int(($max + 64) / 64);
    my @mask = (0) x $longs;
    for my $c (@cpus) {
        my $idx = int($c / 64);
        $mask[$idx] |= (1 << ($c % 64));
    }
    return (pack('Q*', @mask), $longs * 8);
}

sub get_available_cpus {
    # Read the set of online CPUs from /sys/devices/system/cpu/online.
    my $online = '';
    if (open my $fh, '<', '/sys/devices/system/cpu/online') {
        $online = <$fh>;
        chomp $online;
        close $fh;
    }
    return parse_cpu_list($online);
}

sub apply_cpu_affinity_reset {
    # Reset CPU affinity to the full available set (cgroup cpuset or system).
    # This undoes any taskset/affinity constraint inherited from the parent.
    my ($spec) = @_;

    # Determine cpuset from cgroup config or fall back to system online CPUs
    my $cpus_str = '';
    if (my $cpu = $spec->{linux}{resources}{cpu}) {
        $cpus_str = $cpu->{cpus} // '';
    }

    my @cpus;
    if ($cpus_str ne '') {
        @cpus = parse_cpu_list($cpus_str);
    } else {
        @cpus = get_available_cpus();
    }
    return unless @cpus;

    my ($mask, $len) = cpu_list_to_mask(@cpus);
    my $nr  = SYS_sched_setaffinity + 0;
    my $pid = 0 + 0;  # 0 = current process
    my $l   = $len + 0;
    syscall($nr, $pid, $l, $mask);
}

sub apply_exec_cpu_affinity {
    # Apply execCPUAffinity from config/process for exec.
    # Sets initial affinity before exec and returns final affinity to set
    # right before exec (or undef if no final).
    my ($affinity, $dbg) = @_;
    return unless $affinity;

    # Use 'defined' because Perl treats the string "0" (CPU 0 only) as falsy.
    if (defined(my $initial = $affinity->{initial})) {
        my @cpus = parse_cpu_list($initial);
        if (@cpus) {
            my ($mask, $len) = cpu_list_to_mask(@cpus);
            my $nr  = SYS_sched_setaffinity + 0;
            my $pid = 0 + 0;
            my $l   = $len + 0;
            syscall($nr, $pid, $l, $mask);
            # Log in nsexec-compatible format for bats tests.
            # Print directly to stderr (like runc's nsexec.c does),
            # not through the debug logger, so the pattern matches.
            my $hex_mask = 0;
            for my $c (@cpus) { $hex_mask |= (1 << $c); }
            printf STDERR "nsexec: affinity: 0x%x\n", $hex_mask;
        }
    }

    # Return final affinity info for post-setns application
    if (defined(my $final = $affinity->{final})) {
        return $final;
    }
    return;
}

sub apply_final_cpu_affinity {
    my ($final_str) = @_;
    return unless $final_str;
    my @cpus = parse_cpu_list($final_str);
    return unless @cpus;
    my ($mask, $len) = cpu_list_to_mask(@cpus);
    my $nr  = SYS_sched_setaffinity + 0;
    my $pid = 0 + 0;
    my $l   = $len + 0;
    syscall($nr, $pid, $l, $mask);
}

# ═══════════════════════════════════════════════════════════════════════
# Exec Capabilities (--cap flag)
# ═══════════════════════════════════════════════════════════════════════

sub apply_exec_caps {
    # Apply capabilities for exec'd processes.
    # Always applies the container's capability config from the spec.
    # If $cap_list has entries (from --cap), those are added to
    # bounding+permitted+effective (runc semantics).
    my ($cap_list, $spec) = @_;

    my $spec_caps = $spec->{process}{capabilities};
    # If no capabilities in spec and no --cap additions, nothing to do
    return unless $spec_caps || ($cap_list && @$cap_list);
    $spec_caps //= {};

    my $has_inheritable = $spec_caps->{inheritable} && @{$spec_caps->{inheritable}};

    # Build the full capability sets from spec + additions
    my %bnd_caps  = map { $_ => 1 } @{$spec_caps->{bounding}   // []};
    my %prm_caps  = map { $_ => 1 } @{$spec_caps->{permitted}  // []};
    my %eff_caps  = map { $_ => 1 } @{$spec_caps->{effective}  // []};
    my %inh_caps  = map { $_ => 1 } @{$spec_caps->{inheritable}// []};
    my %amb_caps  = map { $_ => 1 } @{$spec_caps->{ambient}    // []};

    for my $cap (@{$cap_list // []}) {
        my $name = $cap;
        $name = "CAP_$name" unless $name =~ /^CAP_/;
        $name = uc($name);
        fatal("unknown capability: $name") unless exists $CAP_NUM{$name};
        $bnd_caps{$name} = 1;
        $prm_caps{$name} = 1;
        $eff_caps{$name} = 1;
        if ($has_inheritable) {
            $amb_caps{$name} = 1;
        }
    }

    # Drop bounding set caps not in the desired set
    for my $name (@CAP_NAMES) {
        next if $bnd_caps{$name};
        my $num = $CAP_NUM{$name} // next;
        do_syscall(SYS_prctl, PR_CAPBSET_DROP, $num, 0, 0, 0);
    }

    # Set KEEPCAPS across setuid
    do_syscall(SYS_prctl, PR_SET_KEEPCAPS, 1, 0, 0, 0);

    # Build capset data
    my ($eff_lo, $eff_hi) = (0, 0);
    my ($prm_lo, $prm_hi) = (0, 0);
    my ($inh_lo, $inh_hi) = (0, 0);

    for my $name (keys %eff_caps) {
        my $n = $CAP_NUM{$name} // next;
        if ($n < 32) { $eff_lo |= (1 << $n); } else { $eff_hi |= (1 << ($n - 32)); }
    }
    for my $name (keys %prm_caps) {
        my $n = $CAP_NUM{$name} // next;
        if ($n < 32) { $prm_lo |= (1 << $n); } else { $prm_hi |= (1 << ($n - 32)); }
    }
    for my $name (keys %inh_caps) {
        my $n = $CAP_NUM{$name} // next;
        if ($n < 32) { $inh_lo |= (1 << $n); } else { $inh_hi |= (1 << ($n - 32)); }
    }
    # Ambient caps require the cap in BOTH permitted AND inheritable sets.
    # Merge ambient into inheritable (same as runc's ApplyCaps).
    for my $name (keys %amb_caps) {
        my $n = $CAP_NUM{$name} // next;
        if ($n < 32) { $inh_lo |= (1 << $n); } else { $inh_hi |= (1 << ($n - 32)); }
    }

    my $hdr = pack('Ii', _LINUX_CAPABILITY_VERSION_3, 0);
    my $data = pack('III III',
        $eff_lo, $prm_lo, $inh_lo,
        $eff_hi, $prm_hi, $inh_hi);
    my $nr_capset = SYS_capset + 0;
    syscall($nr_capset, $hdr, $data);

    # Clear keepcaps
    do_syscall(SYS_prctl, PR_SET_KEEPCAPS, 0, 0, 0, 0);

    # Raise ambient capabilities
    for my $name (keys %amb_caps) {
        my $n = $CAP_NUM{$name} // next;
        do_syscall(SYS_prctl, PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, $n, 0, 0);
    }
}

# ═══════════════════════════════════════════════════════════════════════
# Sysctls
# ═══════════════════════════════════════════════════════════════════════

my %SYSCTL_ALLOWED_PREFIXES = map { $_ => 1 } qw(
    net. fs.mqueue.
    kernel.msgmax kernel.msgmnb kernel.msgmni
    kernel.sem kernel.shmall kernel.shmmax kernel.shmmni
    kernel.domainname
);

sub validate_sysctl {
    my ($key) = @_;
    for my $prefix (keys %SYSCTL_ALLOWED_PREFIXES) {
        return 1 if index($key, $prefix) == 0;
    }
    return 0;
}

sub apply_sysctls {
    my ($spec) = @_;
    my $sysctls = $spec->{linux}{sysctl} // return;
    for my $key (keys %$sysctls) {
        fatal("sysctl '$key' not allowed") unless validate_sysctl($key);
        my $path = '/proc/sys/' . ($key =~ s/\./\//gr);
        eval { write_file($path, $sysctls->{$key}); };
    }
}

our @EXPORT = qw(
    apply_process_security
    validate_rlimits apply_rlimits
    apply_iopriority
    apply_scheduler
    validate_memory_policy apply_memory_policy
    apply_timens_offsets
    apply_cpu_affinity_reset apply_exec_cpu_affinity apply_final_cpu_affinity
    apply_exec_caps
    apply_sysctls
);

1;
