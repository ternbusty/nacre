package Nacre::Seccomp;
use v5.38;
use Exporter 'import';
use Nacre::Const qw(
    SYS_seccomp SECCOMP_SET_MODE_FILTER
    SECCOMP_FILTER_FLAG_TSYNC SECCOMP_FILTER_FLAG_LOG
    SECCOMP_FILTER_FLAG_NEW_LISTENER SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV
);
use Nacre::Util qw(log_debug fatal);

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
    return;
}

# Seccomp actions
use constant {
    SCMP_ACT_KILL => 0x00000000,
    SCMP_ACT_KILL_PROCESS => 0x80000000,
    SCMP_ACT_TRAP => 0x00030000,
    SCMP_ACT_NOTIFY => 0x7fc00000,
    SCMP_ACT_LOG => 0x7ffc0000,
    SCMP_ACT_ALLOW => 0x7fff0000,
    SCMP_ACT_ERRNO_BASE => 0x00050000,
};

sub apply_seccomp_raw ($spec) {
    my $seccomp = $spec->{linux}{seccomp} // return;

    # If FFI::Platypus is available, use it
    if (eval {require FFI::Platypus; 1}) {
        return _apply_seccomp_ffi($spec);
    }

    # Fallback: build and load BPF program directly via seccomp(2)
    return _apply_seccomp_minimal($seccomp);
}

sub _apply_seccomp_ffi ($spec) {
    my $seccomp = $spec->{linux}{seccomp} // return;

    require FFI::Platypus;
    my $ffi = FFI::Platypus->new(api => 2);
    $ffi->lib('/usr/lib/x86_64-linux-gnu/libseccomp.so.2');

    $ffi->attach('seccomp_init' => ['uint32'] => 'opaque');
    $ffi->attach('seccomp_arch_add' => ['opaque', 'uint32'] => 'int');
    $ffi->attach(
        'seccomp_rule_add' => ['opaque', 'uint32', 'int', 'uint'] => 'int',
        sub ($xsub, @args) {
            return $xsub->(@args);
        }
    );
    $ffi->attach('seccomp_syscall_resolve_name' => ['string'] => 'int');
    $ffi->attach('seccomp_load' => ['opaque'] => 'int');
    $ffi->attach('seccomp_release' => ['opaque'] => 'void');
    $ffi->attach('seccomp_export_bpf' => ['opaque', 'int'] => 'int');
    $ffi->attach('seccomp_attr_set' => ['opaque', 'uint32', 'uint32'] => 'int');

    my $default_action_str = $seccomp->{defaultAction} // 'SCMP_ACT_ALLOW';
    my $default_errno_ret = $seccomp->{defaultErrnoRet};
    my $default_action = _seccomp_action_val($default_action_str, $default_errno_ret)
        // fatal("unknown seccomp action: $default_action_str");

    my $ctx = seccomp_init($default_action)
        or fatal("seccomp_init failed");

    seccomp_attr_set($ctx, 2, 0);    # SCMP_FLTATR_CTL_NNP = 2

    my %arch_map = (
        SCMP_ARCH_X86_64 => 0xc000003e,
        SCMP_ARCH_X86 => 0x40000003,
        SCMP_ARCH_AARCH64 => 0xc00000b7,
        SCMP_ARCH_ARM => 0x40000028,
    );

    for my $arch (@{$seccomp->{architectures} // []}) {
        my $arch_val = $arch_map{$arch} // next;
        seccomp_arch_add($ctx, $arch_val);
    }

    for my $rule (@{$seccomp->{syscalls} // []}) {
        my $action_str = $rule->{action} // $default_action_str;
        my $errno_val = $rule->{errnoRet} // $default_errno_ret;
        my $action = _seccomp_action_val($action_str, $errno_val) // next;

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
        local $/ = undef;
        my $bpf_prog = <$rd>;
        close $rd;

        if (defined $bpf_prog && length $bpf_prog >= 8) {
            my $filter_count = length($bpf_prog) / 8;
            my $sock_fprog = pack('S x![P] P', $filter_count, unpack('Q', pack('P', $bpf_prog)));

            my $nr_sec = SYS_seccomp + 0;
            my $op = SECCOMP_SET_MODE_FILTER + 0;
            my $fl = _resolve_seccomp_flags($seccomp, 0);
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
    return;
}

my %_SYSCALL_NR;

sub _init_syscall_table {
    return if %_SYSCALL_NR;
    require Config;
    my $arch = $Config::Config{archname} // '';    ## no critic (ProhibitPackageVars)

    my @hdrs;
    if ($arch =~ /x86_64|amd64/i) {
        @hdrs = ('/usr/include/x86_64-linux-gnu/asm/unistd_64.h', '/usr/include/asm/unistd_64.h',);
    } elsif ($arch =~ /aarch64|arm64/i) {
        @hdrs = ('/usr/include/aarch64-linux-gnu/asm/unistd.h', '/usr/include/asm-generic/unistd.h',);
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
    return;
}

sub _resolve_seccomp_syscall ($name) {
    _init_syscall_table();
    return $_SYSCALL_NR{$name};
}

my %_SECCOMP_RET = (
    SCMP_ACT_KILL => 0x00000000,
    SCMP_ACT_KILL_PROCESS => 0x80000000,
    SCMP_ACT_TRAP => 0x00030000,
    SCMP_ACT_NOTIFY => 0x7fc00000,
    SCMP_ACT_LOG => 0x7ffc0000,
    SCMP_ACT_ALLOW => 0x7fff0000,
);

sub _seccomp_action_val ($str, $errno_override = undef) {
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
    return;
}

sub _resolve_seccomp_flags ($seccomp, $has_notify, $enable_tsync = 1) {
    my %flag_map = (
        SECCOMP_FILTER_FLAG_TSYNC => $enable_tsync ? SECCOMP_FILTER_FLAG_TSYNC : 0,
        SECCOMP_FILTER_FLAG_LOG => SECCOMP_FILTER_FLAG_LOG,
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
        $fl |= (1 << 2);    # SECCOMP_FILTER_FLAG_SPEC_ALLOW
    }

    log_debug("seccomp filter flags: $fl");
    return $fl + 0;
}

# BPF opcodes (classic BPF for seccomp)
use constant {
    _BPF_LD_W_ABS => 0x20,
    _BPF_ALU_AND_K => 0x54,
    _BPF_JMP_JEQ_K => 0x15,
    _BPF_JMP_JGT_K => 0x25,
    _BPF_JMP_JGE_K => 0x35,
    _BPF_JMP_JA => 0x05,
    _BPF_RET_K => 0x06,
};

use constant {
    _AUDIT_ARCH_X86_64 => 0xc000003e,
    _AUDIT_ARCH_AARCH64 => 0xc00000b7,
};

sub _emit_bpf_cond ($body, $c, $is_last, $gp, $arg_off) {
    my $op = $c->{op} // 'SCMP_CMP_EQ';
    my $val = $c->{value} // 0;
    my $val2 = $c->{valueTwo} // 0;

    if ($op eq 'SCMP_CMP_MASKED_EQ') {
        push @$body, {code => _BPF_ALU_AND_K, k => $val, jt => 0, jf => 0};
        if ($is_last) {
            push @$body, {code => _BPF_JMP_JEQ_K, k => $val2, jt => 'pass', jf => 'fail'};
        } else {
            push @$body, {code => _BPF_JMP_JEQ_K, k => $val2, jt => $gp, jf => 'next'};
            push @$body, {code => _BPF_LD_W_ABS, k => $arg_off, jt => 0, jf => 0};
        }
    } else {
        my ($opcode, $swap) = _seccomp_cmp_opcode($op);
        my ($jt_sym, $jf_sym);
        if ($is_last) {
            $jt_sym = $swap ? 'fail' : 'pass';
            $jf_sym = $swap ? 'pass' : 'fail';
        } else {
            $jt_sym = $swap ? 'next' : $gp;
            $jf_sym = $swap ? $gp : 'next';
        }
        push @$body, {code => $opcode, k => $val, jt => $jt_sym, jf => $jf_sym};
    }
    return;
}

sub _gen_seccomp_rule_bpf ($nr, $ret, $args) {

    unless (@$args) {
        return (pack('SCCL', _BPF_JMP_JEQ_K, 0, 1, $nr), pack('SCCL', _BPF_RET_K, 0, 0, $ret),);
    }

    my %by_idx;
    push @{$by_idx{$_->{index}}}, $_ for @$args;
    my @group_idxs = sort {$a <=> $b} keys %by_idx;

    my @body;
    my @group_starts;

    for my $gi (0 .. $#group_idxs) {
        my $idx = $group_idxs[$gi];
        my @conds = @{$by_idx{$idx}};
        my $arg_off = 16 + $idx * 8;
        my $gp = "gp:$gi";

        $group_starts[$gi] = scalar @body;
        push @body, {code => _BPF_LD_W_ABS, k => $arg_off, jt => 0, jf => 0};

        for my $ci (0 .. $#conds) {
            _emit_bpf_cond(\@body, $conds[$ci], ($ci == $#conds), $gp, $arg_off);
        }
    }

    my $ret_pos = scalar @body;
    push @body, {code => _BPF_RET_K, k => $ret, jt => 0, jf => 0};
    my $fail_pos = scalar @body;
    push @body, {code => _BPF_LD_W_ABS, k => 0, jt => 0, jf => 0};

    my %gp_pos;
    for my $gi (0 .. $#group_idxs) {
        $gp_pos{"gp:$gi"} = ($gi < $#group_idxs) ? $group_starts[$gi + 1] : $ret_pos;
    }

    my @insns;
    my $body_len = scalar @body;
    push @insns, pack('SCCL', _BPF_JMP_JEQ_K, 0, $body_len, $nr);

    for my $i (0 .. $#body) {
        my $e = $body[$i];
        my $jt = $e->{jt};
        my $jf = $e->{jf};

        for my $ref (\$jt, \$jf) {
            if (!defined $$ref || $$ref eq '0' || $$ref eq 'next' || $$ref eq 'pass') {$$ref = 0;}
            elsif ($$ref eq 'fail') {$$ref = $fail_pos - $i - 1;}
            elsif (exists $gp_pos{$$ref}) {$$ref = $gp_pos{$$ref} - $i - 1;}
        }

        push @insns, pack('SCCL', $e->{code}, $jt + 0, $jf + 0, $e->{k} // 0);
    }

    return @insns;
}

sub _seccomp_cmp_opcode ($op) {
    return (_BPF_JMP_JEQ_K, 0) if $op eq 'SCMP_CMP_EQ';
    return (_BPF_JMP_JEQ_K, 1) if $op eq 'SCMP_CMP_NE';
    return (_BPF_JMP_JGE_K, 0) if $op eq 'SCMP_CMP_GE';
    return (_BPF_JMP_JGT_K, 0) if $op eq 'SCMP_CMP_GT';
    return (_BPF_JMP_JGT_K, 1) if $op eq 'SCMP_CMP_LE';
    return (_BPF_JMP_JGE_K, 1) if $op eq 'SCMP_CMP_LT';
    return (_BPF_JMP_JEQ_K, 0);
}

sub _apply_seccomp_minimal ($seccomp) {

    my $default_str = $seccomp->{defaultAction} // 'SCMP_ACT_ALLOW';
    my $default_errno_ret = $seccomp->{defaultErrnoRet};

    my $default_ret = _seccomp_action_val($default_str, $default_errno_ret)
        // do {warn "nacre: seccomp: unknown default action $default_str\n"; return};

    my @rules;
    for my $rule (@{$seccomp->{syscalls} // []}) {
        my $act = $rule->{action} // $default_str;
        my $errno_val = $rule->{errnoRet} // $default_errno_ret;
        my $ret = _seccomp_action_val($act, $errno_val);
        next unless defined $ret;
        next if $ret == $default_ret;

        my @rule_args;
        for my $a (@{$rule->{args} // []}) {
            push @rule_args,
                {
                index => $a->{index} // 0,
                value => $a->{value} // 0,
                valueTwo => $a->{valueTwo} // 0,
                op => $a->{op} // 'SCMP_CMP_EQ',
                };
        }

        for my $name (@{$rule->{names} // []}) {
            my $nr = _resolve_seccomp_syscall($name);
            unless (defined $nr) {
                warn "nacre: seccomp: unknown syscall '$name', skipping\n";
                next;
            }
            push @rules, {nr => $nr, ret => $ret, args => \@rule_args};
        }
    }

    my @insns;

    require Config;
    my $arch_val = ($Config::Config{archname} // '') =~ /aarch64|arm64/i ? _AUDIT_ARCH_AARCH64 : _AUDIT_ARCH_X86_64;   ## no critic (ProhibitPackageVars)
    push @insns, pack('SCCL', _BPF_LD_W_ABS, 0, 0, 4);
    push @insns, pack('SCCL', _BPF_JMP_JEQ_K, 1, 0, $arch_val);
    push @insns, pack('SCCL', _BPF_RET_K, 0, 0, 0x00000000);

    push @insns, pack('SCCL', _BPF_LD_W_ABS, 0, 0, 0);

    my $enosys_val = 0x00050000 | 38;
    if ($default_ret != $enosys_val) {
        my $max_nr = $arch_val == _AUDIT_ARCH_AARCH64 ? 294 : 463;
        push @insns, pack('SCCL', _BPF_JMP_JGE_K, 0, 1, $max_nr);
        push @insns, pack('SCCL', _BPF_RET_K, 0, 0, $enosys_val);
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

    my $fl = _resolve_seccomp_flags($seccomp, $has_notify, 0);

    my $nr = SYS_seccomp + 0;
    my $op = SECCOMP_SET_MODE_FILTER + 0;
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
        return;
    }
}

our @EXPORT_OK = qw(init_libseccomp apply_seccomp_raw);

1;
