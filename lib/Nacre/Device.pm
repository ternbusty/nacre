package Nacre::Device;
use strict;
use warnings;
use Exporter 'import';
use Nacre::Const;
use Fcntl qw(O_RDONLY O_DIRECTORY);
use Errno qw(EINTR);

# ═══════════════════════════════════════════════════════════════════════
# eBPF Device Cgroup
# ═══════════════════════════════════════════════════════════════════════

sub apply_device_cgroup {
    my ($cgpath, $spec) = @_;
    my $rules = $spec->{linux}{resources}{devices} // return;

    my ($default_allow, $exceptions) = _emulate_device_rules($rules);

    my $prog = _build_device_bpf($default_allow, $exceptions);
    return unless @$prog;

    my $insns = join('', map { _pack_bpf_insn(@$_) } @$prog);
    my $license = "GPL\0";
    my $log_buf = "\0" x 4096;

    my $attr = pack('L      L      Q      Q      L      L      Q      a*',
        BPF_PROG_TYPE_CGROUP_DEVICE,
        scalar(@$prog),
        unpack('Q', pack('P', $insns)),
        unpack('Q', pack('P', $license)),
        4,
        4096,
        unpack('Q', pack('P', $log_buf)),
    );
    $attr .= "\0" x (256 - length($attr)) if length($attr) < 256;

    my $nr_bpf = SYS_bpf + 0;
    my $bpf_cmd = BPF_PROG_LOAD + 0;
    my $attr_len = length($attr) + 0;
    my $prog_fd;
    do { $prog_fd = syscall($nr_bpf, $bpf_cmd, $attr, $attr_len) }
        while ($prog_fd == -1 && $! == EINTR);
    if ($prog_fd < 0) {
        warn "nacre: BPF_PROG_LOAD failed: $!\n";
        return;
    }

    sysopen(my $cgdir_fh, $cgpath, O_RDONLY | O_DIRECTORY)
        or do { warn "nacre: open cgroup dir: $!\n"; return; };
    my $cgdir_fd = fileno($cgdir_fh);

    my $attach_attr = pack('L L L L',
        $cgdir_fd,
        $prog_fd,
        BPF_CGROUP_DEVICE,
        BPF_F_ALLOW_MULTI,
    );
    $attach_attr .= "\0" x (256 - length($attach_attr)) if length($attach_attr) < 256;

    my $bpf_attach = BPF_PROG_ATTACH + 0;
    my $attach_len = length($attach_attr) + 0;
    my $ret;
    do { $ret = syscall($nr_bpf, $bpf_attach, $attach_attr, $attach_len) }
        while ($ret == -1 && $! == EINTR);
    warn "nacre: BPF_PROG_ATTACH failed: $!\n" if $ret < 0;

    close $cgdir_fh;
    POSIX::close($prog_fd);
}

sub _emulate_device_rules {
    my ($rules) = @_;
    my $default_allow = 0;
    my @exceptions;

    for my $r (@$rules) {
        my $type = $r->{type} // 'a';
        my $allow = $r->{allow} ? 1 : 0;
        my $access = $r->{access} // 'rwm';
        my $major = $r->{major};
        my $minor = $r->{minor};

        if ($type eq 'a') {
            $default_allow = $allow;
            @exceptions = ();
            next;
        }

        my $exc = {
            type   => $type,
            major  => $major // -1,
            minor  => $minor // -1,
            access => $access,
        };

        if ($allow != $default_allow) {
            push @exceptions, $exc;
        } else {
            @exceptions = grep {
                !($_->{type} eq $exc->{type} &&
                  $_->{major} == $exc->{major} &&
                  $_->{minor} == $exc->{minor})
            } @exceptions;
        }
    }

    return ($default_allow, \@exceptions);
}

sub _build_device_bpf {
    my ($default_allow, $exceptions) = @_;
    my @prog;

    return \@prog unless @$exceptions;

    push @prog, _bpf_ld_abs(0);
    push @prog, _bpf_st(0);

    my $num_exc = scalar @$exceptions;
    for my $i (0..$num_exc-1) {
        my $exc = $exceptions->[$i];

        my $jumps_in_this_exc = 0;
        $jumps_in_this_exc++ if $exc->{type};
        $jumps_in_this_exc++ if $exc->{major} != -1;
        $jumps_in_this_exc++ if $exc->{minor} != -1;
        $jumps_in_this_exc++;
        $jumps_in_this_exc++;

        my $type_val = $exc->{type} eq 'b' ? 1 : 2;
        my $skip = $jumps_in_this_exc - 1;

        push @prog, _bpf_ld_mem(0);
        push @prog, _bpf_alu_and(0xffff);
        push @prog, _bpf_jne($type_val, $skip - 2, 0);

        if ($exc->{major} != -1) {
            push @prog, _bpf_ld_abs(4);
            $skip -= 3;
            push @prog, _bpf_jne($exc->{major}, $skip > 0 ? $skip : 0, 0);
        }

        if ($exc->{minor} != -1) {
            push @prog, _bpf_ld_abs(8);
            $skip -= 2;
            push @prog, _bpf_jne($exc->{minor}, $skip > 0 ? $skip : 0, 0);
        }

        push @prog, _bpf_ld_mem(0);
        my $access_mask = 0;
        $access_mask |= 1 if $exc->{access} =~ /m/;
        $access_mask |= 2 if $exc->{access} =~ /r/;
        $access_mask |= 4 if $exc->{access} =~ /w/;
        push @prog, _bpf_alu_rsh(16);
        push @prog, _bpf_alu_and($access_mask);
        push @prog, _bpf_jeq(0, 1, 0);

        push @prog, _bpf_ret($default_allow ? 0 : 1);
    }

    push @prog, _bpf_ret($default_allow ? 1 : 0);

    return \@prog;
}

# eBPF instruction helpers

sub _pack_bpf_insn {
    my ($code, $dst_src, $off, $imm) = @_;
    return pack('CCsl', $code, $dst_src // 0, $off // 0, $imm // 0);
}

use constant {
    _BPF_LDX_MEM_W  => 0x61,
    _BPF_STX_MEM_W  => 0x63,
    _BPF_ALU_AND_K  => 0x54,
    _BPF_ALU_RSH_K  => 0x74,
    _BPF_JNE_K      => 0x55,
    _BPF_JEQ_K      => 0x15,
    _BPF_MOV_K      => 0xb4,
    _BPF_EXIT       => 0x95,
};

sub _bpf_ld_abs {
    my ($off) = @_;
    return [_BPF_LDX_MEM_W, 0x10, $off, 0];
}

sub _bpf_st {
    my ($off) = @_;
    return [_BPF_STX_MEM_W, 0xa0, -4 - $off * 4, 0];
}

sub _bpf_ld_mem {
    my ($off) = @_;
    return [_BPF_LDX_MEM_W, 0x0a, -4 - $off * 4, 0];
}

sub _bpf_alu_and {
    my ($imm) = @_;
    return [_BPF_ALU_AND_K, 0x00, 0, $imm];
}

sub _bpf_alu_rsh {
    my ($imm) = @_;
    return [_BPF_ALU_RSH_K, 0x00, 0, $imm];
}

sub _bpf_jne {
    my ($imm, $jt, $jf) = @_;
    return [_BPF_JNE_K, 0x00, $jt, $imm];
}

sub _bpf_jeq {
    my ($imm, $jt, $jf) = @_;
    return [_BPF_JEQ_K, 0x00, $jt, $imm];
}

sub _bpf_ret {
    my ($val) = @_;
    return [_BPF_MOV_K, 0x00, 0, $val], [_BPF_EXIT, 0x00, 0, 0];
}

our @EXPORT = qw(apply_device_cgroup);

1;
