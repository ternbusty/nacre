package Nacre::Caps;
use strict;
use warnings;
use Exporter 'import';
use Nacre::Const;
use Nacre::Util;

# ═══════════════════════════════════════════════════════════════════════
# Capabilities
# ═══════════════════════════════════════════════════════════════════════

sub validate_capabilities {
    # runc-compatible: ignore unknown capabilities silently.
    # (The OCI spec says MUST error, but runc doesn't, and bats tests
    # expect runc behavior.)
    my ($spec) = @_;
    return unless $spec->{process};  # avoid auto-vivifying {process}
    my $caps = $spec->{process}{capabilities} // return;
    for my $set (qw(bounding effective permitted inheritable ambient)) {
        my @known = grep { exists $CAP_NUM{$_} } @{$caps->{$set} // []};
        $caps->{$set} = \@known;
    }
}

sub apply_capabilities_bounding {
    # Phase 1: Drop bounding caps and set KEEPCAPS.
    # Must be called BEFORE setuid/setgid so that KEEPCAPS preserves the
    # permitted set across the UID transition.
    my ($spec) = @_;
    my $caps = $spec->{process}{capabilities} // return;

    # Drop bounding set
    if (my $bounding = $caps->{bounding}) {
        my %keep = map { $_ => 1 } @$bounding;
        for my $name (@CAP_NAMES) {
            next if $keep{$name};
            my $num = $CAP_NUM{$name} // next;
            do_syscall(SYS_prctl, PR_CAPBSET_DROP, $num, 0, 0, 0);
        }
    }

    # Keep caps across setuid (cleared in phase 2)
    do_syscall(SYS_prctl, PR_SET_KEEPCAPS, 1, 0, 0, 0);
}

sub apply_capabilities_final {
    # Phase 2: Set effective/permitted/inheritable/ambient caps.
    # Must be called AFTER setuid/setgid — the kernel cleared the effective
    # set during setuid but preserved permitted (KEEPCAPS was on).
    my ($spec) = @_;
    my $caps = $spec->{process}{capabilities} // return;

    my ($eff_lo, $eff_hi) = (0, 0);
    my ($prm_lo, $prm_hi) = (0, 0);
    my ($inh_lo, $inh_hi) = (0, 0);

    for my $name (@{$caps->{effective} // []}) {
        my $n = $CAP_NUM{$name} // next;
        if ($n < 32) { $eff_lo |= (1 << $n); } else { $eff_hi |= (1 << ($n - 32)); }
    }
    for my $name (@{$caps->{permitted} // []}) {
        my $n = $CAP_NUM{$name} // next;
        if ($n < 32) { $prm_lo |= (1 << $n); } else { $prm_hi |= (1 << ($n - 32)); }
    }
    for my $name (@{$caps->{inheritable} // []}) {
        my $n = $CAP_NUM{$name} // next;
        if ($n < 32) { $inh_lo |= (1 << $n); } else { $inh_hi |= (1 << ($n - 32)); }
    }
    # Do NOT merge ambient caps into inheritable — runc doesn't.
    # Ambient caps that are not in the spec's inheritable set will
    # fail to raise (EPERM) and produce a warning, matching runc.

    # capset: header (version, pid) + data[2] (effective, permitted, inheritable)
    my $hdr = pack('Ii', _LINUX_CAPABILITY_VERSION_3, 0);
    my $data = pack('III III',
        $eff_lo, $prm_lo, $inh_lo,
        $eff_hi, $prm_hi, $inh_hi);
    my $nr_capset = SYS_capset + 0;
    syscall($nr_capset, $hdr, $data);

    # Clear keepcaps
    do_syscall(SYS_prctl, PR_SET_KEEPCAPS, 0, 0, 0, 0);

    # Raise ambient capabilities
    for my $name (@{$caps->{ambient} // []}) {
        my $n = $CAP_NUM{$name} // next;
        my $ret = do_syscall(SYS_prctl, PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, $n, 0, 0);
        if ($ret == -1) {
            warn "nacre: can't raise ambient capability $name: $!\n";
        }
    }
}

our @EXPORT = qw(
    validate_capabilities apply_capabilities_bounding apply_capabilities_final
);

1;
