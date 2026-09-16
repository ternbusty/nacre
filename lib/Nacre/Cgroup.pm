package Nacre::Cgroup;
use v5.38;
use feature 'try';
no warnings 'experimental::try';
use Exporter 'import';
use Nacre::Util qw(log_debug fatal write_file read_file ensure_dir);
use Errno qw(EBUSY);
use Time::HiRes qw(usleep);

# ═══════════════════════════════════════════════════════════════════════
# Cgroup v2
# ═══════════════════════════════════════════════════════════════════════

my $CGROUP_ROOT = '/sys/fs/cgroup';

sub cgroup_path ($spec, $id) {
    my $rel = $spec->{linux}{cgroupsPath};
    if ($rel && $rel =~ m{^/}) {
        return "$CGROUP_ROOT$rel";
    } elsif ($rel) {
        return "$CGROUP_ROOT/nacre/$rel";
    } else {
        return "$CGROUP_ROOT/nacre/$id";
    }
}

sub cgroup_setup ($cgpath, $spec) {

    # Check if cgroup already exists and has processes (non-empty cgroup)
    if (-d $cgpath) {
        my $procs = read_file("$cgpath/cgroup.procs");
        if (defined $procs && $procs =~ /\d/) {
            fatal("container's cgroup is not empty: $cgpath");
        }

        # Check if cgroup is frozen
        my $freeze = read_file("$cgpath/cgroup.freeze");
        if (defined $freeze) {
            chomp $freeze;
            if ($freeze eq '1') {
                fatal("container's cgroup unexpectedly frozen");
            }
        }
    }

    ensure_dir($cgpath);

    # Enable controllers up the tree
    my @parts = split m{/}, $cgpath;
    my $root_parts = scalar(split m{/}, $CGROUP_ROOT);
    for my $depth ($root_parts .. $#parts - 1) {
        my $ancestor = join('/', @parts[0 .. $depth]);
        my $sc_file = "$ancestor/cgroup.subtree_control";
        next unless -f $sc_file;
        my $current = read_file($sc_file) // '';
        for my $ctrl (qw(cpu memory pids io cpuset hugetlb)) {
            if ($current !~ /\b$ctrl\b/) {
                eval {write_file($sc_file, "+$ctrl\n");};
            }
        }
    }

    # Apply resources
    cgroup_apply_resources($cgpath, $spec);
    return;
}

# ── Private helpers for cgroup_apply_resources ────────────────────────

sub _apply_memory ($cgpath, $mem) {
    my $new_limit = $mem->{limit};
    my $new_swap = $mem->{swap};
    my $cur_limit = read_file("$cgpath/memory.max");
    chomp($cur_limit //= 'max');
    my $cur_val = ($cur_limit eq 'max') ? ~0 : int($cur_limit);
    my $new_val = (defined $new_limit && $new_limit ne 'max') ? int($new_limit) : ~0;

    # cgroup v2: memory.swap.max = swap-only, but OCI spec's "swap"
    # field is memory+swap total.  Convert: swap_only = swap - limit.
    if (defined $new_swap && $new_swap ne 'max') {
        my $mem_for_sub = (defined $new_limit && $new_limit ne 'max') ? int($new_limit) : $cur_val;
        if ($mem_for_sub != ~0) {
            $new_swap = int($new_swap) - int($mem_for_sub);
            $new_swap = 0 if $new_swap < 0;
        }
    }

    if ($new_val > $cur_val) {

        # Increasing memory.max — write limit first so swap stays valid
        cg_write($cgpath, 'memory.max', $new_limit) if defined $new_limit;
        cg_write($cgpath, 'memory.swap.max', $new_swap) if defined $new_swap;
    } else {

        # Decreasing or unchanged — write swap first, then limit
        cg_write($cgpath, 'memory.swap.max', $new_swap) if defined $new_swap;
        cg_write($cgpath, 'memory.max', $new_limit) if defined $new_limit;
    }
    cg_write($cgpath, 'memory.low', $mem->{reservation}) if defined $mem->{reservation};
    return;
}

sub _apply_cpu ($cgpath, $cpu) {
    if (defined $cpu->{shares}) {
        my $weight = convert_cpu_shares($cpu->{shares});
        cg_write($cgpath, 'cpu.weight', $weight);
    }
    if (defined $cpu->{quota} || defined $cpu->{period}) {

        # When only one of quota/period is being updated, read the
        # current value of the other from cpu.max.
        my ($cur_quota, $cur_period) = ('max', 100000);
        my $cur = read_file("$cgpath/cpu.max");
        if (defined $cur && $cur =~ /^(\S+)\s+(\d+)/) {
            ($cur_quota, $cur_period) = ($1, int($2));
        }
        my $quota = $cpu->{quota} // $cur_quota;
        my $period = $cpu->{period} // $cur_period;
        cg_write($cgpath, 'cpu.max', "$quota $period", fatal => 1);
    }
    if (defined $cpu->{burst}) {
        cg_write($cgpath, 'cpu.max.burst', $cpu->{burst});
    }
    if (defined $cpu->{idle}) {
        cg_write($cgpath, 'cpu.idle', $cpu->{idle});
    }
    cg_write($cgpath, 'cpuset.cpus', $cpu->{cpus}) if defined $cpu->{cpus};
    cg_write($cgpath, 'cpuset.mems', $cpu->{mems}) if defined $cpu->{mems};
    return;
}

sub _apply_pids ($cgpath, $pids) {
    my $max = $pids->{limit} // 'max';
    if ($max eq 'max' || $max < 0) {
        $max = 'max';
    } elsif ($max == 0) {

        # pids.limit=0 means 1 (minimum useful value)
        $max = 1;
    }
    cg_write($cgpath, 'pids.max', $max);
    return;
}

sub _apply_io ($cgpath, $io) {
    if (defined $io->{weight}) {
        my $weight = $io->{weight};
        cg_write($cgpath, 'io.weight', "default $weight");
    }
    if (my $tbd = $io->{throttleReadBpsDevice}) {
        for my $d (@$tbd) {
            cg_write($cgpath, 'io.max', "$d->{major}:$d->{minor} rbps=$d->{rate}");
        }
    }
    if (my $tbd = $io->{throttleWriteBpsDevice}) {
        for my $d (@$tbd) {
            cg_write($cgpath, 'io.max', "$d->{major}:$d->{minor} wbps=$d->{rate}");
        }
    }
    if (my $tbd = $io->{throttleReadIOPSDevice}) {
        for my $d (@$tbd) {
            cg_write($cgpath, 'io.max', "$d->{major}:$d->{minor} riops=$d->{rate}");
        }
    }
    if (my $tbd = $io->{throttleWriteIOPSDevice}) {
        for my $d (@$tbd) {
            cg_write($cgpath, 'io.max', "$d->{major}:$d->{minor} wiops=$d->{rate}");
        }
    }
    return;
}

sub _apply_hugetlb ($cgpath, $hugetlb) {
    for my $entry (@$hugetlb) {
        my $size = $entry->{pageSize} // next;
        my $limit = $entry->{limit} // next;
        cg_write($cgpath, "hugetlb.${size}.max", $limit);
    }
    return;
}

# ── Main resource dispatcher ─────────────────────────────────────────

sub cgroup_apply_resources ($cgpath, $spec, %opts) {
    log_debug("applying cgroup resources");
    my $res = $spec->{linux}{resources} // {};

    _apply_memory($cgpath, $res->{memory}) if $res->{memory};
    _apply_cpu($cgpath, $res->{cpu}) if $res->{cpu};
    _apply_pids($cgpath, $res->{pids}) if $res->{pids} && !$opts{defer_pids};
    _apply_hugetlb($cgpath, $res->{hugepageLimits}) if $res->{hugepageLimits};
    _apply_io($cgpath, $res->{blockIO}) if $res->{blockIO};

    # Unified (raw cgroup file writes)
    if (my $u = $res->{unified}) {
        for my $key (keys %$u) {
            my $val = $u->{$key};

            # Multi-line values: write each line separately (cgroup files
            # like io.max only process one device-line per write syscall)
            for my $line (split /\n/, $val) {
                $line =~ s/^\s+//;
                $line =~ s/\s+$//;
                next if $line eq '';
                cg_write($cgpath, $key, $line);
            }
        }
    }
    return;
}

sub cgroup_add_process ($cgpath, $pid) {
    cg_write($cgpath, 'cgroup.procs', $pid);
    return;
}

sub cgroup_cleanup ($cgpath) {
    return unless -d $cgpath;

    # Kill all processes in the cgroup
    my $procs = read_file("$cgpath/cgroup.procs") // '';
    for my $pid (split /\n/, $procs) {
        next unless $pid =~ /^\d+$/;
        kill 9, $pid;
    }

    # Wait a bit for processes to die
    my $deadline = time + 2;
    while (time < $deadline) {
        $procs = read_file("$cgpath/cgroup.procs") // '';
        last unless $procs =~ /\d/;
        usleep(50_000);
    }

    # Remove cgroup directory with retry (EBUSY)
    for my $attempt (1 .. 10) {
        last if rmdir($cgpath);
        last unless $! == EBUSY;
        usleep(50_000 * $attempt);
    }
    return;
}

sub cgroup_pids ($cgpath) {
    my $data = read_file("$cgpath/cgroup.procs") // '';
    return grep {/^\d+$/} split /\n/, $data;
}

sub cg_read ($cgpath, $file) {
    return read_file("$cgpath/$file");
}

sub cg_write ($cgpath, $file, $value, %opts) {
    my $path = "$cgpath/$file";
    try {
        write_file($path, "$value\n");
    } catch ($e) {
        if ($opts{fatal}) {
            $e =~ s/ at \S+ line \d+.*//s;
            chomp $e;
            fatal("unable to write $file: $e");
        }

        # Non-fatal by default: some cgroup files may not exist
    }
    return;
}

sub convert_cpu_shares ($shares) {
    return 0 if !$shares || $shares == 0;
    return 1 if $shares <= 2;
    return 10000 if $shares >= 262144;

    # Logarithmic conversion matching runc's ConvertCPUSharesToCgroupV2Value
    my $l = log($shares) / log(2);
    my $exponent = ($l * $l + 125 * $l) / 612.0 - 7.0 / 34.0;
    return int(exp($exponent * log(10)) + 0.99);
}

our @EXPORT_OK = qw(
    cgroup_path cgroup_setup cgroup_apply_resources
    cgroup_add_process cgroup_cleanup cgroup_pids
    cg_read cg_write
);

1;
