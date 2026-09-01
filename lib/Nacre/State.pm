package Nacre::State;
use v5.38;
use Exporter 'import';
use JSON::PP;
use File::Path qw(remove_tree);
use Nacre::Util;

# ═══════════════════════════════════════════════════════════════════════
# OCI Spec loading
# ═══════════════════════════════════════════════════════════════════════

sub load_spec ($bundle) {
    my $config_path = "$bundle/config.json";
    my $raw = read_file_or_die($config_path);
    my $spec = $JSON->decode($raw);
    fatal("invalid ociVersion") unless ($spec->{ociVersion} // '') =~ /^\d+\.\d+\.\d+/;
    return $spec;
}

sub cache_spec ($root, $id, $spec) {
    # OCI spec: updates to config.json after create MUST NOT affect the
    # container.  Snapshot the spec into the state directory.
    my $dir = state_dir($root, $id);
    ensure_dir($dir);
    write_file_atomic("$dir/config.json", $JSON->encode($spec));
}

sub load_cached_spec ($root, $id, $bundle) {
    # Load the spec snapshot from create time, falling back to the
    # bundle's config.json for backwards compatibility.
    my $cached = state_dir($root, $id) . '/config.json';
    my $raw = read_file($cached);
    if (defined $raw) {
        return $JSON->decode($raw);
    }
    return load_spec($bundle);
}

sub default_spec {
    return {
        ociVersion => '1.2.0',
        root => { path => 'rootfs', readonly => JSON::PP::true },
        process => {
            terminal => JSON::PP::true,
            user => { uid => 0, gid => 0 },
            args => [ 'sh' ],
            env => [
                'PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
                'TERM=xterm',
            ],
            cwd => '/',
            capabilities => {
                bounding   => [qw(CAP_AUDIT_WRITE CAP_KILL CAP_NET_BIND_SERVICE)],
                effective  => [qw(CAP_AUDIT_WRITE CAP_KILL CAP_NET_BIND_SERVICE)],
                permitted  => [qw(CAP_AUDIT_WRITE CAP_KILL CAP_NET_BIND_SERVICE)],
            },
            rlimits => [
                { type => 'RLIMIT_NOFILE', hard => 1024, soft => 1024 },
            ],
            noNewPrivileges => JSON::PP::true,
        },
        hostname => 'nacre',
        mounts => [
            { destination => '/proc', type => 'proc', source => 'proc',
              options => [qw(nosuid noexec nodev)] },
            { destination => '/dev', type => 'tmpfs', source => 'tmpfs',
              options => [qw(nosuid strictatime), 'mode=755', 'size=65536k'] },
            { destination => '/dev/pts', type => 'devpts', source => 'devpts',
              options => [qw(nosuid noexec), 'newinstance', 'ptmxmode=0666', 'mode=0620'] },
            { destination => '/dev/shm', type => 'tmpfs', source => 'shm',
              options => [qw(nosuid noexec nodev), 'mode=1777', 'size=65536k'] },
            { destination => '/dev/mqueue', type => 'mqueue', source => 'mqueue',
              options => [qw(nosuid noexec nodev)] },
            { destination => '/sys', type => 'sysfs', source => 'sysfs',
              options => [qw(nosuid noexec nodev ro)] },
            { destination => '/sys/fs/cgroup', type => 'cgroup', source => 'cgroup',
              options => [qw(nosuid noexec nodev ro)] },
        ],
        linux => {
            resources => {
                devices => [ { allow => JSON::PP::false, access => 'rwm' } ],
            },
            namespaces => [
                { type => 'pid' },
                { type => 'network' },
                { type => 'ipc' },
                { type => 'uts' },
                { type => 'mount' },
                { type => 'cgroup' },
            ],
            maskedPaths => [qw(
                /proc/acpi /proc/asound /proc/kcore /proc/keys
                /proc/latency_stats /proc/timer_list /proc/timer_stats
                /proc/sched_debug /proc/scsi /sys/firmware
                /sys/devices/virtual/powercap
            )],
            readonlyPaths => [qw(
                /proc/bus /proc/fs /proc/irq /proc/sys /proc/sysrq-trigger
            )],
        },
    };
}

# ═══════════════════════════════════════════════════════════════════════
# Container State
# ═══════════════════════════════════════════════════════════════════════

sub state_dir ($root, $id) {
    return "$root/$id";
}

sub load_state ($root, $id) {
    my $path = state_dir($root, $id) . '/state.json';
    my $raw = read_file($path);
    fatal("container '$id' does not exist") unless defined $raw;
    my $state = $JSON->decode($raw);
    refresh_state($state);
    return $state;
}

sub save_state ($root, $state) {
    my $dir = state_dir($root, $state->{id});
    ensure_dir($dir);
    write_file_atomic("$dir/state.json", $JSON->encode($state));
}

sub delete_state ($root, $id) {
    my $dir = state_dir($root, $id);
    remove_tree($dir) if -d $dir;
}

sub refresh_state ($state) {
    my $pid = $state->{pid};
    return unless $pid && $pid > 0;
    my $status = $state->{status};
    return if $status eq 'stopped';

    # Check if process is alive
    my $stat = read_file("/proc/$pid/stat");
    if (!defined $stat) {
        $state->{status} = 'stopped';
        $state->{pid} = 0;
        return;
    }

    # PID reuse detection via starttime
    if ($state->{pidStartTime}) {
        my $current_start = parse_proc_starttime($stat);
        if (defined $current_start && $current_start ne $state->{pidStartTime}) {
            $state->{status} = 'stopped';
            $state->{pid} = 0;
            return;
        }
    }

    # Check zombie/dead
    if ($stat =~ /\)\s+([RSDZTW])/) {
        my $proc_state = $1;
        if ($proc_state eq 'Z' || $proc_state eq 'X') {
            $state->{status} = 'stopped';
        }
    }
}

sub parse_proc_starttime ($stat_line) {
    # /proc/pid/stat: pid (comm) state ppid pgrp session tty_nr tpgid flags
    #   minflt cminflt majflt cmajflt utime stime cutime cstime priority nice
    #   num_threads itrealvalue starttime ...
    # comm can contain spaces and parens, so find the last ')'
    if ($stat_line =~ /\)\s+\S+\s+          # state
                        \S+\s+\S+\s+\S+\s+  # ppid pgrp session
                        \S+\s+\S+\s+\S+\s+  # tty tpgid flags
                        \S+\s+\S+\s+\S+\s+  # minflt cminflt majflt
                        \S+\s+\S+\s+\S+\s+  # cmajflt utime stime
                        \S+\s+\S+\s+\S+\s+  # cutime cstime priority
                        \S+\s+\S+\s+\S+\s+  # nice threads itrealvalue
                        (\S+)/x) {
        return $1;
    }
    return undef;
}

sub get_pid_starttime ($pid) {
    my $stat = read_file("/proc/$pid/stat");
    return undef unless $stat;
    return parse_proc_starttime($stat);
}

sub oci_state_json ($state) {
    my $out = {
        ociVersion  => $state->{ociVersion} // '1.2.0',
        id          => $state->{id},
        status      => $state->{status},
        bundle      => $state->{bundle},
        rootfs      => $state->{rootfs} // '',
        annotations => $state->{annotations} // {},
        created     => $state->{created} // '',
    };
    # OCI spec: pid MUST NOT be present when the container is stopped
    if ($state->{status} ne 'stopped') {
        $out->{pid} = $state->{pid} + 0;
    }
    return $out;
}

our @EXPORT = qw(
    load_spec cache_spec load_cached_spec default_spec
    state_dir load_state save_state delete_state refresh_state
    parse_proc_starttime get_pid_starttime oci_state_json
);

1;
