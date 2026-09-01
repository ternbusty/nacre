package Nacre::Mount;
use v5.38;
use feature 'try';
no warnings 'experimental::try';
use Exporter 'import';
use POSIX qw(_exit);
use File::Basename qw(dirname);
use Fcntl qw(:mode O_RDONLY);
use Errno qw(EINTR EPERM);
use Socket qw(AF_UNIX SOCK_STREAM);
use Cwd qw(abs_path);
use Nacre::Const;
use Nacre::Util;
use Nacre::IPC;

# ═══════════════════════════════════════════════════════════════════════
# Mount / Rootfs
# ═══════════════════════════════════════════════════════════════════════

our %MOUNT_FLAGS = (
    bind        => MS_BIND,
    rbind       => MS_BIND | MS_REC,
    ro          => MS_RDONLY,
    rw          => 0,
    nosuid      => MS_NOSUID,
    suid        => 0,
    nodev       => MS_NODEV,
    dev         => 0,
    noexec      => MS_NOEXEC,
    exec        => 0,
    noatime     => MS_NOATIME,
    atime       => 0,
    nodiratime  => MS_NODIRATIME,
    diratime    => 0,
    relatime    => MS_RELATIME,
    norelatime  => 0,
    strictatime => MS_STRICTATIME,
    nostrictatime => 0,
    remount     => MS_REMOUNT,
    sync        => 16,     # MS_SYNCHRONOUS
    async       => 0,
    dirsync     => 128,    # MS_DIRSYNC
    silent      => MS_SILENT,
    loud        => 0,
    slave       => MS_SLAVE,
    rslave      => MS_SLAVE | MS_REC,
    private     => MS_PRIVATE,
    rprivate    => MS_PRIVATE | MS_REC,
    shared      => MS_SHARED,
    rshared     => MS_SHARED | MS_REC,
    unbindable  => MS_UNBINDABLE,
    runbindable => MS_UNBINDABLE | MS_REC,
    readonly    => MS_RDONLY,
);

# Recursive mount attributes that need mount_setattr() (kernel 5.12+)
my %RECURSIVE_MOUNT_ATTRS = (
    rro            => { set => MOUNT_ATTR_RDONLY,     clear => 0 },
    rrw            => { set => 0,                     clear => MOUNT_ATTR_RDONLY },
    rnosuid        => { set => MOUNT_ATTR_NOSUID,     clear => 0 },
    rsuid          => { set => 0,                     clear => MOUNT_ATTR_NOSUID },
    rnodev         => { set => MOUNT_ATTR_NODEV,      clear => 0 },
    rdev           => { set => 0,                     clear => MOUNT_ATTR_NODEV },
    rnoexec        => { set => MOUNT_ATTR_NOEXEC,     clear => 0 },
    rexec          => { set => 0,                     clear => MOUNT_ATTR_NOEXEC },
    ratime         => { set => 0,                     clear => 0, atime => 0 },  # relatime (default)
    rnoatime       => { set => MOUNT_ATTR_NOATIME,    clear => 0, atime => 1 },
    rstrictatime   => { set => MOUNT_ATTR_STRICTATIME, clear => 0, atime => 1 },
    rnostrictatime => { set => 0,                     clear => 0, atime => 0 },
    rrelatime      => { set => 0,                     clear => 0, atime => 0 },  # relatime
    rnorelatime    => { set => 0,                     clear => 0, atime => 0 },
    rnodiratime    => { set => MOUNT_ATTR_NODIRATIME,  clear => 0 },
    rdiratime      => { set => 0,                     clear => MOUNT_ATTR_NODIRATIME },
);

sub do_mount_setattr ($dirfd, $path, $flags, $attr_set, $attr_clr, $userns_fd = undef) {
    # struct mount_attr { __u64 attr_set, attr_clr, propagation, userns_fd; }
    my $attr = pack('QQQQ', $attr_set, $attr_clr, 0, $userns_fd // 0);
    my $nr = SYS_mount_setattr + 0;
    my $df = $dirfd + 0;
    my $p  = $path . "\0";
    my $fl = $flags + 0;
    my $sz = length($attr) + 0;
    my $ret;
    do { $ret = syscall($nr, $df, $p, $fl, $attr, $sz) }
        while ($ret == -1 && $! == EINTR);
    return $ret == 0;
}

sub do_open_tree ($dirfd, $path, $flags) {
    my $nr = SYS_open_tree + 0;
    my $df = $dirfd + 0;
    my $fl = $flags + 0;
    my $ret;
    do { $ret = syscall($nr, $df, $path, $fl) }
        while ($ret == -1 && $! == EINTR);
    return $ret;
}

sub do_move_mount ($from_fd, $from_path, $to_fd, $to_path, $flags) {
    my $nr = SYS_move_mount + 0;
    my $ffd = $from_fd + 0;
    my $tfd = $to_fd + 0;
    my $fl  = $flags + 0;
    my $ret;
    do { $ret = syscall($nr, $ffd, $from_path, $tfd, $to_path, $fl) }
        while ($ret == -1 && $! == EINTR);
    return $ret == 0;
}

sub parse_mount_options ($opts_ref) {
    my $flags = 0;
    my @data;
    for my $opt (@{$opts_ref // []}) {
        if (exists $MOUNT_FLAGS{$opt}) {
            $flags |= $MOUNT_FLAGS{$opt};
        } else {
            push @data, $opt;
        }
    }
    return ($flags, join(',', @data));
}

sub do_mount ($src, $target, $fstype, $flags, $data) {
    # Perl's syscall() passes strings as pointers, integers as values.
    # The kernel's mount(2) expects NULL pointers for unused args, not
    # pointers to empty strings (which it tries to resolve as paths → ENOENT).
    #
    # IMPORTANT: we call syscall() directly here instead of going through
    # do_syscall(), because Perl's @_ aliasing chain corrupts the argument
    # types when mixing integer 0 (NULL pointer) and string arguments.
    # Fresh lexical scalars with + 0 coercion guarantee clean IOK-only SVs.
    my $nr       = SYS_mount + 0;
    my $src_arg  = (defined $src    && $src    ne '') ? ($src    . "\0") : 0;
    my $tgt_arg  = $target . "\0";
    my $fs_arg   = (defined $fstype && $fstype ne '') ? ($fstype . "\0") : 0;
    my $fl       = $flags + 0;
    my $data_arg = (defined $data   && $data   ne '') ? ($data   . "\0") : 0;
    my $ret;
    do {
        $ret = syscall($nr, $src_arg, $tgt_arg, $fs_arg, $fl, $data_arg);
    } while ($ret == -1 && $! == EINTR);
    return $ret == 0;
}

sub do_umount ($target, $flags = 0) {
    my $nr  = SYS_umount2 + 0;
    my $tgt = $target . "\0";
    my $fl  = $flags + 0;
    my $ret;
    do { $ret = syscall($nr, $tgt, $fl) } while ($ret == -1 && $! == EINTR);
    return $ret == 0;
}

sub do_pivot_root ($new_root, $put_old) {
    my $nr  = SYS_pivot_root + 0;
    my $nrt = $new_root . "\0";
    my $pot = $put_old . "\0";
    my $ret;
    do { $ret = syscall($nr, $nrt, $pot) } while ($ret == -1 && $! == EINTR);
    return $ret == 0;
}

# Default devices to create
my @DEFAULT_DEVICES = (
    { path => '/dev/null',    type => 'c', major => 1, minor => 3, mode => 0o666 },
    { path => '/dev/zero',    type => 'c', major => 1, minor => 5, mode => 0o666 },
    { path => '/dev/full',    type => 'c', major => 1, minor => 7, mode => 0o666 },
    { path => '/dev/random',  type => 'c', major => 1, minor => 8, mode => 0o666 },
    { path => '/dev/urandom', type => 'c', major => 1, minor => 9, mode => 0o666 },
    { path => '/dev/tty',     type => 'c', major => 5, minor => 0, mode => 0o666 },
);

# Default symlinks for /dev
my @DEFAULT_SYMLINKS = (
    { path => '/dev/fd',     target => '/proc/self/fd'     },
    { path => '/dev/stdin',  target => '/proc/self/fd/0'   },
    { path => '/dev/stdout', target => '/proc/self/fd/1'   },
    { path => '/dev/stderr', target => '/proc/self/fd/2'   },
    { path => '/dev/ptmx',   target => 'pts/ptmx'          },
);

my %PROPAGATION_FLAGS = (
    slave    => MS_SLAVE    | MS_REC,
    rslave   => MS_SLAVE    | MS_REC,
    private  => MS_PRIVATE  | MS_REC,
    rprivate => MS_PRIVATE  | MS_REC,
    shared   => MS_SHARED   | MS_REC,
    rshared  => MS_SHARED   | MS_REC,
    unbindable  => MS_UNBINDABLE | MS_REC,
    runbindable => MS_UNBINDABLE | MS_REC,
);

sub _copy_dir_contents ($src, $dst) {
    opendir(my $dh, $src) or return;
    while (my $ent = readdir($dh)) {
        next if $ent eq '.' || $ent eq '..';
        my $s = "$src/$ent";
        my $d = "$dst/$ent";
        if (-d $s && !-l $s) {
            mkdir $d, 0755;
            _copy_dir_contents($s, $d);
            # Preserve permissions
            my @st = stat($s);
            chmod $st[2] & 07777, $d if @st;
        } elsif (-l $s) {
            my $target = readlink($s);
            symlink($target, $d) if defined $target;
        } else {
            # Copy file content
            if (open my $in, '<:raw', $s) {
                if (open my $out, '>:raw', $d) {
                    my $buf;
                    while (sysread($in, $buf, 65536)) {
                        print $out $buf;
                    }
                    close $out;
                    my @st = stat($s);
                    chmod $st[2] & 07777, $d if @st;
                }
                close $in;
            }
        }
    }
    closedir $dh;
}

sub prepare_rootfs ($spec, $rootfs, $mount_source_fds, $chan_w, $chan_r) {

    # ALWAYS make "/" rslave before any rootfs setup to prevent mount
    # events from propagating back to the parent mount namespace.
    # The spec's rootfsPropagation (shared, rslave, etc.) is applied
    # AFTER pivot_root by apply_rootfs_propagation, not here.
    do_mount('', '/', '', MS_SLAVE | MS_REC, '')
        or fatal("mount propagation (setup) /: $!");

    # Make the rootfs mount point (or its nearest parent mount) private.
    # This ensures the bind mount below creates a private copy that won't
    # propagate events back to the host (matching runc's
    # rootfsParentMountPrivate).
    {
        my $p = $rootfs;
        while (!do_mount('', $p, '', MS_PRIVATE, '')) {
            last if $p eq '/';
            $p =~ s{/[^/]*$}{} || ($p = '/');
        }
    }

    # Bind mount rootfs on itself
    do_mount($rootfs, $rootfs, '', MS_BIND | MS_REC, '')
        or fatal("bind mount rootfs: $!");

    # Apply spec mounts (returns whether /dev needs deferred ro remount)
    my $dev_needs_ro = apply_mounts($spec, $rootfs, $mount_source_fds, $chan_w, $chan_r);

    # Create default devices via bind mount
    create_devices($rootfs, $spec);

    # Create default symlinks
    create_symlinks($rootfs);

    # Deferred /dev readonly remount (after devices are created)
    if ($dev_needs_ro) {
        do_mount('', "$rootfs/dev", '', MS_REMOUNT | MS_BIND | MS_RDONLY, '')
            or warn "nacre: remount /dev ro: $!\n";
    }
}

# Build "containerID hostID size\n" mapping string for idmap userns
sub _build_map_string ($maps) {
    return '' unless ref $maps eq 'ARRAY' && @$maps;
    return join('', map { "$_->{containerID} $_->{hostID} $_->{size}\n" } @$maps);
}

# Create a user namespace with specific UID/GID mappings for idmap mounts.
# Returns the userns fd.
sub _create_userns_for_idmap ($uid_maps, $gid_maps, $chan_w, $chan_r) {

    my $uid_str = _build_map_string($uid_maps);
    my $gid_str = _build_map_string($gid_maps);
    $uid_str = "0 0 4294967295\n" if $uid_str eq '';
    $gid_str = "0 0 4294967295\n" if $gid_str eq '';

    # Create socketpair for passing the userns fd back
    socketpair(my $p_sock, my $c_sock, AF_UNIX, SOCK_STREAM, 0)
        or fatal("socketpair: $!");

    # Create sync pipes
    pipe(my $pr, my $cw) or fatal("pipe: $!");
    pipe(my $cr, my $pw) or fatal("pipe: $!");

    my $child = fork();
    fatal("fork: $!") unless defined $child;

    if ($child == 0) {
        close $p_sock;
        close $pr;
        close $pw;
        # Unshare user namespace
        my $nr = SYS_unshare + 0;
        my $fl = CLONE_NEWUSER + 0;
        syscall($nr, $fl) == 0 or _exit(1);
        # Send host PID to parent.  /proc/self resolves to the PID in the
        # procfs's PID namespace (the host one), even when we are inside a
        # new PID namespace.  fork() returns the child PID in the caller's
        # (new) PID namespace, which does NOT match /proc entries when the
        # host /proc is still mounted.
        my $host_pid = readlink('/proc/self') // '';
        # Signal parent: "ready for mappings" — send host PID
        syswrite($cw, "$host_pid\n", length("$host_pid\n"));
        close $cw;
        # Wait for parent to write mappings
        my $buf;
        sysread($cr, $buf, 1);
        close $cr;
        # Send userns fd to parent via SCM_RIGHTS
        sysopen(my $ns_fh, '/proc/self/ns/user', O_RDONLY) or _exit(1);
        send_fd_over_fd(fileno($c_sock), fileno($ns_fh));
        close $ns_fh;
        close $c_sock;
        _exit(0);
    }

    close $c_sock;
    close $cw;
    close $cr;
    # Wait for child to unshare and send its host PID.
    # When this function is called from the init process (which is in a
    # new PID namespace), fork() returns the child's PID in the new PID
    # namespace, but /proc still shows the host PID namespace.  The child
    # reads /proc/self to get its host PID and sends it to us.
    my $buf;
    sysread($pr, $buf, 64);
    close $pr;
    chomp $buf;
    my $proc_pid = ($buf =~ /^(\d+)$/) ? $1 : $child;

    # Write mappings using the host PID (which matches /proc entries).
    # When called from inside a container userns, writing to the host
    # /proc may fail — let the error propagate so callers can fall back
    # to the parent process.
    try {
        write_file("/proc/$proc_pid/setgroups", "deny");
        write_file("/proc/$proc_pid/uid_map", $uid_str);
        write_file("/proc/$proc_pid/gid_map", $gid_str);
    } catch ($err) {
        close $pw;
        close $p_sock;
        kill 'KILL', $child;
        waitpid($child, 0);
        die $err;
    }

    # Signal child: "mappings written"
    syswrite($pw, "D", 1);
    close $pw;

    # Receive userns fd
    my $userns_fd = recv_fd_over_fd(fileno($p_sock));
    close $p_sock;
    waitpid($child, 0);

    fatal("failed to receive userns fd for idmap") if $userns_fd < 0;
    return $userns_fd;
}

# Create a user namespace from pre-built mapping strings (parent-side).
sub _create_userns_from_strings ($uid_map_str, $gid_map_str) {
    socketpair(my $p_sock, my $c_sock, AF_UNIX, SOCK_STREAM, 0) or fatal("socketpair: $!");
    pipe(my $pr, my $cw) or fatal("pipe: $!");
    pipe(my $cr, my $pw) or fatal("pipe: $!");
    my $child = fork();
    fatal("fork: $!") unless defined $child;
    if ($child == 0) {
        close $p_sock; close $pr; close $pw;
        my $nr = SYS_unshare + 0;
        my $fl = CLONE_NEWUSER + 0;
        syscall($nr, $fl) == 0 or _exit(1);
        syswrite($cw, "R", 1); close $cw;
        my $b; sysread($cr, $b, 1); close $cr;
        sysopen(my $fh, '/proc/self/ns/user', O_RDONLY) or _exit(1);
        send_fd_over_fd(fileno($c_sock), fileno($fh));
        close $fh; close $c_sock;
        _exit(0);
    }
    close $c_sock; close $cw; close $cr;
    my $b; sysread($pr, $b, 1); close $pr;
    eval { write_file("/proc/$child/setgroups", "deny") };
    write_file("/proc/$child/uid_map", $uid_map_str);
    write_file("/proc/$child/gid_map", $gid_map_str);
    syswrite($pw, "D", 1); close $pw;
    my $userns_fd = recv_fd_over_fd(fileno($p_sock));
    close $p_sock;
    waitpid($child, 0);
    fatal("failed to create userns for idmap") if $userns_fd < 0;
    return $userns_fd;
}

## Resolve symlinks in a container path, staying within the rootfs.
## Follows each symlink component (absolute targets are relative to rootfs).
## Returns the fully-resolved host path (under $rootfs).
## The final target need not exist (dangling symlink tail is fine).
sub _resolve_in_rootfs ($rootfs, $path) {
    my @parts = grep { $_ ne '' } split('/', $path);
    my @resolved;
    my $depth = 0;
    while (@parts) {
        return undef if ++$depth > 255;   # symlink loop guard
        my $c = shift @parts;
        next if $c eq '.';
        if ($c eq '..') { pop @resolved if @resolved; next; }
        push @resolved, $c;
        my $cur = $rootfs . '/' . join('/', @resolved);
        if (-l $cur) {
            my $target = readlink($cur) // last;
            pop @resolved;                # remove the symlink itself
            if ($target =~ m{^/}) {
                @resolved = ();           # absolute → restart from rootfs
            }
            unshift @parts, grep { $_ ne '' } split('/', $target);
        }
    }
    return $rootfs . '/' . join('/', @resolved);
}

sub apply_mounts ($spec, $rootfs, $mount_source_fds, $chan_w, $chan_r) {
    $mount_source_fds //= {};
    log_debug("applying mounts, rootfs=$rootfs");

    # Track /dev ro remount: defer MS_RDONLY on /dev until after device creation
    my $dev_needs_ro = 0;

    # Track which destination directories pre-existed before ensure_dir
    my %dest_preexisted;

    for my $m (@{$spec->{mounts} // []}) {
        # If the destination already starts with the rootfs path (e.g.
        # container-relative bind mount sources use full paths), use it
        # as-is to avoid doubling the prefix.
        my $dest = (index($m->{destination}, $rootfs) == 0)
            ? $m->{destination}
            : "$rootfs$m->{destination}";
        my $mount_src = $m->{source} // '';
        my $type = $m->{type} // '';

        # Normalize cgroup mount type: runc's default spec uses "cgroup"
        # for both v1 and v2.  On cgroup v2 systems, the kernel filesystem
        # type is "cgroup2".
        if ($type eq 'cgroup' && -f '/sys/fs/cgroup/cgroup.controllers') {
            $type = 'cgroup2';
        }

        log_debug("apply_mounts: processing $m->{destination} type=$type dest=$dest");

        # Security: /proc and /sys must not be symlinks (CVE-2023-27561 / CVE-2019-19921)
        if ($type eq 'proc' || $type eq 'sysfs') {
            if (-l $dest) {
                fatal("$m->{destination} must be mounted on ordinary directory");
            }
        }

        # Resolve symlinks in the destination path (within the rootfs).
        # Mount destinations that go through symlinks (e.g. /etc/hosts →
        # /tmp/hosts) must be resolved so the mount lands at the real path.
        # The resolved target may not exist yet — that's fine, we create it.
        {
            my $container_dest = $m->{destination};
            if (index($container_dest, $rootfs) == 0) {
                $container_dest = substr($container_dest, length($rootfs));
            }
            my $resolved = _resolve_in_rootfs($rootfs, $container_dest);
            if (defined $resolved && $resolved ne $dest) {
                log_debug("  symlink resolved: $dest -> $resolved");
                $dest = $resolved;
            }
        }

        # For bind mounts of files, create a file mount point instead of dir
        if ($mount_src ne '' && -f $mount_src && grep { $_ eq 'bind' || $_ eq 'rbind' } @{$m->{options} // []}) {
            my $parent = dirname($dest);
            ensure_dir($parent);
            if (!-e $dest) {
                open my $fh, '>', $dest;
                close $fh if $fh;
            }
        } elsif ($mount_src ne '' && -d $mount_src && grep { $_ eq 'bind' || $_ eq 'rbind' } @{$m->{options} // []}) {
            # Bind mount of a directory onto a symlink-resolved target:
            # create the target as a directory.
            ensure_dir($dest);
            $dest_preexisted{$dest} = -d $dest;
        } else {
            # Track whether the directory existed before ensure_dir creates it.
            # We only inherit tmpfs mode from pre-existing directories.
            my $dest_preexisted = -d $dest;
            ensure_dir($dest);
            if (!-d $dest) {
                warn "nacre: ensure_dir: $dest still not a dir after ensure_dir (exists=" . (-e $dest ? "yes" : "no") . " uid=$< euid=$>)\n";
            }
            $dest_preexisted{$dest} = $dest_preexisted;
        }

        # Filter out OCI-specific pseudo-options and recursive mount attrs
        my @raw_opts = @{$m->{options} // []};
        my $tmpcopyup = 0;
        my $has_idmap = 0;
        my $has_ridmap = 0;
        my @real_opts;
        my @recursive_attrs;  # recursive mount_setattr options
        for my $o (@raw_opts) {
            if ($o eq 'tmpcopyup' || $o eq 'copy') {
                $tmpcopyup = 1;
            } elsif ($o eq 'idmap') {
                $has_idmap = 1;
            } elsif ($o eq 'ridmap') {
                $has_ridmap = 1;
            } elsif (exists $RECURSIVE_MOUNT_ATTRS{$o}) {
                push @recursive_attrs, $o;
            } else {
                push @real_opts, $o;
            }
        }
        # OCI spec: idmap mounts are also identified by per-mount
        # uidMappings/gidMappings (not just the "idmap" option string).
        if (!$has_idmap && !$has_ridmap && ($m->{uidMappings} || $m->{gidMappings})) {
            $has_idmap = 1;
        }
        my ($flags, $data) = parse_mount_options(\@real_opts);
        my $src  = $m->{source} // $type;

        # For /dev tmpfs mount, defer ro flag until after device creation
        if ($m->{destination} eq '/dev' && $type eq 'tmpfs' && ($flags & MS_RDONLY)) {
            $flags &= ~MS_RDONLY;
            $dev_needs_ro = 1;
        }

        # tmpfs mode= inherit: if mounting tmpfs without explicit mode=
        # in the options, inherit the existing directory's permissions.
        # Only inherit from pre-existing directories — directories freshly
        # created by ensure_dir have mode 0755 which is just the mkdir default,
        # not a user intent.  Let the kernel use its tmpfs default (1777).
        if ($type eq 'tmpfs' && $dest_preexisted{$dest} && $data !~ /\bmode=/) {
            my @st = stat($dest);
            if (@st) {
                my $mode = sprintf('%o', $st[2] & 07777);
                $data = $data ? "$data,mode=$mode" : "mode=$mode";
            }
        }

        # tmpcopyup: bind-mount dest to a temp location, mount tmpfs,
        # then copy content from the temp back into the tmpfs.
        my $tmpcopy_src;
        if ($tmpcopyup && -d $dest) {
            $tmpcopy_src = "$dest.tmpcopyup.$$";
            mkdir $tmpcopy_src, 0755;
            do_mount($dest, $tmpcopy_src, '', MS_BIND, '');
        }

        if ($flags & MS_BIND) {
            # Bind mount — if the source is inaccessible (e.g. after
            # entering a user namespace), fall back to /proc/self/fd/N
            # using a pre-opened fd.
            my $mounted = do_mount($src, $dest, '', $flags, '');
            if (!$mounted && defined $mount_source_fds->{$mount_src}) {
                my $fd = $mount_source_fds->{$mount_src};
                $mounted = do_mount("/proc/self/fd/$fd", $dest, '', $flags, '');
            }
            # If still not mounted and we have a parent channel, ask the
            # parent to open the source fd inside our mount namespace
            # (parent stays in init userns and has root access to
            # inaccessible source directories).
            if (!$mounted && $chan_w) {
                eval {
                    channel_send($chan_w, {
                        type   => 'bind_source_request',
                        source => $mount_src,
                    });
                    my $resp = channel_recv($chan_r);
                    if ($resp && $resp->{type} eq 'bind_source_done' && $resp->{ok}) {
                        my $parent_fd = recv_fd_over_fd($chan_r);
                        if ($parent_fd >= 0) {
                            $mounted = do_mount("/proc/self/fd/$parent_fd", $dest, '', $flags, '');
                            POSIX::close($parent_fd);
                        }
                    }
                };
            }
            unless ($mounted) {
                warn "nacre: mount bind $dest: $!\n";
                next;
            }
            # Apply remaining flags via remount
            if ($flags & ~(MS_BIND | MS_REC)) {
                do_mount('', $dest, '', MS_REMOUNT | MS_BIND | ($flags & ~MS_REC), '')
                    or warn "nacre: remount $dest: $!\n";
            }
        } else {
            # Propagation flags (MS_PRIVATE, MS_SHARED, MS_SLAVE, MS_UNBINDABLE)
            # cannot be combined with a filesystem mount in a single mount(2)
            # call — split them off and apply after the mount.
            my $prop_mask = MS_PRIVATE | MS_SHARED | MS_SLAVE | MS_UNBINDABLE;
            my $prop_flags = $flags & ($prop_mask | MS_REC);
            my $mount_flags = $flags & ~$prop_mask;
            # If ONLY propagation flags + MS_REC were set, strip MS_REC from
            # the mount call (it's for propagation, not the fs mount).
            if ($prop_flags && !($mount_flags & ~MS_REC)) {
                $mount_flags &= ~MS_REC;
            }
            unless (do_mount($src, $dest, $type, $mount_flags, $data)) {
                # cgroup2 mount can fail in userns that doesn't own the
                # cgroup namespace (EBUSY/EPERM).  Fall back to bind-mounting
                # the host cgroup2 hierarchy, matching runc behaviour.
                if ($type eq 'cgroup2' && -d '/sys/fs/cgroup') {
                    unless (do_mount('/sys/fs/cgroup', $dest, '', MS_BIND, '')) {
                        warn "nacre: mount $type on $dest: $!\n";
                        next;
                    }
                    # Apply the same mount flags (e.g. ro, nosuid) via remount
                    if ($mount_flags & ~MS_BIND) {
                        do_mount('', $dest, '', MS_REMOUNT | MS_BIND | $mount_flags, '');
                    }
                } else {
                    warn "nacre: mount $type on $dest: $!\n";
                    next;
                }
            }
            log_debug("mounted $type on $dest ok, isdir=" . (-d $dest ? "yes" : "no"));
            # Now apply propagation flags if any
            if ($prop_flags & $prop_mask) {
                do_mount('', $dest, '', $prop_flags, '')
                    or warn "nacre: mount propagation $dest: $!\n";
            }
        }

        # Apply recursive mount attributes via mount_setattr()
        if (@recursive_attrs) {
            my ($attr_set, $attr_clr) = (0, 0);
            for my $ra (@recursive_attrs) {
                my $def = $RECURSIVE_MOUNT_ATTRS{$ra};
                if (exists $def->{atime} && $def->{atime}) {
                    # Atime setting: clear all atime bits first, then set
                    $attr_clr |= MOUNT_ATTR__ATIME;
                    $attr_set = ($attr_set & ~MOUNT_ATTR__ATIME) | $def->{set};
                } elsif (exists $def->{atime} && !$def->{atime}) {
                    # Reset to relatime (clear atime flags)
                    $attr_clr |= MOUNT_ATTR__ATIME;
                } else {
                    $attr_set |= $def->{set};
                    $attr_clr |= $def->{clear};
                }
            }
            if ($attr_set || $attr_clr) {
                do_mount_setattr(-1, $dest, AT_RECURSIVE, $attr_set, $attr_clr)
                    or warn "nacre: mount_setattr $dest: $!\n";
            }
        }

        # Apply idmap/ridmap via open_tree + mount_setattr + move_mount
        if ($has_idmap || $has_ridmap) {
            my $open_flags = OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC;
            $open_flags |= AT_RECURSIVE if ($flags & MS_REC);
            my $tree_fd = do_open_tree(-1, $dest, $open_flags);
            fatal("open_tree $dest: $!") if $tree_fd < 0;

            # Determine the user namespace fd for the mapping
            my $userns_fd;
            my $per_mount_maps = $m->{uidMappings} || $m->{gidMappings};
            my $delegate_to_parent = 0;
            if ($per_mount_maps) {
                # Per-mount explicit mappings: create a user namespace
                # with those mappings.  This may fail inside a container
                # userns (writing /proc/$child/setgroups from a non-init
                # userns is denied) — fall back to parent in that case.
                my $userns_err;
                try {
                    $userns_fd = _create_userns_for_idmap(
                        $m->{uidMappings} // [],
                        $m->{gidMappings} // [],
                        $chan_w, $chan_r,
                    );
                } catch ($e) {
                    $userns_err = $e;
                }
                if ($userns_err || !defined $userns_fd || $userns_fd < 0) {
                    $delegate_to_parent = 1 if $chan_w;
                    fatal("create userns for idmap: $userns_err") unless $delegate_to_parent;
                }
            } else {
                # Implied mapping: use the container's own user namespace.
                # If we're inside a userns, /proc/self/ns/user is our userns.
                sysopen(my $ns_fh, '/proc/self/ns/user', O_RDONLY)
                    or fatal("open /proc/self/ns/user: $!");
                $userns_fd = fileno($ns_fh);
                # Keep the fh alive
                push @{$mount_source_fds->{_fhs}}, $ns_fh;
            }

            if ($delegate_to_parent) {
                # Delegate entire idmap operation (userns creation +
                # mount_setattr) to the parent, which is outside the
                # container userns and can write /proc mappings.
                channel_send($chan_w, {
                    type      => 'mount_fd_request',
                    ridmap    => $has_ridmap ? 1 : 0,
                    uid_map   => _build_map_string($m->{uidMappings}),
                    gid_map   => _build_map_string($m->{gidMappings}),
                    implied   => 0,
                });
                send_fd_over_fd($chan_w, $tree_fd);
                my $resp = channel_recv($chan_r);
                fatal("mount_setattr idmap failed") unless $resp && $resp->{type} eq 'mount_fd_done';
            } else {
                # Apply mount_setattr(MOUNT_ATTR_IDMAP)
                my $setattr_flags = AT_EMPTY_PATH;
                $setattr_flags |= AT_RECURSIVE if $has_ridmap;
                my $ok = do_mount_setattr($tree_fd, "", $setattr_flags,
                                           MOUNT_ATTR_IDMAP, 0, $userns_fd);
                if (!$ok) {
                    # If init can't do it (in userns), ask parent
                    if ($chan_w && $! == EPERM) {
                        channel_send($chan_w, {
                            type      => 'mount_fd_request',
                            ridmap    => $has_ridmap ? 1 : 0,
                            uid_map   => _build_map_string($m->{uidMappings}),
                            gid_map   => _build_map_string($m->{gidMappings}),
                            implied   => $per_mount_maps ? 0 : 1,
                        });
                        send_fd_over_fd($chan_w, $tree_fd);
                        my $resp = channel_recv($chan_r);
                        fatal("mount_setattr idmap failed") unless $resp && $resp->{type} eq 'mount_fd_done';
                    } else {
                        POSIX::close($tree_fd);
                        fatal("mount_setattr MOUNT_ATTR_IDMAP $dest: $!");
                    }
                }
            }

            # Replace original mount with the idmapped one
            do_umount($dest, MNT_DETACH);
            do_move_mount($tree_fd, "", -1, $dest, MOVE_MOUNT_F_EMPTY_PATH)
                or fatal("move_mount $dest: $!");
            POSIX::close($tree_fd);
        }

        # Restore tmpcopyup content
        if ($tmpcopy_src && -d $tmpcopy_src) {
            _copy_dir_contents($tmpcopy_src, $dest);
            # Unmount and remove the temporary bind mount
            do_umount($tmpcopy_src, 0);
            rmdir $tmpcopy_src;
        }
    }

    return $dev_needs_ro;
}

sub create_devices ($rootfs, $spec) {

    my @devices = @DEFAULT_DEVICES;

    # Spec devices override defaults by path
    for my $d (@{$spec->{linux}{devices} // []}) {
        my $spec_dev = {
            path  => $d->{path},
            type  => $d->{type} // 'c',
            major => $d->{major} // 0,
            minor => $d->{minor} // 0,
            mode  => $d->{fileMode} // 0o666,
            uid   => $d->{uid},
            gid   => $d->{gid},
        };
        my $found = 0;
        for my $i (0..$#devices) {
            if ($devices[$i]{path} eq $spec_dev->{path}) {
                $devices[$i] = $spec_dev;
                $found = 1;
                last;
            }
        }
        push @devices, $spec_dev unless $found;
    }

    for my $dev (@devices) {
        my $dest = "$rootfs$dev->{path}";
        my $dir = dirname($dest);
        ensure_dir($dir);

        # Try mknod first (gives us correct ownership/mode)
        unlink $dest if -e $dest;
        my $dev_num = (($dev->{major} << 8) | $dev->{minor}) + 0;
        my $ftype = $dev->{type} eq 'b' ? S_IFBLK : S_IFCHR;
        # OCI spec default fileMode is 0666 when not specified
        my $file_mode = defined $dev->{mode} ? ($dev->{mode} & 0o7777) : 0o666;
        my $mode  = ($ftype | $file_mode) + 0;
        my $path  = $dest . "\0";
        my $ret;
        if (SYS_mknod > 0) {
            my $nr = SYS_mknod + 0;
            do { $ret = syscall($nr, $path, $mode, $dev_num) }
                while ($ret == -1 && $! == EINTR);
        } else {
            # aarch64: use mknodat with AT_FDCWD (-100)
            my $nr    = SYS_mknodat + 0;
            my $dirfd = -100 + 0;
            do { $ret = syscall($nr, $dirfd, $path, $mode, $dev_num) }
                while ($ret == -1 && $! == EINTR);
        }
        if ($ret == 0) {
            # chmod to ensure correct permissions (mknod is subject to umask)
            chmod $file_mode, $dest;
            chown($dev->{uid} // 0, $dev->{gid} // 0, $dest);
            next;
        }

        # Fallback: bind mount from host (works in user namespaces)
        my $host_dev = $dev->{path};
        if (-e $host_dev) {
            # Create empty file as mount point
            if (!-e $dest) {
                open my $fh, '>', $dest;
                close $fh if $fh;
            }
            if (do_mount($host_dev, $dest, '', MS_BIND, '')) {
                next;  # success
            }
        }
    }
}

sub create_symlinks ($rootfs) {
    for my $s (@DEFAULT_SYMLINKS) {
        my $dest = "$rootfs$s->{path}";
        next if -e $dest || -l $dest;
        symlink($s->{target}, $dest);
    }
}

sub _mask_host_procfs_sysfs ($rootfs) {
    # Unmount or cover all full procfs/sysfs mounts that are outside the
    # container rootfs.  This prevents the container from re-mounting
    # procfs/sysfs after chroot in --no-pivot mode (runc's msMoveRoot).
    my @to_mask;
    if (open my $fh, '<', '/proc/self/mountinfo') {
        while (my $line = <$fh>) {
            chomp $line;
            # mountinfo format: id parent_id major:minor root mountpoint ...
            # fields after " - " are: fstype source super_options
            my ($before, $after) = split / - /, $line, 2;
            next unless defined $after;
            my @b = split ' ', $before;
            my $root = $b[3] // '';
            my $mp   = $b[4] // '';
            my ($fstype) = split ' ', $after;
            next unless $root eq '/';  # only full mounts
            next unless $fstype eq 'proc' || $fstype eq 'sysfs';
            next if $mp =~ /^\Q$rootfs\E(?:\/|$)/;  # skip container's own mounts
            push @to_mask, $mp;
        }
        close $fh;
    }
    for my $p (@to_mask) {
        # Make slave so umount doesn't propagate to host
        do_mount('', $p, '', MS_SLAVE | MS_REC, '');
        unless (do_umount($p, MNT_DETACH)) {
            # If unmount fails (e.g. rootless EPERM), cover with tmpfs
            do_mount('tmpfs', $p, 'tmpfs', 0, '');
        }
    }
}

sub apply_pivot_root ($rootfs) {
    log_debug("applying pivot_root");
    chdir($rootfs) or fatal("chdir to rootfs: $!");

    # pivot_root(".", ".") — old root ends up mounted atop new root
    do_pivot_root('.', '.') or fatal("pivot_root: $!");

    # Unmount old root (lazy)
    do_umount('.', MNT_DETACH) or fatal("umount old root: $!");

    chdir('/') or fatal("chdir /: $!");
}

sub apply_rootfs_propagation ($spec) {
    # Apply the spec's rootfsPropagation AFTER pivot_root, so setup
    # operations (bind mounts, device creation) run under safe slave
    # propagation and the final container root gets the requested type.
    # When the spec doesn't set rootfsPropagation, skip this entirely —
    # matching runc, which only applies propagation when explicitly set.
    my $propagation = $spec->{linux}{rootfsPropagation};
    return unless defined $propagation && $propagation ne '';

    my $prop_flags = $PROPAGATION_FLAGS{$propagation} // return;

    # MS_PRIVATE: nothing to do — rootfsParentMountPrivate already made
    # the parent private, and pivot_root inherits it.
    return if ($prop_flags & MS_PRIVATE);

    # For MS_SHARED/MS_RSHARED: clear inherited slave/shared first by
    # making private, then apply shared.  Without this a slave mount
    # becomes "shared,slave" instead of pure "shared".
    if ($prop_flags & MS_SHARED) {
        do_mount('', '/', '', MS_PRIVATE | MS_REC, '');
    }

    # For MS_SLAVE/MS_RSLAVE: apply directly.  If the mount is already
    # private (e.g. no-pivot mode after MS_MOVE + chroot, or
    # rootfsParentMountPrivate), MS_SLAVE fails with EINVAL because a
    # private mount has no master.  Recover by creating a peer group
    # (MS_SHARED) first, then applying slave.
    unless (do_mount('', '/', '', $prop_flags, '')) {
        do_mount('', '/', '', MS_SHARED | MS_REC, '');
        do_mount('', '/', '', $prop_flags, '')
            or fatal("mount propagation ($propagation) /: $!");
    }
}

sub apply_masked_paths ($paths) {
    my %seen;
    # runc shares a single tmpfs across all masked directories so they
    # have the same device number (testable via stat %d).  We mount
    # tmpfs on the first dir, then bind-mount it to subsequent dirs.
    my $tmpfs_source;
    for my $p (@{$paths // []}) {
        # Deduplicate: don't mask the same path twice (runc compat)
        next if $seen{$p}++;
        # Security: refuse to mask through symlinks — a symlink at /proc
        # or /sys could redirect the mask to an attacker-controlled path.
        if (-l $p) {
            warn "nacre: maskedPaths: refusing to mask symlink $p\n";
            next;
        }
        # Check for symlink components in the path (resolve and compare)
        my $resolved = eval { Cwd::abs_path($p) };
        if (defined $resolved && $resolved ne $p) {
            # Path contains symlink components — skip silently for safety
            # (runc also skips these)
            next;
        }
        if (-d $p) {
            if (!defined $tmpfs_source) {
                # First masked dir: mount a real tmpfs here
                do_mount('tmpfs', $p, 'tmpfs', MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, 'size=0');
                $tmpfs_source = $p;
            } else {
                # Subsequent dirs: bind-mount from the first one (shares device number)
                do_mount($tmpfs_source, $p, '', MS_BIND, '');
                do_mount('', $p, '', MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC, '');
            }
        } elsif (-e $p) {
            do_mount('/dev/null', $p, '', MS_BIND, '');
            # Remount as read-only so rm/write gives EROFS, matching runc behavior.
            # IMPORTANT: do NOT use MS_NODEV here — /dev/null is a character device,
            # and nodev would block open() with EACCES (Permission denied).
            do_mount('', $p, '', MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOSUID | MS_NOEXEC, '')
             || do_mount('', $p, '', MS_REMOUNT | MS_BIND | MS_RDONLY | MS_NOSUID, '')
             || do_mount('', $p, '', MS_REMOUNT | MS_BIND | MS_RDONLY, '')
             || log_debug("maskedPaths: could not remount $p read-only: $!");
        }
    }
}

sub apply_readonly_paths ($paths) {
    for my $p (@{$paths // []}) {
        next unless -e $p;
        do_mount($p, $p, '', MS_BIND | MS_REC, '');
        do_mount('', $p, '', MS_REMOUNT | MS_BIND | MS_RDONLY | MS_REC, '');
    }
}

sub set_rootfs_readonly ($rootfs_readonly) {
    return unless $rootfs_readonly;
    do_mount('', '/', '', MS_REMOUNT | MS_BIND | MS_RDONLY, '')
        or fatal("remount / readonly: $!");
}

our @EXPORT = qw(
    do_mount do_umount do_pivot_root do_mount_setattr
    parse_mount_options
    prepare_rootfs apply_mounts create_devices create_symlinks
    apply_pivot_root apply_rootfs_propagation
    apply_masked_paths apply_readonly_paths set_rootfs_readonly
    _mask_host_procfs_sysfs
    _create_userns_from_strings
    %MOUNT_FLAGS
);

1;
