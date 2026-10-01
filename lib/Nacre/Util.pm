package Nacre::Util;
use v5.38;
use Exporter 'import';
use File::Basename qw(dirname);
use POSIX qw(WIFEXITED WEXITSTATUS WIFSIGNALED WTERMSIG);
use Fcntl qw(:mode);
use Errno qw(EINTR);
use Time::HiRes qw(usleep);
use Nacre::Const qw(SYS_setns SYS_unshare SYS_pidfd_open);

# ═══════════════════════════════════════════════════════════════════════
# JSON encoders (shared across the runtime)
# ═══════════════════════════════════════════════════════════════════════
# JSON::XS when installed (it loads in ~1ms against JSON::PP's ~6ms, and
# every command pays that), else the core JSON::PP. Same API and output.
# Booleans are written as \1 / \0, which both encode as true / false.
my $JSON_CLASS = eval {require JSON::XS; 'JSON::XS'} // do {require JSON::PP; 'JSON::PP'};
our $JSON = $JSON_CLASS->new->utf8->canonical->pretty->allow_nonref;
our $JSON_COMPACT = $JSON_CLASS->new->utf8->canonical->allow_nonref;

# ═══════════════════════════════════════════════════════════════════════
# Debug logging (--debug / --log / --log-format)
# ═══════════════════════════════════════════════════════════════════════
our $LOG_DEBUG = 0;
our $LOG_FH = undef;
our $LOG_FORMAT = 'text';

sub setup_logging (%p) {
    $LOG_DEBUG = $p{debug} // 0;
    $LOG_FORMAT = $p{format} // 'text';
    if ($p{log_file}) {
        open(my $fh, '>>', $p{log_file})
            or die "nacre: cannot open log file $p{log_file}: $!\n";
        $fh->autoflush(1);
        $LOG_FH = $fh;
        return $fh;
    }
    $LOG_FH = \*STDERR;
    return;
}

sub log_msg ($level, $msg) {
    return unless $LOG_FH;
    return if $level eq 'debug' && !$LOG_DEBUG;

    my @t = gmtime();
    my $ts = sprintf('%04d-%02d-%02dT%02d:%02d:%02dZ', $t[5] + 1900, $t[4] + 1, $t[3], $t[2], $t[1], $t[0]);

    if ($LOG_FORMAT eq 'json') {
        my $entry = $JSON_COMPACT->encode(
            {
                level => $level,
                msg => $msg,
                time => $ts,
            }
        );
        print $LOG_FH "$entry\n";
    } else {
        print $LOG_FH "time=\"$ts\" level=$level msg=\"$msg\"\n";
    }
    return;
}

sub log_debug ($msg) {log_msg('debug', $msg); return}
sub log_info ($msg) {log_msg('info', $msg); return}
sub log_warn ($msg) {log_msg('warning', $msg); return}
sub log_error ($msg) {log_msg('error', $msg); return}

# ═══════════════════════════════════════════════════════════════════════
# Utility functions
# ═══════════════════════════════════════════════════════════════════════

sub fatal (@args) {
    $! = 0;
    $? = 0;
    die "nacre: @args\n";
}

sub parse_size ($s) {
    return unless defined $s;
    $s =~ s/^\s+|\s+$//g;
    return -1 if $s eq '-1';
    if ($s =~ /^(-?\d+)$/i) {
        return int($1);
    } elsif ($s =~ /^(\d+(?:\.\d+)?)\s*([kmgtpe])b?$/i) {
        my ($n, $u) = ($1, lc $2);
        my %mult = (
            k => 1024,
            m => 1024**2,
            g => 1024**3,
            t => 1024**4,
            p => 1024**5,
            e => 1024**6
        );
        return int($n * ($mult{$u} // 1));
    }
    fatal("invalid size: '$s'");
    return;
}

sub write_file ($path, $content) {
    open my $fh, '>', $path or fatal("write $path: $!");
    print $fh $content or fatal("write $path: $!");
    close $fh or fatal("close $path: $!");
    return;
}

sub read_file ($path) {
    open my $fh, '<', $path or return;
    local $/ = undef;
    my $data = <$fh>;
    close $fh;
    return $data;
}

sub read_file_or_die ($path) {
    my $data = read_file($path);
    fatal("cannot read $path: $!") unless defined $data;
    return $data;
}

sub write_file_atomic ($path, $content) {
    my $tmp = "$path.tmp.$$";
    write_file($tmp, $content);
    rename($tmp, $path) or do {unlink $tmp; fatal("rename $tmp -> $path: $!");};
    return;
}

sub ensure_dir ($path) {
    return if -d $path;
    my @todo;
    my $p = $path;
    while ($p ne '' && $p ne '/' && !-d $p) {
        push @todo, $p;
        $p = dirname($p);
    }
    for my $d (reverse @todo) {
        my $parent = dirname($d);
        my @pst = stat($parent);
        my $mode = 0755;
        if (@pst && ($pst[2] & S_ISGID)) {
            $mode |= S_ISGID;
        }
        unless (mkdir $d, $mode) {
            next if -d $d;
            warn "nacre: ensure_dir: mkdir $d failed: $!\n";
        }
    }
    return;
}

sub iso8601_now {
    my @t = gmtime(time);
    return sprintf('%04d-%02d-%02dT%02d:%02d:%02dZ', $t[5] + 1900, $t[4] + 1, $t[3], $t[2], $t[1], $t[0]);
}

sub wait_exit_code ($status = $?) {
    return WEXITSTATUS($status) if WIFEXITED($status);
    return 128 + WTERMSIG($status) if WIFSIGNALED($status);
    return 1;
}

sub do_setns ($fd, $flag = 0) {
    return do_syscall(SYS_setns, $fd, $flag) == 0;
}

sub do_unshare ($flag) {
    return do_syscall(SYS_unshare, $flag) == 0;
}

sub lookup_home_from_passwd ($uid) {
    my $home = '/';
    if (open my $pw, '<', '/etc/passwd') {
        while (my $line = <$pw>) {
            chomp $line;
            my @f = split /:/, $line;
            if (@f >= 6 && $f[2] == $uid) {
                $home = $f[5] if $f[5] ne '';
                last;
            }
        }
        close $pw;
    }
    return $home;
}

sub do_syscall (@args) {
    my ($a0, $a1, $a2, $a3, $a4, $a5) = map {$_ + 0} @args;
    my $n = scalar @args;
    my $ret;
    do {
        if ($n <= 1) {$ret = syscall($a0);}    ## no critic (ProhibitCascadingIfElse)
        elsif ($n == 2) {$ret = syscall($a0, $a1);}
        elsif ($n == 3) {$ret = syscall($a0, $a1, $a2);}
        elsif ($n == 4) {$ret = syscall($a0, $a1, $a2, $a3);}
        elsif ($n == 5) {$ret = syscall($a0, $a1, $a2, $a3, $a4);}
        else {$ret = syscall($a0, $a1, $a2, $a3, $a4, $a5);}
    } while ($ret == -1 && $! == EINTR);
    return $ret;
}

# ═══════════════════════════════════════════════════════════════════════
# Exports
# ═══════════════════════════════════════════════════════════════════════
# ═══════════════════════════════════════════════════════════════════════
# Waiting for processes
# ═══════════════════════════════════════════════════════════════════════

# Wait up to $timeout seconds for process $pid to exit, without reaping it.
# Uses a pidfd (Linux 5.3+), which becomes readable when the process exits
# and works for non-children too. Returns 1 if it exited, 0 on timeout, and
# undef if pidfds are unavailable (the caller should poll instead).
sub pidfd_wait ($pid, $timeout) {
    my $pidfd = syscall(SYS_pidfd_open + 0, $pid + 0, 0);
    return if $pidfd < 0;
    my $deadline = Time::HiRes::time() + $timeout;
    my $exited = 0;
    while (1) {
        my $remaining = $deadline - Time::HiRes::time();
        last if $remaining <= 0;
        my $rin = '';
        vec($rin, $pidfd, 1) = 1;
        my $n = select(my $rout = $rin, undef, undef, $remaining);
        next if $n < 0 && $! == EINTR;
        $exited = 1 if $n > 0;
        last;
    }
    POSIX::close($pidfd);
    return $exited;
}

# Poll $done->() until it returns true or $timeout seconds pass, sleeping
# 1ms at first and backing off to 50ms: fast for quick events, cheap for
# slow ones. Returns whether $done->() became true.
sub wait_until ($timeout, $done) {
    my $deadline = Time::HiRes::time() + $timeout;
    my $delay = 1_000;
    until ($done->()) {
        return 0 if Time::HiRes::time() >= $deadline;
        usleep($delay);
        $delay *= 2 if $delay < 50_000;
    }
    return 1;
}

our @EXPORT_OK = qw(
    $JSON $JSON_COMPACT
    $LOG_FH $LOG_DEBUG

    setup_logging log_msg log_debug log_info log_warn log_error
    fatal parse_size
    write_file read_file read_file_or_die write_file_atomic
    ensure_dir iso8601_now do_syscall
    wait_exit_code do_setns do_unshare lookup_home_from_passwd
    pidfd_wait wait_until
);

1;
