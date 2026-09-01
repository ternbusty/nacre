package Nacre::Util;
use strict;
use warnings;
use Exporter 'import';
use JSON::PP;
use File::Basename qw(dirname);
use Fcntl qw(:mode);
use Errno qw(EINTR);

# ═══════════════════════════════════════════════════════════════════════
# JSON encoders (shared across the runtime)
# ═══════════════════════════════════════════════════════════════════════
our $JSON = JSON::PP->new->utf8->canonical->pretty->allow_nonref;
our $JSON_COMPACT = JSON::PP->new->utf8->canonical->allow_nonref;

# ═══════════════════════════════════════════════════════════════════════
# Debug logging (--debug / --log / --log-format)
# ═══════════════════════════════════════════════════════════════════════
our $LOG_DEBUG  = 0;
our $LOG_FH     = undef;
our $LOG_FORMAT = 'text';

sub setup_logging {
    my (%p) = @_;
    $LOG_DEBUG  = $p{debug}  // 0;
    $LOG_FORMAT = $p{format} // 'text';
    if ($p{log_file}) {
        open($LOG_FH, '>>', $p{log_file})
            or die "nacre: cannot open log file $p{log_file}: $!\n";
        $LOG_FH->autoflush(1);
    } else {
        $LOG_FH = \*STDERR;
    }
}

sub log_msg {
    my ($level, $msg) = @_;
    return unless $LOG_FH;
    return if $level eq 'debug' && !$LOG_DEBUG;

    my @t = gmtime();
    my $ts = sprintf('%04d-%02d-%02dT%02d:%02d:%02dZ',
        $t[5]+1900, $t[4]+1, $t[3], $t[2], $t[1], $t[0]);

    if ($LOG_FORMAT eq 'json') {
        my $entry = $JSON_COMPACT->encode({
            level => $level, msg => $msg, time => $ts,
        });
        print $LOG_FH "$entry\n";
    } else {
        print $LOG_FH "time=\"$ts\" level=$level msg=\"$msg\"\n";
    }
}

sub log_debug { log_msg('debug', $_[0]) }
sub log_info  { log_msg('info',  $_[0]) }
sub log_warn  { log_msg('warning', $_[0]) }
sub log_error { log_msg('error', $_[0]) }

# ═══════════════════════════════════════════════════════════════════════
# Utility functions
# ═══════════════════════════════════════════════════════════════════════

sub fatal {
    $! = 0;
    $? = 0;
    die "nacre: @_\n";
}

sub parse_size {
    my ($s) = @_;
    return undef unless defined $s;
    $s =~ s/^\s+|\s+$//g;
    return -1 if $s eq '-1';
    if ($s =~ /^(-?\d+)$/i) {
        return int($1);
    } elsif ($s =~ /^(\d+(?:\.\d+)?)\s*([kmgtpe])b?$/i) {
        my ($n, $u) = ($1, lc $2);
        my %mult = (k => 1024, m => 1024**2, g => 1024**3,
                     t => 1024**4, p => 1024**5, e => 1024**6);
        return int($n * ($mult{$u} // 1));
    }
    fatal("invalid size: '$s'");
}

sub write_file {
    my ($path, $content) = @_;
    open my $fh, '>', $path or fatal("write $path: $!");
    print $fh $content or fatal("write $path: $!");
    close $fh or fatal("close $path: $!");
}

sub read_file {
    my ($path) = @_;
    open my $fh, '<', $path or return undef;
    local $/;
    my $data = <$fh>;
    close $fh;
    return $data;
}

sub read_file_or_die {
    my ($path) = @_;
    my $data = read_file($path);
    fatal("cannot read $path: $!") unless defined $data;
    return $data;
}

sub write_file_atomic {
    my ($path, $content) = @_;
    my $tmp = "$path.tmp.$$";
    write_file($tmp, $content);
    rename($tmp, $path) or do { unlink $tmp; fatal("rename $tmp -> $path: $!"); };
}

sub ensure_dir {
    my ($path) = @_;
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
}

sub iso8601_now {
    my @t = gmtime(time);
    return sprintf('%04d-%02d-%02dT%02d:%02d:%02dZ',
        $t[5]+1900, $t[4]+1, $t[3], $t[2], $t[1], $t[0]);
}

sub do_syscall {
    my ($a0,$a1,$a2,$a3,$a4,$a5) = map { $_ + 0 } @_;
    my $n = scalar @_;
    my $ret;
    do {
        if    ($n <= 1) { $ret = syscall($a0); }
        elsif ($n == 2) { $ret = syscall($a0,$a1); }
        elsif ($n == 3) { $ret = syscall($a0,$a1,$a2); }
        elsif ($n == 4) { $ret = syscall($a0,$a1,$a2,$a3); }
        elsif ($n == 5) { $ret = syscall($a0,$a1,$a2,$a3,$a4); }
        else            { $ret = syscall($a0,$a1,$a2,$a3,$a4,$a5); }
    } while ($ret == -1 && $! == EINTR);
    return $ret;
}

# ═══════════════════════════════════════════════════════════════════════
# Exports
# ═══════════════════════════════════════════════════════════════════════
our @EXPORT = qw(
    $JSON $JSON_COMPACT
    $LOG_FH $LOG_DEBUG

    setup_logging log_msg log_debug log_info log_warn log_error
    fatal parse_size
    write_file read_file read_file_or_die write_file_atomic
    ensure_dir iso8601_now do_syscall
);

1;
