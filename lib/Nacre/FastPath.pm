package Nacre::FastPath;
use v5.38;
use Exporter 'import';
use Nacre::Getopt ();
use Nacre::Util qw($JSON $JSON_COMPACT fatal);
use Nacre::State qw(load_state oci_state_json rootless_default_root);

# ═══════════════════════════════════════════════════════════════════════
# state and list, and their fast path
# ═══════════════════════════════════════════════════════════════════════
#
# Container managers call "state" (and "list") often, and they only read
# state.json. nacre answers them from a BEGIN block at the top of the
# script (try_fast), before the rest -- most of its compile time -- is
# compiled. The regular path uses the same cmd_state / cmd_list.
#
# try_fast() handles the plain forms only and returns, leaving @ARGV
# untouched, for anything else (other commands, help, --debug / --log, a
# missing id): the regular path then deals with it, so behaviour stays the
# same. When it handles the command, it exits.

sub try_fast ($argv) {
    local @ARGV = @$argv;

    # The same global options as main(), parsed the same way.
    my ($root, $root_explicit, $log_file, $log_format, $debug, $systemd_cgroup);
    Nacre::Getopt::Configure('pass_through', 'no_auto_abbrev');
    Nacre::Getopt::GetOptions(
        'root=s' => sub ($name, $value) {$root = $value; $root_explicit = 1},
        'log=s' => \$log_file,
        'log-format=s' => \$log_format,
        'debug' => \$debug,
        'systemd-cgroup' => \$systemd_cgroup,
    );
    my $command = shift @ARGV // return;
    return if $command ne 'state' && $command ne 'list';
    return if $debug || defined $log_file;
    return if grep {$_ eq '-h' || $_ eq '--help'} @ARGV;
    $root = rootless_default_root() // '/run/nacre' unless $root_explicit;

    my $run;
    if ($command eq 'state') {
        my $id = shift @ARGV // return;
        $run = sub {cmd_state(id => $id, root => $root)};
    } else {
        my ($format, $quiet);
        Nacre::Getopt::GetOptions('format|f=s' => \$format, 'quiet|q' => \$quiet);
        $run = sub {cmd_list(root => $root, format => $format, quiet => $quiet, root_explicit => $root_explicit)};
    }

    # As main(): errors go to stderr, exit status 1.
    if (!eval {$run->(); 1}) {
        my $msg = "$@";
        chomp $msg;
        print STDERR "$msg\n" if $msg ne '';
        exit 1;
    }
    exit 0;
}

sub cmd_state (%p) {
    my $id = $p{id} // fatal("container id required");
    my $root = $p{root} // '/run/nacre';

    my $state = load_state($root, $id);
    print $JSON->encode(oci_state_json($state));
    return;
}

sub cmd_list (%p) {
    my $root = $p{root} // '/run/nacre';
    my $format = $p{format} // 'table';
    my $quiet = $p{quiet} // 0;

    my @containers;
    if (opendir(my $dh, $root)) {
        while (my $id = readdir($dh)) {
            next if $id =~ /^\./;
            my $st = eval {load_state($root, $id)};
            next unless $st;
            push @containers, $st;
        }
        closedir($dh);
    } elsif ($p{root_explicit}) {

        # Explicit --root with non-existent directory is an error
        fatal("root directory '$root' does not exist");
    }

    # Default root that doesn't exist is fine — just show empty list

    if ($quiet) {
        print "$_->{id}\n" for sort {$a->{id} cmp $b->{id}} @containers;
        return;
    }

    if ($format eq 'json') {

        # JSON list output: compact, field order matches runc
        # (ociVersion, id, pid, status, bundle, rootfs, created)
        my @entries;
        for my $c (sort {$a->{id} cmp $b->{id}} @containers) {
            my $s = oci_state_json($c);
            my @pairs;
            for my $key (qw(ociVersion id pid status bundle rootfs created)) {
                next unless defined $s->{$key};
                push @pairs, $JSON_COMPACT->encode($key) . ':' . $JSON_COMPACT->encode($s->{$key});
            }
            push @entries, '{' . join(',', @pairs) . '}';
        }
        print '[' . join(',', @entries) . "]\n";
        return;
    }

    # Table format (runc column order: ID PID STATUS BUNDLE CREATED OWNER)
    printf "%-20s %-10s %-10s %-40s %-30s %s\n", 'ID', 'PID', 'STATUS', 'BUNDLE', 'CREATED', 'OWNER';
    for my $c (sort {$a->{id} cmp $b->{id}} @containers) {
        printf "%-20s %-10s %-10s %-40s %-30s %s\n",
            $c->{id}, $c->{pid}, $c->{status},
            $c->{bundle} // '',
            $c->{created} // '',
            '';
    }
    return;
}

our @EXPORT_OK = qw(cmd_state cmd_list try_fast);

1;
