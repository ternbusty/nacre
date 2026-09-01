package Nacre::Hooks;
use strict;
use warnings;
use Exporter 'import';
use POSIX qw(WNOHANG _exit);
use Nacre::Util;
use Nacre::State;

# ═══════════════════════════════════════════════════════════════════════
# Hooks
# ═══════════════════════════════════════════════════════════════════════

sub run_hooks {
    my ($hooks, $state, %opts) = @_;
    return unless $hooks;
    my $must_succeed = $opts{must_succeed} // 0;
    my $hook_type    = $opts{type} // '';
    my $hook_idx     = 0;  # runc uses 0-based indexing
    for my $hook (@$hooks) {
        # Prepare state JSON and pipe BEFORE forking so the child inherits
        # a real file descriptor that survives exec().
        my $state_json = $JSON_COMPACT->encode(oci_state_json($state));
        pipe(my $rd, my $wr) or fatal("pipe for hook stdin: $!");

        my $pid = fork();
        fatal("fork for hook: $!") unless defined $pid;
        if ($pid == 0) {
            close $wr;  # Child doesn't write
            # Set env
            if ($hook->{env}) {
                for my $e (@{$hook->{env}}) {
                    my ($k, $v) = split /=/, $e, 2;
                    $ENV{$k} = $v;
                }
            }
            # Redirect the pipe read-end to STDIN (real fd survives exec)
            open STDIN, '<&', $rd or _exit(1);
            close $rd;
            my @args = @{$hook->{args} // [$hook->{path}]};
            { exec { $hook->{path} } @args };
            _exit(1);
        }
        # Parent: write state JSON into the pipe, then close
        close $rd;
        print $wr $state_json;
        close $wr;

        my $timeout = $hook->{timeout} // 30;
        my $elapsed = 0;
        while ($elapsed < $timeout) {
            my $w = waitpid($pid, WNOHANG);
            last if $w > 0;
            select(undef, undef, undef, 0.1);
            $elapsed += 0.1;
        }
        my $hook_label = $hook_type ? "$hook_type hook #$hook_idx" : "hook $hook->{path}";
        if ($elapsed >= $timeout) {
            kill 9, $pid;
            waitpid($pid, 0);
            if ($must_succeed) {
                fatal("error running $hook_label: hook timed out after ${timeout}s");
            }
            warn "nacre: $hook_label timed out\n";
        } elsif ($?) {
            # Hook exited non-zero or was killed by signal
            my $sig = $? & 127;
            my $exit_code = $? >> 8;
            if ($sig) {
                my %sig_names = (4 => 'illegal instruction', 6 => 'aborted',
                    8 => 'floating point exception', 9 => 'killed',
                    11 => 'segmentation fault', 31 => 'bad system call');
                my $sig_name = $sig_names{$sig} // "signal $sig";
                if ($must_succeed) {
                    fatal("error running $hook_label: $sig_name: $hook->{path}");
                }
                warn "nacre: $hook_label: $sig_name\n";
            } else {
                if ($must_succeed) {
                    fatal("error running $hook_label: hook command exited with error code $exit_code");
                }
                warn "nacre: $hook_label exited with code $exit_code\n";
            }
        }
        $hook_idx++;
    }
}

our @EXPORT = qw(run_hooks);

1;
