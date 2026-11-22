#!/usr/bin/env perl
# "state" and "list" (Nacre::FastPath) load only what they need: not POSIX
# (which also loads Carp), File::Basename or Config_heavy.pl. Nacre::Util
# replaces the functions it used from them; check those against the originals.
use v5.38;
use Test::More;
use FindBin;
use lib "$FindBin::RealBin/../../lib";
use Nacre::Util ();
use File::Basename ();
use POSIX ();

my $lib = "$FindBin::RealBin/../../lib";
my @loaded = split /\n/, `$^X -I'$lib' -e 'require Nacre::FastPath; print join "\\n", sort keys %INC'`;
is($?, 0, 'Nacre::FastPath loads');
for my $file (qw(POSIX.pm Carp.pm File/Basename.pm Config_heavy.pl)) {
    ok(!(grep {$_ eq $file} @loaded), "Nacre::FastPath does not load $file");
}

for my $path (qw(/ // /a /a/ /a/b /a/b/ /a//b //a a a/ a/b a//b/ ./a ../a/b /a/b/c/)) {
    is(Nacre::Util::_dirname($path), File::Basename::dirname($path), "dirname '$path'");
}

my @statuses = (
    (map {$_ << 8} 0, 1, 2, 127, 128, 255),    # exited
    (map {$_, $_ | 0x80} 1, 2, 9, 15, 31, 64),    # killed by a signal, without and with a core dump
    (map {0x7f | ($_ << 8)} 19, 20),    # stopped
);
for my $s (@statuses) {
    my $want
        = POSIX::WIFEXITED($s) ? POSIX::WEXITSTATUS($s)
        : POSIX::WIFSIGNALED($s) ? 128 + POSIX::WTERMSIG($s)
        : 1;
    is(Nacre::Util::wait_exit_code($s), $want, sprintf('wait_exit_code 0x%04x', $s));
}

done_testing;
