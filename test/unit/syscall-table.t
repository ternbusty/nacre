#!/usr/bin/env perl
# The syscall tables for seccomp names (Nacre::SyscallTable, generated from
# the kernel headers by scripts/gen_syscall_table.sh).
use v5.38;
use Test::More;
use FindBin;
use lib "$FindBin::RealBin/../../lib";
use Nacre::SyscallTable ();

my %x86 = Nacre::SyscallTable::table('X86_64');
my %arm = Nacre::SyscallTable::table('AARCH64');
ok(keys %x86 > 300, 'x86_64 table');
ok(keys %arm > 300, 'aarch64 table');

is($x86{read}, 0, 'x86_64 read');
is($x86{kill}, 62, 'x86_64 kill');
is($x86{newfstatat}, 262, 'x86_64 newfstatat');
is($x86{clone3}, 435, 'x86_64 clone3');

# aarch64 (asm-generic/unistd.h) numbers some syscalls as __NR3264_<base>
# and names them through 64-bit and 32-bit aliases: only the 64-bit names
# are syscalls there.
is($arm{getcwd}, 17, 'aarch64 getcwd');
is($arm{openat}, 56, 'aarch64 openat');
is($arm{kill}, 129, 'aarch64 kill');
is($arm{clone3}, 435, 'aarch64 clone3');
is($arm{newfstatat}, 79, 'aarch64 newfstatat is __NR3264_fstatat');
is($arm{fstat}, 80, 'aarch64 fstat is __NR3264_fstat');
is($arm{fcntl}, 25, 'aarch64 fcntl is __NR3264_fcntl');
is($arm{lseek}, 62, 'aarch64 lseek is __NR3264_lseek');
is($arm{mmap}, 222, 'aarch64 mmap is __NR3264_mmap');
is($arm{fadvise64}, 223, 'aarch64 fadvise64 is __NR3264_fadvise64');
ok(!exists $arm{$_}, "aarch64 has no $_")
    for qw(fcntl64 fstatat64 fstat64 mmap2 llseek fstatat clock_gettime64 syscalls arch_specific_syscall);
ok(!exists $x86{$_}, "x86_64 has no $_") for qw(clock_gettime64 mmap2);

# Every number is a plain number, and no two names share one
for my $t (['x86_64', \%x86], ['aarch64', \%arm]) {
    my ($name, $h) = @$t;
    is_deeply([grep {$h->{$_} !~ /\A\d+\z/} sort keys %$h], [], "$name: numbers");
    my %by_nr;
    push @{$by_nr{$h->{$_}}}, $_ for keys %$h;
    is_deeply([grep {@{$by_nr{$_}} > 1} sort keys %by_nr], [], "$name: one name per number");
}

# The table for this machine
require Config;
my $arch = $Config::Config{archname};
my %native = Nacre::SyscallTable::native_table();
if ($arch =~ /x86_64|amd64/i) {
    is_deeply(\%native, \%x86, "native table on $arch");
} elsif ($arch =~ /aarch64|arm64/i) {
    is_deeply(\%native, \%arm, "native table on $arch");
} else {
    is(scalar(%native), 0, "no table on $arch");
}

done_testing;
