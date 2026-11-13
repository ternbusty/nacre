#!/usr/bin/env perl
# The syscall table for seccomp names: on aarch64 the numbers come from
# asm-generic/unistd.h, where some syscalls are numbered as __NR3264_<base>
# and named through 64-bit and 32-bit aliases.
use v5.38;
use Test::More;
use FindBin;
use lib "$FindBin::RealBin/../../lib";
use Nacre::Seccomp ();

my $hdr = '/usr/include/asm-generic/unistd.h';
plan skip_all => "$hdr not installed" unless -r $hdr;

open my $fh, '<', $hdr or die "$hdr: $!";
my %nr = Nacre::Seccomp::_parse_unistd($fh);
close $fh;

# Plain numbers
is($nr{getcwd}, 17, 'getcwd');
is($nr{openat}, 56, 'openat');
is($nr{clone3}, 435, 'clone3');

# 64-bit aliases of __NR3264_* numbers
is($nr{newfstatat}, 79, 'newfstatat is __NR3264_fstatat');
is($nr{fstat}, 80, 'fstat is __NR3264_fstat');
is($nr{fcntl}, 25, 'fcntl is __NR3264_fcntl');
is($nr{lseek}, 62, 'lseek is __NR3264_lseek');
is($nr{mmap}, 222, 'mmap is __NR3264_mmap');
is($nr{fadvise64}, 223, 'fadvise64 is __NR3264_fadvise64');

# The 32-bit aliases and the __NR3264_ bases are not syscall names here
ok(!exists $nr{$_}, "no $_") for qw(fcntl64 fstatat64 fstat64 mmap2 llseek fstatat);

done_testing;
