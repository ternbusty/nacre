#!/usr/bin/env perl
# Nacre::ExeGuard writes the constants for its read-only mount as literals,
# so as not to load Nacre::Const in the process that only re-execs. Check
# them against the generated Nacre::Const, for both architectures in it.
use v5.38;
use Test::More;
use FindBin;
use lib "$FindBin::RealBin/../../lib";
use Nacre::ExeGuard;
use Nacre::Const;

my $const_file = "$FindBin::RealBin/../../lib/Nacre/Const.pm";
open my $fh, '<', $const_file or die "open $const_file: $!";
my $src = do {local $/; <$fh>};

for my $name (qw(SYS_open_tree SYS_mount_setattr)) {
    my @values = $src =~ /^\s+\Q$name\E\s+=>\s+(\d+),/mg;
    is(scalar @values, 2, "$name is in the x86_64 and the aarch64 table");
    is($_, Nacre::ExeGuard->can($name)->(), "$name matches Nacre::Const") for @values;
}

for my $name (qw(OPEN_TREE_CLONE OPEN_TREE_CLOEXEC AT_EMPTY_PATH MOUNT_ATTR_RDONLY)) {
    is(Nacre::ExeGuard->can($name)->(), Nacre::Const->can($name)->(), "$name matches Nacre::Const");
}

done_testing;
