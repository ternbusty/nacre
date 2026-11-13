#!/usr/bin/env perl
# cmd_exec loads only some of the lazily imported modules (Nacre::Lazy::load)
# before forking, because the child sets the exec'd process up inside the
# container's mount namespace, where lib/ can no longer be read. Check that
# everything reachable from cmd_exec only calls lazy subs of those modules:
# a call into any other one would fail at run time.
use v5.38;
use Test::More;
use FindBin;

my $file = "$FindBin::RealBin/../../nacre";
open my $fh, '<', $file or die "open $file: $!";
my $src = do {local $/; <$fh>};

my %lazy;    # sub name -> module
while ($src =~ /use Nacre::Lazy '(Nacre::\w+)' => qw\(([^)]*)\)/g) {
    my $module = $1;
    $lazy{$_} = $module for split ' ', $2;
}
ok(scalar(keys %lazy) > 10, 'found the lazy imports');

my %body;
while ($src =~ /^sub (\w+)\b[^\n]*\n(.*?)^\}/msg) {
    $body{$1} = $2;
}
ok($body{cmd_exec}, 'found cmd_exec');

my ($loaded) = $body{cmd_exec} =~ /Nacre::Lazy::load\(([^)]*)\)/;
ok($loaded, 'cmd_exec calls Nacre::Lazy::load');
my %preloaded = map {$_ => 1} $loaded =~ /'(Nacre::\w+)'/g;

# Subs in nacre reachable from cmd_exec.
my (%seen, @todo);
@todo = ('cmd_exec');
while (defined(my $sub = shift @todo)) {
    next if $seen{$sub}++;
    push @todo, grep {exists $body{$_}} $body{$sub} =~ /\b([a-z_]\w*)\s*\(/g;
}

my @bad;
for my $sub (sort keys %seen) {
    for my $call ($body{$sub} =~ /\b([a-z_]\w*)\s*\(/g) {
        my $module = $lazy{$call} or next;
        push @bad, "$call ($module) called from $sub" unless $preloaded{$module};
    }
}
is_deeply(\@bad, [], 'cmd_exec only uses lazy subs of the modules it loads')
    or diag("add the module to Nacre::Lazy::load(...) in cmd_exec");

done_testing;
