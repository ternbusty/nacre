#!/usr/bin/env perl
# Nacre::Getopt must behave like Getopt::Long configured as nacre used it
# ("pass_through no_auto_abbrev", with permute or require_order). Compare
# the two on fixed edge cases and on random argument lists.
use v5.38;
use Test::More;
use FindBin;
use lib "$FindBin::RealBin/../../lib";
use Getopt::Long ();
use Nacre::Getopt ();

Getopt::Long::Configure(qw(pass_through no_auto_abbrev));

# Every kind of spec nacre uses: flags with one-letter aliases, strings,
# integers, repeatable options, and a callback.
sub parse ($impl, $mode, @argv) {
    my (%o, @env, @gids);
    my @specs = (
        'detach|d' => \$o{detach},
        'force|f' => \$o{force},
        'bundle|b=s' => \$o{bundle},
        'pid-file=s' => \$o{pid_file},
        'preserve-fds=i' => \$o{preserve_fds},
        'env|e=s' => \@env,
        'additional-gids=i' => \@gids,
        'root=s' => sub ($name, $value) {$o{root} = "$name:$value"},
    );
    local @ARGV = @argv;
    my $ok;
    if ($impl eq 'Getopt::Long') {
        Getopt::Long::Configure($mode);
        $ok = Getopt::Long::GetOptions(@specs) ? 1 : 0;
        Getopt::Long::Configure('permute');
    } else {
        Nacre::Getopt::Configure($mode);
        $ok = Nacre::Getopt::GetOptions(@specs) ? 1 : 0;
        Nacre::Getopt::Configure('permute');
    }
    return {ok => $ok, %o, env => [@env], gids => [@gids], argv => [@ARGV]};
}

sub same ($mode, @argv) {
    my $label = "$mode: " . join(' ', map {"'$_'"} @argv);
    is_deeply(parse('Nacre::Getopt', $mode, @argv), parse('Getopt::Long', $mode, @argv), $label)
        or return 0;
    return 1;
}

my @fixed = (
    [qw(-d id cmd)],
    [qw(id --detach -b /x cmd)],
    [qw(--bundle=/x id)],
    [qw(-bundle /x id)],
    [qw(--Detach -D id)],
    [qw(--unknown val id)],
    [qw(--unknown=val id)],
    [qw(-b -d id)],
    [qw(-b)],
    [qw(--preserve-fds abc id)],
    [qw(--preserve-fds=3 id)],
    [qw(--preserve-fds=x id)],
    [qw(--preserve-fds -2 id)],
    [qw(--detach=1 id)],
    [qw(-db /x id)],
    [qw(id -- -d x)],
    [qw(- id)],
    [qw(-e A=1 --env B=2 --env=C=3 id)],
    [qw(--additional-gids 1 --additional-gids=2 id)],
    [qw(--root /r id)],
    [qw(--root=/r id --root /s)],
    [qw(-1 id)],
    ['--bundle=', 'id'],
    ['--bundle', '', 'id'],
    [qw(--pid-file /p --pid-file=/q id)],
    [],
);
for my $mode (qw(permute require_order)) {
    same($mode, @$_) for @fixed;
}

# Random argument lists built from tokens covering the cases above.
my @tokens = (
    qw(-d --detach -D -f --force -b --bundle --bundle=/x -bundle /x /y x id
        -- - -1 --preserve-fds --preserve-fds=3 --preserve-fds=z 7 -7
        -e --env --env=A=1 A=2 --additional-gids 5 --additional-gids=q
        --root --root=/r --unknown --unknown=v -db --detach=1 --pid-file),
    '',
);
srand 4242;
my $failures = 0;
for (1 .. 3000) {
    my @argv = map {$tokens[rand @tokens]} 1 .. int(rand 7);
    my $mode = rand() < 0.5 ? 'permute' : 'require_order';
    $failures++ unless same($mode, @argv);
    last if $failures > 5;
}

done_testing;
