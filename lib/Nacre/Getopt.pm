package Nacre::Getopt;
use v5.38;
use Exporter 'import';

# ═══════════════════════════════════════════════════════════════════════
# Command-line option parsing
# ═══════════════════════════════════════════════════════════════════════
#
# A small stand-in for Getopt::Long, which takes ~3.5ms and ~2MB to load on
# every command. It implements what nacre uses, with Getopt::Long's
# behaviour under "pass_through no_auto_abbrev" (see test/unit/getopt.t):
#
#   GetOptions('name|n' => \$flag, 'opt=s' => \$str, 'num=i' => \$int,
#              'list=s' => \@list, 'cb=s' => sub ($name, $value) {...});
#   Configure('require_order');    # stop at the first non-option
#   Configure('permute');          # options may follow arguments (default)
#
# Options are matched case-insensitively, as "--name", "-name" or a
# one-letter alias; values as "--name=value" or "--name value". Anything
# not understood (unknown options, missing or invalid values) is left in
# @ARGV, in order, together with the non-option arguments. "--" stops
# option processing and is left in @ARGV as well.

my $REQUIRE_ORDER = 0;

sub Configure (@settings) {
    for (@settings) {
        if ($_ eq 'require_order') {$REQUIRE_ORDER = 1}
        elsif ($_ eq 'permute') {$REQUIRE_ORDER = 0}
        elsif ($_ ne 'pass_through' && $_ ne 'no_auto_abbrev') {
            die "Nacre::Getopt: unsupported setting '$_'\n";
        }
    }
    return;
}

sub GetOptions (@specs) {
    my %opts;
    while (my ($spec, $dest) = splice @specs, 0, 2) {
        my ($names, $type) = $spec =~ /^([\w|-]+)(?:=([si]))?$/
            or die "Nacre::Getopt: unsupported option spec '$spec'\n";
        my @names = split /\|/, $names;
        my $opt = {name => $names[0], type => $type // '', dest => $dest};
        $opts{lc $_} = $opt for @names;
    }

    my @rest;
    while (@ARGV) {
        my $arg = shift @ARGV;
        if ($arg eq '--') {
            push @rest, $arg, @ARGV;
            last;
        }
        my ($name, $value) = $arg =~ /^--?([^=]+)(?:=(.*))?$/s;
        my $opt = defined $name ? $opts{lc $name} : undef;
        my $ok = $opt && _take_value($opt, \$value);
        if (!$ok) {

            # Not ours: a non-option argument ("-" included), an unknown
            # option, or a missing or invalid value. Keep it; with
            # require_order, keep everything after it too.
            push @rest, $arg;
            if ($REQUIRE_ORDER) {
                push @rest, @ARGV;
                last;
            }
            next;
        }

        my $dest = $opt->{dest};
        if (ref $dest eq 'CODE') {$dest->($opt->{name}, $value)}
        elsif (ref $dest eq 'ARRAY') {push @$dest, $value}
        else {$$dest = $value}
    }
    @ARGV = @rest;
    return 1;
}

# Work out the value of option $opt, given the "=value" part of the
# argument (undef if none); the value may also be the next argument.
# Returns false when the argument cannot be used as this option.
sub _take_value ($opt, $value_ref) {
    my $value = $$value_ref;
    if ($opt->{type} eq '') {
        return 0 if defined $value;    # a flag takes no value
        $$value_ref = 1;
        return 1;
    }
    if (!defined $value) {
        return 0 if !@ARGV;
        $value = $ARGV[0];
        return 0 if $opt->{type} eq 'i' && $value !~ /^[-+]?\d+$/;    # it stays in @ARGV
        shift @ARGV;
    } elsif ($value eq '' || ($opt->{type} eq 'i' && $value !~ /^[-+]?\d+$/)) {
        return 0;
    }
    $$value_ref = $value;
    return 1;
}

our @EXPORT_OK = qw(GetOptions);

1;
