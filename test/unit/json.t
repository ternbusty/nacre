#!/usr/bin/env perl
# Nacre::JSON must produce and accept the same JSON as JSON::PP configured
# as nacre used it (utf8, canonical, allow_nonref, with or without pretty).
use v5.38;
no warnings 'experimental::builtin';
use builtin qw(true false is_bool blessed);
use Test::More;
binmode Test::More->builder->$_, ':encoding(UTF-8)' for qw(output failure_output todo_output);
use FindBin;
use lib "$FindBin::RealBin/../../lib";
use JSON::PP ();
use Nacre::JSON ();

my %pp = (
    pretty => JSON::PP->new->utf8->canonical->pretty->allow_nonref,
    compact => JSON::PP->new->utf8->canonical->allow_nonref,
);
my %ours = (
    pretty => Nacre::JSON->new(pretty => 1),
    compact => Nacre::JSON->new,
);

# ── encoding ──────────────────────────────────────────────────────────

sub same_encoding ($data, $label) {
    for my $style (qw(pretty compact)) {
        is($ours{$style}->encode($data), $pp{$style}->encode($data), "encode $style: $label") or return 0;
    }
    return 1;
}

my $used_as_number = '42';
{no warnings 'void'; $used_as_number + 0;}
my @scalars = (
    0, 1, -1, 42, 1.5, -0.25, 1e20, 3.0, 2**53, -2**63, 0.1 + 0.2,
    '0', '1', '42', '007', '1e3', '0x10', ' 3', '3 ', '', 'abc', $used_as_number,
    "quote\" backslash\\ slash/ nl\n cr\r tab\t ff\f bs\b",
    join('', map {chr} 0 .. 31, 127), "caf\x{e9}", "smile \x{263a}", "astral \x{1F600}",
    undef, true, false, \1, \0,
);
same_encoding($_, defined $_ ? "'$_'" : 'undef') for @scalars;
same_encoding({}, 'empty hash');
same_encoding([], 'empty array');
same_encoding({nested => {deeper => [[], {}, [1, {a => undef}]]}}, 'nesting');

# Random structures built from the scalars above.
srand 1234;
sub random_data ($depth) {
    my $r = rand;
    if ($depth > 0 && $r < 0.3) {
        return {map {(random_key() => random_data($depth - 1))} 1 .. int(rand 5)};
    }
    if ($depth > 0 && $r < 0.5) {
        return [map {random_data($depth - 1)} 1 .. int(rand 5)];
    }
    my $v = $scalars[rand @scalars];
    return ref $v ? $v : $v;    # a copy keeps the number/string nature
}
sub random_key () {
    my @keys = ('a', 'b', 'Z', 'key with space', "k\x{e9}y", '10', '9', '', "t\tab", 'ociVersion');
    return $keys[rand @keys];
}
my $failures = 0;
for my $n (1 .. 500) {
    $failures++ unless same_encoding(random_data(4), "random #$n");
    last if $failures > 3;
}

# ── decoding ──────────────────────────────────────────────────────────

# JSON::PP decodes booleans to JSON::PP::Boolean objects, Nacre::JSON to
# Perl booleans: normalize both, and record whether each scalar is held as
# a number, which decides how it is encoded again.
sub normalize ($v) {
    if (ref $v eq 'HASH') {return {map {($_ => normalize($v->{$_}))} keys %$v}}
    if (ref $v eq 'ARRAY') {return [map {normalize($_)} @$v]}
    return ['bool', $v ? 1 : 0] if (blessed($v) // '') eq 'JSON::PP::Boolean' || (!ref $v && is_bool($v));
    return ['null'] unless defined $v;
    return [Nacre::JSON::_looks_like_number($v) ? 'number' : 'string', "$v"];
}

sub same_decoding ($text, $label) {
    my $theirs = eval {$pp{compact}->decode($text)};
    my $their_err = $@;
    my $mine = eval {$ours{compact}->decode($text)};
    my $my_err = $@;
    if ($their_err || $my_err) {
        ok($their_err && $my_err, "decode both reject: $label")
            or diag("JSON::PP: " . ($their_err || 'ok') . "Nacre::JSON: " . ($my_err || "ok\n"));
        return;
    }
    is_deeply(normalize($mine), normalize($theirs), "decode: $label") or return;

    # Decoding and encoding again (as nacre does with config.json) must
    # give the same text too.
    is($ours{pretty}->encode($mine), $pp{pretty}->encode($theirs), "round trip: $label");
}

my @texts = (
    '{}', '[]', '0', '-0', '1', '-1', '1.5', '-1.5e3', '1E+2', '1e-2', '123456789012345678',
    '1234567890123456789012345', '"x"', 'true', 'false', 'null',
    '  {"a" : [1, 2 , 3] , "b":{"c":null}}  ',
    qq({"esc":"\\" \\\\ \\/ \\b \\f \\n \\r \\t \\u0041 \\u00e9 \\u263a \\ud83d\\ude00"}),
    qq({"raw":"caf\xc3\xa9 \xe2\x98\xba"}),
    '{"dup":1,"dup":2}',
    "[1,\n2,\t3,\r4]",
    # malformed
    '', ' ', '{', '[1,]', '{"a":1,}', '{"a" 1}', '[1 2]', 'tru', 'nul', '01', '1.', '.5', '+1',
    '"unterminated', qq("ctrl\x01char"), '"\\x"', '"\\u12"', '{"a":1}x', '[1]]',
    qq("bad utf8 \xff"), '{1:2}', "'single'",
);
same_decoding($_, "'$_'") for @texts;

for my $n (1 .. 300) {
    my $data = random_data(4);
    same_decoding($pp{$n % 2 ? 'pretty' : 'compact'}->encode($data), "random #$n");
}

# Files nacre actually handles.
for my $file ("$FindBin::RealBin/../../test-bundle/config.json") {
    open my $fh, '<', $file or next;
    local $/;
    same_decoding(scalar <$fh>, $file);
}
require Nacre::State;
same_encoding(Nacre::State::default_spec(), 'default spec');

done_testing;
