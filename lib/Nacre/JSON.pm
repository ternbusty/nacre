package Nacre::JSON;
use v5.38;
no warnings 'experimental::builtin';
use builtin qw(is_bool);

# ═══════════════════════════════════════════════════════════════════════
# JSON encoding / decoding
# ═══════════════════════════════════════════════════════════════════════
#
# A small stand-in for JSON::PP, which takes ~5.5ms and ~2.8MB to load on
# every command. It does what nacre uses -- JSON::PP->new->utf8->canonical
# ->allow_nonref, optionally ->pretty -- with the same output (see
# test/unit/json.t, which compares the two):
#
#   my $json = Nacre::JSON->new(pretty => 1);
#   my $text = $json->encode($data);    # UTF-8 bytes, keys sorted
#   my $data = $json->decode($text);    # from UTF-8 bytes
#
# Booleans are Perl's own (builtin::true / builtin::false): decoded true and
# false become them, and they encode as true and false. Like JSON::PP, a
# value is written as a number when Perl holds it as one (not as a string).

my %ESCAPE = (
    "\n" => '\n',
    "\r" => '\r',
    "\t" => '\t',
    "\f" => '\f',
    "\b" => '\b',
    '"' => '\"',
    '\\' => '\\\\',
);
my %UNESCAPE = (
    '"' => '"',
    '\\' => '\\',
    '/' => '/',
    b => "\b",
    f => "\f",
    n => "\n",
    r => "\r",
    t => "\t",
);

# Integers with more digits than Perl prints without an exponent stay
# strings (as in JSON::PP).
my $MAX_INT_DIGITS = do {
    my ($check, $digits) = (1111, 0);
    for my $d (5 .. 64) {
        $check .= '1';
        if (eval($check) =~ /[eE]/) {    ## no critic (ProhibitStringyEval)
            $digits = $d - 1;
            last;
        }
    }
    $digits;
};

# Perl's booleans, for building data (in place of JSON::PP::true / false).
sub true () {return builtin::true}
sub false () {return builtin::false}

sub new ($class, %opts) {
    return bless {pretty => $opts{pretty} ? 1 : 0}, $class;
}

# ── Encoding ──────────────────────────────────────────────────────────

sub encode ($self, $data) {
    return $self->{pretty} ? _encode($data, 0) . "\n" : _encode($data, undef);
}

# $level: indentation depth when pretty-printing, undef for compact output.
sub _encode ($value, $level) {
    my $type = ref $value;
    if ($type eq 'HASH' || $type eq 'ARRAY') {
        my @items
            = $type eq 'HASH'
            ? map {_string($_) . (defined $level ? ' : ' : ':') . _encode($value->{$_}, _deeper($level))}
            sort keys %$value
            : map {_encode($_, _deeper($level))} @$value;
        my ($opening, $closing) = $type eq 'HASH' ? ('{', '}') : ('[', ']');
        return "$opening$closing" unless @items;
        return $opening . join(',', @items) . $closing unless defined $level;
        my $inner = "\n" . '   ' x ($level + 1);
        return $opening . $inner . join(",$inner", @items) . "\n" . '   ' x $level . $closing;
    }
    if ($type eq 'SCALAR' && defined $$value) {    # \1 / \0, as JSON::PP
        return 'true' if $$value eq '1';
        return 'false' if $$value eq '0';
    }
    die "Nacre::JSON: cannot encode reference of type $type\n" if $type;
    return 'null' unless defined $value;
    return $value ? 'true' : 'false' if is_bool($value);
    return "$value" if _looks_like_number($value);
    return _string($value);
}

sub _deeper ($level) {return defined $level ? $level + 1 : undef}

# JSON::PP's test: a number held as a number, not a string that merely
# looks like one ("" & $x is "" for strings, 0 for numbers).
sub _looks_like_number ($value) {
    no feature 'bitwise';    # "&" must pick string or numeric "and" by operand
    no warnings 'numeric';
    return 0 if utf8::is_utf8($value);
    return 0 unless length((my $dummy = '') & $value);
    return 0 unless 0 + $value eq $value;
    return 1;
}

sub _string ($str) {
    $str =~ s/(["\\\n\r\t\f\b])/$ESCAPE{$1}/g;
    $str =~ s/([\x00-\x08\x0b\x0e-\x1f])/sprintf('\\u%04x', ord $1)/ge;
    utf8::encode($str);
    return qq{"$str"};
}

# ── Decoding ──────────────────────────────────────────────────────────

our $TEXT;    # the text being decoded; parsed with \G and pos()

sub decode ($self, $text) {
    utf8::decode($text) or die "Nacre::JSON: malformed UTF-8 in JSON text\n";
    local $TEXT = $text;
    pos($TEXT) = 0;
    my $value = _value();
    $TEXT =~ /\G[\x20\t\n\r]*/gc;
    _error('garbage after JSON value') if pos($TEXT) < length $TEXT;
    return $value;
}

sub _error ($what) {
    die sprintf("Nacre::JSON: %s, at character offset %d\n", $what, pos($TEXT) // 0);    ## no critic (ErrorHandling::RequireCarping)
}

sub _value () {
    $TEXT =~ /\G[\x20\t\n\r]*/gc;
    return _object() if $TEXT =~ /\G\{/gc;
    return _array() if $TEXT =~ /\G\[/gc;
    return _string_body() if $TEXT =~ /\G"/gc;
    if ($TEXT =~ /\G(-?(?:0|[1-9][0-9]*))(\.[0-9]+)?([eE][-+]?[0-9]+)?/gc) {
        my $num = $1 . ($2 // '') . ($3 // '');
        return $num / 1.0 if defined $2 || defined $3;
        return length $num > $MAX_INT_DIGITS ? "$num" : 0 + $num;
    }
    return builtin::true if $TEXT =~ /\Gtrue/gc;
    return builtin::false if $TEXT =~ /\Gfalse/gc;
    return undef if $TEXT =~ /\Gnull/gc;    ## no critic (ProhibitExplicitReturnUndef)
    _error(pos($TEXT) < length $TEXT ? 'malformed JSON value' : 'unexpected end of JSON text');
    return;
}

sub _object () {
    my %object;
    $TEXT =~ /\G[\x20\t\n\r]*/gc;
    return \%object if $TEXT =~ /\G\}/gc;
    while (1) {
        $TEXT =~ /\G[\x20\t\n\r]*"/gc or _error('object key (a string) expected');
        my $key = _string_body();
        $TEXT =~ /\G[\x20\t\n\r]*:/gc or _error("':' expected");
        $object{$key} = _value();
        $TEXT =~ /\G[\x20\t\n\r]*/gc;
        next if $TEXT =~ /\G,/gc;
        last if $TEXT =~ /\G\}/gc;
        _error("',' or '}' expected");
    }
    return \%object;
}

sub _array () {
    my @array;
    $TEXT =~ /\G[\x20\t\n\r]*/gc;
    return \@array if $TEXT =~ /\G\]/gc;
    while (1) {
        push @array, _value();
        $TEXT =~ /\G[\x20\t\n\r]*/gc;
        next if $TEXT =~ /\G,/gc;
        last if $TEXT =~ /\G\]/gc;
        _error("',' or ']' expected");
    }
    return \@array;
}

# The rest of a string, after its opening quote.
sub _string_body () {
    my $str = '';
    until ($TEXT =~ /\G"/gc) {
        if ($TEXT =~ /\G([^"\\\x00-\x1f]+)/gc) {
            $str .= $1;
            next;
        }
        if ($TEXT =~ /\G\\(["\\\/bfnrt])/gc) {
            $str .= $UNESCAPE{$1};
            next;
        }
        if ($TEXT =~ /\G\\u([0-9a-fA-F]{4})/gc) {
            $str .= chr _unicode_escape(hex $1);
            next;
        }
        _error(pos($TEXT) < length $TEXT ? 'invalid character in string' : 'unterminated string');
    }
    return $str;
}

# The code point of a \uXXXX escape; a UTF-16 high surrogate takes the
# low surrogate that must follow it.
sub _unicode_escape ($code) {
    if ($code >= 0xDC00 && $code <= 0xDFFF) {
        _error('unexpected low surrogate');
    }
    return $code if $code < 0xD800 || $code > 0xDBFF;
    my $low;
    if ($TEXT =~ /\G\\u([dD][c-fC-F][0-9a-fA-F]{2})/gc) {
        $low = hex $1;
    } else {
        _error('missing low surrogate');
    }
    return 0x10000 + (($code - 0xD800) << 10) + ($low - 0xDC00);
}

1;
