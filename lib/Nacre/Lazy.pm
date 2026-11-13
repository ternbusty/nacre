package Nacre::Lazy;
use v5.38;

# ═══════════════════════════════════════════════════════════════════════
# Lazy imports
# ═══════════════════════════════════════════════════════════════════════
#
#   use Nacre::Lazy 'Nacre::Mount' => qw(prepare_rootfs do_mount);
#
# Installs stubs for the listed subs in the caller; the first call loads the
# module and replaces the stub with the real sub. Commands that never touch
# a module (state, kill, list, ...) then skip compiling it, which is most of
# their run time.
#
# Anything the container init process may call after pivot_root must be
# loaded before it (the lib directory is no longer reachable then): call
# load_all() before forking the container.

my %MODULES;

sub import ($class, $module = undef, @subs) {
    return unless defined $module;
    my $caller = caller;
    (my $file = "$module.pm") =~ s{::}{/}g;
    $MODULES{$module} = $file;
    for my $name (@subs) {
        no strict 'refs';    ## no critic (ProhibitNoStrict)
        *{"${caller}::$name"} = sub {
            require $file;
            my $real = \&{"${module}::$name"};
            no warnings 'redefine';
            *{"${caller}::$name"} = $real;
            goto &$real;
        };
    }
    return;
}

# Load every module registered through a lazy import.
sub load_all () {
    require $_ for values %MODULES;
    return;
}

# Load just these modules (names as given to the lazy import).
sub load (@modules) {
    for my $module (@modules) {
        my $file = $MODULES{$module} // die "Nacre::Lazy: $module is not lazily imported\n";
        require $file;
    }
    return;
}

1;
