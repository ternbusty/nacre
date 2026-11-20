package Nacre::ExeGuard;
use v5.38;

# ═══════════════════════════════════════════════════════════════════════
# Keep the container from overwriting the host's perl (CVE-2019-5736)
# ═══════════════════════════════════════════════════════════════════════
#
# nacre's processes in the container (the init, and the process "nacre
# exec" starts) run the host's perl until they exec the container's
# program, and /proc/<pid>/exe refers to that file from any mount
# namespace. A container whose root is the host's root can take hold of it
# -- for example, by making the program nacre execs a "#!/proc/self/exe"
# script -- and write to it once no process executes it any more: the next
# perl program root runs on the host is then the container's.
#
# As runc does, re-exec perl from a copy the container cannot write before
# doing anything else: a read-only mount of the binary, or, where that is
# not possible, a sealed memfd. /proc/self/exe then refers to that copy,
# also in the processes forked from here. It is called from a BEGIN block
# at the top of nacre, so the rest of nacre is compiled once, after the
# re-exec.

# This runs before nacre loads anything, in a process that only re-execs:
# loading Nacre::Const would add ~3 ms to every create, run and exec. The
# read-only mount needs only these, the same on x86_64 and aarch64 (system
# calls added since Linux 5.1, numbered 424 and up, have one number on all
# architectures); test/unit/exe-guard.t checks them against Nacre::Const.
# The memfd fallback loads Nacre::Const.
# Constant subs rather than "use constant", whose loading costs ~1.5 ms. A
# body of one constant, without "return", is what lets perl inline them.
## no critic (Subroutines::RequireFinalReturn)
sub SYS_open_tree : prototype() {428}
sub SYS_mount_setattr : prototype() {442}
sub OPEN_TREE_CLONE : prototype() {0x00000001}
sub OPEN_TREE_CLOEXEC : prototype() {0x00080000}
sub AT_EMPTY_PATH : prototype() {0x00001000}
sub MOUNT_ATTR_RDONLY : prototype() {0x00000001}
## use critic

my $AT_FDCWD = -100;
my $MARKER = '_NACRE_EXE_GUARDED';

# The memfd's file handle: it must outlive _sealed_memfd(), or closing it
# would close the descriptor exec needs.
my $memfd_fh;

# Re-exec this perl from a protected copy, with the same script and
# arguments; returns once running from it.
# nacre's BEGIN block checks the marker and the uid before loading this
# module; these checks only keep the function safe to call on its own.
sub reexec_from_protected_copy ($argv) {
    return if delete $ENV{$MARKER};    # this is the re-executed perl

    # Without root (rootless), the container's root is not the host's root
    # and cannot write the host's perl.
    return if $> != 0;

    my $fd = _readonly_mount() // _sealed_memfd()
        // die "nacre: cannot make a protected copy of perl to run from: $!\n";
    $ENV{$MARKER} = 1;
    exec {"/proc/self/fd/$fd"} $^X, $0, @$argv;
    die "nacre: cannot re-exec perl from its protected copy: $!\n";
}

# A detached, read-only bind mount of the running perl binary (needs
# CAP_SYS_ADMIN and Linux 5.12): writes through it fail with EROFS.
sub _readonly_mount () {
    my $path = "/proc/self/exe\0";
    my $fd = syscall(SYS_open_tree + 0, $AT_FDCWD, $path, OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
    return if $fd < 0;
    my $attr = pack('QQQQ', MOUNT_ATTR_RDONLY, 0, 0, 0);
    my $empty = "\0";
    return if syscall(SYS_mount_setattr + 0, $fd + 0, $empty, AT_EMPTY_PATH + 0, $attr, length $attr) != 0;
    return $fd;
}

# A copy of the running perl binary in a memfd sealed against writes.
sub _sealed_memfd () {
    unshift @INC, __FILE__ =~ s{/Nacre/ExeGuard\.pm\z}{}r;
    require Nacre::Const;
    my $name = "nacre-perl\0";
    my $fd = syscall(Nacre::Const::SYS_memfd_create() + 0,
        $name, Nacre::Const::MFD_CLOEXEC() | Nacre::Const::MFD_ALLOW_SEALING());
    return if $fd < 0;
    open($memfd_fh, '+<&=', $fd) or return;    ## no critic (RequireBriefOpen) -- open until the exec
    _copy_exe_to($memfd_fh) or return;
    my $seals = Nacre::Const::F_SEAL_SEAL() | Nacre::Const::F_SEAL_SHRINK() | Nacre::Const::F_SEAL_GROW()
        | Nacre::Const::F_SEAL_WRITE();
    fcntl($memfd_fh, Nacre::Const::F_ADD_SEALS(), $seals) or return;
    return $fd;
}

# Copy the running perl binary to $dst; false on an error.
sub _copy_exe_to ($dst) {
    open(my $src, '<:raw', '/proc/self/exe') or return 0;
    my $n;
    while ($n = sysread($src, my $buf, 1 << 20)) {
        my $off = 0;
        while ($off < $n) {
            my $w = syswrite($dst, $buf, $n - $off, $off) // return 0;
            $off += $w;
        }
    }
    close $src;
    return defined $n;
}

1;
