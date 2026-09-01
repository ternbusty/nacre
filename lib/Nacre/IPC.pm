package Nacre::IPC;
use strict;
use warnings;
use Exporter 'import';
use Nacre::Const;
use Nacre::Util;
use Socket qw(AF_UNIX SOCK_STREAM SOCK_SEQPACKET SOL_SOCKET SCM_RIGHTS
              pack_sockaddr_un PF_UNIX);
use Fcntl qw(O_RDWR O_NOCTTY);

# ═══════════════════════════════════════════════════════════════════════
# IPC Channel (socketpair-based)
# ═══════════════════════════════════════════════════════════════════════

sub create_channel {
    socketpair(my $a, my $b, PF_UNIX, SOCK_SEQPACKET, 0)
        or fatal("socketpair: $!");
    return (fileno($a), fileno($b), $a, $b);
}

sub channel_send {
    my ($fd, $msg) = @_;
    my $data = $JSON_COMPACT->encode($msg);
    my $ret = POSIX::write($fd, $data, length($data));
    fatal("channel_send: $!") unless defined $ret && $ret > 0;
}

sub channel_recv {
    my ($fd) = @_;
    my $buf;
    my $ret = POSIX::read($fd, $buf, 65536);
    return undef unless defined $ret && $ret > 0;
    return $JSON_COMPACT->decode($buf);
}

# ═══════════════════════════════════════════════════════════════════════
# Notify Socket (for start command)
# ═══════════════════════════════════════════════════════════════════════

sub create_notify_listener {
    my ($sock_path) = @_;
    unlink $sock_path;
    socket(my $srv, AF_UNIX, SOCK_STREAM, 0) or fatal("socket: $!");
    bind($srv, pack_sockaddr_un($sock_path))  or fatal("bind $sock_path: $!");
    listen($srv, 1)                           or fatal("listen: $!");
    return $srv;
}

sub wait_for_start {
    my ($srv_fh) = @_;
    accept(my $cli, $srv_fh) or fatal("accept on notify socket: $!");
    my $buf;
    sysread($cli, $buf, 4096);
    close $cli;
    return 1;
}

sub notify_container_start {
    my ($sock_path) = @_;
    socket(my $s, AF_UNIX, SOCK_STREAM, 0) or fatal("socket: $!");
    connect($s, pack_sockaddr_un($sock_path)) or fatal("connect $sock_path: $!");
    syswrite($s, "start container");
    close $s;
}

# ═══════════════════════════════════════════════════════════════════════
# FD Passing (SCM_RIGHTS)
# ═══════════════════════════════════════════════════════════════════════

# Send a file descriptor over a Unix domain socket using SCM_RIGHTS.
# Optional $payload is sent as the data (instead of a single NUL byte);
# this is used for seccomp notify listener metadata.
sub send_fd_via_socket {
    my ($socket_path, $fd, $payload) = @_;

    socket(my $sock, AF_UNIX, SOCK_STREAM, 0) or fatal("socket: $!");
    connect($sock, pack_sockaddr_un($socket_path))
        or fatal("connect to console socket '$socket_path': $!");

    my $sock_fd = fileno($sock) + 0;

    # iovec: data payload (required for SCM_RIGHTS; at least one byte)
    my $data = (defined $payload && length($payload)) ? $payload : "\x00";
    my $iov = pack('P L!', $data, length($data));

    # cmsg: SOL_SOCKET / SCM_RIGHTS / fd
    my $cmsg_data = pack('i', $fd);
    my $cmsg_len  = 8 + 4 + 4 + length($cmsg_data);   # cmsghdr + data
    my $cmsg = pack('L! i i', $cmsg_len, SOL_SOCKET, SCM_RIGHTS)
             . $cmsg_data;
    my $pad = (8 - (length($cmsg) % 8)) % 8;
    $cmsg .= "\0" x $pad;

    # msghdr (x86_64 / aarch64 LP64 layout — both are 56 bytes)
    my $msghdr = pack('Q',    0)              # msg_name      (NULL)
               . pack('I x4', 0)              # msg_namelen   (0 + pad)
               . pack('P',    $iov)           # msg_iov
               . pack('Q',    1)              # msg_iovlen
               . pack('P',    $cmsg)          # msg_control
               . pack('Q',    length($cmsg))  # msg_controllen
               . pack('I x4', 0);             # msg_flags     (0 + pad)

    my $nr  = SYS_sendmsg + 0;
    my $ret = syscall($nr, $sock_fd, $msghdr, 0);
    $ret >= 0 or fatal("sendmsg (console socket): $!");

    close($sock);
}

# Send a file descriptor over an already-connected socket fd (not a path).
sub send_fd_over_fd {
    my ($sock_fd, $fd) = @_;
    $sock_fd = $sock_fd + 0;
    my $data = "\x00";
    my $iov  = pack('P L!', $data, 1);
    my $cmsg_data = pack('i', $fd);
    my $cmsg_len  = 8 + 4 + 4 + length($cmsg_data);
    my $cmsg = pack('L! i i', $cmsg_len, SOL_SOCKET, SCM_RIGHTS)
             . $cmsg_data;
    my $pad = (8 - (length($cmsg) % 8)) % 8;
    $cmsg .= "\0" x $pad;
    my $msghdr = pack('Q',    0)
               . pack('I x4', 0)
               . pack('P',    $iov)
               . pack('Q',    1)
               . pack('P',    $cmsg)
               . pack('Q',    length($cmsg))
               . pack('I x4', 0);
    my $nr  = SYS_sendmsg + 0;
    my $ret = syscall($nr, $sock_fd, $msghdr, 0);
    return $ret >= 0;
}

# Receive a file descriptor over a socket fd.
sub recv_fd_over_fd {
    my ($sock_fd) = @_;
    $sock_fd = $sock_fd + 0;
    my $data = "\0";
    my $iov  = pack('P L!', $data, 1);
    # Space for one fd in cmsg
    my $cmsg_space = 8 + 4 + 4 + 4;  # cmsghdr + one int
    my $pad = (8 - ($cmsg_space % 8)) % 8;
    $cmsg_space += $pad;
    my $cmsg_buf = "\0" x $cmsg_space;
    my $msghdr = pack('Q',    0)
               . pack('I x4', 0)
               . pack('P',    $iov)
               . pack('Q',    1)
               . pack('P',    $cmsg_buf)
               . pack('Q',    $cmsg_space)
               . pack('I x4', 0);
    my $nr  = SYS_recvmsg + 0;
    my $ret = syscall($nr, $sock_fd, $msghdr, 0);
    return -1 if $ret < 0;
    # Extract fd from cmsg (offset: L! + i + i = 8+4+4 = 16 on LP64)
    my $fd = unpack('i', substr($cmsg_buf, 16, 4));
    return $fd;
}

# ═══════════════════════════════════════════════════════════════════════
# PTY / Console Socket
# ═══════════════════════════════════════════════════════════════════════

# Create a PTY pair, send the master to the console socket, return the
# slave file descriptor (as an integer fd number).  Must be called before
# pivot_root so that both /dev/ptmx and the console-socket path are
# reachable on the host filesystem.
sub setup_pty_console {
    my ($console_socket_path) = @_;

    # Open PTY master
    sysopen(my $ptm, '/dev/ptmx', O_RDWR | O_NOCTTY | O_CLOEXEC)
        or fatal("open /dev/ptmx: $!");

    # Get slave number
    my $ptn_buf = pack('i', 0);
    ioctl($ptm, TIOCGPTN, $ptn_buf) or fatal("TIOCGPTN: $!");
    my $ptn = unpack('i', $ptn_buf);

    # Unlock slave
    my $unlock = pack('i', 0);
    ioctl($ptm, TIOCSPTLCK, $unlock) or fatal("TIOCSPTLCK: $!");

    # Open slave (keep it open across pivot_root; we dup2 it to 0/1/2 later)
    my $pts_path = "/dev/pts/$ptn";
    sysopen(my $pts, $pts_path, O_RDWR | O_NOCTTY)
        or fatal("open PTY slave $pts_path: $!");

    # Deliver master to whoever is listening on the console socket
    send_fd_via_socket($console_socket_path, fileno($ptm));

    # Master stays open in the receiver; close our copy
    close($ptm);

    # Dup the slave fd so it survives the $pts filehandle going out of scope.
    # POSIX::dup returns a raw fd number not tied to any Perl handle, so it
    # won't be auto-closed when this sub returns.
    my $dup_fd = POSIX::dup(fileno($pts));
    fatal("dup PTY slave: $!") unless defined $dup_fd && $dup_fd >= 0;
    close($pts);

    return $dup_fd;
}

# Set a PTY fd to raw mode (cfmakeraw equivalent).
# Disables OPOST/ONLCR so \n is not converted to \r\n, ECHO so input
# is not reflected, and line-editing (ICANON) so reads return immediately.
sub pty_set_raw {
    my ($fd) = @_;
    # TCGETS = 0x5401, TCSETS = 0x5402 on Linux x86_64/aarch64
    use constant TCGETS_C => 0x5401;
    use constant TCSETS_C => 0x5402;
    # struct termios: 4 x u32 (c_iflag, c_oflag, c_cflag, c_lflag) + u8 c_line + 19 x u8 c_cc + pad
    # total = 16 + 1 + 19 + pad = 60 bytes on Linux
    my $termios = "\0" x 60;
    if (open my $fh, '+<&', $fd) {
        ioctl($fh, TCGETS_C, $termios) or do { close $fh; return; };
        my ($iflag, $oflag, $cflag, $lflag) = unpack('LLLL', $termios);
        # Clear input flags: IGNBRK, BRKINT, PARMRK, ISTRIP, INLCR, IGNCR, ICRNL, IXON
        $iflag &= ~(0x001 | 0x002 | 0x008 | 0x020 | 0x040 | 0x080 | 0x100 | 0x400);
        # Clear output flags: OPOST
        $oflag &= ~0x001;
        # Clear local flags: ECHO, ECHONL, ICANON, ISIG, IEXTEN
        $lflag &= ~(0x008 | 0x040 | 0x002 | 0x001 | 0x8000);
        # Clear char size, set CS8
        $cflag &= ~0x030;   # ~CSIZE
        $cflag |=  0x030;   # CS8
        # VMIN=1, VTIME=0
        substr($termios, 0, 16, pack('LLLL', $iflag, $oflag, $cflag, $lflag));
        my $cc_offset = 16 + 1;  # after c_line byte
        substr($termios, $cc_offset + 6, 1, pack('C', 1));  # VMIN
        substr($termios, $cc_offset + 5, 1, pack('C', 0));  # VTIME
        ioctl($fh, TCSETS_C, $termios);
        close $fh;
    }
}

our @EXPORT = qw(
    create_channel channel_send channel_recv
    create_notify_listener wait_for_start notify_container_start
    send_fd_via_socket send_fd_over_fd recv_fd_over_fd
    setup_pty_console pty_set_raw
);

1;
