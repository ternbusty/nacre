package Nacre::Net;
use v5.38;
use feature 'try';
no warnings 'experimental::try';
use Exporter 'import';
use Nacre::Const;
use Nacre::Util;
use Socket qw(AF_INET inet_aton inet_ntoa inet_pton inet_ntop);
use Fcntl qw(O_RDONLY);

# ═══════════════════════════════════════════════════════════════════════
# Network Device (netlink)
# ═══════════════════════════════════════════════════════════════════════

use constant {
    AF_NETLINK          => 16,
    NETLINK_ROUTE       => 0,
    RTM_SETLINK         => 19,
    RTM_NEWADDR         => 20,
    RTM_GETADDR         => 22,
    NLMSG_DONE          => 3,
    NLMSG_ERROR         => 2,
    NLM_F_REQUEST       => 1,
    NLM_F_ACK           => 4,
    NLM_F_DUMP          => 0x300,
    NLM_F_CREATE        => 0x400,
    NLM_F_EXCL          => 0x200,
    IFLA_IFNAME         => 3,
    IFLA_NET_NS_PID     => 19,
    IFLA_MTU            => 4,
    IFLA_ADDRESS        => 1,
    IFA_ADDRESS_ATTR    => 1,
    IFA_LOCAL           => 2,
    IFA_FLAGS           => 8,
    IFA_F_PERMANENT     => 0x80,
    RT_SCOPE_UNIVERSE   => 0,
    IFF_UP              => 1,
    SIOCGIFINDEX        => 0x8933,
    SIOCGIFHWADDR       => 0x8927,
    SIOCSIFHWADDR       => 0x8924,
    SIOCSIFMTU          => 0x8922,
    _AF_INET            => 2,
    AF_INET6            => 10,
    SOCK_DGRAM          => 2,
};

sub send_netlink ($msg) {
    socket(my $sock, AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)
        or fatal("netlink socket: $!");
    my $sa = pack('S x2 L L', AF_NETLINK, 0, 0);
    bind($sock, $sa) or fatal("netlink bind: $!");
    send($sock, $msg, 0) or fatal("netlink send: $!");
    my $ack = '';
    recv($sock, $ack, 1024, 0) or fatal("netlink recv: $!");
    close $sock;
    my ($len, $type, $flags, $seq, $pid) = unpack('L S S L L', $ack);
    if ($type == NLMSG_ERROR) {
        my $error = unpack('l', substr($ack, 16, 4));
        fatal("netlink error: " . ($error == 0 ? 'ok' : POSIX::strerror(-$error)))
            if $error != 0;
    }
}

sub get_ifindex ($ifname) {
    socket(my $sock, AF_INET, SOCK_DGRAM, 0) or fatal("socket: $!");
    my $ifreq = pack('a16 x16', $ifname);
    ioctl($sock, SIOCGIFINDEX, $ifreq) or fatal("ioctl SIOCGIFINDEX $ifname: $!");
    close $sock;
    return unpack('x16 l', $ifreq);
}

sub netlink_move_to_ns ($ifindex, $ns_pid) {
    my $msg = pack('L S S L L', 40, RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK, 1, 0)
            . pack('C x S l L L', 0, 0, $ifindex, 0, 0)
            . pack('S S L', 8, IFLA_NET_NS_PID, $ns_pid);
    send_netlink($msg);
}

sub netlink_rename ($ifindex, $new_name) {
    my $name_data = pack('Z*', $new_name);
    my $attr_len = 4 + length($name_data);
    my $padded_len = ($attr_len + 3) & ~3;
    my $total = 16 + 16 + $padded_len;
    my $msg = pack('L S S L L', $total, RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK, 1, 0)
            . pack('C x S l L L', 0, 0, $ifindex, 0, 0)
            . pack('S S', $attr_len, IFLA_IFNAME)
            . $name_data
            . ("\0" x ($padded_len - $attr_len));
    send_netlink($msg);
}

sub netlink_set_up ($ifindex) {
    my $msg = pack('L S S L L', 32, RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK, 1, 0)
            . pack('C x S l L L', 0, 0, $ifindex, IFF_UP, IFF_UP);
    send_netlink($msg);
}

sub netlink_set_down ($ifindex) {
    my $msg = pack('L S S L L', 32, RTM_SETLINK, NLM_F_REQUEST | NLM_F_ACK, 1, 0)
            . pack('C x S l L L', 0, 0, $ifindex, 0, IFF_UP);
    send_netlink($msg);
}

sub set_mtu ($ifname, $mtu) {
    socket(my $sock, AF_INET, SOCK_DGRAM, 0) or fatal("socket: $!");
    my $ifreq = pack('a16 l x12', $ifname, $mtu);
    ioctl($sock, SIOCSIFMTU, $ifreq) or fatal("ioctl SIOCSIFMTU $ifname: $!");
    close $sock;
}

sub set_mac_address ($ifname, $mac_str) {
    my @bytes = map { hex } split /:/, $mac_str;
    fatal("invalid MAC: $mac_str") unless @bytes == 6;
    socket(my $sock, AF_INET, SOCK_DGRAM, 0) or fatal("socket: $!");
    my $sa = pack('S C6 x8', 1, @bytes);
    my $ifreq = pack('a16 a16', $ifname, $sa);
    ioctl($sock, SIOCSIFHWADDR, $ifreq) or fatal("ioctl SIOCSIFHWADDR $ifname: $!");
    close $sock;
}

sub netlink_add_addr ($ifindex, $addr_str) {
    my ($addr, $prefix) = split m{/}, $addr_str;
    $prefix //= ($addr =~ /:/) ? 128 : 32;
    my $family = ($addr =~ /:/) ? AF_INET6 : AF_INET;
    my $addr_bytes = ($family == AF_INET6)
        ? inet_pton(AF_INET6, $addr)
        : inet_aton($addr);
    fatal("invalid address: $addr") unless defined $addr_bytes;
    my $addr_len = length $addr_bytes;
    my $attr_len = 4 + $addr_len;
    my $padded_attr = ($attr_len + 3) & ~3;
    my $total = 16 + 8 + $padded_attr * 2;
    my $msg = pack('L S S L L', $total,
                   RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, 1, 0)
            . pack('C C C C l', $family, $prefix, 0, RT_SCOPE_UNIVERSE, $ifindex)
            . pack('S S', $attr_len, IFA_LOCAL)
            . $addr_bytes . ("\0" x ($padded_attr - $attr_len))
            . pack('S S', $attr_len, IFA_ADDRESS_ATTR)
            . $addr_bytes . ("\0" x ($padded_attr - $attr_len));
    send_netlink($msg);
}

sub netlink_list_addrs ($ifindex) {
    socket(my $sock, AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE)
        or fatal("netlink socket: $!");
    my $sa = pack('S x2 L L', AF_NETLINK, 0, 0);
    bind($sock, $sa) or fatal("netlink bind: $!");
    my $req = pack('L S S L L', 24, RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, 1, 0)
            . pack('C C C C l', 0, 0, 0, 0, 0);
    send($sock, $req, 0) or fatal("netlink send: $!");
    my @addrs;
    my $buf;
    while (1) {
        $buf = '';
        recv($sock, $buf, 65536, 0) or last;
        my $offset = 0;
        my $type;
        while ($offset + 16 <= length($buf)) {
            my ($len, $flags, $seq, $pid);
            ($len, $type, $flags, $seq, $pid) = unpack('L S S L L', substr($buf, $offset, 16));
            last if $len < 16 || $offset + $len > length($buf);
            last if $type == NLMSG_DONE;
            if ($type == RTM_NEWADDR && $len >= 24) {
                my ($ifa_family, $ifa_prefixlen, $ifa_flags, $ifa_scope, $ifa_index) =
                    unpack('C C C C l', substr($buf, $offset + 16, 8));
                if ($ifa_index == $ifindex && $ifa_scope == RT_SCOPE_UNIVERSE) {
                    my $attr_off = $offset + 24;
                    my ($addr_data, $ext_flags);
                    while ($attr_off + 4 <= $offset + $len) {
                        my ($rta_len, $rta_type) = unpack('S S', substr($buf, $attr_off, 4));
                        last if $rta_len < 4;
                        my $data = substr($buf, $attr_off + 4, $rta_len - 4);
                        if ($rta_type == IFA_LOCAL || ($rta_type == IFA_ADDRESS_ATTR && !defined $addr_data)) {
                            $addr_data = $data;
                        } elsif ($rta_type == IFA_FLAGS) {
                            $ext_flags = unpack('L', $data) if length($data) >= 4;
                        }
                        $attr_off += ($rta_len + 3) & ~3;
                    }
                    my $final_flags = defined $ext_flags ? $ext_flags : $ifa_flags;
                    if (defined $addr_data && ($final_flags & IFA_F_PERMANENT)) {
                        push @addrs, {
                            family    => $ifa_family,
                            prefix    => $ifa_prefixlen,
                            addr_data => $addr_data,
                        };
                    }
                }
            }
            $offset += ($len + 3) & ~3;
        }
        last if $type == NLMSG_DONE;
    }
    close $sock;
    return @addrs;
}

sub move_net_devices ($netdevs, $ns_pid) {
    for my $host_name (sort keys %$netdevs) {
        my $dev = $netdevs->{$host_name};
        log_debug("netdev: moving $host_name to ns of PID $ns_pid");
        my $ifindex;
        try { $ifindex = get_ifindex($host_name) }
        catch ($e) { fatal("netdev: interface '$host_name' not found: $e") }
        my @saved_addrs = eval { netlink_list_addrs($ifindex) };
        netlink_move_to_ns($ifindex, $ns_pid);

        my $want_rename = $dev->{name} && $dev->{name} ne $host_name;
        next unless @saved_addrs || $dev->{addresses} || $want_rename;

        sysopen(my $host_ns, '/proc/self/ns/net', O_RDONLY)
            or fatal("open host netns: $!");
        sysopen(my $ctr_ns, "/proc/$ns_pid/ns/net", O_RDONLY)
            or fatal("open container netns: $!");
        my $nr = SYS_setns + 0;
        my $fd = fileno($ctr_ns) + 0;
        my $fl = CLONE_NEWNET + 0;
        syscall($nr, $fd, $fl) == 0 or fatal("setns container netns: $!");
        close $ctr_ns;

        my $new_idx = eval { get_ifindex($host_name) };
        if (defined $new_idx) {
            if ($want_rename) {
                eval { netlink_set_down($new_idx) };
                netlink_rename($new_idx, $dev->{name});
            }
            for my $a (@saved_addrs) {
                my $addr_str;
                if ($a->{family} == AF_INET) {
                    $addr_str = inet_ntoa($a->{addr_data});
                } elsif ($a->{family} == AF_INET6) {
                    $addr_str = inet_ntop(AF_INET6, $a->{addr_data});
                }
                if ($addr_str) {
                    eval { netlink_add_addr($new_idx, "$addr_str/$a->{prefix}") };
                }
            }
            eval { netlink_set_up($new_idx) };
        }

        $nr = SYS_setns + 0;
        $fd = fileno($host_ns) + 0;
        $fl = CLONE_NEWNET + 0;
        syscall($nr, $fd, $fl) == 0 or fatal("setns host netns: $!");
        close $host_ns;
    }
}

sub rename_net_devices ($netdevs) {
    for my $host_name (sort keys %$netdevs) {
        my $dev = $netdevs->{$host_name};
        my $new_name = $dev->{name} // next;
        my $ifindex = eval { get_ifindex($host_name) };
        next unless defined $ifindex;
        log_debug("netdev: renaming $host_name -> $new_name (idx=$ifindex)");
        netlink_rename($ifindex, $new_name);
    }
}

our @EXPORT = qw(
    move_net_devices rename_net_devices
);

1;
