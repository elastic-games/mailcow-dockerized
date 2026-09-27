"""Kernel peer + systemd unit identity boundary for a Unix control socket.

UID alone is insufficient: upstream rootfs numeric accounts overlap. Controller
must run on the host, own its policy, and keep service cgroups non-delegated.
No socket request supplies its own service identity or expands this allowlist.
"""
from pathlib import Path
import re
import socket
import struct


class PeerDenied(PermissionError):
    pass


def peer_unit(connection):
    if not hasattr(socket,'SO_PEERPIDFD'):
        # Linux SO_PEERPIDFD has UAPI value 77 (since Linux 6.5). Getting the fd
        # from the socket binds the exact peer task rather than reopening a PID
        # that could have been recycled after the peer exited.
        peer_pidfd_option=77
    else:peer_pidfd_option=socket.SO_PEERPIDFD
    import os,select
    pidfd=connection.getsockopt(socket.SOL_SOCKET,peer_pidfd_option)
    try:
        poll=select.poll();poll.register(pidfd,select.POLLIN)
        if poll.poll(0):raise PeerDenied('Exited peer')
        pid,uid,gid=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        rows=Path('/proc')/str(pid)/'cgroup'
        unified=[line[3:] for line in rows.read_text().splitlines() if line.startswith('0::')]
        if len(unified)!=1 or not re.fullmatch(r'(?:/system.slice/|/mailcow.slice/mailcow-jobs.slice/)[a-zA-Z0-9_.@-]+\.service',unified[0]):
            raise PeerDenied('Unregistered service cgroup')
        if poll.poll(0):raise PeerDenied('Exited peer')
        # Fixed scheduled-job slice is a distinct boundary: a service name
        # alone must not inherit permissions registered for system.slice.
        return unified[0].rsplit('/',1)[1] if unified[0].startswith('/system.slice/') else unified[0]
    except (OSError,ValueError) as error:raise PeerDenied('Kernel service identity unavailable') from error
    finally:os.close(pidfd)


def authorize(connection,allowed_units):
    unit=peer_unit(connection)
    # Only this actual upstream scheduled job calls the control API. The
    # root-owned launcher supplies UUID instances; no caller-defined role.
    if re.fullmatch(r'/mailcow.slice/mailcow-jobs.slice/mailcow-job-dovecot_sarules@[0-9a-f]{32}\.service', unit):
        unit='/mailcow.slice/mailcow-jobs.slice/mailcow-job-dovecot_sarules@.service'
    if unit not in allowed_units:raise PeerDenied('Service has no control permission')
    return allowed_units[unit]
