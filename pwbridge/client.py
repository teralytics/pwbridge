from __future__ import print_function

import socket
import sys
import yaml


class ProtocolError(Exception): pass


class AuthClient(object):

    def __init__(self, socketpath):
        self.socketpath = socketpath

    def by_username(self, username):
        """Returns full name, UID, GID, and all users' groups as {gid: name}.

        Returns None if user not found."""
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self.socketpath)
        try:
            data = {"request": "by_username", "username": username}
            sock.sendall(bytearray(yaml.safe_dump(data), "ascii"))
            sock.shutdown(socket.SHUT_WR)
            resp = sock.recv(1048576)
            if not resp:
                raise ProtocolError("server response was empty")
            resp = yaml.load(resp) # FIXME: use safe_load, requires server changes.
            if resp["response"] == "notfound":
                # User does not exist.
                return None
            grp = resp['grp']
            groups = dict((gn.gr_gid, gn.gr_name) for gn in grp if gn.gr_gid == resp["gid"])
            return resp["gecos"], resp["uid"], resp["gid"], groups
        finally:
            sock.close()


if __name__ == "__main__":
    s = AuthClient(sys.argv[1])
    print(s.by_username(sys.argv[2]))
