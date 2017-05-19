from __future__ import print_function

import os
import socket
import sys
import yaml


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
            resp = yaml.load(resp) # FIXME: use safe_load, requires server changes.
            if resp["response"] == "notfound":
                # User does not exist.
                return None
            pwnam = resp["pwnam"]
            grp = resp['grp']
            groups = dict((gn.gr_gid, gn.gr_name) for gn in grp if gn.gr_gid == pwnam.pw_gid)
            return pwnam.pw_gecos, pwnam.pw_uid, pwnam.pw_gid, groups
        finally:
            sock.close()


if __name__ == "__main__":
    s = AuthClient(sys.argv[1])
    print(s.by_username(os.environ["USER"]))
