import errno
import grp
import os
import pwd
import socket
import subprocess
import sys
import yaml


class AuthServer(object):

    def __init__(self, socketpath):
        try:
            os.unlink(socketpath)
        except (IOError, OSError) as e:
            if e.errno != errno.ENOENT:
                raise

        try:
            os.mkdir(os.path.dirname(socketpath))
        except (IOError, OSError) as e:
            if e.errno != errno.EEXIST:
                raise

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(socketpath)
        self.sock = sock

    def serve(self):
        sock = self.sock
        sock.listen(1)

        while True:
            connection, clientinfo = sock.accept()
            sys.stderr.write("%s: new connection\n" % clientinfo)
            try:
                data = connection.recv(1024)
                if not data:
                    sys.stderr.write("%s: zero data received\n" % clientinfo)
                data = yaml.safe_load(data)
                if data["request"] == "by_username":
                    user = data["username"]
                    try:
                        pwnam = pwd.getpwnam(user)
                        grps = subprocess.check_output(["id", "-Gn", "--", user])
                        grps = dict((grp.getgrnam(g).gr_gid, g) for g in grps.strip().split())
                        pwinfo = {
                            "response": "found",
                            "gecos": pwnam.pw_gecos,
                            "uid": pwnam.pw_uid,
                            "gid": pwnam.pw_gid,
                            "grp": grps,
                        }
                        # FIXME: use safe_dump, requires changes here and in the client.
                        connection.sendall(bytearray(yaml.dump(pwinfo), "ascii"))
                    except KeyError:
                        connection.sendall(bytearray(yaml.dump({"response": "notfound"}), "ascii"))
                else:
                    sys.stderr.write("%s: unknown command %r received\n" % (clientinfo, data["request"]))
            except Exception as e:
                sys.stderr.write("%s: exception: %s\n" % (clientinfo, e))
            connection.close()


if __name__ == "__main__":
    s = AuthServer(sys.argv[1])
    s.serve()
