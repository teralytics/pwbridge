import errno
import grp
import os
import pwd
import socket
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
            sys.stderr.write("%s: new connection" % clientinfo)
            try:
                data = connection.recv(256)
                if not data:
                    sys.stderr.write("%s: zero data received" % clientinfo)
                if data[0] == '0':
                    user = data[1:]
                    try:
                        pwnam = pwd.getpwnam(user)
                        pwinfo = {
                            "response": "found",
                            "pwnam": pwnam,
                            "grp": grp.getgrall(),
                        }
                        connection.sendall(yaml.dump(pwinfo))
                    except KeyError:
                        connection.sendall(yaml.dump({"response": "notfound"}))
                else:
                    sys.stderr.write("%s: unknown command %r received" % (clientinfo, data[0]))
                if data:
                    connection.sendall(data)
            except Exception as e:
                sys.stderr.write("%s: exception: %s" % (clientinfo, e))
            connection.close()


if __name__ == "__main__":
    s = AuthServer(sys.argv[1])
    s.serve()
