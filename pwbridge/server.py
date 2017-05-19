import cPickle as pickle
import errno
import grp
import os
import pwd
import socket
import sys


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
            # Wait for a connection
            connection, client_address = sock.accept()
            try:
                # Receive the data in small chunks and retransmit it
                data = connection.recv(256)
                if data[0] == '0':
                    user = data[1:]
                    try:
                        pwnam = pwd.getpwnam(user)
                        pwinfo = {
                            "pwnam": pwnam,
                            "grp": grp.getgrall()
                        }
                        connection.sendall('0' + pickle.dumps(pwinfo))
                    except KeyError:
                        connection.sendall('1')
                else:
                    sys.stderr.write("Unknown command %s" % data[0])
                if data:
                    connection.sendall(data)
            finally:
                # Clean up the connection
                connection.close()


if __name__ == "__main__":
    s = AuthServer(sys.argv[1])
    s.serve()
