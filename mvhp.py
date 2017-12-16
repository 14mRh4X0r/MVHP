#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This program is free software. It comes without any warranty, to
# the extent permitted by applicable law. You can redistribute it
# and/or modify it under the terms of the Do What The Fuck You Want
# To Public License, Version 2, as published by Sam Hocevar. See
# http://sam.zoy.org/wtfpl/COPYING for more details.

import asyncore
import asynchat
import socket
import re
import signal
import sys
import os
import pwd
import grp
import io

try:
    import json
except:
    import simplejson as json

from codecs import utf_16_be_encode, utf_16_be_decode
from struct import pack, unpack


CONFIG_PATH = "config.json"


def drop_privileges(uid_name='nobody', gid_name='nogroup'):
    if os.getuid() != 0:
        # We're not root so, like, whatever dude
        return

    # Get the uid/gid from the name
    running_uid = pwd.getpwnam(uid_name).pw_uid
    running_gid = grp.getgrnam(gid_name).gr_gid

    # Remove group privileges
    os.setgroups([])

    # Try setting the new uid/gid
    os.setgid(running_gid)
    os.setuid(running_uid)

    # Ensure a very conservative umask
    old_umask = os.umask(077)

def pack_string(string):
    '''
    Packs a string into UCS-2 and prefixes it with its length as a short int.

    This function can't actually handle UCS-2, therefore kick messages and
    the MOTD can't contain special characters.
    '''
    string = u"".join(i if ord(i) < 65536 else u"?" for i in string)
    return (pack(">h", len(string)) +
            utf_16_be_encode(string, "replace")[0])


def varint_from_string(string):
    data = io.BytesIO(string)
    num = 0
    byte = ord(data.read(1))
    read = 1
    while byte & 0x80 > 0:
        num += (byte & 0x7F) << (7 * (read - 1))
        byte = ord(data.read(1))
        read += 1
    num += byte << (7 * (read - 1))
    return read, num

def num_to_varint(num):
    data = str()
    while (num >> 7) > 0:
        data += chr((num & 0x7F) | 0x80)
        num = num >> 7
    data += chr(num & 0x7F)
    return data

def unpack_string(data):
    '''
    Extracts a string from a data stream.

    Like in the pack method, UCS-2 isn't handled correctly. Since usernames
    and hosts can't contain special characters this isn't an issue.
    '''
    (l,) = unpack(">h", data[:2])
    assert len(data) >= 2 + 2 * l
    return utf_16_be_decode(data[2:2 + l * 2])[0]


class Router:
    '''
    The router finds the target server from the string sent in the handshake.
    '''
    PATTERN = re.compile("^([^;]+);([^;]+):(\d{1,5})$")

    @staticmethod
    def route(info):
        '''
        Finds the target host and port based on the handshake string.
        '''
        host = info['hostname']
        target = config.hosts.get(host, config.hosts.get(config.fallback_host, None))
        if target is None:
            return None
        return (target.get("host", "localhost"), target.get("port", 25565))

    #@staticmethod
    #def find_host(name):
    #    '''
    #    Extracts the host from the handshake string.
    #    '''
    #    match = re.match(Router.PATTERN, name)
    #    if match is None:
    #        return
    #    host = match.group(2)
    #    if host not in config.hosts:
    #        return
    #    return host


class Listener(asyncore.dispatcher):
    '''
    Listens for connecting clients.
    '''
    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        self.clients = []
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(5)
        print "Listening for connections on %s:%s" % (host, port)

    def handle_accept(self):
        '''
        Accepts a new connections and assigns it to a new ClientTunnel.
        '''
        pair = self.accept()
        if pair is None:
            pass
        else:
            sock, addr = pair
            self.clients.append(ClientTunnel(sock, addr, self))

    def remove(self, client):
        '''
        Removes a client from the list of connections.
        '''
        if client in self.clients:
            self.clients.remove(client)

    def terminate(self):
        '''
        Disconnects all clients and stops listening for new ones.
        '''
        print "Shutting down..."
        for client in self.clients:
            client.kick("The proxy server is shutting down")
        self.close()

    @staticmethod
    def loop():
        '''
        Starts the main I/O loop.
        '''
        asyncore.loop()


class ClientTunnel(asynchat.async_chat):
    '''
    Handles a connecting client and assigns it to a server
    '''
    def __init__(self, sock, addr, parent):
        asynchat.async_chat.__init__(self, sock)
        self.parent = parent
        self.set_terminator(None)
        self.ibuffer = ""
        self.ibuf_pos = 0
        self.bound = False
        self.server = None
        self.addr = "%s:%s" % addr
        self.state = 0 # Handshake
        self.log("Incoming connection")

    def log(self, message):
        '''
        Feedback to user
        '''
        print "%s - %s" % (self.addr, message)

    def collect_incoming_data(self, data):
        '''
        Listens for data and forwards it to the server.

        If the client is not yet connected to a server this method waits
        for a handshake packet to read the host from. If the client sends
        a server list query (0xfe) the connection is closed after sending
        the static server list data to the client.
        '''
        if self.bound:
            if not self.server.connected:
                self.ibuffer += data
            else:
                self.server.push(data)
        else:
            print "received data: %r" % data
            self.ibuffer += data
            try:
                read, length = varint_from_string(self.ibuffer[self.ibuf_pos:])
            except Exception as e:
                return

            if len(self.ibuffer[self.ibuf_pos + read:]) >= length:
		self.ibuf_pos += read
                data = self.ibuffer[self.ibuf_pos:self.ibuf_pos + length]
                self.ibuf_pos += length

                pos = 0
                read, packetId = varint_from_string(data)
                pos += read
                if self.state == 0:        # Handshake
                    read, proto_ver = varint_from_string(data[pos:])
                    pos += read

                    read, host_len = varint_from_string(data[pos:])
                    pos += read
                    host = data[pos:pos + host_len].decode('utf-8')
                    pos += host_len

                    port = unpack('!H', data[pos:pos + 2])
                    pos += 2

                    _, self.state = varint_from_string(data[pos:])

                    if self.state == 2:
                        self.bind_server({'proto_ver':  proto_ver,
                                          'hostname':   host,
                                          'port':       port})
                    else:
                        self.proto_ver = proto_ver
                        self.host = host
                elif self.state == 1:      # Handle status
                    if packetId == 0x01:
                        self.push(num_to_varint(len(data)) + data)
                        return

                    if packetId == 0x00:
                        response = json.dumps({
                                'version': {
                                    'name':     'MVHP 14mRh4X0r',
                                    'protocol': self.proto_ver
                                },
                                'players': {
                                    'max': config.capacity,
                                    'online': len(server.clients) - 1
                                },
                                'description': {
                                    'text': config.motd +
                                        '\nForwarding to: %s:%d' % Router.route({'hostname': self.host})
                                }
                        }).encode('utf-8')
                        data = '\x00' + num_to_varint(len(response)) + response
                        self.push(num_to_varint(len(data)) + data)
                else:
                    self.kick("Unexpected state")

    def parse_handshake_info(self):
        read_pos = 1
        to_read_pos = read_pos + 1 + 2

        if len(self.ibuffer) < to_read_pos:
            return None
        (proto_ver, uname_len) = unpack("!Bh", self.ibuffer[read_pos:to_read_pos])
        read_pos = read_pos + 1

        to_read_pos = to_read_pos + uname_len * 2
        if len(self.ibuffer) < to_read_pos:
            return None
        uname = unpack_string(self.ibuffer[read_pos:])
        read_pos = to_read_pos

        to_read_pos = read_pos + 2
        if len(self.ibuffer) < to_read_pos:
            return None
        (hname_len,) = unpack("!h", self.ibuffer[read_pos:to_read_pos])

        to_read_pos = to_read_pos + hname_len * 2
        if len(self.ibuffer) < to_read_pos:
            return None
        hname = unpack_string(self.ibuffer[read_pos:])
        read_pos = to_read_pos

        to_read_pos = read_pos + 4
        if len(self.ibuffer) < to_read_pos:
            return None
        (port,) = unpack("!i", self.ibuffer[read_pos:to_read_pos])
        read_pos = to_read_pos

        return {'proto_ver':    proto_ver,
                'username':     uname,
                'hostname':     hname,
                'port':         port}


    def bind_server(self, info):
        '''
        Finds the target server and creates a ServerTunnel to it.
        '''
        server = Router.route(info)
        if server is None:
            self.kick("No minecraft server exists at this address")
            return
        (host, port) = server
        self.log("Forwarding to %s:%s" % (host, port))
        self.server = ServerTunnel(host, port, self, info)
        self.bound = True

    def kick(self, reason):
        '''
        Kicks the client.
        '''
        if self.state != 2: return
        self.log("Kicking (%s)" % reason)
        message = json.dumps({'text': reason}).encode('utf-8')
        data = '\x40' + num_to_varint(len(message)) + message
        self.push(num_to_varint(len(data)) + data)
        self.close()

    def handle_close(self):
        self.log("Client closed connection")
        self.close()

    def close(self):
        '''
        Terminates the ServerTunnel if the client closes the connection.
        '''
        self.parent.remove(self)
        if self.server is not None:
            self.server.close()
        asynchat.async_chat.close(self)


class ServerTunnel(asynchat.async_chat):
    '''
    Represents the server side of a connection.

    Data from the server is forwarded to the client.
    '''
    def __init__(self, host, port, client, handshake):
        asynchat.async_chat.__init__(self)
        self.set_terminator(None)
        self.client = client
        self.handshake_msg = handshake
        self.connected = False
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect((host, port))

    def log(self, message):
        '''
        Feedback to user
        '''
        self.client.log(message)

    def handle_error(self):
        '''
        Handles socket errors
        '''
        try:
            err = self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if err == 61:
                self.client.kick("Server unreachable")
                return
        except:
            pass
        self.client.kick("Unexpected error")

    def handle_connect(self):
        '''
        Repeats the handshake packet for the actual server
        '''
        #self.push(pack(">B", 0x02) + pack_string(self.handshake_msg))
        self.push(self.client.ibuffer)
        self.connected = True

    def handle_close(self):
        '''
        Terminates the ClientTunnel if the server closes the connection.
        '''
        self.log("Server closed connection")
        self.client.close()
        self.close()
        self.client.parent.remove(self.client)

    def collect_incoming_data(self, data):
        '''
        Forwards incoming data to the client
        '''
        self.client.push(data)


class Config:
    '''
    Global configuration
    '''
    def __init__(self, path):
        self._path = path
        self.reload()

    def reload(self):
        '''
        Loads the configuration from file .
        '''
        fp = open(self._path, "r")
        try:
            raw_config = json.load(fp)
        finally:
            fp.close()
        if not isinstance(raw_config, dict):
            raise Exception("Invalid structure")
        self.hosts = self._expand(raw_config.get("hosts", {}))
	self.fallback_host = raw_config.get("fallback_host", next(iter(self.hosts)))
        self.capacity = raw_config.get("capacity", 0)
        self.motd = raw_config.get("motd", "Minecraft VirtualHost Proxy")
        print "Loaded %s host definitions" % len(self.hosts)

    def _expand(self, hosts):
        '''
        Resolves aliases in hosts and validates hosts.
        '''
        for host, config in hosts.items():
            if not isinstance(config, dict):
                hosts.pop(host)
                continue
            if "port" in config:
                port = config.get("port")
                if not isinstance(port, int) or port < 0 or port > 65535:
                    print "Invalid port for host %s: %s" % (host, port)
                    config.pop("port")
            if isinstance(config.get("alias"), list):
                for alias in config.get("alias"):
                    if alias not in hosts:
                        hosts.update({alias: config})
                config.pop("alias")
        return hosts


def refresh(signum, frame):
    '''
    Reload the configuration on SIGHUP
    '''
    try:
        config.reload()
    except Exception as e:
        print "Invalid configuration file:"
        print e


def info(signum, frame):
    '''
    Show client count on SIGINFO
    '''
    print "Hosts: %s Clients: %s" % (len(config.hosts), len(server.clients))


def terminate(signum, frame):
    '''
    Disconnect all clients before terminating
    '''
    server.terminate()
    sys.exit(0)


if __name__ == "__main__":
    try:
        config = Config(CONFIG_PATH)
    except Exception as e:
        print "Invalid configuration file:"
        print e
        sys.exit(1)

    try:
        signal.signal(signal.SIGHUP, refresh)
    except Exception as e:
        print "NOTICE: SIGHUP not supported on your OS"

    try:
        signal.signal(signal.SIGINFO, info)
    except Exception as e:
        print "NOTICE: SIGINFO not supported on your OS, binding to SIGUSR1"
        try:
            signal.signal(signal.SIGUSR1, info)
        except:
            print "NOTICE: SIGUSR1 not supported on your OS either."

    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, terminate)
    server = Listener('0.0.0.0', 443)
    drop_privileges('willem', 'willem')
    Listener.loop()
