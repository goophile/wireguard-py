#!/usr/bin/env python3

import logging
import time
import socket
import argparse
import traceback
# from multiprocessing import Process as Worker
from threading import Thread as Worker

from wireguard import handshake, message, tunnel


server_private = "wO/ijc4zUq9GNZp+9ugE7cBbcS6uJ3h3mSdsrKDJykI="
server_public  = "zkGICx04YArHifC+lS0jX4qrcquI5Fvl77vVbY+JlV4="
client_private = "qD17OTguyZSmb0467XEeB9mUbNPI9Nh/37V220Nzzk8="
client_public  = "Vs25OG9m9Upl6oR5/1KSy9fPaH+iSbP0Vaq1/WoDNA4="
preshared_key  = "FpCyhws9cxwWoV4xELtfJvjJN+zQVRPISllRWgeopVE="

peer_addr = ("127.0.0.1", 51820)


def worker_send(sock, tun, wg):

    pkt = message.DataHeader()
    pkt.type = message.TYPE_TRANSPORT_DATA
    pkt.receiver = wg.remote_id
    counter = 0

    while True:
        try:
            body = tun.read(1500)
            pkt.counter = counter.to_bytes(8, 'little')
            outter = pkt.to_network() + wg.noise.encrypt(bytes(body))
            counter += 1
            sock.sendto(outter, peer_addr)

        except OSError as err:
            # If tunif deleted:
            # OSError: [Errno 14] Bad address
            # OSError: [Errno 77] File descriptor in bad state
            print(f'Got Exception in worker_send: {err.__class__.__name__}: {err}')

        except Exception as exc:
            print(traceback.format_exc())
            print(f'Got Exception in worker_send: {exc.__class__.__name__}: {exc}')


def worker_recv(sock, tun, wg):

    pkt = message.DataHeader()

    while True:
        try:
            packet, _ = sock.recvfrom(1500)
            pkt.from_network(packet[:message.DataHeader.HEADER_SIZE])
            body = wg.noise.decrypt(packet[message.DataHeader.HEADER_SIZE:])
            if body:
                tun.write(body)

        except Exception as exc:
            print(traceback.format_exc())
            print(f'Got Exception in worker_recv: {exc.__class__.__name__}: {exc}')


def start_server(sock, tun):

    wg = handshake.Responder(
        our_private     = server_private,
        their_public    = client_public,
        psk             = preshared_key,
    )

    global peer_addr
    packet, peer_addr = sock.recvfrom(148)
    wg.recv(packet)
    sock.sendto(wg.send(), peer_addr)
    print("server handshake response sent")

    Worker(target=worker_send, args=(sock, tun, wg)).start()
    Worker(target=worker_recv, args=(sock, tun, wg)).start()

    while True:
        time.sleep(0.1)


def start_client(sock, tun):

    wg = handshake.Initiator(
        our_private     = client_private,
        their_public    = server_public,
        psk             = preshared_key,
    )

    sock.sendto(wg.send(), peer_addr)
    packet = sock.recv(92)
    wg.recv(packet)
    print("client handshake success")

    Worker(target=worker_send, args=(sock, tun, wg)).start()
    Worker(target=worker_recv, args=(sock, tun, wg)).start()

    while True:
        time.sleep(0.1)

def main():
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('-s', action='store_true', default=False, help='Start as server.')
    parser.add_argument('-c', action='store_true', default=False, help='Start as client.')
    parser.add_argument('-p', default="", help='Peer address.')
    args = parser.parse_args()

    tun_nic = tunnel.Tunnel("tun1", "192.168.2.3/24")
    tun_fd = tun_nic.add().open()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', 51820))

    if args.p:
        global peer_addr
        peer_addr = (args.p, 51820)

    if args.s:
        start_server(sock, tun_fd)
    if args.c:
        start_client(sock, tun_fd)


if __name__ == "__main__":
    main()
