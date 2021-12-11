
import struct
import fcntl
import subprocess


DEFAULT_MTU = 1420

IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
TUNSETIFF = 0x400454ca


def cmd(cmd: str, strict=True) -> str:
    sh_cmd = ['sh', '-c', cmd]
    child = subprocess.Popen(
        sh_cmd,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        universal_newlines=True, shell=False)

    stdout, _stderr = child.communicate()
    rc = child.returncode

    if stdout.strip():
        print(f'{cmd} (error: {stdout.strip()})')
    else:
        print(cmd)

    if strict and int(rc) != 0:
        raise Exception(f'cmd ({cmd}) error: {stdout}')

    return stdout


class Tunnel:
    def __init__(self, name: str, addr: str, mtu: int=DEFAULT_MTU):
        self.name = name
        self.addr = addr
        self.mtu = mtu

    def add(self) -> 'Tunnel':
        cmd(f'ip tuntap add dev {self.name} mode tun', strict=False)
        cmd(f'ip link set {self.name} mtu {self.mtu}')
        cmd(f'ip addr add {self.addr} dev {self.name}', strict=False)
        cmd(f'ip link set {self.name} up')
        return self

    def open(self) -> int:
        ifr = struct.pack('16sH', str.encode(self.name), IFF_TUN | IFF_NO_PI)
        tun_fd = open('/dev/net/tun', mode='r+b', buffering=0)
        fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
        return tun_fd
