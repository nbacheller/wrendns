#!/usr/bin/env python3
"""Writes the two SNMP walks the poller's tests serve from a fake agent.

They are SYNTHETIC: laid out as `snmpwalk -On` prints the tables of a Net-SNMP gateway (the shape
a UniFi gateway answers: ipNetToPhysicalTable with 100 IPv4 and 72 IPv6 entries, 162 with
a MAC; ipNetToMediaTable with 100; no BRIDGE, Q-BRIDGE or LLDP MIB) and of an L2 managed switch (a
Q-BRIDGE forwarding table whose FDB IDs differ from its VLAN IDs, an uplink with more than 8 MACs,
a trunk to the gateway found by LLDP). No device was asked: nothing here was recorded from a real
network. Run `python3 generate.py` to rewrite the files.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def mac_text(m):
    return " ".join("%02X" % b for b in m) + " "


def mac(prefix, n):
    return bytes(prefix) + bytes([(n >> 8) & 0xFF, n & 0xFF])


class Walk:
    def __init__(self):
        self.rows = []

    def add(self, oid, typ, value):
        self.rows.append((oid, typ, value))

    def s(self, oid, text):
        self.add(oid, "STRING", text)

    def i(self, oid, n):
        self.add(oid, "INTEGER", str(n))

    def h(self, oid, raw):
        if raw:
            self.add(oid, "Hex-STRING", mac_text(raw))
        else:
            self.add(oid, "STRING", "")

    def o(self, oid, val):
        self.add(oid, "OID", val)

    def dump(self, path):
        def key(r):
            return [int(x) for x in r[0].strip(".").split(".")]

        with open(path, "w", newline="\n") as f:
            for oid, typ, val in sorted(self.rows, key=key):
                f.write(".%s = %s: %s\n" % (oid.strip("."), typ, val))


def gateway():
    w = Walk()
    gw_mac = bytes([0x70, 0xA7, 0x41, 0xAA, 0x00, 0x01])
    w.o("1.3.6.1.2.1.1.2.0", ".1.3.6.1.4.1.8072.3.2.10")
    ifs = [
        (1, "lo", None, 1),
        (2, "eth4", bytes([0x70, 0xA7, 0x41, 0xAA, 0x00, 0x02]), 1),
        (3, "br0", gw_mac, 1),
        (4, "br20", gw_mac, 1),
        (5, "br30", gw_mac, 2),
    ]
    for idx, name, m, oper in ifs:
        w.s("1.3.6.1.2.1.2.2.1.2.%d" % idx, name)
        w.h("1.3.6.1.2.1.2.2.1.6.%d" % idx, m or b"")
        w.i("1.3.6.1.2.1.2.2.1.8.%d" % idx, oper)
        w.s("1.3.6.1.2.1.31.1.1.1.1.%d" % idx, name)
    # ipAddrTable (the agent's own addresses) and ipAddressTable.
    own = [("127.0.0.1", 1), ("10.99.0.2", 2), ("10.0.10.1", 3), ("192.168.20.1", 4), ("192.168.30.1", 5)]
    for ip, idx in own:
        w.i("1.3.6.1.2.1.4.20.1.2.%s" % ip, idx)
        w.i("1.3.6.1.2.1.4.34.1.3.1.4.%s" % ip, idx)
    # ipNetToPhysicalTable: 100 IPv4 (90 with a MAC, 10 incomplete) and 72 IPv6.
    hosts = [("10.0.10.%d" % n, 3) for n in range(10, 62)]
    hosts += [("192.168.20.%d" % n, 4) for n in range(10, 48)]
    assert len(hosts) == 90
    n = 0
    for ip, idx in hosts:
        n += 1
        m = mac([0x3C, 0x22, 0xFB, 0x01], n)
        base = "%d.1.4.%s" % (idx, ip)
        w.h("1.3.6.1.2.1.4.35.1.4.%s" % base, m)
        w.i("1.3.6.1.2.1.4.35.1.6.%s" % base, 3)
        w.i("1.3.6.1.2.1.4.35.1.7.%s" % base, 1 if n % 3 else 2)
        w.i("1.3.6.1.2.1.4.35.1.8.%s" % base, 1)
        mb = "%d.%s" % (idx, ip)
        w.h("1.3.6.1.2.1.4.22.1.2.%s" % mb, m)
        w.i("1.3.6.1.2.1.4.22.1.4.%s" % mb, 3)
    for k in range(1, 11):
        ip = "192.168.30.%d" % (10 + k)
        base = "5.1.4.%s" % ip
        w.h("1.3.6.1.2.1.4.35.1.4.%s" % base, b"")
        w.i("1.3.6.1.2.1.4.35.1.6.%s" % base, 3)
        w.i("1.3.6.1.2.1.4.35.1.7.%s" % base, 7)
        mb = "5.%s" % ip
        w.h("1.3.6.1.2.1.4.22.1.2.%s" % mb, b"")
        w.i("1.3.6.1.2.1.4.22.1.4.%s" % mb, 2)
    for k in range(1, 73):
        v6 = [0xFE, 0x80] + [0] * 6 + [0x02, 0x11, 0x22, 0xFF, 0xFE, 0x00, 0x00, k]
        base = "3.2.16.%s" % ".".join(str(b) for b in v6)
        w.h("1.3.6.1.2.1.4.35.1.4.%s" % base, mac([0x3C, 0x22, 0xFB, 0x02], k))
        w.i("1.3.6.1.2.1.4.35.1.6.%s" % base, 3)
        w.i("1.3.6.1.2.1.4.35.1.7.%s" % base, 2)
        w.i("1.3.6.1.2.1.4.34.1.3.2.16.%s" % ".".join(str(b) for b in v6), 3)
    # Something after the tables, so a GETNEXT out of a missing table lands outside it.
    w.s("1.3.6.1.2.1.31.1.1.1.18.1", "")
    w.dump(os.path.join(HERE, "unifi-gateway.walk"))


def switch():
    w = Walk()
    sw_mac = bytes([0x94, 0x60, 0xD5, 0xBB, 0x00, 0x01])
    w.o("1.3.6.1.2.1.1.2.0", ".1.3.6.1.4.1.11.2.3.7.11.171")
    ports = 24
    for p in range(1, ports + 1):
        w.s("1.3.6.1.2.1.2.2.1.2.%d" % p, "%d" % p)
        w.s("1.3.6.1.2.1.31.1.1.1.1.%d" % p, "%d" % p)
        w.h("1.3.6.1.2.1.2.2.1.6.%d" % p, mac([0x94, 0x60, 0xD5, 0xBB], p))
        w.i("1.3.6.1.2.1.2.2.1.8.%d" % p, 1)
        w.i("1.3.6.1.2.1.17.1.4.1.2.%d" % p, p)
    # VLAN 10 uses FDB ID 2, VLAN 20 uses FDB ID 3, VLAN 1 uses 1 (so an FDB ID is not a VLAN ID).
    for vlan, fdb_id in ((1, 1), (10, 2), (20, 3)):
        w.i("1.3.6.1.2.1.17.7.1.4.2.1.3.0.%d" % vlan, fdb_id)

    def fdb(fid, m, port, status=3):
        key = "%d.%s" % (fid, ".".join(str(b) for b in m))
        w.i("1.3.6.1.2.1.17.7.1.2.2.1.2.%s" % key, port)
        w.i("1.3.6.1.2.1.17.7.1.2.2.1.3.%s" % key, status)

    # Access ports: VLAN 10 on ports 3, 5, 7; VLAN 20 on port 9.
    fdb(2, mac([0x3C, 0x22, 0xFB, 0x01], 1), 3)
    fdb(2, mac([0x3C, 0x22, 0xFB, 0x01], 2), 5)
    fdb(2, mac([0x3C, 0x22, 0xFB, 0x01], 3), 7)
    fdb(3, mac([0x3C, 0x22, 0xFB, 0x01], 60), 9)
    # The uplink (port 24, 12 MACs, over the limit of 8).
    for k in range(1, 13):
        fdb(2 if k % 2 else 3, mac([0x3C, 0x22, 0xFB, 0x01], 10 + k), 24)
    # Port 23: an LLDP neighbour that is a listed agent: 2 MACs it learned itself.
    fdb(2, mac([0x3C, 0x22, 0xFB, 0x01], 30), 23)
    fdb(2, mac([0x3C, 0x22, 0xFB, 0x01], 31), 23)
    # The switch's own MAC (self) and a management entry.
    fdb(1, sw_mac, 1, 4)
    fdb(1, mac([0x3C, 0x22, 0xFB, 0x01], 99), 11, 5)
    # LLDP: an AP on port 5, the gateway on port 23 (by chassis MAC and name), and a neighbour
    # whose chassis ID is not a MAC (left out).
    base = "1.0.8802.1.1.2.1.4.1.1"

    def rem(port, idx, csub, chassis, psub, pid, pdesc, name):
        k = "0.%d.%d" % (port, idx)
        w.i("%s.4.%s" % (base, k), csub)
        if csub == 4:
            w.h("%s.5.%s" % (base, k), chassis)
        else:
            w.s("%s.5.%s" % (base, k), chassis.decode())
        w.i("%s.6.%s" % (base, k), psub)
        w.s("%s.7.%s" % (base, k), pid)
        w.s("%s.8.%s" % (base, k), pdesc)
        w.s("%s.9.%s" % (base, k), name)

    rem(5, 1, 4, bytes([0xB4, 0xFB, 0xE4, 0x10, 0x20, 0x30]), 5, "eth0", "Ethernet", "ap-lobby")
    rem(23, 1, 4, bytes([0x70, 0xA7, 0x41, 0xAA, 0x00, 0x01]), 5, "eth4", "WAN", "unifi-gateway")
    rem(11, 1, 7, b"chassis-local-id", 7, "1", "", "printer-x")
    for p in range(1, ports + 1):
        w.s("1.0.8802.1.1.2.1.3.7.1.3.%d" % p, "%d" % p)
        w.s("1.0.8802.1.1.2.1.3.7.1.4.%d" % p, "Port %d" % p)
    # A few ARP rows of its own management VLAN.
    for k in range(1, 4):
        w.h("1.3.6.1.2.1.4.22.1.2.1.10.0.10.%d" % (200 + k), mac([0x3C, 0x22, 0xFB, 0x01], 40 + k))
        w.i("1.3.6.1.2.1.4.22.1.4.1.10.0.10.%d" % (200 + k), 3)
    w.i("1.3.6.1.2.1.4.20.1.2.10.0.10.2", 1)
    w.s("1.3.6.1.2.1.31.1.1.1.18.1", "")
    w.dump(os.path.join(HERE, "managed-switch.walk"))


if __name__ == "__main__":
    gateway()
    switch()
