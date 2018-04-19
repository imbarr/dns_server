from dnslib import DNSRecord, DNSError
from datetime import datetime as dt, timedelta
import socket
import pickle


FILENAME = "save.pickle"


class Pair:
    def __init__(self, rr, time):
        self.rr = rr
        self.time = time

    def __hash__(self):
        return hash(self.rr.rtype)

    def __eq__(self, other):
        if type(other) != type(self):
            return False
        else:
            attrs = ('rname', 'rclass', 'rtype', 'rdata')
            return all([getattr(self.rr, x) == getattr(other.rr, x) for x in attrs])


def add_record(rr):
    k = (str(rr.rname).lower(), rr.rtype)
    if k in database:
        database[k].add(Pair(rr, dt.now()))
    else:
        database[k] = {Pair(rr, dt.now())}


def add_all_records(dns):
    for r in dns.rr + dns.auth + dns.ar:
        if r.rtype in {1, 2}:
            add_record(r)
            log("Record added.")


def get_resp(dns):
    if dns.q.qtype in {1, 2}:
        k = (str(dns.q.qname).lower(), dns.q.qtype)
        if k in database and database[k]:
            reply = dns.reply()
            reply.rr = [p.rr for p in database[k]]
            return reply


def is_expired(rr, time):
    return dt.now() - time > timedelta(seconds=rr.ttl)


def clear_expired():
    delta = 0
    for k, s in database.items():
        l = len(database[k])
        database[k] = set(p for p in s if not is_expired(p.rr, p.time))
        delta += l - len(database[k])
    if delta > 0:
        log(str(delta) + " record(s) expired.")


def get_with_caching():
    p = r.send("ns1.e1.ru")
    d = DNSRecord.parse(p)
    add_all_records(d)
    return p


def log(msg):
    print(str(dt.now()) + ": " + msg)


def get_sock():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("", 40000))
    return s


def send_to(pck, ip, port):
    global sock
    sock.connect((ip, port))
    sock.sendall(pck)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", 40000))


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("", 40000))


database = {}
try:
    with open(FILENAME, 'rb') as f:
        database = pickle.load(f)
        log("File loaded.")
except OSError:
    log("Failed to load from file")

try:
    while True:
        data, addr = sock.recvfrom(2048)
        clear_expired()

        try:
            r = DNSRecord.parse(data)
        except DNSError:
            continue
        add_all_records(r)
        if not r.header.qr:
            resp = get_resp(r)
            try:
                send_to(get_with_caching() if resp is None else resp.pack(), *addr)
                log("Response sent.")
            except (OSError, DNSError):
                log("Failed to respond.")
finally:
    try:
        with open(FILENAME, 'wb') as f:
            pickle.dump(database, f)
        log("Data saved\n")
    except OSError:
        log("Failed to save\n")
