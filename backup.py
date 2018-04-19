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


def get_port_and_body(pck):
    l = int.from_bytes([pck[0] & 15], byteorder='big') * 4
    return int.from_bytes(pck[l: l + 2], byteorder='big'), pck[l + 8:]


def add_all_records(dns):
    for r in dns.rr + dns.auth + dns.ar:
        if r.rtype in {1, 2}:
            add_record(r)
            log("Record added.")


def get_resp(dns):
    if dns.q.qtype in {1, 2}:
        k = (str(dns.q.qname).lower(), dns.q.qtype)
        if k not in database:
            return None
        answers = database[k]
        if answers:
            reply = dns.reply()
            reply.rr = [p.rr for p in answers]
            return reply
        return None


def is_expired(rr, time):
    return dt.now() - time > timedelta(seconds=rr.ttl)


def clear_expired():
    for k, s in database.items():
        database[k] = set(p for p in s if not is_expired(p.rr, p.time))


def send_to(pck, ip, port):
    sock.connect((ip, port))
    sock.sendall(pck)


def log(msg):
    print(str(dt.now()) + ": " + msg)


listen = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
listen.bind(("0.0.0.0", 0))

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", 40000))


database = {}
try:
    with open(FILENAME, 'rb') as f:
        database = pickle.load(f)
    log("File loaded.")
except OSError:
    log("Failed to load from file")

try:
    while True:
        clear_expired()

        data, addr = listen.recvfrom(8200)
        port, body = get_port_and_body(data)
        try:
            r = DNSRecord.parse(body)
            print(len(body))
        except DNSError:
            continue
        if r.header.qr:
            add_all_records(r)
        else:
            resp = get_resp(r)
            try:
                send_to(r.send("8.8.8.8") if resp is None else resp.pack(), addr[0], port)
                log("Response sent.")
            except OSError:
                log("Failed to respond.")
finally:
    try:
        with open(FILENAME, 'wb') as f:
            pickle.dump(database, f)
        log("Data saved\n")
    except OSError:
        log("Failed to save\n")
