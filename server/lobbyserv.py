# lobbyserv.py — OW 1.74 lobby server, v131

import socket, os, hmac, hashlib, struct, time, sys
# ============================ HELPER FUNCTIONS =============================
def varint(v):
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        out.append(b | 0x80 if v else b)
        if not v:
            return bytes(out)

# ---------------------------- RESPONSE BODY --------------------------------
HARDCODED_BODY = bytes.fromhex(
    "0a0c08aac0a2c50f10aea09ca506120a0895df0310edf8aca50630a5f0a3d6dd828003425e0a5c0d53550000157274656d1a203488f45185ae7e8501db89583de0cc291589347588777fd3bcb299e24df8c5e1222e68747470733a2f2f70726f642e6465706f742e626174746c652e6e65742f247b686173687d2e247b75736167657d4a21463841384130324136344137313032452d303030303030303030303030454639355001"
)

F8_RAW  = HARDCODED_BODY[37:131]
F2_F1   = 0xEF95
F2_F2   = 0x64AB3C6D
F6_VAL  = 1688943725180965
F10_VAL = 1

ORIG_KEY_HI = 0xF8A8A02A
ORIG_KEY_LO = 0x64A7102E

# "both" | "f1" | "f9"
KEY_SOURCE = "both"

PENDING_KEY_FILE = r"CHANGE TO YOUR DESIRED PATH"

def _tag(f, wt): return varint((f << 3) | wt)
def _ld(f, data): return _tag(f, 2) + varint(len(data)) + data
def _vi(f, v):    return _tag(f, 0) + varint(v)

def read_pending_key():
    try:
        with open(PENDING_KEY_FILE, "r") as f:
            line = f.readline().strip()
        if len(line) < 16:
            return None
        return int(line[0:8], 16), int(line[8:16], 16)
    except (FileNotFoundError, OSError, ValueError):
        return None

def build_body(key_hi, key_lo):
    if KEY_SOURCE == "f9":
        f1_hi, f1_lo = ORIG_KEY_HI, ORIG_KEY_LO
    else:
        f1_hi, f1_lo = key_hi, key_lo
    if KEY_SOURCE == "f1":
        s_hi, s_lo = ORIG_KEY_HI, ORIG_KEY_LO
    else:
        s_hi, s_lo = key_hi, key_lo

    f1  = _ld(1, _vi(1, f1_hi) + _vi(2, f1_lo))
    f2  = _ld(2, _vi(1, F2_F1) + _vi(2, F2_F2))
    f6  = _vi(6, F6_VAL)
    f8  = _ld(8, F8_RAW)
    f9  = _ld(9, f"{s_hi:08X}{s_lo:08X}-{F2_F1:016X}".encode())
    f10 = _vi(10, F10_VAL)
    return f1 + f2 + f6 + f8 + f9 + f10

def build_response_body():
    k = read_pending_key()
    if k is None:
        return HARDCODED_BODY, False, None
    body = build_body(k[0], k[1])
    return body, True, f"{k[0]:08X}{k[1]:08X}"

def build_response_envelope(token_int, body, status=0):
    hdr = (b"\x08" + varint(254) + b"\x18" + varint(token_int)
           + b"\x28" + varint(len(body)) + b"\x30" + varint(status))
    return len(hdr).to_bytes(2, "big") + hdr + body

def build_response_record(msgid, counter, envelope):
    FAMILY_ID = 0x11D82194
    return msgid.to_bytes(2, "big") + counter.to_bytes(4, "little") + FAMILY_ID.to_bytes(4, "little") + envelope

TYPE2_REPLY_PAYLOAD = bytes.fromhex("0102010000009421d811")

# ============================ JAM CIPHER ====================================
HELLO_CLIENT = b"HELLO PRO CLIENT\x00"
HELLO_SERVER = b"HELLO PRO SERVER\x00"
LISTEN = ("127.0.0.1", 3724)
ZERO_KEY = b"\x00" * 32
DIFFICULTY = 0
M32 = 0xFFFFFFFF

def rol32(x, n):
    x &= M32
    return ((x << n) | (x >> (32 - n))) & M32

def jam_round(s, ctrB):
    c1 = [((~s[4]) & M32 | s[8]) ^ s[12],
          ((~s[5]) & M32 | s[9]) ^ s[13],
          ((~s[6]) & M32 | s[10]) ^ s[14],
          ((~s[7]) & M32 | s[11]) ^ s[15]]
    c2 = [((~s[0]) & M32 | s[4]) ^ s[8],
          ((~s[1]) & M32 | s[5]) ^ s[9],
          ((~s[2]) & M32 | s[6]) ^ s[10],
          ((~s[3]) & M32 | s[7]) ^ s[11]]
    c3 = [((~s[13]) & M32 | s[0]) ^ s[4],
          ((~s[14]) & M32 | s[1]) ^ s[5],
          ((~s[15]) & M32 | s[2]) ^ s[6],
          ((~ctrB) & M32 | s[3]) ^ s[7]]
    c4 = [((~s[9]) & M32 | s[13]) ^ s[0],
          ((~s[10]) & M32 | s[14]) ^ s[1],
          ((~s[11]) & M32 | s[15]) ^ s[2],
          ((~s[12]) & M32 | ctrB) ^ s[3]]
    o = [0]*16
    o[13] = rol32(c1[0], 15); o[1] = rol32(c1[1], 4);  o[6] = rol32(c1[2], 2);  o[11] = rol32(c1[3], 9)
    o[10] = rol32(c2[0], 23); o[15] = rol32(c2[1], 27); o[3] = rol32(c2[2], 8);  o[8] = rol32(c2[3], 3)
    o[7] = rol32(c3[0], 24);  o[12] = rol32(c3[1], 1);  o[0] = rol32(c3[2], 10); o[5] = rol32(c3[3], 28)
    o[4] = rol32(c4[0], 6);   o[9] = rol32(c4[1], 21);  o[14] = rol32(c4[2], 13); o[2] = rol32(c4[3], 14)
    return o

IC_IDX = (0, 2, 4, 6, 1, 3, 5, 7)
IA_IDX = (5, 7, 0, 2, 4, 6, 1, 3)
KS_WORDS = (14, 10, 6, 2, 15, 11, 7, 3)

class Jam:
    def __init__(self, key: bytes):
        assert len(key) == 32
        self.keyw = list(struct.unpack("<8I", key))
        self.s = [0]*16
        self.ctrB = 0
        self.counter = 0
        self.ring = [[0]*8 for _ in range(32)]
        self.cur = bytearray()
        self.pos = 0
        self.initialized = False

    def _absorb(self, kw):
        A = self.ring[((self.counter + 0x20) & 0x3E0) >> 5]
        B = self.ring[((self.counter + 0x100) & 0x3E0) >> 5]
        for k in range(8):
            t = A[IC_IDX[k]]
            A[IC_IDX[k]] = (t ^ kw[k]) & M32
            B[IA_IDX[k]] ^= t
        sp = jam_round(self.s, self.ctrB)
        ctrB_mix = (((~self.s[8]) & M32 | self.s[12]) ^ self.ctrB) & M32
        new_ctrB = (sp[0] ^ sp[12] ^ ctrB_mix ^ 1) & M32
        C = self.ring[((self.counter - 0x200) & 0x3E0) >> 5]
        s17 = sp + [ctrB_mix]
        core = [(sp[i] ^ s17[(i+1)%17] ^ s17[(i-4)%17]) & M32 for i in range(16)]
        extra = [kw[3], kw[7], C[6], C[7],
                 kw[2], kw[6], C[4], C[5],
                 kw[1], kw[5], C[2], C[3],
                 kw[0], kw[4], C[0], C[1]]
        self.s = [(core[i] ^ extra[i]) & M32 for i in range(16)]
        self.ctrB = new_ctrB
        self.counter = (self.counter + 0x20) & M32

    def _permute(self, count):
        for _ in range(count):
            old = self.s[:]
            ctrB_mix = (((~old[8]) & M32 | old[12]) ^ self.ctrB) & M32
            sp = jam_round(old, self.ctrB)
            Q = self.ring[((self.counter + 0x20) & 0x3E0) >> 5]
            P = self.ring[((self.counter + 0x100) & 0x3E0) >> 5]
            v41 = Q[0:4]
            for j, w in enumerate((old[12], old[13], old[8], old[9])):
                Q[j] ^= w
            P[4] ^= v41[1]; P[5] ^= v41[0]; P[6] ^= v41[3]; P[7] ^= v41[2]
            v42 = Q[4:8]
            for j, w in enumerate((old[4], old[5], old[0], old[1])):
                Q[4+j] ^= w
            for j in range(4):
                P[j] ^= v42[j]
            T = self.ring[((self.counter - 0x80) & 0x3E0) >> 5]
            R = self.ring[((self.counter + 0x200) & 0x3E0) >> 5]
            s17 = sp + [ctrB_mix]
            core = [(sp[i] ^ s17[(i+1)%17] ^ s17[(i-4)%17]) & M32 for i in range(16)]
            ringw = [T[6], T[7], R[6], R[7],
                     T[4], T[5], R[4], R[5],
                     T[2], T[3], R[2], R[3],
                     T[0], T[1], R[0], R[1]]
            self.s = [(core[i] ^ ringw[i]) & M32 for i in range(16)]
            self.ctrB = (sp[0] ^ sp[12] ^ ctrB_mix ^ 1) & M32
            self.counter = (self.counter + 0x20) & M32

    def _init(self):
        self.s = [0]*16
        self.ctrB = 0
        self.counter = 1
        self.ring = [[0]*8 for _ in range(32)]
        for _ in range(2):
            self._absorb(self.keyw)
        self._permute(32)
        self.initialized = True

    def _squeeze_block(self):
        w = self.s
        out = b"".join(struct.pack("<I", w[i]) for i in KS_WORDS)
        self._permute(1)
        return out

    def crypt(self, data: bytes) -> bytes:
        if not self.initialized:
            self._init()
        out = bytearray()
        for b in data:
            if self.pos >= len(self.cur):
                self.cur = bytearray(self._squeeze_block())
                self.pos = 0
            out.append(b ^ self.cur[self.pos])
            self.pos += 1
        return bytes(out)

BLOB_KEY = bytes([
    0x35, 0x86, 0xF3, 0x62, 0x8A, 0x63, 0x1B, 0x70,
    0x57, 0x12, 0x40, 0x5B, 0x8A, 0xCC, 0x71, 0xD4,
    0x0F, 0xD1, 0x67, 0x0C, 0xC1, 0xB0, 0x3E, 0xA3,
    0x84, 0x97, 0x4A, 0x6F, 0xB1, 0xA7, 0x61, 0x96,
    0xB1, 0x42, 0xF0, 0xB7, 0x23, 0x10, 0xEA, 0x81,
    0x16, 0xD0, 0x0A, 0x4C, 0x35, 0x2F, 0x09, 0xAC,
    0xDB, 0xFB, 0x50, 0xA6, 0x3E, 0xC5, 0x15, 0x3E,
    0x62, 0xE4, 0xD6, 0x7F, 0xE0, 0x9B, 0xEE, 0xCC,
])

def build_state_blob() -> bytes:
    blob = bytearray(256)
    for i in range(256):
        blob[i] = i & 0xFF
    blob[0] = 0x02
    blob[1:5] = bytes([0x7F, 0x00, 0x00, 0x01])
    blob[255] = 0xFF
    msg = bytes(blob[0:176]) + bytes(blob[208:256])
    blob[176:208] = hmac.new(BLOB_KEY, msg, hashlib.sha256).digest()
    return bytes(blob) + bytes(36)

def recvn(c, n, timeout=30):
    c.settimeout(timeout)
    buf = b""
    while len(buf) < n:
        chunk = c.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("client closed")
        buf += chunk
    return buf


# ---------------------------- MSGID SWEEP ----------------------------------
SWEEP_ENABLED = False
SWEEP_LO      = 0x001
SWEEP_HI      = 0x4F0
SWEEP_STATE   = "sweep_state.txt"
FIXED_MSGID   = 0x003

def sweep_load():
    try:
        with open(SWEEP_STATE) as f:
            v = int(f.readline().strip(), 0)
        if SWEEP_LO <= v <= SWEEP_HI:
            return v
    except (FileNotFoundError, OSError, ValueError):
        pass
    return SWEEP_LO

def sweep_save(v):
    try:
        with open(SWEEP_STATE, "w") as f:
            f.write("0x%03X" % v)
    except OSError:
        pass

def next_msgid():
    if not SWEEP_ENABLED:
        return FIXED_MSGID
    v = sweep_load()
    sweep_save(v + 1 if v < SWEEP_HI else SWEEP_LO)
    return v




# ---------------------------- SHORT REPLY SWEEP ----------------------------
SHORT_REPLY_ENABLED = True
SHORT_LO    = 0x00
SHORT_HI    = 0xFF
SHORT_STATE = "short_state.txt"

def short_load():
    try:
        with open(SHORT_STATE) as f:
            v = int(f.readline().strip(), 0)
        if SHORT_LO <= v <= SHORT_HI:
            return v
    except (FileNotFoundError, OSError, ValueError):
        pass
    return SHORT_LO

def short_save(v):
    try:
        with open(SHORT_STATE, "w") as f:
            f.write("0x%02X" % v)
    except OSError:
        pass

def next_short():
    v = short_load()
    short_save(v + 1 if v < SHORT_HI else SHORT_LO)
    return v

# ---------------------------- BODY VARIANTS --------------------------------
BODY_SWEEP_ENABLED = True
BODY_STATE = "body_state.txt"

def body_variants():
    full, _, _ = build_response_body()
    return [
        ("captured_bgs",    full,                       0),
        ("empty",           b"",                        0),
        ("empty_status1",   b"",                        1),
        ("captured_status1", full,                      1),
        ("f10_only",        _vi(10, 1),                 0),
        ("f1_only",         _ld(1, _vi(1, ORIG_KEY_HI) + _vi(2, ORIG_KEY_LO)), 0),
        ("single_byte",     b"\x00",                    0),
        ("captured_status2", full,                      2),
    ]

def body_load():
    try:
        with open(BODY_STATE) as f:
            return int(f.readline().strip(), 0)
    except (FileNotFoundError, OSError, ValueError):
        return 0

def body_save(v):
    try:
        with open(BODY_STATE, "w") as f:
            f.write(str(v))
    except OSError:
        pass

def next_body():
    vs = body_variants()
    i = body_load() % len(vs)
    body_save((i + 1) % len(vs))
    return vs[i]

# ---------------------------- PROBE SWEEP ----------------------------------
PROBE_ENABLED = False
PROBE_LO      = 0x001
PROBE_HI      = 0x4F0
PROBE_STATE   = "probe_state.txt"
KEEPALIVE_MSGID = 0x003

def probe_load():
    try:
        with open(PROBE_STATE) as f:
            v = int(f.readline().strip(), 0)
        if PROBE_LO <= v <= PROBE_HI:
            return v
    except (FileNotFoundError, OSError, ValueError):
        pass
    return PROBE_LO

def probe_save(v):
    try:
        with open(PROBE_STATE, "w") as f:
            f.write("0x%03X" % v)
    except OSError:
        pass

def next_probe():
    v = probe_load()
    probe_save(v + 1 if v < PROBE_HI else PROBE_LO)
    return v

# ============================ MAIN SERVER ==================================
conn_count = 0
TOKEN = 1  # Default matches debug client --key default

def handle(c, addr):
    global conn_count
    conn_count += 1
    print(f"\n[lobby] === connection #{conn_count} from {addr} ===")

    d = recvn(c, len(HELLO_CLIENT))
    if d != HELLO_CLIENT:
        print("[lobby] BAD hello"); return
    c.sendall(HELLO_SERVER)

    d = recvn(c, 40)
    cn = d[8:40]
    sn = os.urandom(32)
    srv_rand = os.urandom(32)
    c.sendall(srv_rand + bytes([DIFFICULTY]) + sn)

    d = recvn(c, 40)
    mac1 = d[8:40]
    expect1 = hmac.new(ZERO_KEY, cn + sn, hashlib.sha256).digest()
    if mac1 != expect1:
        print("[lobby] MAC1 mismatch, ignoring")
        return

    mac2 = hmac.new(ZERO_KEY, sn + cn, hashlib.sha256).digest()
    s2c_key = hmac.new(ZERO_KEY, cn + sn, hashlib.sha256).digest()
    c2s_key = hmac.new(ZERO_KEY, sn + cn, hashlib.sha256).digest()

    blob = build_state_blob()
    txjam = Jam(s2c_key)
    c.sendall(mac2 + txjam.crypt(blob))
    print("[lobby] -> MAC2 + blob")

    # v65 gate: first reply must have counter=0 (< conn+0x88 init 1)
    token = TOKEN
    counter = 0
    print(f"[lobby] Using token={token}, counter={counter} (counter=0 for first 0x101), live-key patched body")

    reply_msgid = next_msgid()
    print(f"[lobby] *** SWEEP: this connection replies with msgid 0x{reply_msgid:03X} ***")

    rxjam = Jam(c2s_key)
    dec_buf = b""
    acked = False
    responded = False
    post_reply_frames = 0
    repeat_replies = 0
    last_probe = 0
    cur_variant = ("captured_bgs", 0)
    cur_body = b""
    t_reply = None
    t0 = time.time()

    while True:
        try:
            c.settimeout(2)
            d = c.recv(4096)
        except socket.timeout:
            d = None
        except (ConnectionAbortedError, ConnectionResetError) as e:
            print(f"[lobby] client aborted ({e})")
            return
        if d:
            dec_buf += rxjam.crypt(d)
            while len(dec_buf) >= 3:
                ln = int.from_bytes(dec_buf[:3], "big")
                if ln > 4096:
                    dec_buf = b""
                    break
                if len(dec_buf) < 3 + ln:
                    break
                frame = dec_buf[3:3+ln]
                dec_buf = dec_buf[3+ln:]
                print(f"[lobby] <<< CLIENT FRAME ({ln} bytes): {frame.hex()}")
                if frame.hex() != "0103" and frame[:2] != b"\x01\x00":
                    print(f"[lobby] ############################################")
                    print(f"[lobby] ### NON-0103 FRAME: {frame.hex()}")
                    print(f"[lobby] ### last probe msgid = 0x{last_probe:03X}")
                    print(f"[lobby] ############################################")
                    with open("probe_hits.txt", "a") as pf:
                        pf.write(f"probe=0x{last_probe:03X} frame={frame.hex()}\n")
                if responded:
                    post_reply_frames += 1
                    print(f"[lobby] !!! FRAME AFTER REPLY (msgid 0x{reply_msgid:03X}) "
                          f"#{post_reply_frames}: {frame.hex()} <<< INTERESTING")

                if frame[:2] == b"\x01\x00" and not acked:
                    acked = True
                    reply = len(TYPE2_REPLY_PAYLOAD).to_bytes(3, "big") + TYPE2_REPLY_PAYLOAD
                    c.sendall(txjam.crypt(reply))
                    print("[lobby] >>> sent 0102 ACK")
                    continue

                if frame.hex() == "0103":
                    if responded:
                        repeat_replies += 1
                        print(f"[lobby] >>> answering repeat 0103 #{repeat_replies}")
                    responded = True
                    if SHORT_REPLY_ENABLED:
                        sb = next_short()
                        cur_variant = (f"short_0103_{sb:02X}", 0)
                        payload = bytes([0x01, sb])
                        framed = len(payload).to_bytes(3, "big") + payload
                        c.sendall(txjam.crypt(framed))
                        print(f"[lobby] >>> SHORT reply 01{sb:02X} (2 bytes)")
                        if t_reply is None:
                            t_reply = time.time()
                        continue
                    vname, vstatus = cur_variant
                    body = cur_body
                    cur_body = body
                    envelope = build_response_envelope(token, body, vstatus)
                    payload = build_response_record(reply_msgid, counter, envelope)
                    framed = len(payload).to_bytes(3, "big") + payload
                    c.sendall(txjam.crypt(framed))
                    if t_reply is None:
                        t_reply = time.time()
                    print(f"[lobby] >>> keepalive msgid=0x{reply_msgid:03X} "
                          f"(counter={counter})")
                    counter += 1

                    if PROBE_ENABLED and repeat_replies > 0:
                        last_probe = next_probe()
                        pbody, _, _ = build_response_body()
                        penv = build_response_envelope(token, pbody)
                        ppay = build_response_record(last_probe, counter, penv)
                        pframed = len(ppay).to_bytes(3, "big") + ppay
                        c.sendall(txjam.crypt(pframed))
                        print(f"[lobby] >>> PROBE msgid=0x{last_probe:03X} "
                              f"(counter={counter})")
                        counter += 1
                    continue

                print(f"[lobby] >>> extra frame: {frame.hex()} (ignoring)")
                continue
        if d == b"":
            if t_reply is not None:
                held = time.time() - t_reply
                print(f"[lobby] client closed. variant='{cur_variant[0]}' "
                      f"held={held:.2f}s exchanges={post_reply_frames}")
                with open("body_results.txt", "a") as bf:
                    bf.write(f"{cur_variant[0]:16s} status={cur_variant[1]} "
                             f"held={held:8.2f} exchanges={post_reply_frames}\n")
                if held > 3.0 or post_reply_frames:
                    print(f"[lobby] *** ANOMALY on msgid 0x{reply_msgid:03X} "
                          f"— held {held:.2f}s, {post_reply_frames} frames after reply ***")
                    with open("sweep_hits.txt", "a") as f:
                        f.write(f"0x{reply_msgid:03X} held={held:.2f} "
                                f"frames={post_reply_frames}\n")
            else:
                print(f"[lobby] client closed. msgid=0x{reply_msgid:03X} (no reply sent)")
            return
        if time.time() - t0 > 300:
            print("[lobby] 300s silence"); return

def main():
    global TOKEN
    # Parse --token argument
    if len(sys.argv) > 2 and sys.argv[1] == "--token":
        try:
            TOKEN = int(sys.argv[2], 0)  # supports hex or decimal
        except ValueError:
            print(f"Invalid token value: {sys.argv[2]}, using default 1.")
    print(f"[lobby] Using token = {TOKEN} (default 1, matches debug client --key)")

    blob = build_state_blob()
    assert len(blob) == 292
    k = bytes(range(32))
    a, b = Jam(k), Jam(k)
    assert b.crypt(a.crypt(bytes(range(256)))) == bytes(range(256))
    assert build_body(ORIG_KEY_HI, ORIG_KEY_LO) == HARDCODED_BODY, "body rebuild mismatch"
    print(f"[lobby] self-check OK (v130: body rebuild byte-exact, KEY_SOURCE={KEY_SOURCE})")
    if not SWEEP_ENABLED:
        print(f"[lobby] keepalive msgid pinned to 0x{FIXED_MSGID:03X}")
    if BODY_SWEEP_ENABLED:
        print(f"[lobby] BODY SWEEP ON: {len(body_variants())} variants, "
              f"results -> body_results.txt")
    if PROBE_ENABLED:
        print(f"[lobby] PROBE SWEEP ON: 0x{PROBE_LO:03X}..0x{PROBE_HI:03X}, "
              f"resuming at 0x{probe_load():03X}")
        print(f"[lobby] non-0103 frames -> probe_hits.txt")
    if SWEEP_ENABLED:
        print(f"[lobby] MSGID SWEEP ON: 0x{SWEEP_LO:03X}..0x{SWEEP_HI:03X}, "
              f"resuming at 0x{sweep_load():03X}")
        print(f"[lobby] anomalies -> sweep_hits.txt ; progress -> {SWEEP_STATE}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(LISTEN); s.listen(5)
    print(f"[lobby] listening on {LISTEN[0]}:{LISTEN[1]}")
    while True:
        c, a = s.accept()
        try: handle(c, a)
        except Exception as e: print(f"[lobby] conn ended: {e}")
        finally: c.close()

if __name__ == "__main__":
    main()
