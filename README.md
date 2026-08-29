# Overwatch 1.74 - Lobby Protocol Research

Reverse-engineering the Overwatch 1 lobby protocol (build **1.74.0.0 / 104319**),
with the goal of reaching the main menu on a fully local, offline server. Game
preservation, own machine, own copy.

**Status: The client has been made to advance PAST the lobby wall for the first
time.** The transport is solved, the client completes the handshake and holds an
open connection, and - new - the client's own accept path can be driven so it
leaves the retry loop and moves to "ENTERING GAME". What remains is the second
server message: the accept and the client's poll loop are two separate
subsystems, and the poll still wants a response we can't yet form. This repo
exists so that work isn't repeated.

(Also, someone has managed to get into the main menu already and is planning to release a full game server, 
this project is to see weather or not we can get intot he Main Menu before they release their private server.)

---

## What is solved

- **JAM stream cipher** - reimplemented server-side, byte-exact.
  Known-answer test (key = `00 01 02 … 1f`), first 64 bytes of keystream:
  ```
  f07e5df1c8d51c0d754da6ddde34cca01db0ed26334eb94ae277135a0764c6a6
  794d7ab0cc0978ef43de30766a7ee1d7c90e159df239d4016d450fa3d8207842
  ```
  Independently confirmed by a second implementer. If your cipher reproduces
  this, it is correct.

- **Full key schedule** - confirmed against real Blizzard traffic (see below).
  ```
  MAC1           = HMAC-SHA256(k0, cn || sn)
  MAC2           = HMAC-SHA256(k1, sn || cn)
  c2s cipher key = HMAC-SHA256(k3, sn || cn)
  s2c cipher key = HMAC-SHA256(k2, cn || sn)
  ```
  Four separate 64-byte key slots, one role each, sourced from the Battle.net
  session. Tournament mode zeroes all four, which is why a zero key works locally.

- **292-byte state blob** - construction and embedded HMAC key recovered. NOTE:
  a two-session diff proved the real blob is 291/292 session-specific RSA key
  material; the fixed blob here is a tournament-mode shortcut that works only
  because zeroed keys let the client skip validating it. See PROJECT_STATE.txt.

- **Full handshake to state 6** - `HELLO PRO CLIENT` / `HELLO PRO SERVER`,
  nonce exchange, MAC1/MAC2, encrypted blob. Reproducible every connection.

- **Counter gate** - the first server reply must carry counter `0`, not `1`.
  (`01 00 00 00` encodes 1. This off-by-one silently killed every reply for
  weeks.)

- **The first accepted server message** - a bare two-byte frame, msgid `0x0102`,
  framed as `00 00 02 01 02`. No counter, no family id, no body. Found by
  sweeping 338 msgids: `0x0102` is the only value the client accepts.
  This is the first server->client message the 1.74 client has ever accepted.

- **The "reject" is a 5-second timeout, not a content judgment.** Read live from
  the session object's verdict field (session+0x60: 2=reject, 7=accept,
  6=awaiting). The client reaches status=6, waits exactly 5000ms for the message
  that advances the lobby, and times out to status=2. Every "retry count" we
  measured for weeks was really this timeout window.

- **The accept can be driven directly.** `Success()` at RVA `0xE38600` sets the
  verdict to accepted. It is NOT Arxan-encrypted (prologue `48 83 c1 f0`) and can
  be called from an injected DLL with the session object as `this`. When called,
  the client screen advances from the retry/stop/retry loop to a continuous
  "ENTERING GAME" state - the first time the client has ever moved past the wall.

- **Holding the connection open** - answer every `0x0103` poll with a bare
  `0x0003` keepalive. The socket then stays open indefinitely (tested 36+
  polls) instead of closing after five silent retries.

- **Message body format** - bodies are a sequence of `[u32le block_len][protobuf
  block]` interleaved with fixed fields (356 blocks decoded across 94 real
  frames; one decodes to a player BattleTag, confirming the reading). 16-byte
  entity handles are `[u32le id][8 zero bytes][u32le type]`.

- **The 1.74 message schema, live-decrypted from Arxan'd .rdata** - the family
  table (family 0x11D82194, messages 0x01-0x04), message 0x02's field layout
  (16-byte handle + enum + repeated array), and the JamMessage envelope field
  names (`seq`, `src`, `_msgID`). Also: the client has TWO decode paths, binary
  AND json, selected by a "Protocol Type". See PROJECT_STATE.txt Sections 2H-2I.

- **Arxan boundaries** - mapped precisely. Inline code hooking inside
  `Overwatch.exe` is impossible (VirtualProtect denied on all 11,408 executable
  pages). Heap writes and external-module hooks work. Hardware breakpoints
  (debug registers) are detected and crash the process. Read-only memory
  polling is safe. See PROJECT_STATE.txt.

- **Real lobby traffic decrypted, both directions** - see below.

---

## What is not solved - THE central question

The accept and the client's poll loop are independent. `Success()` advances the
verdict (the screen moves to "ENTERING GAME"), but the client also runs a
`0x0103` poll loop waiting for the real second server message, and that loop is
not satisfied by the verdict. So the client sits at "ENTERING GAME" without
completing.

Any content frame sent as a poll response closes the client immediately - even
`0x0104` with an empty body - while bare `0x0003` keepalives never do. The
leading theory is a JAM cipher counter desync on content frames: keepalives stay
in sync, but a frame the client actually decodes surfaces the desync as a
garbage body and it disconnects. Confirming the s2c counter behaviour (continuous
vs per-frame reset) is the current open thread.

A two-session diff proved the retail capture can't supply the answer: essentially
every byte inside a frame is session-specific. The correct second message must be
built from the 1.74 client's **own** session state.

**A Tournament Mode capture remains the one artifact that would unblock the
project** - same code path as this build, zeroed keys, decryptable with the
tooling already here. No key dump needed, just the raw lobby pcap.

Three-plus people have independently reached the lobby wall. This is the first
work to drive the client past the accept and characterize exactly what remains.

---

## Decrypted real Blizzard lobby traffic

`research/cli_dec.bin` (client->server) and `research/srv_dec.bin`
(server->client) are both directions of a genuine Overwatch 1 lobby session
against a real Blizzard server, fully decrypted. Client: 211 frames, 61,712/61,712
bytes. Server: 94 frames, 383,890/383,890 bytes. Zero parse errors either way.
Player BattleTags in this data have been redacted.

The s2c cipher key was contributed by **Zagrion**, who redid the TCP reassembly
with tshark - a hand-rolled scapy reassembly had mishandled overlapping
retransmits, and one byte of misalignment destroys a stream cipher downstream.
Use: `tshark -r capture.pcap -q -z follow,tcp,raw,0`.

Frame format: `[u24be frame_len][u16be msgid][ … ]`. The third field is
msgid-dependent (a u32le length for some, e.g. `0x4401`; a counter for others).
Bare two-byte msgid-only frames are normal.

Reading it:
```python
pt = open('research/cli_dec.bin', 'rb').read()
off = 0
while off + 3 <= len(pt):
    ln = int.from_bytes(pt[off:off+3], 'big')
    f = pt[off+3:off+3+ln]
    print(f"[{ln:5d}] msgid=0x{f[:2].hex()} {f[2:40].hex()}")
    off += 3 + ln
```
Note these are **retail** message ids and will not match 1.74 directly. What
transfers is the grammar, not the numbers.

---

## Repo layout
```
docs/PROJECT_STATE.txt   full technical state: addresses, findings, dead ends
server/lobbyserv.py      lobby server - JAM, blob, handshake, experiments
inject/owobs.cpp         in-process observer; also calls Success() to advance
research/cli_dec.bin      decrypted real lobby traffic (client -> server)
research/srv_dec.bin      decrypted real lobby traffic (server -> client)
```
Read `docs/PROJECT_STATE.txt` before starting anything. It contains a
**"VOID - DO NOT USE"** section listing a subsystem that was misidentified for
three weeks. Reading it will save you that time.

## Quick start
```
python server/lobbyserv.py
Overwatch.exe --tank_TournamentMode --lobbyServer=127.0.0.1:3724 --console
```
Tournament mode locks alt-tab; use the Windows key to tab out.

## Not included
Game binaries, memory dumps, decrypted game code, and raw packet captures are
not distributed here. Generate your own with the tooling described in the docs.

## Credits
Independent work by several people who hit the same wall (ty Sidiusz, and Zagrion
for the s2c key). The Prometheus project (OW 0.8 beta) and Plasmawatch (login
server emulation) are prior art worth reading; neither solved the 1.74 lobby
handshake.

## Licence
MIT. For preservation and interoperability research on software you own.
