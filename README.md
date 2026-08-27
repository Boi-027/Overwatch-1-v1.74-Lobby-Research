# Overwatch 1.74 - Lobby Protocol Research

Reverse-engineering the Overwatch 1 lobby protocol (build **1.74.0.0 / 104319**),
with the goal of reaching the main menu on a fully local, offline server. Game
preservation, own machine, own copy.

**Status: On hiatus until someone cracks the second server message, or sends me a
Tournament Mode Wireshark capture.** The transport layer is solved and a client
will complete the handshake and hold an open connection against this server. The
client also *accepts* the first server reply now (see below) - but the message
after that is still unsolved, so the client never reaches the menu. This repo
exists so that work isn't repeated.

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
  sweeping 338 msgids: `0x0102` is the only value the client accepts (it then
  waits out its full 5-retry budget), every other value is rejected instantly.
  This is the first server->client message the 1.74 client has ever accepted.

- **Message body format** - bodies are a sequence of `[u32le block_len][protobuf
  block]` interleaved with fixed fields (356 blocks decoded across 94 real
  frames; one decodes to a player BattleTag, confirming the reading). 16-byte
  entity handles are `[u32le id][8 zero bytes][u32le type]`.

- **Arxan boundaries** - mapped precisely. See `docs/PROJECT_STATE.txt`.
  Short version: inline code hooking inside `Overwatch.exe` is impossible
  (VirtualProtect denied on 11,408 of 11,408 executable pages); heap writes and
  external-module hooks work fine; no live debugger survives.

- **Real lobby traffic decrypted, both directions** - see below.

## What is not solved - THE central question

After the bare `0x0102` ack, the client keeps polling and nothing advances it.
Every follow-up tried is rejected: all msgids as a full reply, bare frames, and
payload frames - including a **byte-exact real retail `0x3004` frame**. The
rejection is content- and msgid-independent, so it happens at a framing layer
before dispatch.

A two-session diff proved why the retail capture can't answer this: essentially
every byte inside a frame (blob, opening message, entity handles) is
session-specific. The correct second message has to be built from the 1.74
client's **own** session state, and that schema lives in encrypted `.rdata`
behind Arxan.

**This is why a Tournament Mode capture is the one artifact that would unblock
the project** - same code path as this build, zeroed keys, decryptable with the
tooling already here. No key dump needed, just the raw lobby pcap.

Three-plus people have independently reached this exact wall. None has passed it.

---

## Decrypted real Blizzard lobby traffic

`research/cli_dec.bin` (client->server) and `research/srv_dec.bin`
(server->client) are both directions of a genuine Overwatch 1 lobby session
against a real Blizzard server, fully decrypted. Client: 211 frames, 61,712/61,712
bytes. Server: 94 frames, 383,890/383,890 bytes. Zero parse errors either way.

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
inject/                  bink2w64 proxy, cert injection, in-process observer
research/cli_dec.bin     decrypted real lobby traffic (client -> server)
research/srv_dec.bin     decrypted real lobby traffic (server -> client)
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
