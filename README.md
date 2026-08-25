# Overwatch 1.74 - Lobby Protocol Research

Reverse-engineering the Overwatch 1 lobby protocol (build **1.74.0.0 / 104319**,
Windows x64 QA-dev) with the goal of reaching the main menu on a fully local,
offline server. Game preservation, own machine, own copy.

**Status: not finished.** The transport layer is solved and a client will
complete the handshake and hold an open connection against this server. The
connect handshake that follows is *not* solved - the client polls forever and
never reaches the menu. This repo exists so that work isn't repeated.

---

## What is actually solved

- **JAM stream cipher** - reimplemented server-side, byte-exact.
  Known-answer test (key = `00 01 02 … 1f`), first 64 bytes of keystream:
  ```
  f07e5df1c8d51c0d754da6ddde34cca01db0ed26334eb94ae277135a0764c6a6
  794d7ab0cc0978ef43de30766a7ee1d7c90e159df239d4016d450fa3d8207842
  ```
  Independently confirmed by a second implementer. If your cipher reproduces
  this, it is correct.

- **292-byte state blob** - construction and embedded HMAC key recovered, and
  the 292-byte length is confirmed against real Blizzard server traffic.

- **Full handshake to state 6** - `HELLO PRO CLIENT` / `HELLO PRO SERVER`,
  nonce exchange, MAC1/MAC2, encrypted blob. Reproducible every connection.

- **Counter gate** - the first server reply must carry counter `0`, not `1`.
  (`01 00 00 00` encodes 1. This off-by-one silently killed every reply for
  weeks.)

- **Arxan boundaries** - mapped precisely. See `docs/PROJECT_STATE.txt`.
  Short version: inline code hooking inside `Overwatch.exe` is impossible
  (VirtualProtect denied on 11,408 of 11,408 executable pages); heap writes and
  external-module hooks work fine; no live debugger survives.

- **Real lobby traffic decrypted** - see below.

## What is not solved

The client sends a 10-byte connect request and then a 2-byte poll frame, and
closes unless answered. **No reply anyone has constructed advances it.** Reply
msgid `0x003` keeps the socket alive for the full 300 s instead of closing
instantly, but the body is provably not parsed (an empty body behaves
identically to a valid one), so it is a benign no-op rather than a handshake
step.

Three people have independently reached this exact wall. None has passed it.

---

## Decrypted real Blizzard lobby traffic

`research/cli_dec.bin` is the decrypted **client → server** half of a genuine
Overwatch 1 lobby session against a real Blizzard server. 211 frames, 61,712 of
61,712 bytes consumed with zero parse errors.

Key schedule, confirmed against that traffic:

```
MAC1           = HMAC-SHA256(k0, cn || sn)
MAC2           = HMAC-SHA256(k1, sn || cn)
c2s cipher key = HMAC-SHA256(k3, sn || cn)
s2c cipher key = not yet recovered (k2 expected)
```

Four separate 64-byte key slots, one role each, sourced from the Battle.net
session. Tournament mode zeroes all four, which is why a zero key works locally.

Frame format: `[u24be frame_len][u16be msgid][ … ]`. For msgid `0x4401` the
next field is a u32le payload length (verified 96/96).

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

## Highest-value open problem

The **server → client** direction of that same capture is still encrypted. The
session keys are known, so this is very likely a TCP reassembly issue rather
than a key problem - the post-blob segments overlap (offset 406 length 6, then
offset 411 length 109), and one byte of misalignment destroys a stream cipher's
output downstream.

Recovering it would show, in real bytes, exactly what a genuine lobby server
replies - which is precisely the unknown blocking this project. **If you want
to help with one thing, make it this one.**

---

## Repo layout

```
docs/PROJECT_STATE.txt   full technical state: addresses, findings, dead ends
server/lobbyserv.py      lobby server - JAM, blob, handshake, experiments
inject/                  bink2w64 proxy, cert injection, in-process observer
research/cli_dec.bin     decrypted real lobby traffic (client -> server)
```

Read `docs/PROJECT_STATE.txt` before starting anything. It contains a
**"VOID - DO NOT USE"** section listing a subsystem that was misidentified for
three weeks. Reading it will save you that time.

## Quick start

```
python server/lobbyserv.py
Overwatch.exe --tank_TournamentMode --lobbyServer=127.0.0.1:3724 --console
```

Tournament mode locks alt-tab; use Windows key to tab out.

## Not included

Game binaries, memory dumps, decrypted game code, and packet captures are not
distributed here. Generate your own with the tooling described in the docs.

## Credits

Independent work by several people who hit the same wall (ty to Sidiusz). The Prometheus
project (OW 0.8 beta) and Plasmawatch (login server emulation) are prior art
worth reading; neither solved the 1.74 lobby handshake.

## Licence

MIT. For preservation and interoperability research on software you own.
