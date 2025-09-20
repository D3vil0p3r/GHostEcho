#!/usr/bin/env python3
"""
icmp_receiver.py
Listens for ICMP Echo Requests, verifies CRC32 for chunked payloads,
sends ACK/NAK ICMP Echo Reply payloads back, and reassembles the file.
Prints single-line progress updates.

Run as root (sudo).
"""

import socket
import struct
import binascii
import time
import os
import tempfile
import sys

def icmp_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    s = sum(struct.unpack('!%dH' % (len(data)//2), data))
    s = (s >> 16) + (s & 0xffff)
    s += (s >> 16)
    return (~s) & 0xffff

def build_icmp_echo_reply(ident, seq, payload: bytes) -> bytes:
    icmp_type = 0  # echo reply
    code = 0
    header = struct.pack('!BBHHH', icmp_type, code, 0, ident, seq)
    chksum = icmp_checksum(header + payload)
    header = struct.pack('!BBHHH', icmp_type, code, chksum, ident, seq)
    return header + payload

def parse_ip_header(packet: bytes):
    if len(packet) < 20:
        return 0, None
    ver_ihl = packet[0]
    ihl = (ver_ihl & 0x0f) * 4
    src_ip = socket.inet_ntoa(packet[12:16])
    return ihl, src_ip

def parse_icmp_header(icmp_packet: bytes):
    if len(icmp_packet) < 8:
        return None
    icmp_type, code, chksum, ident, seq = struct.unpack('!BBHHH', icmp_packet[:8])
    payload = icmp_packet[8:]
    return icmp_type, code, chksum, ident, seq, payload

def safe_int(v, default=0):
    try:
        return int(v)
    except Exception:
        return default

def newline_if_inline():
    # Move to a new line if progress was printed inline recently
    # (we print progress using '\r' so ensure subsequent messages start on a fresh line)
    sys.stdout.write("\n")
    sys.stdout.flush()

def main(listen_iface_ip='0.0.0.0'):
    # raw socket that receives IP packets containing ICMP (Linux)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.bind((listen_iface_ip, 0))
    print("[*] Listening for ICMP Echo Requests (requires root). Press Ctrl-C to stop.")

    # Transfer state
    filename = None
    filesize = None
    total_chunks = None
    expected_chunk_size = None
    chunks_tmpfiles = {}   # seq -> tmp file path
    last_report = 0.0
    src_peer = None
    inline_progress_shown = False

    try:
        while True:
            packet, addr = s.recvfrom(65535)
            ip_hdr_len, src_ip = parse_ip_header(packet)
            icmp_packet = packet[ip_hdr_len:]
            parsed = parse_icmp_header(icmp_packet)
            if not parsed:
                continue
            icmp_type, code, chksum, ident, seq, payload = parsed
            # only handle echo requests (type 8)
            if icmp_type != 8:
                continue

            # detect metadata packets: payload starts with b'FileName:' (case-insensitive)
            is_meta = False
            try:
                if payload[:9].lower() == b'filename:' or payload[:8].lower() == b'filename':
                    is_meta = True
            except Exception:
                is_meta = False

            if is_meta:
                # ensure any inline progress is moved to the next line for clean output
                if inline_progress_shown:
                    newline_if_inline()
                    inline_progress_shown = False

                # parse metadata lines (ASCII tolerant)
                try:
                    text = payload.decode('ascii', errors='ignore')
                    meta = {}
                    for line in text.splitlines():
                        if ':' in line:
                            k, v = line.split(':', 1)
                            meta[k.strip().lower()] = v.strip()
                    filename = meta.get('filename') or f"received_{int(time.time())}"
                    filesize = safe_int(meta.get('filesize'), 0)
                    total_chunks = safe_int(meta.get('totalchunks'), None)
                    expected_chunk_size = safe_int(meta.get('chunksize'), None)
                    src_peer = src_ip
                    print(f"[META] From {src_ip}: filename={filename}, filesize={filesize}, total_chunks={total_chunks}, chunk_size={expected_chunk_size}")
                except Exception as e:
                    print("[!] Failed to parse metadata:", e)

                # reply META|OK
                ack_payload = b'META|OK'
                reply = build_icmp_echo_reply(ident, seq, ack_payload)
                try:
                    s.sendto(reply, (src_ip, 0))
                except Exception as e:
                    print("[!] Failed to send META reply:", e)

                # reset chunk containers (and remove old tmp files)
                for p in chunks_tmpfiles.values():
                    try:
                        os.remove(p)
                    except Exception:
                        pass
                chunks_tmpfiles = {}
                last_report = time.time()
                continue

            # non-meta: treat as chunk packet: [4 bytes seq][0x7C '|'][checksum ASCII][0x7C '|'][payload]
            if len(payload) < 6:
                # malformed
                nack_payload = b'NAK|-1'
                reply = build_icmp_echo_reply(ident, seq, nack_payload)
                s.sendto(reply, (src_ip, 0))
                continue

            # parse sequence number (4 byte little-endian)
            try:
                seq_num = struct.unpack('<I', payload[0:4])[0]
            except Exception:
                nack_payload = b'NAK|-1'
                reply = build_icmp_echo_reply(ident, seq, nack_payload)
                s.sendto(reply, (src_ip, 0))
                continue

            # locate delimiters (pipe '|' 0x7C)
            try:
                delim1 = payload.index(b'|', 4)
                delim2 = payload.index(b'|', delim1 + 1)
            except ValueError:
                nack_payload = f'NAK|{seq_num}'.encode('ascii')
                reply = build_icmp_echo_reply(ident, seq, nack_payload)
                s.sendto(reply, (src_ip, 0))
                continue

            checksum_ascii = payload[delim1 + 1:delim2]
            chunk_bytes = payload[delim2 + 1:]

            # compute crc32 unsigned
            computed = binascii.crc32(chunk_bytes) & 0xffffffff
            try:
                expected = int(checksum_ascii.decode('ascii'), 16)
            except Exception:
                expected = None

            if expected is not None and expected == computed:
                # good chunk: store to a temp file named by seq (avoid duplicates)
                if seq_num not in chunks_tmpfiles:
                    fd, tmp_path = tempfile.mkstemp(prefix=f"chunk_{seq_num}_")
                    os.close(fd)
                    try:
                        with open(tmp_path, 'wb') as fh:
                            fh.write(chunk_bytes)
                        chunks_tmpfiles[seq_num] = tmp_path
                    except Exception as e:
                        # failed to write; respond with NAK
                        nack_payload = f'NAK|{seq_num}'.encode('ascii')
                        reply = build_icmp_echo_reply(ident, seq, nack_payload)
                        s.sendto(reply, (src_ip, 0))
                        continue

                ack_payload = f'ACK|{seq_num}'.encode('ascii')
                reply = build_icmp_echo_reply(ident, seq, ack_payload)
                s.sendto(reply, (src_ip, 0))
            else:
                # bad chunk
                nack_payload = f'NAK|{seq_num}'.encode('ascii')
                reply = build_icmp_echo_reply(ident, seq, nack_payload)
                s.sendto(reply, (src_ip, 0))

            # progress reporting (single-line)
            now = time.time()
            if now - last_report > 1.0:
                last_report = now
                got = len(chunks_tmpfiles)
                if total_chunks:
                    # print inline progress with carriage return, no newline
                    sys.stdout.write(f"\r[+] Received {got}/{total_chunks} chunks")
                else:
                    sys.stdout.write(f"\r[+] Received {got} chunks (metadata not yet received)")
                sys.stdout.flush()
                inline_progress_shown = True

            # assembly when all chunks present (only if total_chunks known)
            if total_chunks and len(chunks_tmpfiles) >= total_chunks:
                # move to fresh line before verbose messages
                if inline_progress_shown:
                    newline_if_inline()
                    inline_progress_shown = False

                outname = filename or f"received_{int(time.time())}"
                print(f"[+] All chunks received; assembling {outname} ...")
                try:
                    with open(outname, 'wb') as outfh:
                        for i in range(total_chunks):
                            p = chunks_tmpfiles.get(i)
                            if not p:
                                print(f"[!] Missing chunk {i} during assembly; aborting")
                                raise RuntimeError("Missing chunk during assembly")
                            with open(p, 'rb') as chfh:
                                outfh.write(chfh.read())
                    print(f"[+] Wrote {outname}")
                except Exception as e:
                    print("[!] Assembly/write error:", e)

                # cleanup temporary chunk files
                for p in chunks_tmpfiles.values():
                    try:
                        os.remove(p)
                    except Exception:
                        pass

                # reset state for next transfer
                filename = None
                filesize = None
                total_chunks = None
                expected_chunk_size = None
                chunks_tmpfiles = {}
                last_report = time.time()
                src_peer = None

    except KeyboardInterrupt:
        if inline_progress_shown:
            newline_if_inline()
        print("\n[!] Interrupted by user")
    finally:
        s.close()

if __name__ == '__main__':
    main()
