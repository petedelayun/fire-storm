# Operation FIRE STORM

My solution to CoreTech Security's FIRE STORM challenge, in C++. Both parts are implemented:

- **Stage 1:** a TCP proxy that forwards traffic from port 5733 to 5744, removes the CTFS packets from the stream, and rebuilds the PDF they contain.
- **Stage 2 ("Superheated"):** routes Ethernet frames to different ports by MAC address and protocol, rebuilds several files by file ID, and can optionally verify packet checksums.

The original brief is in [`BRIEF.md`](BRIEF.md).

## Building

Requires `g++` with C++17 and `make`. Tested on Ubuntu 24.04 with g++ 13.3. There are no third-party dependencies.

```bash
make            # builds stage1/firestorm and stage2/firestorm
make debug      # rebuilds both with AddressSanitizer and UndefinedBehaviorSanitizer
make clean      # removes the binaries and any generated PDFs
```

Both build with `-Wall -Wextra` and no warnings.

## Running and verifying

Each stage is run from its own folder, which is where its PDFs are written.

### Stage 1

```bash
cd stage1
./firestorm             # terminal 1
python3 test.py         # terminal 2: should print OK
```

The rebuilt document is written to `stage1/output.pdf` and begins with `%PDF-1.3`.

### Stage 2

```bash
cd stage2
./firestorm             # terminal 1 (or ./firestorm --verify-checksum, see below)
python3 test.py         # terminal 2: should print OK
```

Five documents are written to `stage2/`, `0.pdf` to `4.pdf`, one per file ID.

| Option | Effect |
|---|---|
| *(none)* | Checksums are not verified. All five PDFs are complete. |
| `--verify-checksum` | Packets that fail the checksum are ignored, as the specification describes. See [Checksum](#checksum). |
| `-h`, `--help` | Prints usage. |

## The CTFS protocol

The brief gave the first two fields. The header length I worked out by inspecting the traffic in Wireshark: every CTFS packet has a 16-byte header, and the payload starts straight after it.

| Bytes | Field | Notes |
|---|---|---|
| 0–3 | Marker | `CTFS` |
| 4–5 | Sequence number | Big-endian |
| 6–7 | Payload length | Big-endian |
| 8 | File ID | Unknown in stage 1, given in the stage 2 brief |
| 9–12 | Checksum | Big-endian |
| 13–15 | Padding | Expected to be `00 00 00` |

Two things the traffic showed that the brief didn't mention:

- **Packets arrive out of order** (for example 5, 7, 6, 9, 8), so payloads are stored by sequence number and written in order at the end.
- **The final stage 1 packet has a payload length of 0.** I treat it as a valid empty chunk, most likely an end-of-transfer marker.

## Design

### Shared approach

- **TCP is a byte stream, not a series of messages.** One `recv()` can contain half a packet or several packets, so incoming bytes are appended to a buffer, and a record is only processed once it has fully arrived.
- **Lazy outbound connections.** The proxy connects to an output port the first time it has data for it, rather than as soon as a client connects. The test harness connects to 5733 before its receivers start listening, so connecting straight away failed with "connection refused".
- **Robust sending.** `send()` can accept fewer bytes than requested, so `send_all()` loops until everything is sent, and retries if it is interrupted by a signal. `SIGPIPE` is ignored so that a closed receiver produces an error rather than terminating the program.
- **Output is written whenever a connection ends**, including after an error, so data received before a problem isn't lost. A file with missing sequence numbers produces a warning.

### Stage 1: finding packets in the stream

Stage 1 has to find CTFS packets inside arbitrary traffic, so it searches the buffer for the `CTFS` marker:

- Data before a marker is forwarded.
- A packet is only taken out once its header and payload have both arrived.
- **The last 3 bytes of the buffer are held back** when no marker is found, because a marker split across two reads (`CT` then `FS`) would otherwise be forwarded and the packet lost. They are forwarded when the connection closes.
- **A length over 512 is rejected as a false match.** Without this check, a chance `CTFS` in normal traffic with a large "length" would make the proxy wait for, and swallow, data that isn't a packet. The marker bytes are forwarded and the search continues.

### Stage 2: reading records by length

Stage 2 traffic contains only CTFS packets and IPv4 Ethernet frames, with each record starting immediately after the previous one ends. Every record states its own length, so no searching is needed:

- **CTFS packet:** 16 + the payload length.
- **Ethernet frame:** 14 + the IP header's total length.

At each record boundary, the first 4 bytes decide which kind of record it is. The record is read once complete, and the parser moves to the next. This removes the stage 1 marker search and 3-byte holdback entirely. Headers are read through the system `ether_header` and `ip` structs rather than hard-coded offsets. The parser reads the entire test stream this way, with no unrecognised records or leftover bytes.

If a record can't be identified (not CTFS and not IPv4, or an impossible length), the proxy has lost its place in the stream and has no safe way to find the next boundary, so it closes the connection rather than guess and misroute data.

### Stage 2: routing

`route_frame()` decides where each Ethernet frame goes, and returns a list because a frame can go to two ports. It answers two separate questions:

1. **Should it be monitored?** If the destination MAC belongs to Microsoft or Dell (`00:1A:A0`, `00:1E:C9`, `00:15:5D`), a copy goes to **5745**.
2. **Where does it normally go?** Traffic from a VMware source MAC (`00:0C:29`, `00:50:56`, `00:1C:14`) is dropped. Otherwise TCP goes to **5744** and UDP to **5746**. Anything else is dropped.

The monitoring check runs first, so a frame sent to a Microsoft or Dell device is still copied to 5745 even when its normal route is dropped, whether because it comes from a VMware device or uses a protocol other than TCP or UDP.

Each output port has its own lazily opened connection, kept in a map from port to socket.

### Stage 2: validation

- **Padding:** a packet whose padding bytes aren't zero is ignored.
- **Duplicates:** if a sequence number arrives twice, the first valid copy is kept.
- **Incomplete records at close:** discarded with a warning. Forwarding them would send a corrupt frame or leak CTFS data, and storing them would corrupt a file.

## Checksum

I implemented the checksum as specified. Reading words big-endian is correct: little-endian rejected every packet.

With verification on, every packet verified except the final chunk of files 0, 2, 3 and 4. Each of those has a length that isn't a multiple of 4 bytes, so the specified zero padding seems to be where the reference implementation differs. No other copies of those chunks arrive, so strict checking leaves four files incomplete.

Rather than drop data or change the algorithm to match, I made verification optional: by default every file is complete, and `--verify-checksum` applies the specification strictly.

## Testing

- Both provided test scripts pass on a clean build.
- Building with AddressSanitizer and UndefinedBehaviorSanitizer (now `make debug`) caught a null pointer being passed to `fwrite` for the zero-length final packet.
- Compiling with `-Wall -Wextra` flagged a possible out-of-bounds write in `has_valid_checksum`. The caller already checks the length, but I added a check inside the function too, so it's safe however it's called.
- Every reassembled PDF was opened and checked to render correctly.

## Limitations and possible improvements

- **One connection at a time, and blocking I/O.** The proxy only waits on the inbound socket, so if a receiver closes first, its socket stays in CLOSE-WAIT until the next send fails or the sender closes. Watching all sockets with `poll()` would detect this immediately and allow several clients at once.
- **Removing processed bytes from the front of the buffer.** Each erase moves every remaining byte forward to fill the gap, which gets slow if a large backlog builds up. Keeping a read offset instead, and only removing processed bytes occasionally (for example once the offset passes half the buffer), would avoid the repeated copying.
- **The stage 2 parser assumes the stream contains only CTFS packets and IPv4 frames.** An ARP or IPv6 frame, or junk bytes between records, would leave it unable to find the next boundary. A real Ethernet frame whose destination MAC began `43:54:46:53` would also be mistaken for CTFS, although that prefix is a multicast address, not one used by normal devices. Reading the lengths of other frame types, and resyncing after junk by scanning for the next valid record, would make it more robust.
- **The 512-byte payload limit comes from the test traffic, not the brief.** Every packet in both stages carries at most 512 bytes. Stage 1 uses it to reject chance `CTFS` matches in normal traffic, and stage 2 treats a larger length as a broken stream. If the protocol allowed larger chunks, those packets would be rejected, so the limit would need confirming against a full protocol specification.
- **Outbound connections are not retried.** A receiver is connected to the first time there is data for it. If it isn't listening yet, the connection fails and that data isn't delivered. A short retry, for example five attempts 100 ms apart, would cover a receiver that starts late, at the cost of briefly delaying the stream.

## Use of AI

I used Claude throughout this project, alongside YouTube tutorials.

- **Learning:** I'd used C/C++ in a university module, but socket programming and Wireshark were new to me. I used Claude to explain them, and to get back up to speed with C++.
- **Design:** for most of the work I proposed an approach and Claude filled the gaps. The main exception is the stage 1 stream parser: its structure was largely Claude's suggestion, which I then reworked and studied until I could explain each branch.
- **My own work:** I worked out the CTFS header layout from the traffic, wrote the stage 2 routing logic, and made the design decisions described above, including making checksum verification optional.
- **Debugging and analysis:** I traced a "connection timed out" error to a map passed by value, fixed a null pointer caught by the sanitiser build, and found the checksum's byte order by testing both. Claude wrote a short script I used to inspect the structure of the stage 2 traffic.
- **Review:** Claude reviewed my code for standard practice, and I went through every function to understand it. Nothing was kept without passing the tests and a clean sanitiser build.

## Repository layout

```
stage1/    main.cpp and CoreTech's stage 1 test harness
stage2/    main.cpp and CoreTech's stage 2 test harness
BRIEF.md   the original challenge brief
Makefile
```