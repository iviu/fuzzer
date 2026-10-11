<p align="center"> <em>a single-file FTP fuzzer with a proper protocol client, six fuzzing strategies, thread-pool workers and a dark-mode GUI — my offensive security/software testing exam project</em> </p><p align="center"> <img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-blueviolet?style=for-the-badge&logo=python"> <img alt="License" src="https://img.shields.io/badge/license-MIT-lightgrey?style=for-the-badge"> <img alt="Fuzzing" src="https://img.shields.io/badge/fuzzing-6%20strategies-ff69b4?style=for-the-badge"> <img alt="Status" src="https://img.shields.io/badge/exam%20project-%E2%9C%94%20submitted-success?style=for-the-badge"> </p>

---

## hello
#### this is my offensive security/software testing exam project it's called FTP Fuzzer and it's a single-file Python tool that fuzzes FTP servers — properly, with:
- a real FTP client (multi-line replies, TLS, full login state machine)
- 6 fuzzing strategies (fixed-length, increment, random, cyclic De Bruijn, format-string, path traversal)
- a thread-pool worker system with rate limiting, exponential backoff, and graceful pause/resume
- a resumable corpus so an interrupted run picks up where it left off
- a dark-mode Tkinter GUI with live results, log bus, and about-everything tabs
- a headless CLI for scripting and CI
#### i built it because FTP is the classic example of a text protocol with lots of weird commands, and i wanted to write a fuzzer that wasn't just "throw bytes at it" — one that actually understands the protocol it's fuzzing.
#### read this first: fuzzing is intrusive. only run this against servers you own or have explicit written permission to test. unauthorized fuzzing may be illegal in your jurisdiction and will get you kicked off networks. the About tab says so. this README says so. please don't be that person.

---

## what it actually does
### the FTP client (yes, a real one)
- Multi-line reply handling — correctly reads 220- continuation lines until the terminating 220 line
- Full login state machine — USER → optional 331 → PASS → 230/202
- TLS support (explicit FTPS) with optional certificate verification
- Configurable timeout on connect and recv
- Clean error typing — FTPConnectionError distinguishes timeouts from resets from failures
- Greeting validation — refuses to fuzz if the server doesn't send a 2xx greeting
### 6 fuzzing strategies
1. Fixed — repeat a seed character to growing lengths (A × step, A × 2·step, …). the bread-and-butter buffer-overflow hunt
2. Increment — grow one byte at a time. slow but exact
3. Random — random bytes of growing length. great for parser stress tests
4. Cyclic (De Bruijn) — aaabaaacaaad... sequences. if the server crashes, you can find the exact offset that overwrites EIP/RIP
5. Format — %n, %s, %x, %p, %99999999d, plus every 2-token combination. classic format-string bug hunting
6. Traversal — ../, ..\, /etc/, C:\, ....//, .%%2e/ — path traversal probes for RETR/STOR/CWD/LIST
### worker system
- Thread pool with bounded pending futures (threads × 4 queue depth) so memory stays flat
- Rate limiter — precise monotonic-clock token bucket, not time.sleep guesswork
- Exponential backoff — automatic on connection failures and timeouts, resets on success
- Pause / resume — cooperative threading.Event checked at every job boundary
- Graceful stop — signal-safe, drains in-flight jobs, writes the corpus before exiting
- Per-job dedup — (command, hash(payload)) set prevents sending identical payloads
### corpus
- JSONL format — append-only, human-readable, jq-friendly
- Resume-aware — on startup, reads the corpus and skips already-tested payloads
- Only records interesting results — timeouts, resets, send failures. NOT every OK
- Records hash + length + first 64 bytes hex so you can replay any hit without the full payload
- Thread-safe writer with a single lock
### report
- Structured JSON report at the end of every run — config, stats, corpus path
- Live stats counters — sent / ok / error / timeout / reset / send_fail / conn_fail / skipped / hits
- Rate and ETA computed live from monotonic clock
- Per-result detail in the GUI tree — timestamp, command, label, verdict, code, length, response
### two interfaces
- Tkinter GUI — dark mode, live log, sortable results tree, test-connection button, config import/export, right-click to copy rows
- Headless CLI — full argument parity, JSON config file merging, --verbose, --quiet, SIGINT/SIGTERM handling
----

## installation
#### you'll need Python 3.10+ (uses X | Y typing and modern dataclass features).
#### required: none — pure stdlib
#### optional:
- tkinter is bundled with most Python installs; on Debian/Ubuntu minimal installs you might need sudo apt install python3-tk
- on headless servers, run with --cli
## run it
```
# GUI (default)
python main.py

# CLI mode
python main.py --cli --target 127.0.0.1 --username user --password pass --extensive

# Help
python main.py --help
python main.py --cli --help
```
---
