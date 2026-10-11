from __future__ import annotations
import argparse, concurrent.futures, dataclasses, enum, itertools
import json, os, queue, random, re, signal, socket, ssl, threading
import string, sys, time, traceback
from typing import Callable, Iterable, Iterator, List, Optional, Sequence, Tuple

APP_NAME    = "Fuzzer"
APP_VERSION = "0.1"
DEFAULT_PORT        = 21
DEFAULT_MAX_LEN     = 10_000
DEFAULT_STEP        = 100
DEFAULT_THREADS     = 4
DEFAULT_TIMEOUT     = 10.0
DEFAULT_RATE        = 0.0
DEFAULT_BACKOFF     = 1.5
DEFAULT_BACKOFF_MAX = 30.0
CORPUS_FILE_DEFAULT = "fuzz_corpus.jsonl"
REPORT_FILE_DEFAULT = "fuzz_report.json"
FTP_COMMANDS: List[str] = sorted({
    "ABOR", "ACCT", "ADAT", "ALLO", "APPE", "AUTH", "CCC",
    "CDUP", "CONF", "CWD",  "DELE", "ENC",  "EPRT", "EPSV",
    "FEAT", "HELP", "LANG", "LIST", "LPRT", "LPSV", "MDTM",
    "MIC",  "MKD",  "MLSD", "MLST", "MODE", "NLST", "NOOP",
    "OPTS", "PASS", "PASV", "PORT", "PROT", "PWD",  "QUIT",
    "REIN", "REST", "RETR", "RMD",  "RNFR", "RNTO", "SITE",
    "SIZE", "STAT", "STOR", "STOU", "STRU", "SYST", "TYPE",
    "USER", "XCUP", "XMKD", "XPWD", "XRSQ", "XSEM", "XSEN",
})
NO_ARG_COMMANDS = {"ABOR", "CDUP", "FEAT", "HELP", "LIST", "MLSD", "MLST",
                   "NLST", "NOOP", "PASV", "PWD", "QUIT", "REIN", "STAT",
                   "SYST", "XCUP", "XPWD"}

class Strategy(str, enum.Enum):
    FIXED     = "fixed"
    INCREMENT = "increment"
    RANDOM    = "random"
    CYCLIC    = "cyclic"
    FORMAT    = "format"
    TRAVERSAL = "traversal"

class Verdict(str, enum.Enum):
    OK        = "ok"
    ERROR     = "error"
    TIMEOUT   = "timeout"
    RESET     = "reset"
    SEND_FAIL = "send_fail"
    CONN_FAIL = "conn_fail"

@dataclasses.dataclass
class Config:
    target: str = ""
    port: int = DEFAULT_PORT
    username: Optional[str] = None
    password: Optional[str] = None
    max_len: int = DEFAULT_MAX_LEN
    step: int = DEFAULT_STEP
    threads: int = DEFAULT_THREADS
    timeout: float = DEFAULT_TIMEOUT
    rate: float = DEFAULT_RATE
    backoff: float = DEFAULT_BACKOFF
    backoff_max: float = DEFAULT_BACKOFF_MAX
    extensive: bool = False
    strategy: Strategy = Strategy.FIXED
    commands: List[str] = dataclasses.field(default_factory=lambda: list(FTP_COMMANDS))
    include_no_arg: bool = True
    tls: bool = False
    tls_verify: bool = False
    corpus: str = CORPUS_FILE_DEFAULT
    report: str = REPORT_FILE_DEFAULT
    resume: bool = True
    dry_run: bool = False
    show_payloads: bool = False
    seed: Optional[int] = None
    def copy(self) -> "Config":
        return dataclasses.replace(self, commands=list(self.commands))

@dataclasses.dataclass
class Result:
    command: str
    payload: bytes
    label: str
    verdict: Verdict
    code: Optional[int] = None
    detail: str = ""
    elapsed: float = 0.0
    @property
    def interesting(self) -> bool:
        return self.verdict in (Verdict.TIMEOUT, Verdict.RESET, Verdict.SEND_FAIL)

class LogLevel(str, enum.Enum):
    DEBUG   = "DEBUG"
    INFO    = "INFO"
    OK      = "OK"
    WARN    = "WARN"
    ERROR   = "ERROR"
    HIT     = "HIT"

@dataclasses.dataclass
class LogRecord:
    ts: float
    level: LogLevel
    message: str

class LogBus:
    def __init__(self) -> None:
        self._subs: List[queue.Queue] = []
        self._lock = threading.Lock()

    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=10_000)
        with self._lock:
            self._subs.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            try:
                self._subs.remove(q)
            except ValueError:
                pass

    def publish(self, level: LogLevel, msg: str) -> None:
        rec = LogRecord(time.time(), level, msg)
        with self._lock:
            subs = list(self._subs)
        for q in subs:
            try:
                q.put_nowait(rec)
            except queue.Full:
                pass

LOG_BUS = LogBus()

def log(level: LogLevel, msg: str) -> None:
    LOG_BUS.publish(level, msg)

class PayloadGenerator:
    def __init__(self, cfg: Config, rng: random.Random) -> None:
        self.cfg = cfg
        self.rng = rng

    def __call__(self, seed: bytes) -> Iterator[Tuple[str, bytes]]:
        s = self.cfg.strategy
        if s is Strategy.FIXED:       yield from self._fixed(seed)
        elif s is Strategy.INCREMENT: yield from self._increment(seed)
        elif s is Strategy.RANDOM:    yield from self._random()
        elif s is Strategy.CYCLIC:    yield from self._cyclic()
        elif s is Strategy.FORMAT:    yield from self._format()
        elif s is Strategy.TRAVERSAL: yield from self._traversal()

    def _fixed(self, seed: bytes) -> Iterator[Tuple[str, bytes]]:
        n, step = self.cfg.step, self.cfg.step
        while n <= self.cfg.max_len:
            yield f"len={n}", seed * n
            n += step

    def _increment(self, seed: bytes) -> Iterator[Tuple[str, bytes]]:
        n = 1
        while n <= self.cfg.max_len:
            yield f"len={n}", seed * n
            n += 1

    def _random(self) -> Iterator[Tuple[str, bytes]]:
        n = self.cfg.step
        while n <= self.cfg.max_len:
            yield f"rnd-len={n}", bytes(self.rng.randrange(256) for _ in range(n))
            n += self.cfg.step

    def _cyclic(self) -> Iterator[Tuple[str, bytes]]:
        pattern = _de_bruijn(string.ascii_lowercase.encode(), 3)
        n = self.cfg.step
        while n <= self.cfg.max_len:
            yield f"cyc-len={n}", pattern[:n]
            n += self.cfg.step

    def _format(self) -> Iterator[Tuple[str, bytes]]:
        tokens = [b"%n", b"%s", b"%x", b"%p", b"%99999999d", b"%.1000000f",
                  b"%99999999999999999999s", b"%1$n", b"%hn", b"%hhn"]
        for t in tokens:
            yield f"fmt={t.decode(errors='replace')}", t
        for a, b in itertools.product(tokens, repeat=2):
            yield f"fmt={a.decode()}{b.decode()}", a + b

    def _traversal(self) -> Iterator[Tuple[str, bytes]]:
        for b in (b"../", b"..\\", b"/etc/", b"C:\\", b"....//", b".%2e/"):
            yield f"trav={b!r}", b * self.cfg.step

def _de_bruijn(alphabet: bytes, n: int) -> bytes:
    k = len(alphabet)
    a = [0] * (k * n)
    seq: List[int] = []
    def db(t: int, p: int) -> None:
        if t > n:
            if n % p == 0:
                seq.extend(a[1:p + 1])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)
    db(1, 1)
    return bytes(alphabet[i] for i in seq)

class FTPConnectionError(Exception):
    pass

class FTPClient:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.sock: Optional[socket.socket] = None
        self.buf = b""

    def __enter__(self) -> "FTPClient":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def connect(self) -> None:
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(self.cfg.timeout)
        try:
            raw.connect((self.cfg.target, self.cfg.port))
        except OSError as e:
            raw.close()
            raise FTPConnectionError(f"connect failed: {e}") from e
        if self.cfg.tls:
            ctx = ssl.create_default_context()
            if not self.cfg.tls_verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            try:
                raw = ctx.wrap_socket(raw, server_hostname=self.cfg.target)
            except ssl.SSLError as e:
                raw.close()
                raise FTPConnectionError(f"TLS handshake failed: {e}") from e
        self.sock = raw
        self.buf = b""
        code, _ = self.read_reply()
        if code // 100 != 2:
            raise FTPConnectionError(f"bad greeting: {code}")
        if self.cfg.username:
            self._login()

    def _login(self) -> None:
        self.send_line(b"USER " + self.cfg.username.encode())
        code, _ = self.read_reply()
        if code not in (230, 331):
            raise FTPConnectionError(f"USER rejected: {code}")
        if code == 331:
            if not self.cfg.password:
                raise FTPConnectionError("password required but not provided")
            self.send_line(b"PASS " + self.cfg.password.encode())
            code, _ = self.read_reply()
            if code not in (230, 202):
                raise FTPConnectionError(f"login failed: {code}")

    def send_line(self, payload: bytes) -> None:
        if not self.sock:
            raise FTPConnectionError("not connected")
        self.sock.sendall(payload + b"\r\n")

    def _recv(self, n: int = 4096) -> bytes:
        if not self.sock:
            raise FTPConnectionError("not connected")
        try:
            chunk = self.sock.recv(n)
        except socket.timeout as e:
            raise FTPConnectionError("timeout") from e
        except OSError as e:
            raise FTPConnectionError(f"recv error: {e}") from e
        if not chunk:
            raise FTPConnectionError("connection closed by peer")
        return chunk

    def read_reply(self) -> Tuple[int, bytes]:
        while b"\r\n" not in self.buf:
            self.buf += self._recv()
        first_line, self.buf = self.buf.split(b"\r\n", 1)
        m = re.match(rb"(\d{3})([ -])(.*)", first_line)
        if not m:
            return 0, first_line
        code = int(m.group(1))
        sep = m.group(2)
        if sep == b"-":
            terminator = f"{code} ".encode()
            while True:
                while b"\r\n" not in self.buf:
                    self.buf += self._recv()
                line, self.buf = self.buf.split(b"\r\n", 1)
                if line.startswith(terminator):
                    break
        return code, first_line

    def close(self) -> None:
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

class Corpus:
    def __init__(self, path: str) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._seen: set = set()
        self._load()

    def _key(self, r: Result) -> str:
        return f"{r.command}|{r.label}|{hash(r.payload)}"

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        o = json.loads(line)
                        self._seen.add(f"{o['command']}|{o['label']}|{o.get('phash')}")
                    except Exception:
                        continue
        except OSError:
            pass

    def already_done(self, r: Result) -> bool:
        return self._key(r) in self._seen

    def add(self, r: Result) -> None:
        key = self._key(r)
        with self._lock:
            if key in self._seen:
                return
            self._seen.add(key)
            rec = {
                "ts": time.time(),
                "command": r.command,
                "label": r.label,
                "verdict": r.verdict.value,
                "code": r.code,
                "detail": r.detail[:500],
                "len": len(r.payload),
                "phash": hash(r.payload),
                "preview": r.payload[:64].hex(),
            }
            try:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec) + "\n")
            except OSError as e:
                log(LogLevel.WARN, f"could not write corpus: {e}")

class RateLimiter:
    def __init__(self, rate: float) -> None:
        self.rate = rate
        self._lock = threading.Lock()
        self._next = 0.0

    def wait(self) -> None:
        if self.rate <= 0:
            return
        with self._lock:
            now = time.monotonic()
            if now < self._next:
                time.sleep(self._next - now)
                now = time.monotonic()
            self._next = now + 1.0 / self.rate

class Backoff:
    def __init__(self, base: float, cap: float) -> None:
        self.base, self.cap = base, cap
        self._lock = threading.Lock()
        self._delay = 0.0

    def on_fail(self) -> float:
        with self._lock:
            self._delay = min(self.cap, max(self.base, self._delay * self.base)) \
                if self._delay else self.base
            d = self._delay
        time.sleep(d)
        return d

    def on_success(self) -> None:
        with self._lock:
            self._delay = 0.0

@dataclasses.dataclass
class Stats:
    sent: int = 0
    ok: int = 0
    error: int = 0
    timeout: int = 0
    reset: int = 0
    send_fail: int = 0
    conn_fail: int = 0
    skipped: int = 0
    hits: int = 0
    start: float = dataclasses.field(default_factory=time.monotonic)
    _lock: threading.Lock = dataclasses.field(default_factory=threading.Lock,
                                              repr=False, compare=False)

    def record(self, r: Result) -> None:
        with self._lock:
            self.sent += 1
            setattr(self, r.verdict.value, getattr(self, r.verdict.value) + 1)
            if r.interesting:
                self.hits += 1

    def skip(self) -> None:
        with self._lock:
            self.skipped += 1

    def elapsed(self) -> float:
        return time.monotonic() - self.start

    def to_dict(self) -> dict:
        return {
            "sent": self.sent, "ok": self.ok, "error": self.error,
            "timeout": self.timeout, "reset": self.reset,
            "send_fail": self.send_fail, "conn_fail": self.conn_fail,
            "skipped": self.skipped, "hits": self.hits,
            "elapsed_s": round(self.elapsed(), 3),
            "rate_per_s": round(self.sent / self.elapsed(), 2) if self.elapsed() else 0,
        }

    def summary(self) -> str:
        d = self.to_dict()
        return ("sent={sent} ok={ok} err={error} t/o={timeout} reset={reset} "
                "fail={send_fail}/{conn_fail} skip={skipped} hits={hits} "
                "elapsed={elapsed_s}s rate={rate_per_s}/s").format(**d)

def build_seeds(cfg: Config) -> Iterable[bytes]:
    normal = [bytes([c]) for c in range(0x20, 0x80)]
    if cfg.extensive:
        extra = [bytes([c]) for c in list(range(0x01, 0x20)) + list(range(0x80, 0x100))]
        return normal + extra
    return normal

def produce_jobs(cfg: Config, rng: random.Random) -> Iterator[Tuple[str, str, bytes]]:
    gen = PayloadGenerator(cfg, rng)
    if cfg.strategy in (Strategy.RANDOM, Strategy.CYCLIC,
                        Strategy.FORMAT, Strategy.TRAVERSAL):
        for cmd in cfg.commands:
            for label, payload in gen(b""):
                yield cmd, label, payload
        return
    for seed in build_seeds(cfg):
        for cmd in cfg.commands:
            for label, payload in gen(seed):
                yield cmd, label, payload

class EngineEvent(str, enum.Enum):
    STARTED     = "started"
    PROGRESS    = "progress"
    RESULT      = "result"
    HIT         = "hit"
    FINISHED    = "finished"
    ERROR       = "error"

@dataclasses.dataclass
class EngineMessage:
    kind: EngineEvent
    payload: dict = dataclasses.field(default_factory=dict)

class Engine:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.stop = threading.Event()
        self.pause = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.stats = Stats()
        self.corpus = Corpus(cfg.corpus)
        self.limiter = RateLimiter(cfg.rate)
        self.backoff = Backoff(cfg.backoff, cfg.backoff_max)
        self._seen: set = set()
        self._seen_lock = threading.Lock()
        self._queue: "queue.Queue[EngineMessage]" = queue.Queue(maxsize=50_000)
        self.total_jobs: int = 0
        self._done_jobs: int = 0
        self._done_lock = threading.Lock()

    def messages(self) -> "queue.Queue[EngineMessage]":
        return self._queue

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.is_running():
            return
        self.stop.clear()
        self.pause.clear()
        self._thread = threading.Thread(target=self._run, name="ftp-fuzz-engine",
                                        daemon=True)
        self._thread.start()

    def request_stop(self) -> None:
        self.stop.set()
        self.pause.clear()

    def toggle_pause(self) -> bool:
        if self.pause.is_set():
            self.pause.clear()
            return False
        else:
            self.pause.set()
            return True

    def _emit(self, kind: EngineEvent, **kw) -> None:
        try:
            self._queue.put_nowait(EngineMessage(kind, kw))
        except queue.Full:
            pass

    def _run(self) -> None:
        try:
            self._emit(EngineEvent.STARTED)
            log(LogLevel.INFO,
                f"target={self.cfg.target}:{self.cfg.port} "
                f"tls={self.cfg.tls} strategy={self.cfg.strategy.value} "
                f"max_len={self.cfg.max_len} step={self.cfg.step} "
                f"threads={self.cfg.threads} rate={self.cfg.rate or '∞'}")
            rng = random.Random(self.cfg.seed)
            jobs = produce_jobs(self.cfg, rng)
            self.total_jobs = 0
            self._done_jobs = 0
            worker = Worker(self.cfg, self.corpus, self.stats,
                            self.limiter, self.backoff, self.stop, self.pause,
                            self._seen, self._seen_lock,
                            progress_cb=self._on_job_done,
                            result_cb=self._on_result)
            with concurrent.futures.ThreadPoolExecutor(
                    max_workers=self.cfg.threads,
                    thread_name_prefix="fuzz") as pool:
                pending: set = set()
                for job in jobs:
                    if self.stop.is_set():
                        break
                    while self.pause.is_set() and not self.stop.is_set():
                        time.sleep(0.05)
                    self.total_jobs += 1
                    fut = pool.submit(worker.run_job, *job)
                    pending.add(fut)
                    if len(pending) >= self.cfg.threads * 4:
                        done, pending = concurrent.futures.wait(
                            pending,
                            return_when=concurrent.futures.FIRST_COMPLETED)
                        for f in done:
                            _swallow(f)
                for f in concurrent.futures.as_completed(pending):
                    _swallow(f)
            self._emit(EngineEvent.FINISHED, stats=self.stats.to_dict())
            log(LogLevel.INFO, f"SUMMARY: {self.stats.summary()}")
        except Exception as e:  # pragma: no cover
            log(LogLevel.ERROR, f"engine crashed: {e}")
            log(LogLevel.DEBUG, traceback.format_exc())
            self._emit(EngineEvent.ERROR, error=str(e))

    def _on_job_done(self) -> None:
        with self._done_lock:
            self._done_jobs += 1
            done = self._done_jobs
        self._emit(EngineEvent.PROGRESS, done=done, total=self.total_jobs,
                   stats=self.stats.to_dict())

    def _on_result(self, r: Result) -> None:
        self._emit(EngineEvent.RESULT,
                   command=r.command, label=r.label, verdict=r.verdict.value,
                   code=r.code, detail=r.detail, length=len(r.payload),
                   elapsed=r.elapsed,
                   preview=r.payload[:64].hex(),
                   ascii_preview=_safe_ascii(r.payload[:64]))
        if r.interesting:
            self._emit(EngineEvent.HIT,
                       command=r.command, label=r.label, verdict=r.verdict.value,
                       detail=r.detail, length=len(r.payload))

def _safe_ascii(b: bytes) -> str:
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b)

def _swallow(fut: concurrent.futures.Future) -> None:
    try:
        fut.result()
    except Exception:
        log(LogLevel.DEBUG, "worker exception:\n" + traceback.format_exc())

class Worker:
    def __init__(self, cfg: Config, corpus: Corpus, stats: Stats,
                 limiter: RateLimiter, backoff: Backoff,
                 stop_event: threading.Event, pause_event: threading.Event,
                 seen_payloads: set, seen_lock: threading.Lock,
                 progress_cb: Callable[[], None],
                 result_cb: Callable[[Result], None]) -> None:
        self.cfg = cfg
        self.corpus = corpus
        self.stats = stats
        self.limiter = limiter
        self.backoff = backoff
        self.stop = stop_event
        self.pause = pause_event
        self.seen_payloads = seen_payloads
        self.seen_lock = seen_lock
        self.progress_cb = progress_cb
        self.result_cb = result_cb

    def run_job(self, command: str, label: str, payload: bytes) -> None:
        try:
            if self.stop.is_set():
                return
            while self.pause.is_set() and not self.stop.is_set():
                time.sleep(0.05)
            if self.stop.is_set():
                return
            key = (command, hash(payload))
            with self.seen_lock:
                if key in self.seen_payloads:
                    self.stats.skip()
                    return
                self.seen_payloads.add(key)
            probe = Result(command=command, payload=payload, label=label,
                           verdict=Verdict.OK)
            if self.cfg.resume and self.corpus.already_done(probe):
                self.stats.skip()
                return
            if self.cfg.dry_run:
                self.stats.skip()
                return
            self.limiter.wait()
            result = self._execute(command, payload, label)
            self.stats.record(result)
            if result.interesting:
                log(LogLevel.HIT,
                    f"{result.verdict.value.upper()}  {command} {label} "
                    f"({len(payload)}B) {result.detail}")
                self.corpus.add(result)
            elif result.verdict is Verdict.ERROR:
                log(LogLevel.DEBUG,
                    f"{command} {label} -> {result.code} {result.detail[:60]}")
            self.result_cb(result)
        finally:
            self.progress_cb()

    def _execute(self, command: str, payload: bytes, label: str) -> Result:
        line = command.encode() + b" " + payload
        t0 = time.monotonic()
        try:
            with FTPClient(self.cfg) as client:
                try:
                    client.send_line(line)
                except FTPConnectionError as e:
                    return Result(command, payload, label, Verdict.SEND_FAIL,
                                  detail=str(e), elapsed=time.monotonic() - t0)
                try:
                    code, first = client.read_reply()
                except FTPConnectionError as e:
                    v = Verdict.TIMEOUT if "timeout" in str(e) else Verdict.RESET
                    self.backoff.on_fail()
                    return Result(command, payload, label, v,
                                  detail=str(e), elapsed=time.monotonic() - t0)
                self.backoff.on_success()
                verdict = Verdict.OK if 200 <= code < 400 else Verdict.ERROR
                return Result(command, payload, label, verdict, code=code,
                              detail=first.decode("latin-1", "replace"),
                              elapsed=time.monotonic() - t0)
        except FTPConnectionError as e:
            self.backoff.on_fail()
            return Result(command, payload, label, Verdict.CONN_FAIL,
                          detail=str(e), elapsed=time.monotonic() - t0)
        except Exception as e:  # pragma: no cover
            return Result(command, payload, label, Verdict.SEND_FAIL,
                          detail=f"{type(e).__name__}: {e}",
                          elapsed=time.monotonic() - t0)
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox, scrolledtext
    _TK_AVAILABLE = True
except Exception:  # pragma: no cover
    _TK_AVAILABLE = False

BG          = "#1e1f22"
BG_ALT      = "#2b2d31"
FG          = "#e6e6e6"
FG_DIM      = "#a0a0a0"
ACCENT      = "#4c9aff"
ACCENT_HI   = "#6fb1ff"
OK_COLOR    = "#4caf50"
WARN_COLOR  = "#ffb74d"
ERR_COLOR   = "#ef5350"
HIT_COLOR   = "#e040fb"

class FuzzerGUI:
    def __init__(self, root: "tk.Tk", cfg: Config, cli_mode: bool = False) -> None:
        self.root = root
        self.cfg = cfg
        self.engine: Optional[Engine] = None
        self.engine_log_queue: Optional[queue.Queue] = None
        self.log_queue: Optional[queue.Queue] = None
        self._running = False
        self._paused = False
        self._cli_mode = cli_mode
        self._start_ts: float = 0.0
        self._results_written = 0
        self._build_ui()
        self._poll_engine()
        self._poll_log()

    def _build_ui(self) -> None:
        self.root.title(f"{APP_NAME} {APP_VERSION}")
        self.root.geometry("1100x760")
        self.root.minsize(900, 620)
        self._apply_theme()
        self._build_menu()
        outer = ttk.Frame(self.root, padding=8)
        outer.pack(fill=tk.BOTH, expand=True)
        self.notebook = ttk.Notebook(outer)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        self._build_target_tab()
        self._build_payload_tab()
        self._build_options_tab()
        self._build_results_tab()
        self._build_log_tab()
        self._build_about_tab()
        bar = ttk.Frame(outer, padding=(0, 6, 0, 0))
        bar.pack(fill=tk.X)
        self.btn_start  = ttk.Button(bar, text="▶  Start", style="Accent.TButton",
                                     command=self._on_start)
        self.btn_pause  = ttk.Button(bar, text="⏸  Pause", command=self._on_pause,
                                     state="disabled")
        self.btn_stop   = ttk.Button(bar, text="■  Stop", command=self._on_stop,
                                     state="disabled")
        self.btn_export = ttk.Button(bar, text="⇩  Export results",
                                     command=self._on_export)
        self.btn_start.pack(side=tk.LEFT)
        self.btn_pause.pack(side=tk.LEFT, padx=(6, 0))
        self.btn_stop.pack(side=tk.LEFT, padx=(6, 0))
        self.btn_export.pack(side=tk.RIGHT)
        prog_frame = ttk.Frame(outer, padding=(0, 6, 0, 0))
        prog_frame.pack(fill=tk.X)
        self.progress = ttk.Progressbar(prog_frame, mode="determinate")
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.lbl_progress = ttk.Label(prog_frame, width=40, anchor="e",
                                      text="idle")
        self.lbl_progress.pack(side=tk.RIGHT, padx=(8, 0))
        status = ttk.Frame(outer, padding=(0, 4, 0, 0))
        status.pack(fill=tk.X)
        self.lbl_status = ttk.Label(status, text="Ready.", anchor="w")
        self.lbl_status.pack(side=tk.LEFT, fill=tk.X, expand=True)

    def _apply_theme(self) -> None:
        try:
            self.root.configure(bg=BG)
            style = ttk.Style(self.root)
            try:
                style.theme_use("clam")
            except tk.TclError:
                pass
            style.configure(".", background=BG, foreground=FG, fieldbackground=BG_ALT)
            style.configure("TFrame", background=BG)
            style.configure("TLabel", background=BG, foreground=FG)
            style.configure("TButton", background=BG_ALT, foreground=FG,
                            bordercolor=BG_ALT, focuscolor=BG_ALT)
            style.map("TButton",
                      background=[("active", "#3a3d43")])
            style.configure("Accent.TButton",
                            background=ACCENT, foreground="#ffffff")
            style.map("Accent.TButton",
                      background=[("active", ACCENT_HI)])
            style.configure("TNotebook", background=BG, borderwidth=0)
            style.configure("TNotebook.Tab", background=BG_ALT, foreground=FG,
                            padding=(14, 6))
            style.map("TNotebook.Tab",
                      background=[("selected", BG)],
                      foreground=[("selected", ACCENT_HI)])
            style.configure("Treeview",
                            background=BG_ALT, fieldbackground=BG_ALT,
                            foreground=FG, bordercolor=BG, rowheight=22)
            style.map("Treeview",
                      background=[("selected", ACCENT)],
                      foreground=[("selected", "#ffffff")])
            style.configure("Treeview.Heading",
                            background="#33363c", foreground=FG)
            style.configure("TEntry", fieldbackground=BG_ALT, foreground=FG,
                            insertcolor=FG)
            style.configure("TCheckbutton", background=BG, foreground=FG)
            style.configure("TCombobox", fieldbackground=BG_ALT, foreground=FG)
            style.configure("TProgressbar", troughcolor=BG_ALT,
                            background=ACCENT)
            style.configure("TLabelframe", background=BG, foreground=FG)
            style.configure("TLabelframe.Label", background=BG, foreground=ACCENT_HI)
        except Exception:
            pass

    def _build_menu(self) -> None:
        m = tk.Menu(self.root)
        file_m = tk.Menu(m, tearoff=0)
        file_m.add_command(label="Load config…", command=self._menu_load_cfg)
        file_m.add_command(label="Save config…", command=self._menu_save_cfg)
        file_m.add_separator()
        file_m.add_command(label="Export results…", command=self._on_export)
        file_m.add_separator()
        file_m.add_command(label="Quit", command=self._on_close)
        m.add_cascade(label="File", menu=file_m)
        run_m = tk.Menu(m, tearoff=0)
        run_m.add_command(label="Start", command=self._on_start)
        run_m.add_command(label="Pause / Resume", command=self._on_pause)
        run_m.add_command(label="Stop", command=self._on_stop)
        m.add_cascade(label="Run", menu=run_m)
        view_m = tk.Menu(m, tearoff=0)
        view_m.add_command(label="Clear results",
                           command=lambda: self._clear_tree(self.tree_results))
        view_m.add_command(label="Clear log",
                           command=lambda: self.txt_log.delete("1.0", tk.END))
        m.add_cascade(label="View", menu=view_m)
        help_m = tk.Menu(m, tearoff=0)
        help_m.add_command(label="About", command=lambda:
                           self.notebook.select(self.tab_about))
        m.add_cascade(label="Help", menu=help_m)
        self.root.config(menu=m)

    def _build_target_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=14)
        self.notebook.add(tab, text="Target")
        row = 0
        ttk.Label(tab, text="Host / IP:").grid(row=row, column=0, sticky="w", pady=4)
        self.var_target = tk.StringVar(value=self.cfg.target)
        ttk.Entry(tab, textvariable=self.var_target, width=40)\
            .grid(row=row, column=1, sticky="ew", pady=4, padx=(8, 8))
        ttk.Label(tab, text="Port:").grid(row=row, column=2, sticky="w", pady=4)
        self.var_port = tk.StringVar(value=str(self.cfg.port))
        ttk.Entry(tab, textvariable=self.var_port, width=8)\
            .grid(row=row, column=3, sticky="w", pady=4, padx=(8, 0))
        row += 1
        ttk.Label(tab, text="Username:").grid(row=row, column=0, sticky="w", pady=4)
        self.var_user = tk.StringVar(value=self.cfg.username or "")
        ttk.Entry(tab, textvariable=self.var_user, width=40)\
            .grid(row=row, column=1, sticky="ew", pady=4, padx=(8, 8))
        row += 1
        ttk.Label(tab, text="Password:").grid(row=row, column=0, sticky="w", pady=4)
        self.var_pass = tk.StringVar(value=self.cfg.password or "")
        ttk.Entry(tab, textvariable=self.var_pass, width=40, show="•")\
            .grid(row=row, column=1, sticky="ew", pady=4, padx=(8, 8))
        row += 1
        self.var_tls = tk.BooleanVar(value=self.cfg.tls)
        ttk.Checkbutton(tab, text="Use TLS (FTPS)",
                        variable=self.var_tls).grid(row=row, column=1, sticky="w",
                                                    pady=(10, 0))
        row += 1
        self.var_tls_verify = tk.BooleanVar(value=self.cfg.tls_verify)
        ttk.Checkbutton(tab, text="Verify TLS certificate",
                        variable=self.var_tls_verify)\
            .grid(row=row, column=1, sticky="w", pady=(2, 8))
        row += 1
        ttk.Button(tab, text="Test connection", command=self._on_test_conn)\
            .grid(row=row, column=1, sticky="w", pady=(12, 0))
        tab.columnconfigure(1, weight=1)

    def _build_payload_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=14)
        self.notebook.add(tab, text="Payload")
        row = 0
        ttk.Label(tab, text="Strategy:").grid(row=row, column=0, sticky="w", pady=4)
        self.var_strategy = tk.StringVar(value=self.cfg.strategy.value)
        cb = ttk.Combobox(tab, textvariable=self.var_strategy, state="readonly",
                          values=[s.value for s in Strategy], width=14)
        cb.grid(row=row, column=1, sticky="w", pady=4, padx=(8, 0))
        cb.bind("<<ComboboxSelected>>", lambda *_: self._update_strategy_hint())
        self.lbl_strat_hint = ttk.Label(tab, text="", foreground=FG_DIM)
        self.lbl_strat_hint.grid(row=row, column=2, columnspan=3,
                                 sticky="w", padx=(12, 0))
        row += 1
        ttk.Label(tab, text="Max payload length:").grid(row=row, column=0,
                                                        sticky="w", pady=4)
        self.var_maxlen = tk.StringVar(value=str(self.cfg.max_len))
        ttk.Entry(tab, textvariable=self.var_maxlen, width=10)\
            .grid(row=row, column=1, sticky="w", pady=4, padx=(8, 0))
        ttk.Label(tab, text="bytes").grid(row=row, column=2, sticky="w")
        row += 1
        ttk.Label(tab, text="Step:").grid(row=row, column=0, sticky="w", pady=4)
        self.var_step = tk.StringVar(value=str(self.cfg.step))
        ttk.Entry(tab, textvariable=self.var_step, width=10)\
            .grid(row=row, column=1, sticky="w", pady=4, padx=(8, 0))
        ttk.Label(tab, text="bytes").grid(row=row, column=2, sticky="w")
        row += 1
        self.var_extensive = tk.BooleanVar(value=self.cfg.extensive)
        ttk.Checkbutton(tab, text="Extensive fuzzing (add control + high-bit bytes)",
                        variable=self.var_extensive)\
            .grid(row=row, column=0, columnspan=4, sticky="w", pady=(8, 4))
        row += 1
        self.var_no_no_arg = tk.BooleanVar(value=not self.cfg.include_no_arg)
        ttk.Checkbutton(tab, text="Skip commands that take no argument (bare probes)",
                        variable=self.var_no_no_arg)\
            .grid(row=row, column=0, columnspan=4, sticky="w", pady=(0, 8))
        row += 1
        lf = ttk.Labelframe(tab, text="FTP commands to fuzz", padding=8)
        lf.grid(row=row, column=0, columnspan=5, sticky="nsew", pady=(8, 0))
        tab.rowconfigure(row, weight=1)
        tab.columnconfigure(4, weight=1)
        self.txt_cmds = scrolledtext.ScrolledText(
            lf, height=12, bg=BG_ALT, fg=FG, insertbackground=FG,
            relief=tk.FLAT, font=("Consolas", 10))
        self.txt_cmds.pack(fill=tk.BOTH, expand=True)
        self.txt_cmds.insert("1.0", " ".join(self.cfg.commands))
        btns = ttk.Frame(lf)
        btns.pack(fill=tk.X, pady=(6, 0))
        ttk.Button(btns, text="Select all",
                   command=lambda: self.txt_cmds.tag_add("sel", "1.0", tk.END))\
            .pack(side=tk.LEFT)
        ttk.Button(btns, text="Reset to default",
                   command=self._reset_commands)\
            .pack(side=tk.LEFT, padx=(6, 0))
        ttk.Button(btns, text="Sort",
                   command=self._sort_commands)\
            .pack(side=tk.LEFT, padx=(6, 0))
        self._update_strategy_hint()

    def _update_strategy_hint(self) -> None:
        hints = {
            Strategy.FIXED.value:     "Repeat each seed char to lengths step…max.",
            Strategy.INCREMENT.value: "Grow payload one byte at a time.",
            Strategy.RANDOM.value:    "Random bytes of growing length.",
            Strategy.CYCLIC.value:    "De Bruijn pattern — great for offset discovery.",
            Strategy.FORMAT.value:    "Format-string specifiers like %n, %s, %p.",
            Strategy.TRAVERSAL.value: "Directory traversal patterns.",
        }
        self.lbl_strat_hint.configure(text=hints.get(self.var_strategy.get(), ""))

    def _reset_commands(self) -> None:
        self.txt_cmds.delete("1.0", tk.END)
        self.txt_cmds.insert("1.0", " ".join(FTP_COMMANDS))

    def _sort_commands(self) -> None:
        items = self._read_commands()
        self.txt_cmds.delete("1.0", tk.END)
        self.txt_cmds.insert("1.0", " ".join(sorted(set(items))))

    def _build_options_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=14)
        self.notebook.add(tab, text="Options")
        row = 0
        ttk.Label(tab, text="Threads:").grid(row=row, column=0, sticky="w", pady=4)
        self.var_threads = tk.StringVar(value=str(self.cfg.threads))
        ttk.Entry(tab, textvariable=self.var_threads, width=10)\
            .grid(row=row, column=1, sticky="w", pady=4, padx=(8, 0))
        row += 1
        ttk.Label(tab, text="Timeout (s):").grid(row=row, column=0, sticky="w", pady=4)
        self.var_timeout = tk.StringVar(value=str(self.cfg.timeout))
        ttk.Entry(tab, textvariable=self.var_timeout, width=10)\
            .grid(row=row, column=1, sticky="w", pady=4, padx=(8, 0))
        row += 1
        ttk.Label(tab, text="Rate (payloads/s, 0 = ∞):")\
            .grid(row=row, column=0, sticky="w", pady=4)
        self.var_rate = tk.StringVar(value=str(self.cfg.rate))
        ttk.Entry(tab, textvariable=self.var_rate, width=10)\
            .grid(row=row, column=1, sticky="w", pady=4, padx=(8, 0))
        row += 1
        ttk.Label(tab, text="Random seed:").grid(row=row, column=0, sticky="w", pady=4)
        self.var_seed = tk.StringVar(value="" if self.cfg.seed is None else str(self.cfg.seed))
        ttk.Entry(tab, textvariable=self.var_seed, width=10)\
            .grid(row=row, column=1, sticky="w", pady=4, padx=(8, 0))
        row += 1
        self.var_resume = tk.BooleanVar(value=self.cfg.resume)
        ttk.Checkbutton(tab, text="Resume (skip payloads already in corpus)",
                        variable=self.var_resume)\
            .grid(row=row, column=0, columnspan=3, sticky="w", pady=(10, 2))
        row += 1
        self.var_dry = tk.BooleanVar(value=self.cfg.dry_run)
        ttk.Checkbutton(tab, text="Dry run (enumerate payloads without sending)",
                        variable=self.var_dry)\
            .grid(row=row, column=0, columnspan=3, sticky="w", pady=(2, 2))
        row += 1
        lf = ttk.Labelframe(tab, text="Files", padding=10)
        lf.grid(row=row, column=0, columnspan=3, sticky="ew", pady=(14, 0))
        tab.columnconfigure(0, weight=1)
        ttk.Label(lf, text="Corpus (JSONL):").grid(row=0, column=0, sticky="w", pady=4)
        self.var_corpus = tk.StringVar(value=self.cfg.corpus)
        ttk.Entry(lf, textvariable=self.var_corpus, width=50)\
            .grid(row=0, column=1, sticky="ew", pady=4, padx=(8, 8))
        ttk.Button(lf, text="…", width=3,
                   command=lambda: self._browse_save(self.var_corpus))\
            .grid(row=0, column=2)
        ttk.Label(lf, text="Report (JSON):").grid(row=1, column=0, sticky="w", pady=4)
        self.var_report = tk.StringVar(value=self.cfg.report)
        ttk.Entry(lf, textvariable=self.var_report, width=50)\
            .grid(row=1, column=1, sticky="ew", pady=4, padx=(8, 8))
        ttk.Button(lf, text="…", width=3,
                   command=lambda: self._browse_save(self.var_report))\
            .grid(row=1, column=2)
        lf.columnconfigure(1, weight=1)

    def _build_results_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=6)
        self.notebook.add(tab, text="Results")
        cols = ("time", "command", "label", "verdict", "code", "length", "detail")
        self.tree_results = ttk.Treeview(tab, columns=cols, show="headings",
                                         selectmode="browse")
        widths = {"time": 80, "command": 80, "label": 140, "verdict": 80,
                  "code": 60, "length": 70, "detail": 500}
        for c in cols:
            self.tree_results.heading(c, text=c.title(),
                                      command=lambda cc=c: self._sort_tree(cc))
            self.tree_results.column(c, width=widths[c], anchor="w", stretch=(c == "detail"))
        self.tree_results.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)
        vsb = ttk.Scrollbar(tab, orient="vertical", command=self.tree_results.yview)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree_results.configure(yscrollcommand=vsb.set)
        self.tree_results.tag_configure("hit", background="#3a003a", foreground=HIT_COLOR)
        self.tree_results.tag_configure("err", foreground=ERR_COLOR)
        self.tree_results.tag_configure("ok",  foreground=FG)
        self.tree_results.bind("<Double-1>", self._on_tree_double)
        self.tree_results.bind("<Button-3>", self._on_tree_right_click)
        self._sort_state: dict = {}
        self._results_count = 0

    def _build_log_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=6)
        self.notebook.add(tab, text="Log")
        self.txt_log = scrolledtext.ScrolledText(
            tab, bg=BG_ALT, fg=FG, insertbackground=FG,
            relief=tk.FLAT, font=("Consolas", 9))
        self.txt_log.pack(fill=tk.BOTH, expand=True)
        self.txt_log.tag_configure("DEBUG", foreground=FG_DIM)
        self.txt_log.tag_configure("INFO",  foreground=FG)
        self.txt_log.tag_configure("OK",    foreground=OK_COLOR)
        self.txt_log.tag_configure("WARN",  foreground=WARN_COLOR)
        self.txt_log.tag_configure("ERROR", foreground=ERR_COLOR)
        self.txt_log.tag_configure("HIT",   foreground=HIT_COLOR)
        bar = ttk.Frame(tab)
        bar.pack(fill=tk.X, pady=(6, 0))
        self.var_autoscroll = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="Autoscroll",
                        variable=self.var_autoscroll).pack(side=tk.LEFT)
        ttk.Button(bar, text="Copy all",
                   command=self._copy_log).pack(side=tk.RIGHT)
        ttk.Button(bar, text="Clear",
                   command=lambda: self.txt_log.delete("1.0", tk.END))\
            .pack(side=tk.RIGHT, padx=(0, 6))

    def _build_about_tab(self) -> None:
        self.tab_about = ttk.Frame(self.notebook, padding=20)
        self.notebook.add(self.tab_about, text="About")
        txt = (
            f"{APP_NAME} {APP_VERSION}\n\n"
            "FTP fuzzer with GUI.\n\n"
            "Features:\n"
            "  • Robust FTP client (multi-line replies, TLS, login state machine)\n"
            "  • Strategies: fixed, increment, random, cyclic (De Bruijn),\n"
            "    format-string, directory traversal\n"
            "  • Multi-threaded worker pool with rate limiting and backoff\n"
            "  • Corpus + resume, structured JSON report at the end\n"
            "  • Live progress, counters, ETA and anomaly highlighting\n\n"
            "⚠  Only use against systems you own or are explicitly authorized\n"
            "   to test. Unauthorized use may be illegal.\n\n"
        )
        lbl = ttk.Label(self.tab_about, text=txt, justify=tk.LEFT)
        lbl.pack(anchor="nw")

    def _read_commands(self) -> List[str]:
        raw = self.txt_cmds.get("1.0", tk.END)
        toks = [t.strip().upper() for t in raw.replace(",", " ").split()]
        return [t for t in toks if t]

    def _browse_save(self, var: tk.StringVar) -> None:
        path = filedialog.asksaveasfilename(defaultextension="",
                                            initialfile=os.path.basename(var.get()))
        if path:
            var.set(path)

    def _clear_tree(self, tree: ttk.Treeview) -> None:
        for i in tree.get_children():
            tree.delete(i)

    def _sort_tree(self, col: str) -> None:
        reverse = self._sort_state.get(col, False)
        self._sort_state[col] = not reverse
        items = [(self.tree_results.set(k, col), k)
                 for k in self.tree_results.get_children("")]
        def key(t):
            v = t[0]
            try:
                return (0, float(v))
            except ValueError:
                return (1, v)
        items.sort(key=key, reverse=reverse)
        for idx, (_, k) in enumerate(items):
            self.tree_results.move(k, "", idx)

    def _on_tree_double(self, event) -> None:
        sel = self.tree_results.selection()
        if not sel:
            return
        vals = self.tree_results.item(sel[0], "values")
        if not vals:
            return
        command, label = vals[1], vals[2]
        msg = (f"Command: {command}\nLabel: {label}\n"
               f"Verdict: {vals[3]}   Code: {vals[4]}   Length: {vals[5]}\n\n"
               f"Detail:\n{vals[6]}")
        messagebox.showinfo("Result detail", msg, parent=self.root)

    def _on_tree_right_click(self, event) -> None:
        sel = self.tree_results.selection()
        if not sel:
            return
        menu = tk.Menu(self.root, tearoff=0)
        menu.add_command(label="Copy row",
                         command=lambda: self._copy_tree_row(sel[0]))
        menu.add_command(label="Copy payload preview",
                         command=lambda: self._copy_preview(sel[0]))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _copy_tree_row(self, iid: str) -> None:
        vals = self.tree_results.item(iid, "values")
        self.root.clipboard_clear()
        self.root.clipboard_append("\t".join(str(v) for v in vals))

    def _copy_preview(self, iid: str) -> None:
        vals = self.tree_results.item(iid, "values")
        self.root.clipboard_clear()
        self.root.clipboard_append(str(vals[6])[:500])

    def _copy_log(self) -> None:
        text = self.txt_log.get("1.0", tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def _menu_save_cfg(self) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                            filetypes=[("JSON", "*.json")])
        if not path:
            return
        try:
            cfg = self._collect_cfg()
            with open(path, "w", encoding="utf-8") as f:
                json.dump(dataclasses.asdict(cfg), f, indent=2, default=str)
            self._set_status(f"Config saved to {path}")
        except Exception as e:
            messagebox.showerror("Save config", str(e), parent=self.root)

    def _menu_load_cfg(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            cfg = Config(**{**dataclasses.asdict(self.cfg), **data})
            if isinstance(cfg.strategy, str):
                cfg.strategy = Strategy(cfg.strategy)
            self._apply_cfg_to_ui(cfg)
            self._set_status(f"Config loaded from {path}")
        except Exception as e:
            messagebox.showerror("Load config", str(e), parent=self.root)

    def _apply_cfg_to_ui(self, cfg: Config) -> None:
        self.var_target.set(cfg.target)
        self.var_port.set(str(cfg.port))
        self.var_user.set(cfg.username or "")
        self.var_pass.set(cfg.password or "")
        self.var_tls.set(cfg.tls)
        self.var_tls_verify.set(cfg.tls_verify)
        self.var_strategy.set(cfg.strategy.value)
        self.var_maxlen.set(str(cfg.max_len))
        self.var_step.set(str(cfg.step))
        self.var_extensive.set(cfg.extensive)
        self.var_no_no_arg.set(not cfg.include_no_arg)
        self.var_threads.set(str(cfg.threads))
        self.var_timeout.set(str(cfg.timeout))
        self.var_rate.set(str(cfg.rate))
        self.var_seed.set("" if cfg.seed is None else str(cfg.seed))
        self.var_resume.set(cfg.resume)
        self.var_dry.set(cfg.dry_run)
        self.var_corpus.set(cfg.corpus)
        self.var_report.set(cfg.report)
        self.txt_cmds.delete("1.0", tk.END)
        self.txt_cmds.insert("1.0", " ".join(cfg.commands))
        self._update_strategy_hint()

    def _collect_cfg(self) -> Config:
        cfg = Config()
        cfg.target   = self.var_target.get().strip()
        cfg.port     = int(self.var_port.get() or DEFAULT_PORT)
        cfg.username = self.var_user.get().strip() or None
        cfg.password = self.var_pass.get() or None
        cfg.tls      = bool(self.var_tls.get())
        cfg.tls_verify = bool(self.var_tls_verify.get())
        cfg.strategy = Strategy(self.var_strategy.get())
        cfg.max_len  = int(self.var_maxlen.get() or DEFAULT_MAX_LEN)
        cfg.step     = int(self.var_step.get() or DEFAULT_STEP)
        cfg.extensive = bool(self.var_extensive.get())
        cfg.include_no_arg = not bool(self.var_no_no_arg.get())
        cfg.threads  = int(self.var_threads.get() or DEFAULT_THREADS)
        cfg.timeout  = float(self.var_timeout.get() or DEFAULT_TIMEOUT)
        cfg.rate     = float(self.var_rate.get() or 0.0)
        seed_s = self.var_seed.get().strip()
        cfg.seed     = int(seed_s) if seed_s else None
        cfg.resume   = bool(self.var_resume.get())
        cfg.dry_run  = bool(self.var_dry.get())
        cfg.corpus   = self.var_corpus.get() or CORPUS_FILE_DEFAULT
        cfg.report   = self.var_report.get() or REPORT_FILE_DEFAULT
        cfg.commands = self._read_commands() or list(FTP_COMMANDS)
        if not cfg.include_no_arg:
            cfg.commands = [c for c in cfg.commands if c not in NO_ARG_COMMANDS]
        return cfg

    def _on_test_conn(self) -> None:
        try:
            cfg = self._collect_cfg()
        except Exception as e:
            messagebox.showerror("Config error", str(e), parent=self.root)
            return
        self._set_status("Testing connection…")
        def worker():
            try:
                with FTPClient(cfg) as c:
                    log(LogLevel.OK,
                        f"Connected to {cfg.target}:{cfg.port}"
                        + (" (TLS)" if cfg.tls else ""))
                    self._set_status("Connection OK.")
            except FTPConnectionError as e:
                log(LogLevel.ERROR, f"Connect failed: {e}")
                self._set_status("Connection failed.")
            except Exception as e:
                log(LogLevel.ERROR, f"Unexpected error: {e}")
        threading.Thread(target=worker, daemon=True).start()

    def _on_start(self) -> None:
        if self._running:
            return
        try:
            cfg = self._collect_cfg()
            if not cfg.target:
                raise ValueError("Target host is required.")
            if cfg.username and not cfg.password:
                raise ValueError("Password required when username is set.")
        except Exception as e:
            messagebox.showerror("Config error", str(e), parent=self.root)
            return

        self._clear_tree(self.tree_results)
        self._results_count = 0
        self._start_ts = time.time()
        self.engine = Engine(cfg)
        self.engine.start()
        self._running = True
        self._paused = False
        self.btn_start.configure(state="disabled")
        self.btn_pause.configure(state="normal", text="⏸  Pause")
        self.btn_stop.configure(state="normal")
        self.progress.configure(value=0, maximum=1)
        self._set_status("Running…")

    def _on_pause(self) -> None:
        if not self.engine or not self._running:
            return
        self._paused = self.engine.toggle_pause()
        self.btn_pause.configure(text="▶  Resume" if self._paused else "⏸  Pause")
        self._set_status("Paused." if self._paused else "Running…")

    def _on_stop(self) -> None:
        if self.engine:
            self.engine.request_stop()
            self._set_status("Stopping…")

    def _on_export(self) -> None:
        path = filedialog.asksaveasfilename(
            defaultextension=".jsonl",
            filetypes=[("JSONL", "*.jsonl"), ("CSV", "*.csv"), ("JSON", "*.json")],
            initialfile="fuzz_results.jsonl")
        if not path:
            return
        rows = []
        for iid in self.tree_results.get_children(""):
            rows.append(self.tree_results.item(iid, "values"))
        try:
            if path.endswith(".csv"):
                import csv
                with open(path, "w", newline="", encoding="utf-8") as f:
                    w = csv.writer(f)
                    w.writerow(["time", "command", "label", "verdict",
                                "code", "length", "detail"])
                    w.writerows(rows)
            else:
                with open(path, "w", encoding="utf-8") as f:
                    for r in rows:
                        f.write(json.dumps({
                            "time": r[0], "command": r[1], "label": r[2],
                            "verdict": r[3], "code": r[4], "length": r[5],
                            "detail": r[6],
                        }) + "\n")
            self._set_status(f"Exported {len(rows)} row(s) to {path}")
        except Exception as e:
            messagebox.showerror("Export", str(e), parent=self.root)

    def _on_close(self) -> None:
        if self._running:
            if not messagebox.askyesno("Quit",
                                       "A fuzz run is active. Stop and quit?",
                                       parent=self.root):
                return
            if self.engine:
                self.engine.request_stop()
        self.root.destroy()

    def _poll_log(self) -> None:
        if self.log_queue is None:
            self.log_queue = LOG_BUS.subscribe()
        try:
            while True:
                rec: LogRecord = self.log_queue.get_nowait()
                self._append_log(rec)
        except queue.Empty:
            pass
        self.root.after(80, self._poll_log)

    def _append_log(self, rec: LogRecord) -> None:
        line = f"{time.strftime('%H:%M:%S', time.localtime(rec.ts))} " \
               f"[{rec.level.value:5}] {rec.message}\n"
        self.txt_log.insert(tk.END, line, rec.level.value)
        if self.var_autoscroll.get():
            self.txt_log.see(tk.END)

    def _poll_engine(self) -> None:
        if self.engine is not None:
            q = self.engine.messages()
            try:
                while True:
                    msg = q.get_nowait()
                    self._handle_engine_msg(msg)
            except queue.Empty:
                pass
        self.root.after(80, self._poll_engine)

    def _handle_engine_msg(self, msg: EngineMessage) -> None:
        if msg.kind is EngineEvent.PROGRESS:
            done = msg.payload.get("done", 0)
            total = msg.payload.get("total", 1) or 1
            stats = msg.payload.get("stats", {})
            self.progress.configure(maximum=total, value=done)
            rate = stats.get("rate_per_s", 0)
            eta = ""
            if rate and total and done:
                remain = max(0, (total - done) / max(rate, 0.01))
                eta = f"  ETA {int(remain)}s"
            self.lbl_progress.configure(
                text=f"{done}/{total}  {rate}/s{eta}")
        elif msg.kind is EngineEvent.RESULT:
            self._add_result_row(msg.payload)
        elif msg.kind is EngineEvent.HIT:
            p = msg.payload
            self._set_status(f"HIT: {p['command']} {p['label']} "
                             f"({p['verdict']}) — {p['detail'][:80]}")
        elif msg.kind is EngineEvent.FINISHED:
            self._running = False
            self.btn_start.configure(state="normal")
            self.btn_pause.configure(state="disabled", text="⏸  Pause")
            self.btn_stop.configure(state="disabled")
            self._set_status("Finished.")
        elif msg.kind is EngineEvent.ERROR:
            self._running = False
            self.btn_start.configure(state="normal")
            self.btn_pause.configure(state="disabled", text="⏸  Pause")
            self.btn_stop.configure(state="disabled")
            self._set_status(f"Error: {msg.payload.get('error')}")
        elif msg.kind is EngineEvent.STARTED:
            self._set_status("Started.")

    def _add_result_row(self, p: dict) -> None:
        tag = "ok"
        verdict = p["verdict"]
        if verdict in ("timeout", "reset", "send_fail"):
            tag = "hit"
        elif verdict in ("error", "conn_fail"):
            tag = "err"
        self.tree_results.insert(
            "", tk.END,
            values=(time.strftime("%H:%M:%S"), p["command"], p["label"],
                    verdict, p.get("code") or "", p.get("length"),
                    p.get("detail", "")[:400]),
            tags=(tag,))
        self._results_count += 1

    def _set_status(self, text: str) -> None:
        self.lbl_status.configure(text=text)

def _build_cli_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ftp_fuzzer",
        description="Modern FTP fuzzer (CLI mode).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s --cli -t 192.168.0.10 -p 21 -U user -P pass -e\n"
            "  %(prog)s --cli -t 10.0.0.5 --strategy cyclic --max-len 5000 --threads 8\n"
            "\n"
            "Run without --cli to launch the Tkinter GUI.\n"
            "Only use against systems you own or are explicitly authorized to test.\n"
        ),
    )
    p.add_argument("--cli", action="store_true", help="Run in headless CLI mode.")
    p.add_argument("-t", "--target", help="Target host or IP.")
    p.add_argument("-p", "--port", type=int, default=DEFAULT_PORT)
    p.add_argument("-U", "--username")
    p.add_argument("-P", "--password")
    p.add_argument("-m", "--max-len", type=int, default=DEFAULT_MAX_LEN, dest="max_len")
    p.add_argument("-s", "--step", type=int, default=DEFAULT_STEP)
    p.add_argument("-e", "--extensive", action="store_true")
    p.add_argument("--strategy", choices=[s.value for s in Strategy],
                   default=Strategy.FIXED.value)
    p.add_argument("--commands", nargs="+", metavar="CMD")
    p.add_argument("--no-no-arg", action="store_true")
    p.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    p.add_argument("--rate", type=float, default=DEFAULT_RATE)
    p.add_argument("--tls", action="store_true")
    p.add_argument("--tls-verify", action="store_true")
    p.add_argument("--corpus", default=CORPUS_FILE_DEFAULT)
    p.add_argument("--report", default=REPORT_FILE_DEFAULT)
    p.add_argument("--no-resume", action="store_true")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--seed", type=int, default=None)
    p.add_argument("--config", help="JSON config file (GUI or CLI fields).")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    return p

def _cfg_from_cli_args(args: argparse.Namespace) -> Config:
    cfg = Config()
    cfg.target   = args.target or ""
    cfg.port     = args.port
    cfg.username = args.username
    cfg.password = args.password
    cfg.max_len  = args.max_len
    cfg.step     = args.step
    cfg.threads  = args.threads
    cfg.timeout  = args.timeout
    cfg.rate     = args.rate
    cfg.extensive = args.extensive
    cfg.strategy = Strategy(args.strategy)
    if args.commands:
        cfg.commands = [c.upper() for c in args.commands]
    cfg.include_no_arg = not args.no_no_arg
    cfg.tls = args.tls
    cfg.tls_verify = args.tls_verify
    cfg.corpus = args.corpus
    cfg.report = args.report
    cfg.resume = not args.no_resume
    cfg.dry_run = args.dry_run
    cfg.seed = args.seed
    if not cfg.include_no_arg:
        cfg.commands = [c for c in cfg.commands if c not in NO_ARG_COMMANDS]
    return cfg

def _merge_cli_config_file(args: argparse.Namespace) -> argparse.Namespace:
    if not args.config:
        return args
    try:
        with open(args.config, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise SystemExit(f"could not load config file: {e}")
    for key, val in data.items():
        attr = key.replace("-", "_")
        if hasattr(args, attr) and getattr(args, attr) in (None, False, []):
            setattr(args, attr, val)
    return args

def run_cli(argv: Sequence[str]) -> int:
    parser = _build_cli_parser()
    args = parser.parse_args(argv)
    args = _merge_cli_config_file(args)
    if not args.target:
        parser.error("--target is required in CLI mode")
    if args.username and not args.password:
        parser.error("--username requires --password")
    if args.password and not args.username:
        parser.error("--password requires --username")
    if args.max_len <= 0 or args.step <= 0 or args.threads <= 0:
        parser.error("max-len, step, threads must be > 0")
    cfg = _cfg_from_cli_args(args)

    def print_log(rec: LogRecord) -> None:
        if rec.level is LogLevel.DEBUG and not args.verbose:
            return
        if args.quiet and rec.level in (LogLevel.INFO, LogLevel.DEBUG, LogLevel.OK):
            return
        ts = time.strftime("%H:%M:%S", time.localtime(rec.ts))
        print(f"{ts} [{rec.level.value:5}] {rec.message}", file=sys.stderr)
    q = LOG_BUS.subscribe()
    stop_flag = threading.Event()

    def on_sig(signum, frame):
        log(LogLevel.WARN, f"signal {signum} — stopping…")
        stop_flag.set()
        if engine_ref[0]:
            engine_ref[0].request_stop()
    engine_ref: List[Optional[Engine]] = [None]
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, on_sig)
        except (ValueError, OSError):
            pass
    engine = Engine(cfg)
    engine_ref[0] = engine
    engine.start()
    while True:
        try:
            rec = q.get(timeout=0.2)
            print_log(rec)
        except queue.Empty:
            pass
        try:
            while True:
                engine.messages().get_nowait()
        except queue.Empty:
            pass
        if not engine.is_running() and q.empty() and engine.messages().empty():
            break
    LOG_BUS.unsubscribe(q)
    try:
        report = {
            "config": {
                "target": cfg.target, "port": cfg.port, "tls": cfg.tls,
                "strategy": cfg.strategy.value, "max_len": cfg.max_len,
                "step": cfg.step, "threads": cfg.threads,
                "extensive": cfg.extensive, "commands": cfg.commands,
                "finished": time.strftime("%Y-%m-%dT%H:%M:%S"),
            },
            "stats": engine.stats.to_dict(),
            "corpus": cfg.corpus,
        }
        with open(cfg.report, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        log(LogLevel.OK, f"report written: {cfg.report}")
    except OSError as e:
        log(LogLevel.WARN, f"could not write report: {e}")
    try:
        while True:
            print_log(q.get_nowait())
    except queue.Empty:
        pass
    log(LogLevel.INFO, f"SUMMARY: {engine.stats.summary()}")
    return 0

def _run_gui(cfg: Config) -> int:
    if not _TK_AVAILABLE:
        print("Tkinter is not available on this Python installation.",
              file=sys.stderr)
        print("Install python3-tk (Linux) or use --cli mode.", file=sys.stderr)
        return 2
    root = tk.Tk()
    try:
        root.tk.call("tk", "scaling", 1.15)
    except Exception:
        pass
    app = FuzzerGUI(root, cfg)
    root.protocol("WM_DELETE_WINDOW", app._on_close)
    root.mainloop()
    return 0

def main(argv: Optional[Sequence[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--cli" in argv:
        return run_cli(argv)
    parser = _build_cli_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        return int(e.code or 0)
    if args.target or args.config:
        cfg = _cfg_from_cli_args(args)
    else:
        cfg = Config()
    return _run_gui(cfg)

if __name__ == "__main__":
    sys.exit(main())
