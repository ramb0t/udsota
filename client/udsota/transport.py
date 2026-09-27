"""The bus side: the TX guard (only the profile's request ID, never a deny_tx ID), pre-flight listening with
the optional busy detector and pre-roll, the second-tester monitor and the kernel ISO-TP binding."""
import selectors
import threading
import time

import can
import udsoncan.configs
from udsoncan.client import Client
from udsoncan.connections import BaseConnection, IsoTPSocketConnection

from .errors import Busy, Refused, SecondTester
from .uds import Uds

PAD = 0xAA               # ISO-TP padding byte; every frame goes out at DLC 8, which some servers require
LISTEN_S = 2.0
PREROLL_DATA = bytes([0x02, 0x3E, 0x80]) + bytes([PAD] * 5)   # TesterPresent, positive response suppressed
PREROLL_GAP_S = 0.01
P2_S = 0.15              # client P2
P2_STAR_S = 5.5          # client P2*; the server repeats 0x78 every 1.5 s
REQUEST_TIMEOUT_S = 100.0   # overall per request: above the server's 90 s flash-job cap
GRACE_S = 0.25           # a response frame this soon after our last response is its tail, not a second tester
RX_ERROR_PAUSE_S = 0.02  # the receive thread's pause after a socket error, before it listens again


# Raise Refused unless can_id is the profile's request ID as a standard frame; deny_tx IDs are a hard limit.
def check_tx_id(profile, can_id, extended=False):
    if not extended and can_id in profile.deny_tx:
        raise Refused("hard limit: never transmit on 0x%03X (profile %s deny_tx)" % (can_id, profile.name))
    if extended or can_id != profile.req_id:
        raise Refused("refusing to transmit on 0x%X: this tool sends only on 0x%03X" % (can_id, profile.req_id))


# A python-can bus whose send() passes check_tx_id() first; nothing else can reach the wire.
class GuardedBus:
    # Wrap an open python-can bus for profile.
    def __init__(self, bus, profile):
        self.bus, self.profile = bus, profile

    # Send msg only if its ID passes check_tx_id(); raises Refused otherwise.
    def send(self, msg, timeout=None):
        check_tx_id(self.profile, msg.arbitration_id, msg.is_extended_id)
        self.bus.send(msg, timeout)

    # Receive one frame or None after timeout seconds.
    def recv(self, timeout=None):
        return self.bus.recv(timeout)

    # Close the underlying bus.
    def shutdown(self):
        self.bus.shutdown()


# The busy detector's byte from msg, or None when msg is not the profile's busy frame (or there is no detector).
def busy_value(profile, msg):
    b = profile.busy
    if b is None or msg.is_extended_id or msg.arbitration_id != b.id or msg.dlc <= b.byte:
        return None
    return msg.data[b.byte]


# Send the profile's pre-roll: tester_present_frames x 3E 80 on the request ID (none when 0).
def send_preroll(bus, profile, sleep=time.sleep):
    for _ in range(profile.preroll_frames):
        bus.send(can.Message(arbitration_id=profile.req_id, is_extended_id=False, data=PREROLL_DATA))
        sleep(PREROLL_GAP_S)


# Listen listen_s seconds; raise Busy on a busy value, SecondTester on any response-ID frame; pre-roll
# if fewer frames than the pre-roll count were heard. Returns the number of frames heard.
def preflight(bus, profile, listen_s=LISTEN_S, clock=time.monotonic, sleep=time.sleep):
    heard = 0
    end = clock() + listen_s
    while (left := end - clock()) > 0:
        m = bus.recv(timeout=left)
        if m is None or m.is_error_frame:
            continue
        heard += 1
        if not m.is_extended_id and m.arbitration_id == profile.resp_id:
            raise SecondTester("heard 0x%03X before sending: another tester is talking to the server"
                               % profile.resp_id)
        value = busy_value(profile, m)
        if value is not None and value in profile.busy.values:
            raise Busy("0x%03X byte %d is %d: another tester holds a session (or a previous one has not "
                       "timed out; wait 5 s)" % (profile.busy.id, profile.busy.byte, value))
    if heard < profile.preroll_frames:
        send_preroll(bus, profile, sleep)
    return heard


# Watches raw response-ID frames; one arriving while no request of ours is outstanding means a second tester.
class SecondTesterMonitor:
    # resp_id: the profile's response ID; clock: monotonic seconds (injectable for tests).
    def __init__(self, resp_id, clock=time.monotonic):
        self.resp_id = resp_id
        self._clock = clock
        self._lock = threading.Lock()
        self._busy = False
        self._quiet_after = clock()   # response frames up to this time can still be ours
        self.alarm = None

    # A request of ours is being sent; response frames are expected until end().
    def begin(self):
        with self._lock:
            self._busy = True

    # Our request got its final answer, or timed out (then pass grace_s=P2_STAR_S: a late answer is still ours).
    # A later, shorter grace never cuts short the window an earlier timed-out request opened.
    def end(self, grace_s=GRACE_S):
        with self._lock:
            self._busy = False
            self._quiet_after = max(self._quiet_after, self._clock() + grace_s)

    # Notifier callback: flag a response frame that no request of ours explains.
    def on_frame(self, msg):
        if msg.is_extended_id or msg.arbitration_id != self.resp_id:
            return
        with self._lock:
            if not self._busy and self._clock() > self._quiet_after and self.alarm is None:
                self.alarm = "unsolicited 0x%03X frame %s: a second tester is talking to the server" % (
                    self.resp_id, bytes(msg.data).hex(" "))

    # Raise SecondTester if an alarm was raised.
    def check(self):
        if self.alarm:
            raise SecondTester(self.alarm)


# udsoncan connection wrapper: refuses to send after a second-tester alarm and tells the monitor
# when a request is outstanding (a 0x78 keeps it outstanding).
class GuardedConnection(BaseConnection):
    # Wrap inner (a udsoncan connection) and report to monitor.
    def __init__(self, inner, monitor):
        BaseConnection.__init__(self, "udsota")
        self.inner, self.monitor = inner, monitor

    # Open the inner connection.
    def open(self):
        self.inner.open()
        return self

    # Close the inner connection.
    def close(self):
        self.inner.close()

    # True while the inner connection is open.
    def is_open(self):
        return self.inner.is_open()

    # Drop unread responses.
    def empty_rxqueue(self):
        self.inner.empty_rxqueue()

    # Send one request after the second-tester check.
    def specific_send(self, payload, timeout=None):
        self.monitor.check()
        self.monitor.begin()
        try:
            self.inner.send(payload)
        except BaseException:
            self.monitor.end()
            raise

    # Wait for one response; any answer but NRC 0x78 ends the outstanding request.
    def specific_wait_frame(self, timeout=None):
        try:
            frame = self.inner.wait_frame(timeout=timeout, exception=True)
        except BaseException:
            self.monitor.end(grace_s=P2_STAR_S)
            raise
        if frame is None or not (len(frame) >= 3 and frame[0] == 0x7F and frame[2] == 0x78):
            self.monitor.end()
        return frame


# isotp.Address for the profile's pair (or txid/rxid); the TX ID passes check_tx_id() first.
def isotp_address(profile, txid=None, rxid=None):
    txid = profile.req_id if txid is None else txid
    rxid = profile.resp_id if rxid is None else rxid
    check_tx_id(profile, txid)
    import isotp
    return isotp.Address(isotp.AddressingMode.Normal_11bits, txid=txid, rxid=rxid)


# udsoncan's kernel ISO-TP connection with a receive thread that survives a socket error. A TX timeout
# (no FC within N_Bs) puts ECOMM on the socket, and whichever of recv() and sendmsg() reads it first clears
# it. udsoncan's own thread ends on any exception from recv(), which leaves the client deaf to every later
# answer. Tied to udsoncan 1.26.1 (pinned in pyproject.toml): rxthread_task is that version's loop.
class RxResilientIsoTPConnection(IsoTPSocketConnection):
    # udsoncan 1.26.1's receive loop, except that an OSError is logged and the loop listens again. Any other
    # error still ends it, and it stops once close() sets exit_requested or the socket is closed.
    def rxthread_task(self):
        sel = selectors.DefaultSelector()
        sel.register(self.tpsock._socket, selectors.EVENT_READ)
        try:
            while not self.exit_requested and not self.tpsock.closed:
                try:
                    events = sel.select(timeout=0.2)
                    if events:
                        data = self.tpsock.recv()
                        if data is not None:
                            self.rxqueue.put(data)
                except OSError as e:
                    if self.exit_requested or self.tpsock.closed:
                        break
                    self.logger.debug("ISO-TP receive error, still listening: %s", e)
                    time.sleep(RX_ERROR_PAUSE_S)
                except Exception:
                    self.exit_requested = True
        finally:
            sel.close()


# Kernel ISO-TP connection on interface: blocking send that returns once the whole PDU is out
# (so P2 starts after the last CF), padding 0xAA, STmin and BS always from the server's FC.
def isotp_connection(profile, interface):
    import isotp
    address = isotp_address(profile)
    sock = isotp.socket()   # no timeout: a 4093-byte block takes ~1.4 s at STmin 2 ms
    sock.set_opts(optflag=isotp.socket.flags.WAIT_TX_DONE, txpad=PAD)   # never FORCE_TXSTMIN
    return RxResilientIsoTPConnection(interface, address, tpsock=sock)


# udsoncan client config: client timing, P2 counted from the end of the request.
def client_config():
    cfg = dict(udsoncan.configs.default_client_config)
    cfg.update({"request_timeout": REQUEST_TIMEOUT_S, "p2_timeout": P2_S,
                "p2_star_timeout": P2_STAR_S, "use_server_timing": False})
    return cfg


# The real bus: a guarded raw SocketCAN bus for pre-flight and the response monitor, plus the kernel ISO-TP link.
class Transport:
    # Open the raw bus on interface (SocketCAN) for profile.
    def __init__(self, profile, interface):
        self.profile, self.interface = profile, interface
        self.raw = GuardedBus(can.Bus(interface="socketcan", channel=interface), profile)
        self.monitor = SecondTesterMonitor(profile.resp_id)
        self.notifier = None
        self.client = None

    # Listen, stop on a busy server or another tester, pre-roll on a quiet bus.
    def preflight(self):
        return preflight(self.raw, self.profile)

    # The profile's pre-roll on the raw bus (used while the server restarts).
    def preroll(self):
        send_preroll(self.raw, self.profile)

    # Start the response monitor and open the UDS client over the kernel ISO-TP socket.
    def uds(self):
        self.raw.bus.set_filters([{"can_id": self.profile.resp_id, "can_mask": 0x7FF, "extended": False}])
        self.notifier = can.Notifier(self.raw.bus, [self.monitor.on_frame])
        self.client = Client(GuardedConnection(isotp_connection(self.profile, self.interface), self.monitor),
                             config=client_config())
        self.client.open()
        return Uds(self.client)

    # Enter the with-block.
    def __enter__(self):
        return self

    # Close the client, the monitor and the raw bus.
    def __exit__(self, *exc):
        if self.client is not None:
            self.client.close()
        if self.notifier is not None:
            self.notifier.stop()
        self.raw.shutdown()
