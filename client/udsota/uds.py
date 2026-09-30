"""The UDS requests the client makes, over a udsoncan Client (NRC 0x78 is handled inside udsoncan)."""
import time

from udsoncan import Request, services
from udsoncan.exceptions import (InvalidResponseException, NegativeResponseException, TimeoutException,
                                 UnexpectedResponseException)

from .errors import NoResponse, Nrc, SendFailed, UpdateFailed
from .keys import SEED_LEN
from .wire import DL_ALFID, DL_DFI, DL_MAX_DATA, NRC_BUSY, NRC_PENDING, NRC_TIME_DELAY

BUSY_BACKOFF_S = (0.05, 0.1, 0.2, 0.4, 0.8, 1.6)   # waits before each retry after NRC 0x21
SA_DELAY_S = 10.0        # the server's 0x27 delay after boot or after three wrong keys
KEEPALIVE_S = 2.0        # 3E 00 interval in a session: iso14229 restarts S3 (5.1 s) only on 10 and 3E
P2_STAR_S = 5.5          # client P2*: the wait for a late answer, or a running job's next 0x78 (sent every 1.5 s)
SIG_P2_S = 2.0           # P2 for a signed key: an ESP32-S3 checks P-256 in software (~0.45 s), and iso14229 answers
                         # no 0x78 to 0x27


# One request method per service the update uses.
class Uds:
    # client: an open udsoncan Client; sleep and clock are injectable for tests.
    def __init__(self, client, sleep=time.sleep, clock=time.monotonic):
        self.client, self.sleep, self.clock = client, sleep, clock
        self.in_session, self.kept = False, clock()

    # Send one request; return the positive response after its SID. Retries NRC 0x21 with backoff;
    # raises Nrc on other NRCs, NoResponse on a timeout, SendFailed when the send fails twice, and
    # UpdateFailed on an answer udsoncan cannot parse or that belongs to another service.
    # In a non-default session, a 3E 00 goes first when the last 10 or 3E is more than KEEPALIVE_S old.
    def request(self, service, sub=None, data=b""):
        sid = service.request_id()
        if sid not in (0x10, 0x3E) and self.in_session and self.clock() - self.kept > KEEPALIVE_S:
            self.tester_present()
        req = Request(service=service, subfunction=sub, data=bytes(data))
        for delay in BUSY_BACKOFF_S + (None,):
            try:
                resp = self.send_resending(req)
                if sid in (0x10, 0x3E):
                    self.kept = self.clock()
                    self.in_session = self.in_session if sid == 0x3E else sub != 0x01
                return bytes(resp.data or b"")
            except NegativeResponseException as e:
                if e.response.code == NRC_BUSY and delay is not None:
                    # 0x21 often means an earlier send of this request is still being served (its 0x78 was
                    # lost): listen out the backoff for that answer rather than sleep through its 0x78s.
                    late = self.await_answer(service, delay)
                    if late is not None:
                        return late
                    continue
                raise Nrc(service.request_id(), e.response.code)
            except TimeoutException as e:
                raise NoResponse("no response to service 0x%02X: %s" % (service.request_id(), e))
            except (InvalidResponseException, UnexpectedResponseException) as e:
                raise UpdateFailed("unexpected answer to service 0x%02X: %s" % (service.request_id(), e))
        raise AssertionError("unreachable")

    # Listen window_s seconds for an answer to service that no send of ours is waiting for: a late one, or one
    # still being served. A 0x78 extends the wait by P2_STAR_S each time, as it would for a request. Returns the
    # positive response after its SID, raises Nrc for a final NRC, and returns None when nothing arrives. 0x21 and
    # frames for other services are passed over. The second-tester monitor counts the wait as a request of ours.
    def await_answer(self, service, window_s):
        sid, conn = service.request_id(), self.client.conn
        timeout = window_s
        while True:
            expect = getattr(conn, "expect", None)
            if expect is not None:
                expect()
            frame = conn.wait_frame(timeout=timeout)
            if frame is None:
                return None
            if len(frame) >= 3 and frame[0] == 0x7F and frame[1] == sid:
                if frame[2] == NRC_PENDING:
                    timeout = P2_STAR_S
                    continue
                if frame[2] != NRC_BUSY:
                    raise Nrc(sid, frame[2])
            elif len(frame) >= 1 and frame[0] == sid | 0x40:
                return bytes(frame[1:])

    # send_request, resent once after an ISO-TP send error (OSError: no FC within N_Bs, e.g. one a rate cap
    # dropped). Safe: without the FC the server never got the request, and a seed stays valid 30 s.
    def send_resending(self, req):
        try:
            return self.client.send_request(req)
        except OSError:
            pass
        try:
            return self.client.send_request(req)
        except OSError as e:
            raise SendFailed("service 0x%02X: the server ended the transfer (no flow control)"
                             % req.service.request_id()) from e

    # DiagnosticSessionControl.
    def session(self, n):
        return self.request(services.DiagnosticSessionControl, n)

    # ReadDataByIdentifier for one DID; returns the record without the DID echo.
    def read_did(self, did):
        d = self.request(services.ReadDataByIdentifier, data=did.to_bytes(2, "big"))
        if d[:2] != did.to_bytes(2, "big"):
            raise UpdateFailed("DID echo %s does not match 0x%04X" % (d[:2].hex(), did))
        return d[2:]

    # WriteDataByIdentifier: data to one DID; checks the DID echo.
    def write_did(self, did, data):
        d = self.request(services.WriteDataByIdentifier, data=did.to_bytes(2, "big") + bytes(data))
        if d[:2] != did.to_bytes(2, "big"):
            raise UpdateFailed("write echo %s does not match 0x%04X" % (d[:2].hex(), did))

    # RoutineControl startRoutine; returns the status record after the RID echo.
    def routine(self, rid, data=b""):
        d = self.request(services.RoutineControl, 0x01, rid.to_bytes(2, "big") + bytes(data))
        if d[:3] != bytes([0x01]) + rid.to_bytes(2, "big"):
            raise UpdateFailed("routine echo %s does not match 0x%04X" % (d[:3].hex(), rid))
        return d[3:]

    # ReadDTCInformation sub-function sub with data; checks the sub-function echo and returns what follows it.
    def read_dtc(self, sub, data=b""):
        d = self.request(services.ReadDTCInformation, sub, data)
        if d[:1] != bytes([sub]):
            raise UpdateFailed("19 %02X answered with sub-function %s" % (sub, d[:1].hex() or "none"))
        return d[1:]

    # ClearDiagnosticInformation for the 3-byte groupOfDTC group (wire.DTC_GROUP_ALL: every DTC).
    def clear_dtc(self, group):
        self.request(services.ClearDiagnosticInformation, data=group.to_bytes(3, "big"))

    # TesterPresent 3E 00. Never 3E 80 here: a suppressed answer would leave the monitor waiting.
    def tester_present(self):
        self.request(services.TesterPresent, 0x00)

    # SecurityAccess seed then key at seed_level, keys a keys.DeviceKeys (16-byte keys) or keys.SigningKeys (64-byte
    # signatures); an all-zero seed means already unlocked. NRC 0x37 (the server's delay after boot) is waited out
    # once, with 3E 00 keeping S3 alive.
    def unlock(self, seed_level, keys):
        try:
            seed = self.request(services.SecurityAccess, seed_level)[1:]
        except Nrc as e:
            if e.code != NRC_TIME_DELAY:
                raise
            for _ in range(int(SA_DELAY_S / KEEPALIVE_S)):
                self.sleep(KEEPALIVE_S)
                self.tester_present()
            seed = self.request(services.SecurityAccess, seed_level)[1:]
        if not any(seed):
            return                                   # already unlocked: iso14229 answers a 2-byte zero seed
        if len(seed) != SEED_LEN:
            raise UpdateFailed("seed is %d bytes, expected %d" % (len(seed), SEED_LEN))
        key = keys.key(seed, seed_level)
        set_config, p2 = getattr(self.client, "set_config", None), getattr(self.client, "config", {}).get("p2_timeout")
        slow = len(key) > SEED_LEN and set_config is not None and p2 is not None
        if slow:
            set_config("p2_timeout", max(p2, SIG_P2_S))
        try:
            self.request(services.SecurityAccess, seed_level + 1, key)
        finally:
            if slow:
                set_config("p2_timeout", p2)

    # RequestDownload of size bytes at address 0, in data format dfi (DL_DFI_DEFLATE: the blocks carry a raw DEFLATE
    # stream of those size bytes); returns the data bytes per 0x36 block.
    def request_download(self, size, dfi=DL_DFI):
        d = self.request(services.RequestDownload,
                         data=bytes([dfi, DL_ALFID]) + (0).to_bytes(4, "big") + size.to_bytes(4, "big"))
        n = d[0] >> 4 if d else 0
        if n == 0 or len(d) < 1 + n:
            raise UpdateFailed("bad RequestDownload response %s" % d.hex())
        max_block = int.from_bytes(d[1:1 + n], "big")
        if max_block < 3:
            raise UpdateFailed("maxNumberOfBlockLength %d is too small" % max_block)
        return min(max_block - 2, DL_MAX_DATA)

    # TransferData: one block with its counter; checks the counter echo. A 76 with the previous block's counter
    # is that block's late answer to a resend (its first answer came after P2): it is passed over, and this
    # block's own answer awaited.
    def transfer(self, bsc, chunk):
        d = self.request(services.TransferData, data=bytes([bsc]) + bytes(chunk))
        previous = bytes([(bsc - 1) & 0xFF])
        while d[:1] == previous:
            d = self.await_answer(services.TransferData, P2_STAR_S)
            if d is None:
                raise NoResponse("no response to service 0x36 block %d after a late answer to block %d"
                                 % (bsc, previous[0]))
        if d[:1] != bytes([bsc]):
            raise UpdateFailed("block %d answered with counter %s" % (bsc, d[:1].hex()))

    # RequestTransferExit.
    def transfer_exit(self):
        self.request(services.RequestTransferExit)

    # ECUReset hardReset (keyed when the server has security).
    def ecu_reset(self):
        self.request(services.ECUReset, 0x01)
