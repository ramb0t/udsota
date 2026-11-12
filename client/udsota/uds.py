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
UNLOCKED_SEED_LEN = 2    # iso14229's seed when already unlocked: two zero bytes


# One request method per service the update uses.
class Uds:
    # client: an open udsoncan Client; sleep and clock are injectable for tests.
    def __init__(self, client, sleep=time.sleep, clock=time.monotonic):
        self.client, self.sleep, self.clock = client, sleep, clock
        self.in_session, self.kept, self.unanswered, self.last_block = False, clock(), None, None

    # Send one request; return the positive response after its SID. Retries NRC 0x21 with backoff;
    # raises Nrc on other NRCs, NoResponse on a timeout, SendFailed when the send fails twice, and
    # UpdateFailed on an answer udsoncan cannot parse or that belongs to another service (a 3E 00 passes over it,
    # and any request passes over a late answer to the request that went unanswered, or the last block's 76 to its
    # repeat).
    # In a non-default session, a 3E 00 goes before the request and before each 0x21 retry whenever the last 10 or 3E
    # is more than KEEPALIVE_S old, so a backoff cannot outlast S3. A late answer to an earlier send of this request
    # that lands on such a 3E is passed over, and the retry gets the server's answer to a repeat.
    # stale, when given, picks out a positive answer that belongs to an earlier request of the same service (see
    # transfer): it is passed over wherever it comes, and this request's own answer awaited within its P2.
    def request(self, service, sub=None, data=b"", stale=None):
        sid = service.request_id()
        req = Request(service=service, subfunction=sub, data=bytes(data))
        for delay in BUSY_BACKOFF_S + (None,):
            if sid not in (0x10, 0x3E) and self.in_session and self.clock() - self.kept > KEEPALIVE_S:
                self.keep_alive()
            try:
                answer = self.exchange(service, req)
                if stale is not None and stale(answer):
                    answer = self.await_answer(service, self.client.config["p2_timeout"], busy_ends=True, stale=stale)
                    if answer is None:
                        self.unanswered = sid
                        raise NoResponse("no response to service 0x%02X after a late answer to an earlier one" % sid)
            except Nrc as e:
                if e.code != NRC_BUSY or delay is None:
                    raise
                # 0x21 often means an earlier send of this request is still being served (its 0x78 was
                # lost): listen out the backoff for that answer rather than sleep through its 0x78s.
                answer = self.await_answer(service, delay, stale=stale)
                if answer is None:
                    continue
            self.answered(sid, sub)
            return answer
        raise AssertionError("unreachable")

    # Send req (resent as send_resending allows) and return its positive response after the SID; raise as request()
    # does, with Nrc for 0x21 too. A request that gets no answer, or whose send fails, is the one that went unanswered
    # until another request is answered.
    def exchange(self, service, req):
        sid = service.request_id()
        try:
            return bytes(self.send_resending(req).data or b"")
        except SendFailed:
            self.unanswered = sid
            raise
        except NegativeResponseException as e:
            self.settled(sid)
            raise Nrc(sid, e.response.code)
        except TimeoutException as e:
            self.unanswered = sid
            raise NoResponse("no response to service 0x%02X: %s" % (sid, e))
        except UnexpectedResponseException as e:
            other = e.response.service.request_id()
            late_block = (other == 0x36 and e.response.positive and self.last_block is not None
                          and bytes(e.response.data or b"")[:1] == bytes([self.last_block]))
            if sid != 0x3E and other != self.unanswered and not late_block:
                raise UpdateFailed("unexpected answer to service 0x%02X: %s" % (sid, e))
            # A late answer to an earlier request can come first: to the keepalive, a block's answer to its
            # resend (see transfer); to any request, the answer to the request that went unanswered (a keepalive's
            # 7E, or the 7F 22 31 to a read the adapter held while the unit was off), or the last block's 76 to its
            # resend. Pass over it and await this request's own answer within its P2, as if the stray frame had not
            # come.
            late = self.await_answer(service, self.client.config["p2_timeout"], busy_ends=True)
            if late is None:
                self.unanswered = sid
                raise NoResponse("no response to service 0x%02X after an answer to service 0x%02X" % (sid, other))
            return late
        except InvalidResponseException as e:
            raise UpdateFailed("unexpected answer to service 0x%02X: %s" % (sid, e))

    # The keepalive's 3E 00. One that gets no answer is not the failure of the request it goes ahead of: the request
    # goes at once, and the next one sends another 3E. Its 7E may still come, so the requests after it pass over a 7E
    # until one of them is answered (exchange).
    def keep_alive(self):
        try:
            self.tester_present()
        except NoResponse:
            pass

    # Track the session after a positive answer to sid with sub-function sub: a 10 or 3E restarts the keepalive
    # timer, 10 01 and 11 01 (the server restarts) leave the non-default session, and other 10s enter one.
    def answered(self, sid, sub):
        if sid in (0x10, 0x3E):
            self.kept = self.clock()
        self.settled(sid)
        if sid == 0x10:
            self.in_session = sub != 0x01
        elif sid == 0x11 and sub == 0x01:
            self.in_session = False

    # An answer to sid, positive or not, means no earlier answer is still on its way, since a server answers in order:
    # no 76 to the last block's repeat, and none to the request that went unanswered unless both are 3E (this 7E may
    # be the earlier 3E's). transfer() sets last_block again after each block's own answer.
    def settled(self, sid):
        if not sid == self.unanswered == 0x3E:
            self.unanswered = None
        self.last_block = None

    # The server restarted (it answers in the default session): no keepalive until the next 10.
    def restarted(self):
        self.in_session = False

    # Listen window_s seconds for an answer to service that no send of ours is waiting for: a late one, or one
    # still being served. A 0x78 extends the wait by pending_s each time, P2_STAR_S as it would be for a request.
    # Returns the positive response after its SID, raises Nrc for a final NRC, and returns None when nothing arrives.
    # Frames for other services are passed over, as is a positive answer stale picks out, and so is 0x21 (an earlier
    # send's) unless busy_ends, when the send being awaited is this one and 0x21 is its answer. The second-tester
    # monitor counts the wait as a request of ours.
    def await_answer(self, service, window_s, busy_ends=False, stale=None, pending_s=P2_STAR_S):
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
                    timeout = pending_s
                    continue
                if frame[2] != NRC_BUSY or busy_ends:
                    self.settled(sid)
                    raise Nrc(sid, frame[2])
            elif len(frame) >= 1 and frame[0] == sid | 0x40 and not (stale is not None and stale(bytes(frame[1:]))):
                return bytes(frame[1:])

    # Pass over every frame that comes until settle_s passes with none, or max_s in all: answers still on their way
    # to earlier sends, which the next request must not take for its own, nor reach the server while it still sends
    # them. The second-tester monitor counts the wait as a request of ours. Returns how many frames it passed over.
    def drain(self, settle_s, max_s):
        conn, end, n = self.client.conn, self.clock() + max_s, 0
        while (left := end - self.clock()) > 0:
            expect = getattr(conn, "expect", None)
            if expect is not None:
                expect()
            if conn.wait_frame(timeout=min(settle_s, left)) is None:
                break
            n += 1
        return n

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

    # One try at session n on a unit that may not be listening yet: one 10 n, every wait for its answer window_s, in
    # place of P2, of P2* after a 0x78, and of request()'s retries after 0x21, so no answer holds the try longer. True
    # once a 50 n answers it. False when nothing does within window_s, and after window_s spent listening for a 50 n to
    # an earlier send when the send failed or the answer was an NRC (0x21 among them) or another service's, so tries
    # never come faster than one per window_s.
    def try_session(self, n, window_s):
        service = services.DiagnosticSessionControl
        p2, p2_star = self.client.config["p2_timeout"], self.client.config["p2_star_timeout"]
        self.client.set_config("p2_timeout", window_s)
        self.client.set_config("p2_star_timeout", window_s)
        try:
            answer = self.exchange(service, Request(service=service, subfunction=n))
        except NoResponse:
            return False
        except UpdateFailed:
            answer = None
        finally:
            self.client.set_config("p2_timeout", p2)
            self.client.set_config("p2_star_timeout", p2_star)
        if answer is None:
            try:
                answer = self.await_answer(service, window_s, pending_s=window_s)
            except Nrc:
                return False
        if answer is None or answer[:1] != bytes([n]):
            return False
        self.answered(0x10, n)
        return True

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
    # signatures, sent with P2 raised to SIG_P2_S); an all-zero seed of SEED_LEN or UNLOCKED_SEED_LEN bytes means
    # already unlocked. NRC 0x37 (the server's delay after boot) is waited out once, with 3E 00 keeping S3 alive.
    def unlock(self, seed_level, keys):
        try:
            seed = self.request(services.SecurityAccess, seed_level)[1:]
        except Nrc as e:
            if e.code != NRC_TIME_DELAY:
                raise
            for _ in range(int(SA_DELAY_S / KEEPALIVE_S)):
                self.sleep(KEEPALIVE_S)
                self.keep_alive()
            seed = self.request(services.SecurityAccess, seed_level)[1:]
        if len(seed) in (SEED_LEN, UNLOCKED_SEED_LEN) and not any(seed):
            return                                   # already unlocked
        if len(seed) != SEED_LEN:
            raise UpdateFailed("seed is %d bytes, expected %d" % (len(seed), SEED_LEN))
        key, p2 = keys.key(seed, seed_level), self.client.config["p2_timeout"]
        if len(key) > SEED_LEN:
            self.client.set_config("p2_timeout", max(p2, SIG_P2_S))
        try:
            self.request(services.SecurityAccess, seed_level + 1, key)
        finally:
            self.client.set_config("p2_timeout", p2)

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
    # is that block's late answer to a resend (its first answer came after P2): it is passed over wherever it comes,
    # and this block's own answer awaited within P2, so a lost one is resent before S3 can lapse, and a 0x21 to this
    # block is retried with backoff like any other. After the last block, exchange() passes over that 76 instead.
    def transfer(self, bsc, chunk):
        previous = bytes([(bsc - 1) & 0xFF])
        d = self.request(services.TransferData, data=bytes([bsc]) + bytes(chunk), stale=lambda a: a[:1] == previous)
        if d[:1] != bytes([bsc]):
            raise UpdateFailed("block %d answered with counter %s" % (bsc, d[:1].hex()))
        self.last_block = bsc

    # RequestTransferExit.
    def transfer_exit(self):
        self.request(services.RequestTransferExit)

    # ECUReset hardReset (keyed when the server has security).
    def ecu_reset(self):
        self.request(services.ECUReset, 0x01)
