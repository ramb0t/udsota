"""The UDS requests the client makes, over a udsoncan Client (NRC 0x78 is handled inside udsoncan)."""
import time

from udsoncan import Request, services
from udsoncan.exceptions import (InvalidResponseException, NegativeResponseException, TimeoutException,
                                 UnexpectedResponseException)

from .errors import NoResponse, Nrc, SendFailed, UpdateFailed
from .keys import SEED_LEN
from .wire import DL_ALFID, DL_DFI, DL_MAX_DATA, NRC_BUSY, NRC_TIME_DELAY

BUSY_BACKOFF_S = (0.05, 0.1, 0.2, 0.4, 0.8, 1.6)   # waits before each retry after NRC 0x21
SA_DELAY_S = 10.0        # the server's 0x27 delay after boot or after three wrong keys
KEEPALIVE_S = 2.0        # 3E 00 interval while waiting in a session (at least every 2 s)


# One request method per service the update uses.
class Uds:
    # client: an open udsoncan Client; sleep is injectable for tests.
    def __init__(self, client, sleep=time.sleep):
        self.client, self.sleep = client, sleep

    # Send one request; return the positive response after its SID. Retries NRC 0x21 with backoff;
    # raises Nrc on other NRCs, NoResponse on a timeout, SendFailed when the send fails twice, and
    # UpdateFailed on an answer udsoncan cannot parse or that belongs to another service.
    def request(self, service, sub=None, data=b""):
        req = Request(service=service, subfunction=sub, data=bytes(data))
        for delay in BUSY_BACKOFF_S + (None,):
            try:
                resp = self.send_resending(req)
                return bytes(resp.data or b"")
            except NegativeResponseException as e:
                if e.response.code == NRC_BUSY and delay is not None:
                    self.sleep(delay)
                    continue
                raise Nrc(service.request_id(), e.response.code)
            except TimeoutException as e:
                raise NoResponse("no response to service 0x%02X: %s" % (service.request_id(), e))
            except (InvalidResponseException, UnexpectedResponseException) as e:
                raise UpdateFailed("unexpected answer to service 0x%02X: %s" % (service.request_id(), e))
        raise AssertionError("unreachable")

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

    # RoutineControl startRoutine; returns the status record after the RID echo.
    def routine(self, rid, data=b""):
        d = self.request(services.RoutineControl, 0x01, rid.to_bytes(2, "big") + bytes(data))
        if d[:3] != bytes([0x01]) + rid.to_bytes(2, "big"):
            raise UpdateFailed("routine echo %s does not match 0x%04X" % (d[:3].hex(), rid))
        return d[3:]

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
        if len(seed) != SEED_LEN:
            raise UpdateFailed("seed is %d bytes, expected %d" % (len(seed), SEED_LEN))
        if any(seed):
            self.request(services.SecurityAccess, seed_level + 1, keys.key(seed, seed_level))

    # RequestDownload of size bytes at address 0; returns the data bytes per 0x36 block.
    def request_download(self, size):
        d = self.request(services.RequestDownload,
                         data=bytes([DL_DFI, DL_ALFID]) + (0).to_bytes(4, "big") + size.to_bytes(4, "big"))
        n = d[0] >> 4 if d else 0
        if n == 0 or len(d) < 1 + n:
            raise UpdateFailed("bad RequestDownload response %s" % d.hex())
        max_block = int.from_bytes(d[1:1 + n], "big")
        if max_block < 3:
            raise UpdateFailed("maxNumberOfBlockLength %d is too small" % max_block)
        return min(max_block - 2, DL_MAX_DATA)

    # TransferData: one block with its counter; checks the counter echo.
    def transfer(self, bsc, chunk):
        d = self.request(services.TransferData, data=bytes([bsc]) + bytes(chunk))
        if d[:1] != bytes([bsc]):
            raise UpdateFailed("block %d answered with counter %s" % (bsc, d[:1].hex()))

    # RequestTransferExit.
    def transfer_exit(self):
        self.request(services.RequestTransferExit)

    # ECUReset hardReset (keyed when the server has security).
    def ecu_reset(self):
        self.request(services.ECUReset, 0x01)
