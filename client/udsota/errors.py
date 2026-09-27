"""The errors the client reports; each carries the exit code main() returns."""


# Base of every error the tool reports; exit_code is main's return value.
class ToolError(Exception):
    exit_code = 1


# Refused before or instead of transmitting (deny list, bad input, bad profile, precheck stop).
class Refused(ToolError):
    exit_code = 2


# The profile's busy detector shows another tester's session.
class Busy(ToolError):
    exit_code = 3


# A response-ID frame no request of ours explains: another tester is on the bus.
class SecondTester(ToolError):
    exit_code = 4


# The server refused or failed a step; its session times out on its own (S3).
class UpdateFailed(ToolError):
    exit_code = 1


# No answer within P2/P2*.
class NoResponse(UpdateFailed):
    pass


# The ISO-TP send failed twice (no FC within N_Bs, or no echo): the server ended the transfer.
# Not a NoResponse, so the 0x36, 0x37 and FF01 resends don't add a third send.
class SendFailed(UpdateFailed):
    pass


# A negative response: sid is the request SID, code the NRC.
class Nrc(UpdateFailed):
    # Keep the SID and NRC for callers that retry or explain specific codes.
    def __init__(self, sid, code):
        super().__init__("service 0x%02X answered NRC 0x%02X" % (sid, code))
        self.sid, self.code = sid, code
