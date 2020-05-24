from typing import ByteString
from struct import pack, unpack
from ..const import *
from ..exceptions import DecodeError

__all__ = ["CtlPacket"]


class CtlPacket:
    """
    Object of Generic BFD Control Packet
    """

    vers: int = 1               # According to rfc5880 it is always 1
    multipoint: bool = False    # According to rfc5880 it MUST be zero on both transmit and receipt.

    @classmethod
    def frombytes(cls, data: ByteString):
        """
        Construct a CtlPacket from bytes
        :param data:
            Bytedata (can be bytes\bytearra\memoryview)
        :return:
            CtlPacket object
        """
        obj: CtlPacket = cls()
        # Pycharm bug https://youtrack.jetbrains.com/oauth?state=%2Fissue%2FPY-41867
        # noinspection PyTypeChecker
        b1, b2, \
        detect_mult, \
        msg_len, \
        my_discr, \
        obj.your_discr, \
        obj.min_tx_intvl, \
        obj.min_rx_intvl, \
        obj.min_echo_rx_intvl = unpack(CTL_FMT, data)
        ver: int = (b1 & 0xE0) >> 5
        obj.diag = b1 & 0x1F
        obj.state = (b2 & 0xC0) >> 6
        obj.poll = bool((b2 & 0x20) >> 5)
        obj.final = bool((b2 & 0x10) >> 4)
        obj.cpi = bool((b2 & 0x08) >> 3)
        obj.auth = bool((b2 & 0x04) >> 2)
        obj.demand = bool((b2 & 0x02) >> 1)
        if ver != 1:
            raise DecodeError("Bad version %s. Can't be other than 1" % ver)
        elif not detect_mult:
            raise DecodeError("Incorrect Detect Mult. Can't be zero")
        elif bool(b2 & 0x1):
            raise DecodeError("Incorrect Multipoint flag. Can't be nonzero")
        elif not my_discr:
            raise DecodeError("Incorrect My Discriminator. Can't be zero.")
        obj.detect_mult = detect_mult
        obj.my_discr = my_discr
        return obj

    def __init__(self):
        self.diag: int = Diag.NoDiag
        self.state: int = SessionState.AdminDown
        self.poll: bool = False
        self.final: bool = False
        self.cpi: bool = False
        self.demand: bool = False
        self.detect_mult: int = 1
        self.my_discr: int = 1
        self.your_discr: int = 0
        self.min_tx_intvl: int = 1_000_000
        self.min_rx_intvl: int = 1_000_000
        self.min_echo_rx_intvl: int = 1_000_000
        self.auth: bool = False

    def __len__(self):
        return CTL_LEN

    def __bytes__(self):
        b1: int = (self.vers << 5) + self.diag
        b2: int = ((self.state << 6) +
                   (self.poll << 5) +
                   (self.final << 4) +
                   (self.cpi << 3) +
                   (self.auth << 2) +
                   (self.demand << 1) +
                   self.multipoint)
        data: bytes = pack(CTL_FMT, b1, b2, self.detect_mult, len(self), self.my_discr, self.your_discr,
                           self.min_tx_intvl, self.min_rx_intvl, self.min_echo_rx_intvl)
        return data

    def __hash__(self):
        return hash((self.__class__, self.diag, self.state, self.poll, self.final, self.cpi, self.demand,
                     self.detect_mult, self.my_discr, self.your_discr, self.min_tx_intvl, self.min_rx_intvl,
                     self.min_echo_rx_intvl, self.auth))

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __ne__(self, other):
        return not hash(self) == hash(other)

    def __str__(self):
        return "<%s => %s %s>" % (self.my_discr, self.your_discr, SessionState(self.state))