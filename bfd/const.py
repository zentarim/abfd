from .enum import T_Enum as _Enum
from struct import calcsize as _calcsize

MD5_LEN: int = 16
SHA_LEN: int = 20

MAX8: int = 2 ** 8
MAX16: int = 2 ** 16
MAX32: int = 2 ** 32
MAX64: int = 2 ** 64

CTL_FMT: str = '!BBBBIIIII'
CTL_LEN: int = _calcsize(CTL_FMT)

BFD_PORT: int = 3784


class Diag(_Enum):
    NoDiag: int = 0
    Expired: int = 1
    EchoFailed: int = 2
    NeighborDown: int = 3
    FPReset: int = 4
    PathDown: int = 5
    ConPathDown: int = 6
    AdminDown: int = 7
    RConPathDown: int = 8


class SessionState(_Enum):
    AdminDown: int = 0
    Down: int = 1
    Init: int = 2
    Up: int = 3


class AuthType(_Enum):
    NoAuth: int = 0
    Simple: int = 1
    KeyMD5: int = 2
    MKeyMD5: int = 3
    KeySha1: int = 4
    MKeySha1: int = 5


class SessionRole(_Enum):
    Passive: str = 'Passive'
    Active: str = 'Active'
