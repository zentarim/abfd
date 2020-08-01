"""
These are just some wrappers and common functions
"""
from typing import Iterable, Any, Optional, Type
from binascii import unhexlify
from weakref import WeakKeyDictionary

__all__ = ['clname', 'hr_bytes', 'tobytes', 'WrapInt', 'tryint']

_O = Any
_C = Type[_O]


class WrapInt:
    """
    Mimic to 'overflowing' variable
    """

    __slots__ = ('_vault', '_maxval')

    def __init__(self, maxval: int):
        self._vault: WeakKeyDictionary = WeakKeyDictionary()    # Dict[Weakref[_T], int]
        self._maxval: int = maxval

    def __get__(self, instance: Optional[_C], owner: _O) -> int:
        if instance is None:    # Access through class var. I guess, in that case, it is better to expose this instance.
            # noinspection PyTypeChecker
            return self
        return self._vault.setdefault(instance, 0)

    def __set__(self, instance: _C, value: int):
        self._vault[instance] = value % self._maxval


def clname(obj: object) -> str:     # pragma: no cover
    return obj.__name__ if obj.__class__ is type else obj.__class__.__name__


def hr_bytes(data: Iterable[int], delimiter: str = ' ') -> str:     # pragma: no cover
    """
    Print bytes (or another int iterable) as hex and delimiters
    :param data:
        Bytes or iterable object
    :param delimiter:
        Delimiter (str value)
    :return:
        str value (02 02 04 05 06 00)
    """
    return delimiter.join(("%02x" % byte for byte in data))


def tryint(val: str or int) -> Optional[int]:     # pragma: no cover
    """
    Ensure of int value
    :param val:
        str or val
    :return:
    """
    if val is None:
        return None
    if type(val) is int:
        return val
    return int(val, 0)  # str


def tobytes(val: Any) -> bytes:     # pragma: no cover
    """
    Try to convert value to bytes
    :param val:
        Any value
    :return:
    """
    if type(val) is str:
        return bytes(unhexlify(val.strip().replace(' ', '').replace(':', '').replace('\n', '').replace('-', '')))
    elif type(val) is bytes:
        return val
    elif hasattr(val, '__bytes__') or type(val) in (list, tuple):
        return bytes(val)
    raise Exception("%s: Bad input type: %s" % (__name__, type(val)))
