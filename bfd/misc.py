"""
These are just some wrappers and common functions
"""
from typing import Dict, Iterable, Any, Optional
from binascii import unhexlify
from weakref import WeakSet, ref as wref


__all__ = ['clname', 'hr_bytes', 'tobytes', 'WrapInt', 'tryint']


class WrapInt:
    """
    Mimic to 'overflowing' variable
    """

    __slots__ = ('_wrap', '_vault', '_maxval', '__weakref__')

    _instances: WeakSet = WeakSet()     # WeakSet[WrapInt]

    def __init__(self, maxval: int):
        self._vault: Dict[type, int] = {}
        self._maxval: int = maxval
        self._instances.add(self)

    def __get__(self, instance, owner) -> int:
        return self._vault.setdefault(wref(instance), 0)

    def __set__(self, instance, value: int):
        cur_val: int = self._vault.setdefault(wref(instance), 0)
        abs_val: int = abs(value) % self._maxval
        if value >= 0:
            self._vault[wref(instance)] = value % self._maxval
        elif abs_val > cur_val:
            self._vault[wref(instance)] = self._maxval - (abs_val - cur_val)
        else:
            self._vault[wref(instance)] = abs_val - cur_val


def clname(cls: object) -> str:     # pragma: no cover
    return cls.__class__.__name__


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
    if type(val) == str:
        return bytes(unhexlify(val.strip().replace(' ', '').replace(':', '').replace('\n', '').replace('-', '')))
    elif type(val) == bytes:
        return val
    elif hasattr(val, '__bytes__') or type(val) in (list, tuple):
        return bytes(val)
    raise Exception("%s: Bad input type: %s" % (__name__, type(val)))
