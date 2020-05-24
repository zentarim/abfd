"""
This module implements handlers for auth data.
Purposes of these handlers:
1) Check Auth objects                                                       class.check_auth()
2) Add Auth data to Control Packet and convert it to bytes                  class.add_auth()
"""

from .misc import clname, WrapInt, tryint, hr_bytes
from .const import *
from .proto import *
from .exceptions import *
from .bfd_session import BFDSession
from typing import Optional, AnyStr, Union, Type, Dict
from hashlib import md5, sha1
from random import randint


__all__ = ['SimpleAuthHandler', 'KeyMD5AuthHandler', 'MKeyMD5AuthHandler', 'KeySHA1AuthHandler', 'MKeySHA1AuthHandler',
           'AuthHandlerObj', 'AuthHandlerCls', 'AuthHandlerFactory']


def _chk_seq(msg_seq: int, sess_seq: int, detect_mult: int) -> bool:
    """
    Check of the sequence number according to https://tools.ietf.org/html/rfc5880#section-6.7.4
    :param msg_seq:
        Message's sequence number
    :param sess_seq:
        Session's sequence number
    :param detect_mult:
        Detect Mult
    :return:
        Check result
    """
    seq_start: int = sess_seq % MAX32
    seq_end: int = (sess_seq + (detect_mult * 3)) % MAX32
    return _chk_sequence(msg_seq, seq_start, seq_end)


def _chk_mseq(msg_seq: int, sess_seq: int, detect_mult: int) -> bool:
    """
    Meticulous check of the sequence number according to https://tools.ietf.org/html/rfc5880#section-6.7.4
    :param msg_seq:
        Message's sequence number
    :param sess_seq:
        Session's sequence number
    :param detect_mult:
        Detect Mult
    :return:
        Check result
    """
    seq_start: int = (sess_seq + 1) % MAX32
    seq_end: int = (sess_seq + (detect_mult * 3)) % MAX32
    return _chk_sequence(msg_seq, seq_start, seq_end)


def _chk_sequence(msg_seq: int, seq_start: int, seq_end: int) -> bool:
    return (0 <= msg_seq <= seq_end or seq_start <= msg_seq <= MAX32
            if seq_start > seq_end
            else seq_start <= msg_seq <= seq_end)


class _AuthHandler:

    _auth_len: int = 0
    type: int = AuthType.NoAuth

    seq_num = WrapInt(MAX32)

    def __init__(self, auth_len: int):
        self._buf: bytearray = bytearray(CTL_LEN + auth_len)

    def add_auth(self, msg: CtlPacket) -> bytearray:
        return self._buf

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __ne__(self, other):
        return not hash(self) == hash(other)


class SimpleAuthHandler(_AuthHandler):

    _auth_len: int = 3
    type: int = AuthType.Simple

    def __init__(self, key_id: int, passwd: bytes):
        if not 1 <= len(passwd) <= 16:
            raise ValueError("Password MUST be from 1 to 16 bytes in length. Got: %s" % len(passwd))
        elif 0 > key_id > 0xFF:
            raise ValueError("key_id must be 0 > key_id > 0xFF. Got: %s" % key_id)
        super().__init__(self._auth_len + len(passwd))
        self.key_id: int = key_id
        self.passwd: bytes = passwd
        self._buf[CTL_LEN:] = (self.type, len(self.passwd) + self._auth_len, self.key_id, *self.passwd)

    def __hash__(self):
        return hash((type(self), self.key_id))

    def __str__(self):
        return "%s: <%s> '%s' " % (clname(self), self.key_id, self.passwd)

    def add_auth(self, msg: CtlPacket) -> bytearray:
        msg.auth = True
        self._buf[:CTL_LEN] = bytes(msg)
        self._buf[3] = len(self._buf)
        return self._buf

    def check_auth(self, auth: AuthObj, mdata: memoryview, session: BFDSession):
        if auth.passwd != self.passwd:
            raise BadAuth("%s: Password mismatch. Got: %s. Expected: %s" %
                          (self.key_id, auth.passwd.decode(), self.passwd.decode()))
        elif auth.key_id != self.key_id:
            raise BadAuth("%s: Key_id mismatch. Got: %s" % (self.key_id, auth.key_id))


class KeyAuthHandler(_AuthHandler):

    type: int = AuthType.NoAuth
    _meticulous: bool = False
    _auth_len: int = 0
    _hash_len: int = 0
    _hash_func: md5 or sha1 = None
    _header_len: int = 8

    def __init__(self, key_id: int, passwd: bytes):
        if 0 > key_id > 0xFF:
            raise ValueError("key_id must be 0 > key_id > 0xFF. Got: %s" % key_id)
        super().__init__(self._auth_len)
        self._header_end: int = CTL_LEN + self._header_len
        self._pwd_start: int = self._header_end
        self._pwd_end: int = self._pwd_start + self._hash_len
        self.key_id: int = key_id
        self.passwd: bytes = passwd
        self.seq_num: int = randint(0, MAX32)
        self._buf[CTL_LEN:self._header_end] = (self.type, self._hash_len + 8, self.key_id, 0)

    def __hash__(self):
        return hash((type(self), self.key_id))

    def __str__(self):
        return "%s: <%s> %s" % (clname(self), self.key_id, self.passwd)

    def add_auth(self, msg: CtlPacket) -> bytearray:
        msg.auth = True
        self._buf[:CTL_LEN] = bytes(msg)
        self._buf[3] = len(self._buf)
        self._buf[CTL_LEN + 4:self._pwd_start] = self.seq_num.to_bytes(4, byteorder='big')
        self._buf[self._pwd_start:self._pwd_end] = self.passwd.ljust(self._hash_len, b'\x00')
        if self._meticulous:
            self.seq_num += 1
        self._buf[self._pwd_start:self._pwd_end] = self._hash_func(self._buf).digest().ljust(self._hash_len, b'\x00')
        return self._buf

    def check_auth(self, auth: AuthObj, mdata: memoryview, session: BFDSession):
        if session.AuthSeqKnown:
            if not _chk_seq(auth.seq_num, session.RcvAuthSeq, session.DetectMult):
                raise BadAuth('Bad message seq_num: %s. Session seq_num: %s, detect_mult: %s' % \
                   (auth.seq_num, session.RcvAuthSeq, session.DetectMult))
        else:
            session.AuthSeqKnown = True
        session.RcvAuthSeq = auth.seq_num

        msg_hash: bytes = auth.hash
        mdata[self._pwd_start:self._pwd_end] = self.passwd.ljust(self._hash_len, b'\x00')
        my_hash: bytes = self._hash_func(mdata).digest().ljust(self._hash_len, b'\x00')
        if msg_hash != my_hash:
            raise BadAuth("Bad hash. Got: %s. Expected: %s" % (hr_bytes(msg_hash, ''), hr_bytes(my_hash, '')))


class KeyMD5AuthHandler(KeyAuthHandler):

    type: int = AuthType.KeyMD5
    _meticulous: bool = False
    _hash_len: int = MD5_LEN
    _auth_len: int = _hash_len + 8
    _hash_func: md5 = md5


class MKeyMD5AuthHandler(KeyMD5AuthHandler):

    type: int = AuthType.MKeyMD5
    _meticulous: bool = True


class KeySHA1AuthHandler(KeyAuthHandler):

    type: int = AuthType.KeySha1
    _meticulous: bool = False
    _hash_len: int = SHA_LEN
    _auth_len: int = _hash_len + 8
    _hash_func: sha1 = sha1


class MKeySHA1AuthHandler(KeySHA1AuthHandler):

    type: int = AuthType.MKeySha1
    _meticulous: bool = True


AuthHandlerObj = Union[SimpleAuthHandler, KeyMD5AuthHandler, MKeyMD5AuthHandler, KeySHA1AuthHandler,
                       MKeySHA1AuthHandler]
AuthHandlerCls = Union[Type[SimpleAuthHandler], Type[KeyMD5AuthHandler], Type[MKeyMD5AuthHandler],
                       Type[KeySHA1AuthHandler], Type[MKeySHA1AuthHandler]]


class AuthHandlerFactory:
    """
    Factory which returns appropriate Authenticate Handler object
    """

    cls_mapping: Dict[str, AuthHandlerCls] = {
        "simple"    : SimpleAuthHandler,
        "key_md5"   : KeyMD5AuthHandler,
        "mkey_md5"  : MKeyMD5AuthHandler,
        "key_sha1"  : KeySHA1AuthHandler,
        "mkey_sha1" : MKeySHA1AuthHandler,
    }

    def __new__(cls, auth_type: str, key_id: int or str, passwd: AnyStr) -> AuthHandlerObj:
        auth_cls: Optional[AuthHandlerCls] = cls.cls_mapping.get(auth_type)
        if not auth_cls:
            raise KeyError("Unknown Auth type: %s. Possible types: %s" % (auth_type, list(cls.cls_mapping.keys())))
        if type(passwd) is str:
            passwd = passwd.encode('ascii')
        return auth_cls(tryint(key_id), passwd)