"""
Module for all BFD Authentication types objects.
"""
from struct import calcsize, pack, unpack
from typing import Optional, Dict, Union, Type, ByteString
from ..misc import clname, hr_bytes
from ..const import AuthType, MD5_LEN, SHA_LEN


__all__ = ['AuthObj', 'AuthCls', 'SimpleAuth', 'KeyMD5Auth', 'MKeyMD5Auth', 'KeySHA1Auth', 'MKeySHA1Auth',
           'AuthFactory']


class _KeyAuth:
    """
    Template for all key-based authentication objects
    """

    type: int = 0xFF
    _hashlen: int = MD5_LEN
    _fmt: str = '!BBBBI%ss' % _hashlen
    _fmt_size: int = calcsize(_fmt)

    @classmethod
    def frombytes(cls, data: ByteString):
        """
        By some reason, Juniper adds excess zero bytes AFTER the auth section.
        These bytes are included in the whole packet length and considered in the hashing process
        but I have no clue what they are for
        :param data:
            Auth data (bytes or memoryview)
        :return:
            Auth object (key-based)
        """
                                                                # snag here \/
        atype, alen, key_id, _, seq_num, _hash = unpack(cls._fmt, data[:cls._fmt_size])
        if alen != cls._fmt_size:
            raise ValueError("Incorrect length. Got: %s. Expected: %s." % (alen, cls._fmt_size))
        return cls(key_id, seq_num, _hash)

    def __init__(self, key_id: int, seq_num: int, hash: bytes):
        self.key_id: int = key_id
        self.seq_num: int = seq_num
        self.hash: bytes = hash

    def __hash__(self):
        return hash((self.__class__, self.key_id, self.seq_num, self.hash))

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __ne__(self, other):
        return not hash(self) == hash(other)

    def __len__(self):
        return self._fmt_size

    def __bytes__(self):
        return pack(self._fmt, self.type, len(self), self.key_id, 0, self.seq_num,
                    self.hash.ljust(self._hashlen, b'\x00'))

    def __str__(self):
        return "%s: key_id: %s seq_num: %s hash: '%s'" % (clname(self), self.key_id, self.seq_num, hr_bytes(self.hash))


class KeyMD5Auth(_KeyAuth):

    type: int = AuthType.KeyMD5
    _hashlen: int = MD5_LEN
    _fmt: str = '!BBBBI%ss' % _hashlen
    _fmt_size: int = calcsize(_fmt)


class MKeyMD5Auth(KeyMD5Auth):

    type: int = AuthType.MKeyMD5


class KeySHA1Auth(_KeyAuth):

    type: int = AuthType.KeySha1
    _hashlen: int = SHA_LEN
    _fmt: str = '!BBBBI%ss' % _hashlen
    _fmt_size: int = calcsize(_fmt)


class MKeySHA1Auth(KeySHA1Auth):

    type: int = AuthType.MKeySha1


class SimpleAuth:
    """
    Simple auth object
    """

    type: int = AuthType.Simple
    _fmt: str = '!BBB16s'
    _fmt_size: int = calcsize(_fmt)

    @classmethod
    def frombytes(cls, data: ByteString):
        """
        By some reason Juniper adds excess zero bytes AFTER the auth section.
        These bytes are included in the whole packet length and considered in the hashing process
        but I have no clue what they are for
        :param data:
            Auth data (bytes or memoryview)
        :return:
            Auth object (simple)
        """
        atype, alen, key_id = data[:3]
        if atype != cls.type:
            raise ValueError("%s got %s AuthType" % (cls.__name__, AuthType(atype)))
        passwd: bytes = bytes(data[3:alen])
        return cls(key_id, passwd)

    def __init__(self, key_id: int, passwd: bytes):
        self.key_id: int = key_id
        self.passwd: bytes = passwd

    def __hash__(self):
        return hash((self.__class__, self.key_id, self.passwd))

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __ne__(self, other):
        return not hash(self) == hash(other)

    def __len__(self):
        return self._fmt_size

    def __bytes__(self):
        return pack(self._fmt, self.type, len(self), self.key_id, self.passwd)

    def __str__(self):
        return "%s: <%s> '%s'" % (clname(self), self.key_id, self.passwd.decode('ascii'))


AuthObj = Union[SimpleAuth, KeyMD5Auth, MKeyMD5Auth, KeySHA1Auth, MKeySHA1Auth]
AuthCls = Union[Type[SimpleAuth], Type[KeyMD5Auth], Type[MKeyMD5Auth], Type[KeySHA1Auth], Type[MKeySHA1Auth]]


class AuthFactory:
    """
    Factory which returns appropriate Authenticate object
    """

    _auth_type_mapping: Dict[int, AuthCls] = {
        AuthType.Simple   : SimpleAuth,
        AuthType.KeyMD5   : KeyMD5Auth,
        AuthType.MKeyMD5  : MKeyMD5Auth,
        AuthType.KeySha1  : KeySHA1Auth,
        AuthType.MKeySha1 : MKeySHA1Auth
    }

    def __new__(cls, data: ByteString) -> AuthObj:
        auth_cls: Optional[AuthCls] = cls._auth_type_mapping.get(data[0])
        if not auth_cls:
            raise KeyError("Unknown Auth type: %s" % data[0])
        return auth_cls.frombytes(data)

