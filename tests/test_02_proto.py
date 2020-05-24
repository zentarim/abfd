from bfd.proto import *
from bfd.misc import *
from bfd.const import *
import pytest
import logging
from hashlib import md5, sha1
from _md5 import MD5Type
from _sha1 import SHA1Type


@pytest.mark.parametrize("strdata", [
    "20 00 01 18 00 00 00 01 00 00 00 00 00 0f 42 40 00 0f 42 40 00 0f 42 40"
])
def test_packet_frombytes(strdata: str):
    # arrange
    data_in: bytes = tobytes(strdata)
    logging.info(hr_bytes(data_in))
    # act
    msg: CtlPacket = CtlPacket.frombytes(data_in)
    data_out: bytes = bytes(msg)
    # assert
    assert data_in == data_out


def test_simple_auth():
    # arrange
    passwd: str = 'password'
    msg: SimpleAuth = SimpleAuth(0xff, passwd.encode('ascii'))
    # act
    logging.info(msg)
    logging.info(hr_bytes(bytes(msg)))
    # assert
    assert bytes(msg) == b'\x01\x13\xFFpassword\x00\x00\x00\x00\x00\x00\x00\x00'
    assert len(msg) == 19


def test_key_md5_auth():
    # arrange
    passwd: str = 'password'
    msg: KeyMD5Auth = KeyMD5Auth(0xff, 0xff, passwd.encode('ascii'))
    # act
    msg_bytes: memoryview = memoryview(bytearray(bytes(msg)))
    logging.info(msg)

    md5_hash: MD5Type = md5(msg_bytes)
    logging.info("msg: %s" % hr_bytes(msg_bytes))
    md5_bytes: bytes = md5_hash.digest()
    logging.info("md5: %s" % hr_bytes(md5_bytes))
    msg_bytes[-MD5_LEN:] = md5_bytes.ljust(MD5_LEN, b'\x00')
    # assert
    logging.info("msg: %s" % hr_bytes(msg_bytes))
    assert len(msg) == 24


def test_mkey_md5_auth():
    # arrange
    passwd: str = 'password'
    msg: MKeyMD5Auth = MKeyMD5Auth(0xff, 0xff, passwd.encode('ascii'))
    # act
    msg_bytes: memoryview = memoryview(bytearray(bytes(msg)))
    logging.info(msg)

    md5_hash: MD5Type = md5(msg_bytes)
    logging.info("msg: %s" % hr_bytes(msg_bytes))
    md5_bytes: bytes = md5_hash.digest()
    logging.info("md5: %s" % hr_bytes(md5_bytes))
    msg_bytes[-MD5_LEN:] = md5_bytes.ljust(MD5_LEN, b'\x00')
    # assert
    logging.info("msg: %s" % hr_bytes(msg_bytes))
    assert len(msg) == 24


def test_key_sha1_auth():
    # arrange
    passwd: str = 'password'
    msg: KeySHA1Auth = KeySHA1Auth(0xff, 0xff, passwd.encode('ascii'))
    # act
    msg_bytes: memoryview = memoryview(bytearray(bytes(msg)))
    logging.info(msg)

    sha1_hash: SHA1Type = sha1(msg_bytes)
    logging.info("msg: %s" % hr_bytes(msg_bytes))
    sha1_bytes: bytes = sha1_hash.digest()
    logging.info("sha1: %s" % hr_bytes(sha1_bytes))
    msg_bytes[-SHA_LEN:] = sha1_bytes.ljust(SHA_LEN, b'\x00')
    # assert
    logging.info("msg: %s" % hr_bytes(msg_bytes))
    assert len(msg) == 28


def test_mkey_sha1_auth():
    # arrange
    passwd: str = 'password'
    msg: MKeySHA1Auth = MKeySHA1Auth(0xff, 0xff, passwd.encode('ascii'))
    # act
    msg_bytes: memoryview = memoryview(bytearray(bytes(msg)))
    logging.info(msg)

    sha1_hash: SHA1Type = sha1(msg_bytes)
    logging.info("msg: %s" % hr_bytes(msg_bytes))
    sha1_bytes: bytes = sha1_hash.digest()
    logging.info("sha1: %s" % hr_bytes(sha1_bytes))
    msg_bytes[-SHA_LEN:] = sha1_bytes.ljust(SHA_LEN, b'\x00')
    # assert
    logging.info("msg: %s" % hr_bytes(msg_bytes))
    assert len(msg) == 28


@pytest.mark.parametrize("strdata, auth_cls", [
    ("01 13 ff 70 61 73 73 77 6f 72 64 00 00 00 00 00 00 00 00", SimpleAuth),
    ("02 18 ff 00 00 00 00 ff f6 94 e5 fd e6 e1 69 d1 3c 49 74 27 c6 9e ee f6", KeyMD5Auth),
    ("03 18 ff 00 00 00 00 ff 71 3c aa e9 69 52 b6 c0 86 49 5d 74 0f b2 22 da", MKeyMD5Auth),
    ("04 1c ff 00 00 00 00 ff 13 8f e2 f9 93 6b 38 99 50 c4 01 b0 84 e5 f8 0f 4c 7a a4 c3", KeySHA1Auth),
    ("05 1c ff 00 00 00 00 ff 95 02 10 89 02 5f 38 40 ca 2c 4f 81 93 16 d4 64 90 e4 e8 28", MKeySHA1Auth),
])
def test_auth_factory(strdata: str, auth_cls: AuthObj):
    # arrange
    bytedata: bytes = tobytes(strdata)
    # act
    obj: AuthObj = AuthFactory(bytedata)
    logging.info(obj)
    # assert
    assert type(obj) == auth_cls
