from bfd.proto import *
from bfd.bfd_session import BFDSession
from bfd.misc import *
from bfd.auth_handlers import *
from bfd.auth_handlers import _chk_seq, _chk_mseq
from bfd.exceptions import *
from bfd.bfd import msg_factory
from bfd.const import *
from typing import Dict, Type, Optional
import pytest
import logging
from contextlib import contextmanager
from pytest import raises as _raises


Exc = Optional[Type[Exception]]
@contextmanager
def raises(exception: Exc = None):
    if exception:
        with _raises(exception):
            yield
    else:
        yield


@pytest.mark.parametrize("msg_seq, sess_seq, detect_mult, retval", [
    (100, 100, 2, True),
    (101, 100, 2, True),
    (100+2*3, 100, 2, True),
    (100+2*3+1, 100, 2, False),
    (99, 100, 2, False),
    (MAX32, 1, 2, False),
    (2*3, MAX32, 2, True)
])
def test_chk_seq(msg_seq: int, sess_seq: int, detect_mult: int, retval: bool):
    # arrange
    # act
    res: bool = _chk_seq(msg_seq, sess_seq, detect_mult)
    logging.info("msg_seq: %s, sess_seq: %s, detect_mult: %s, retval: %s, res: %s" %
                 (msg_seq, sess_seq, detect_mult, retval, res))
    # assert
    assert res == retval


@pytest.mark.parametrize("msg_seq, sess_seq, detect_mult, retval", [
    (100, 100, 2, False),
    (101, 100, 2, True),
    (100+2*3, 100, 2, True),
    (100+2*3+1, 100, 2, False),
    (99, 100, 2, False),
    (MAX32, 1, 2, False),
    (2*3, MAX32, 2, True)
])
def test_chk_mseq(msg_seq: int, sess_seq: int, detect_mult: int, retval: bool):
    # arrange
    # act
    res: bool = _chk_mseq(msg_seq, sess_seq, detect_mult)
    logging.info("msg_seq: %s, sess_seq: %s, detect_mult: %s, retval: %s, res: %s" %
                 (msg_seq, sess_seq, detect_mult, retval, res))
    # assert
    assert res == retval


@pytest.mark.parametrize("data, handler_cls", [
    ({"auth_type": "simple", "key_id": 123, "passwd": "werty"}, SimpleAuthHandler),
    ({"auth_type": "key_md5", "key_id": 123, "passwd": "werty"}, KeyMD5AuthHandler),
    ({"auth_type": "mkey_md5", "key_id": 123, "passwd": "werty"}, MKeyMD5AuthHandler),
    ({"auth_type": "key_sha1", "key_id": 123, "passwd": "werty"}, KeySHA1AuthHandler),
    ({"auth_type": "mkey_sha1", "key_id": 123, "passwd": "werty"}, MKeySHA1AuthHandler)
])
def test_factory(data: Dict[str, str or int], handler_cls: AuthHandlerCls):
    # arrange
    # act
    obj: AuthHandlerObj = AuthHandlerFactory(**data)
    logging.info(obj)
    # assert
    assert type(obj) is handler_cls


def test_simple_add():
    # arrange
    passwd: bytes = b"123456"
    key_id: int = 1
    msg_in: CtlPacket = CtlPacket()
    auth_in: SimpleAuth = SimpleAuth(key_id, passwd)
    auth_handler: SimpleAuthHandler = SimpleAuthHandler(key_id, passwd)
    # act
    data: bytearray = auth_handler.add_auth(msg_in)
    logging.info(hr_bytes(data))
    msg_out, auth_out = msg_factory(data)
    # assert
    assert msg_in == msg_out
    assert auth_in == auth_out


@pytest.mark.parametrize("hkey_id, hpasswd, mkey_id, mpasswd, exc", [
    (100, b'password', 100, b'password', None),
    (100, b'password', 110, b'password', BadAuth),
    (100, b'password', 100, b'12121212', BadAuth),
])
def test_simple_check(hkey_id: int, hpasswd: bytes, mkey_id: int, mpasswd: bytes, exc: Exc):
    # arrange
    sess: BFDSession = BFDSession("127.0.0.1", 1)
    msg: CtlPacket = CtlPacket()
    mdata: memoryview = memoryview(bytearray(bytes(msg)))
    auth: SimpleAuth = SimpleAuth(mkey_id, mpasswd)
    auth_handler: SimpleAuthHandler = SimpleAuthHandler(hkey_id, hpasswd)
    # act

    with raises(exc):
        auth_handler.check_auth(auth, mdata, sess)
    # assert


def test_simple_md5key_add():
    # arrange
    passwd: bytes = b"123456"
    _hash: bytes = tobytes("6f d7 e5 2e 65 2e 4d bb a4 a7 a9 fe 61 df af d2")
    key_id: int = 1
    seq_num: int = 100
    msg_in: CtlPacket = CtlPacket()
    auth_in: KeyMD5Auth = KeyMD5Auth(key_id, seq_num, _hash)
    auth_handler: KeyMD5AuthHandler = KeyMD5AuthHandler(key_id, passwd)
    auth_handler.seq_num = seq_num
    # act
    data: bytearray = auth_handler.add_auth(msg_in)
    logging.info(hr_bytes(data))
    msg_out, auth_out = msg_factory(data)
    logging.info(hr_bytes(auth_out.hash))
    # assert
    assert msg_in == msg_out
    assert auth_in == auth_out


def test_simple_md5key_check():
    # arrange
    passwd: bytes = b"123456"
    _hash: bytes = tobytes("6f d7 e5 2e 65 2e 4d bb a4 a7 a9 fe 61 df af d2")
    key_id: int = 1
    seq_num: int = 100
    sess: BFDSession = BFDSession("127.0.0.1", 1)
    msg_in: CtlPacket = CtlPacket()
    auth_in: KeyMD5Auth = KeyMD5Auth(key_id, seq_num, _hash)
    auth_handler: KeyMD5AuthHandler = KeyMD5AuthHandler(key_id, passwd)
    auth_handler.seq_num = seq_num
    data: bytes = bytes(auth_handler.add_auth(msg_in))
    mdata: memoryview = memoryview(bytearray(data))
    # act
    auth_handler.check_auth(auth_in, mdata, sess)
    # assert
    assert auth_handler.seq_num == seq_num


def test_md5mkey_add():
    # arrange
    passwd: bytes = b"123456"
    _hash: bytes = tobytes("78 12 8b fe 57 cc ca 68 ed d8 5d 35 66 1f 60 5a")
    key_id: int = 1
    seq_num: int = 100
    msg_in: CtlPacket = CtlPacket()
    auth_in: MKeyMD5Auth = MKeyMD5Auth(key_id, seq_num, _hash)
    auth_handler: MKeyMD5AuthHandler = MKeyMD5AuthHandler(key_id, passwd)
    auth_handler.seq_num = seq_num
    # act
    data: bytearray = auth_handler.add_auth(msg_in)
    logging.info(hr_bytes(data))
    msg_out, auth_out = msg_factory(data)
    logging.info(hr_bytes(auth_out.hash))
    # assert
    assert msg_in == msg_out
    assert auth_in == auth_out


def test_md5mkey_check():
    # arrange
    passwd: bytes = b"123456"
    _hash: bytes = tobytes("78 12 8b fe 57 cc ca 68 ed d8 5d 35 66 1f 60 5a")
    key_id: int = 1
    seq_num: int = 100
    sess: BFDSession = BFDSession("127.0.0.1", 1)
    msg_in: CtlPacket = CtlPacket()
    auth_in: MKeyMD5Auth = MKeyMD5Auth(key_id, seq_num, _hash)
    auth_handler: MKeyMD5AuthHandler = MKeyMD5AuthHandler(key_id, passwd)
    auth_handler.seq_num = seq_num
    data: bytes = bytes(auth_handler.add_auth(msg_in))
    mdata: memoryview = memoryview(bytearray(data))
    # act
    auth_handler.check_auth(auth_in, mdata, sess)
    # assert
    assert auth_handler.seq_num == seq_num + 1


def test_sha1key_add():
    # arrange
    passwd: bytes = b"123456"
    _hash: bytes = tobytes("76 4c b8 e0 e3 5e b2 bb f2 46 13 b1 f2 12 1c 7c ed 70 ba 8b")
    key_id: int = 1
    seq_num: int = 100
    msg_in: CtlPacket = CtlPacket()
    auth_in: KeySHA1Auth = KeySHA1Auth(key_id, seq_num, _hash)
    auth_handler: KeySHA1AuthHandler = KeySHA1AuthHandler(key_id, passwd)
    auth_handler.seq_num = seq_num
    # act
    data: bytearray = auth_handler.add_auth(msg_in)
    logging.info(hr_bytes(data))
    msg_out, auth_out = msg_factory(data)
    logging.info(hr_bytes(auth_out.hash))
    # assert
    assert msg_in == msg_out
    assert auth_in == auth_out


def test_sha1key_check():
    # arrange
    passwd: bytes = b"123456"
    _hash: bytes = tobytes("76 4c b8 e0 e3 5e b2 bb f2 46 13 b1 f2 12 1c 7c ed 70 ba 8b")
    key_id: int = 1
    seq_num: int = 100
    sess: BFDSession = BFDSession("127.0.0.1", 1)
    msg_in: CtlPacket = CtlPacket()
    auth_in: KeySHA1Auth = KeySHA1Auth(key_id, seq_num, _hash)
    auth_handler: KeySHA1AuthHandler = KeySHA1AuthHandler(key_id, passwd)
    auth_handler.seq_num = seq_num
    data: bytes = bytes(auth_handler.add_auth(msg_in))
    mdata: memoryview = memoryview(bytearray(data))
    # act
    auth_handler.check_auth(auth_in, mdata, sess)
    # assert
    assert auth_handler.seq_num == seq_num


def test_sha1mkey_add():
    # arrange
    passwd: bytes = b"123456"
    _hash: bytes = tobytes("f3 dd a7 4d 1b 50 99 4f 18 2d 65 55 cc 2f 6c d6 7a 24 39 d0")
    key_id: int = 1
    seq_num: int = 100
    msg_in: CtlPacket = CtlPacket()
    auth_in: MKeySHA1Auth = MKeySHA1Auth(key_id, seq_num, _hash)
    auth_handler: MKeySHA1AuthHandler = MKeySHA1AuthHandler(key_id, passwd)
    auth_handler.seq_num = seq_num
    # act
    data: bytearray = auth_handler.add_auth(msg_in)
    logging.info(hr_bytes(data))
    msg_out, auth_out = msg_factory(data)
    logging.info(hr_bytes(auth_out.hash))
    # assert
    assert msg_in == msg_out
    assert auth_in == auth_out


def test_sha1mkey_check():
    # arrange
    passwd: bytes = b"123456"
    _hash: bytes = tobytes("f3 dd a7 4d 1b 50 99 4f 18 2d 65 55 cc 2f 6c d6 7a 24 39 d0")
    key_id: int = 1
    seq_num: int = 100
    sess: BFDSession = BFDSession("127.0.0.1", 1)
    msg_in: CtlPacket = CtlPacket()
    auth_in: MKeySHA1Auth = MKeySHA1Auth(key_id, seq_num, _hash)
    auth_handler: MKeySHA1AuthHandler = MKeySHA1AuthHandler(key_id, passwd)
    auth_handler.seq_num = seq_num
    data: bytes = bytes(auth_handler.add_auth(msg_in))
    mdata: memoryview = memoryview(bytearray(data))
    # act
    auth_handler.check_auth(auth_in, mdata, sess)
    # assert
    assert auth_handler.seq_num == seq_num + 1