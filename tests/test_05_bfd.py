import pytest
import logging
from bfd import *
from asyncio import sleep, gather, wait_for, Future
from typing import Tuple, List, Optional
from functools import partial
import socket


class TestBFD:

    _auth_cases: List[Tuple[Optional[AuthHandlerObj], Optional[bytes]]] = [
        (None, None),
        (SimpleAuthHandler, b'pass1'),
        (KeySHA1AuthHandler, b'pass2'),
        (MKeySHA1AuthHandler, b'pass3'),
        (KeyMD5AuthHandler, b'pass4'),
        (MKeyMD5AuthHandler, b'pass5')
    ]

    @pytest.mark.asyncio
    async def test_context(self):
        # arrange
        config: BFDConfig = BFDConfig()
        # act
        async with BFD(config) as bfd:
            logging.info(bfd)
        # assert

    @pytest.mark.asyncio
    async def test_decode_err(self):
        # arrange
        config: BFDConfig = BFDConfig()
        # act
        async with BFD(config) as bfd:
            bfd.datagram_received(b'\x00\x00', ('127.0.0.1', 111), 0xFF)
            bfd.datagram_received(b'\x00\x00\x03', ('127.0.0.1', 111), 0xFF)
            assert bfd.counters.pkts_decode_err == 2
        # assert

    @pytest.mark.asyncio
    async def test_general_err(self):
        # arrange
        config: BFDConfig = BFDConfig()
        # act
        async with BFD(config) as bfd:
            bfd.datagram_received(1.0, 2, 0xFF)
            bfd.datagram_received(1.0, "dsds", 0xFF)
            assert bfd.counters.internal_errors == 2
        # assert

    @pytest.mark.parametrize("authcls, passwd", _auth_cases)
    @pytest.mark.asyncio
    async def test_auth_sess(self, authcls: AuthHandlerCls, passwd: bytes):
        # arrange
        addr1: str = '127.0.0.2'
        config1: BFDConfig = BFDConfig(addr1)
        addr2: str = '127.0.0.3'
        config2: BFDConfig = BFDConfig(addr2)
        # act
        async with BFD(config1) as bfd1, BFD(config2) as bfd2:
            sess1: BFDSession = bfd1.add_session(addr2)
            sess2: BFDSession = bfd2.add_session(addr1)
            if authcls:
                bfd1.add_auth(addr2, authcls, passwd)
                bfd2.add_auth(addr1, authcls, passwd)
            await wait_for(gather(sess1.wait_state(SessionState.Up),
                                  sess2.wait_state(SessionState.Up)), timeout=10)
            logging.info("All session up")
        # assert
        logging.info("EOT")

    @pytest.mark.asyncio
    async def test_up3(self):
        # arrange
        addr1: str = '127.0.0.2'
        config1: BFDConfig = BFDConfig(addr1)
        addr2: str = '127.0.0.3'
        config2: BFDConfig = BFDConfig(addr2)
        addr3: str = '127.0.0.4'
        config3: BFDConfig = BFDConfig(addr3)
        # act
        async with BFD(config1) as bfd1, BFD(config2) as bfd2, BFD(config3) as bfd3:
            sess12: BFDSession = bfd1.add_session(addr2)
            sess13: BFDSession = bfd1.add_session(addr3)

            sess21: BFDSession = bfd2.add_session(addr1)
            sess23: BFDSession = bfd2.add_session(addr3)

            sess31: BFDSession = bfd3.add_session(addr1)
            sess32: BFDSession = bfd3.add_session(addr2)

            await wait_for(gather(sess12.wait_state(SessionState.Up), sess13.wait_state(SessionState.Up),
                         sess21.wait_state(SessionState.Up), sess23.wait_state(SessionState.Up),
                         sess31.wait_state(SessionState.Up), sess32.wait_state(SessionState.Up)), timeout=10)
            logging.info("All session up")
        # assert
        logging.info("EOT")

    @pytest.mark.asyncio
    async def test_up3_auth(self):
        # arrange
        addr1: str = '127.0.0.2'
        config1: BFDConfig = BFDConfig(addr1)
        addr2: str = '127.0.0.3'
        config2: BFDConfig = BFDConfig(addr2)
        addr3: str = '127.0.0.4'
        config3: BFDConfig = BFDConfig(addr3)
        # act
        async with BFD(config1) as bfd1, BFD(config2) as bfd2, BFD(config3) as bfd3:
            sess12: BFDSession = bfd1.add_session(addr2)
            sess13: BFDSession = bfd1.add_session(addr3)
            bfd1.add_auth(addr2, SimpleAuthHandler, b'pass1')
            bfd1.add_auth(addr3, MKeySHA1AuthHandler, b'pass2')

            sess21: BFDSession = bfd2.add_session(addr1)
            sess23: BFDSession = bfd2.add_session(addr3)
            bfd2.add_auth(addr1, SimpleAuthHandler, b'pass1')
            bfd2.add_auth(addr3, MKeyMD5AuthHandler, b'pass3')

            sess31: BFDSession = bfd3.add_session(addr1)
            sess32: BFDSession = bfd3.add_session(addr2)
            bfd3.add_auth(addr1, MKeySHA1AuthHandler, b'pass2')
            bfd3.add_auth(addr2, MKeyMD5AuthHandler, b'pass3')

            await wait_for(gather(sess12.wait_state(SessionState.Up), sess13.wait_state(SessionState.Up),
                         sess21.wait_state(SessionState.Up), sess23.wait_state(SessionState.Up),
                         sess31.wait_state(SessionState.Up), sess32.wait_state(SessionState.Up)), timeout=10)
            logging.info("All sessions gathered")
        # assert
        logging.info("EOT")

    @pytest.mark.asyncio
    async def test_bad_auth(self):
        # arrange
        addr1: str = '127.0.0.2'
        config1: BFDConfig = BFDConfig(addr1)
        addr2: str = '127.0.0.3'
        config2: BFDConfig = BFDConfig(addr2)
        # act
        async with BFD(config1) as bfd1, BFD(config2) as bfd2:
            sess1: BFDSession = bfd1.add_session(addr2)
            bfd1.add_auth(addr2, SimpleAuthHandler, b'pass11')
            sess2: BFDSession = bfd2.add_session(addr1)
            bfd2.add_auth(addr1, SimpleAuthHandler, b'pass22')
            logging.info("Wait for 1 sec")
            await sleep(1)
            # assert
            assert sess1.counters.pkts_bad_auth
            assert sess2.counters.pkts_bad_auth
        logging.info("EOT")

    @pytest.mark.asyncio
    async def test_nosess(self):
        # arrange
        addr1: str = '127.0.0.2'
        config1: BFDConfig = BFDConfig(addr1)
        addr2: str = '127.0.0.3'
        config2: BFDConfig = BFDConfig(addr2)
        # act
        async with BFD(config1) as bfd1, BFD(config2) as bfd2:
            sess1: BFDSession = bfd1.add_session(addr2)
            logging.info("Wait for 1 sec")
            await sleep(1)
            # assert
            assert bfd2.counters.pkts_drop_no_sess
        logging.info("EOT")

    # @pytest.mark.asyncio
    # async def test_mikrotik(self):
    #     # arrange
    #     addr: str = '192.168.80.4'
    #     config: BFDConfig = BFDConfig(addr)
    #     # act
    #     async with BFD(config) as _bfd:
    #         sess1: BFDSession = _bfd.add_session(addr)
    #         await sess1.wait_state(SessionState.Up)
    #         await sleep(120)
    #     # assert
    #     logging.info("EOT")

    # @pytest.mark.asyncio
    # async def test_bfdd(self):
    #     # arrange
    #     addr: str = '192.168.80.1'
    #     config: BFDConfig = BFDConfig(addr)
    #     # act
    #     async with BFD(config) as _bfd:
    #         sess1: BFDSession = _bfd.add_session(addr)
    #         await sess1.wait_state(SessionState.Up)
    #         await sleep(120)
    #     # assert
    #     logging.info("EOT")

    # @pytest.mark.asyncio
    # async def test_juniper(self):
    #     # arrange
    #     addr: str = '192.168.80.83'
    #     config: BFDConfig = BFDConfig(addr)
    #     # act
    #     async with BFD(config) as _bfd:
    #         sess1: BFDSession = _bfd.add_session(addr)
    #         await sess1.wait_state(SessionState.Up)
    #         await sleep(120)
    #     # assert
    #     logging.info("EOT")

    # @pytest.mark.asyncio
    # async def test_juniper_msha1(self):
    #     # arrange
    #     addr: str = '192.168.80.83'
    #     config: BFDConfig = BFDConfig(addr)
    #     # act
    #     async with BFD(config) as _bfd:
    #         sess1: BFDSession = _bfd.add_session(addr)
    #         _bfd.add_auth(addr, MKeySHA1AuthHandler, b'pass')
    #         await sess1.wait_state(SessionState.Up)
    #         await sleep(120)
    #     # assert
    #     logging.info("EOT")

    # @pytest.mark.asyncio
    # async def test_juniper_msha1_pasv(self):
    #     # arrange
    #     addr: str = '192.168.80.83'
    #     config: BFDConfig = BFDConfig(addr)
    #     # act
    #     async with BFD(config) as _bfd:
    #         sess1: BFDSession = _bfd.add_session(addr, role=SessionRole.Passive)
    #         _bfd.add_auth(addr, MKeySHA1AuthHandler, b'pass')
    #         await sess1.wait_state(SessionState.Up)
    #         await sleep(120)
    #     # assert
    #     logging.info("EOT")

    # @pytest.mark.asyncio
    # async def test_juniper_sha1(self):
    #     # arrange
    #     addr: str = '192.168.80.83'
    #     config: BFDConfig = BFDConfig(addr)
    #     # act
    #     async with BFD(config) as _bfd:
    #         sess1: BFDSession = _bfd.add_session(addr)
    #         _bfd.add_auth(addr, KeySHA1AuthHandler, b'pass')
    #         await sess1.wait_state(SessionState.Up)
    #         await sleep(120)
    #     # assert
    #     logging.info("EOT")

    # @pytest.mark.asyncio
    # async def test_juniper_md5(self):
    #     # arrange
    #     addr: str = '192.168.80.83'
    #     config: BFDConfig = BFDConfig(addr)
    #     # act
    #     async with BFD(config) as _bfd:
    #         sess1: BFDSession = _bfd.add_session(addr)
    #         _bfd.add_auth(KeyMD5AuthHandler, b'pass')
    #         await sess1.wait_state(SessionState.Up)
    #         await sleep(120)
    #     # assert
    #     logging.info("EOT")

    # @pytest.mark.asyncio
    # async def test_juniper_mmd5(self):
    #     # arrange
    #     addr: str = '192.168.80.83'
    #     config: BFDConfig = BFDConfig(addr)
    #     # act
    #     async with BFD(config) as _bfd:
    #         sess1: BFDSession = _bfd.add_session(addr)
    #         _bfd.add_auth(MKeyMD5AuthHandler, b'pass')
    #         await sess1.wait_state(SessionState.Up)
    #         await sleep(120)
    #     # assert
    #     logging.info("EOT")

    # @pytest.mark.asyncio
    # async def test_juniper_simple(self):
    #     # arrange
    #     addr: str = '192.168.80.83'
    #     config: BFDConfig = BFDConfig(addr)
    #     # act
    #     async with BFD(config) as _bfd:
    #         sess1: BFDSession = _bfd.add_session(addr)
    #         _bfd.add_auth(SimpleAuthHandler, b'pass')
    #         await sess1.wait_state(SessionState.Up)
    #         await sleep(120)
    #     # assert
    #     logging.info("EOT")

    @pytest.mark.asyncio
    async def test_callback1(self):
        # arrange
        def _callback(fut: Future, sess: BFDSession, state: int):
            logging.warning("Callback with %s, %s" % (sess, SessionState(state)))
            if state == SessionState.Up:
                fut.set_result((sess, state))

        fut1: Future = Future()
        fut2: Future = Future()
        addr1: str = '127.0.0.2'
        config1: BFDConfig = BFDConfig(addr1)
        addr2: str = '127.0.0.3'
        config2: BFDConfig = BFDConfig(addr2)
        async with BFD(config1) as bfd1, BFD(config2) as bfd2:
            sess1: BFDSession = bfd1.add_session(addr2)
            sess2: BFDSession = bfd2.add_session(addr1)
            cb1, cb2 = partial(_callback, fut1), partial(_callback, fut2)
            bfd1.add_sess_callback(addr2, cb1)
            bfd2.add_sess_callback(addr1, cb2)
            # act
            fut1_res, fut2_res = await wait_for(gather(fut1, fut2), timeout=10)
            logging.info("act1")
            logging.info(bfd1._stwaiters)
            logging.info(bfd2._stwaiters)
            logging.info("act2")
            bfd1.del_sess_callback(addr2, cb1)
            bfd2.del_sess_callback(addr1, cb2)
            logging.info("assert")
            await gather(*(task for task, handlers in bfd1._stwaiters.values()),
                         *(task for task, handlers in bfd2._stwaiters.values()), return_exceptions=True)
            # assert
            assert not bfd1._stwaiters
            assert not bfd2._stwaiters
            assert fut1_res == (sess1, SessionState.Up)
            assert fut2_res == (sess2, SessionState.Up)
        logging.info("EOT")

    @pytest.mark.asyncio
    async def test_multiple_callbacks(self):
        # arrange
        def _callback(fut: Future, sess: BFDSession, state: int):
            logging.warning("Callback with %s, %s" % (sess, SessionState(state)))
            if state == SessionState.Up:
                fut.set_result((sess, state))

        fut11: Future = Future()
        fut12: Future = Future()
        fut21: Future = Future()
        fut22: Future = Future()
        addr1: str = '127.0.0.2'
        config1: BFDConfig = BFDConfig(addr1)
        addr2: str = '127.0.0.3'
        config2: BFDConfig = BFDConfig(addr2)
        async with BFD(config1) as bfd1, BFD(config2) as bfd2:
            sess1: BFDSession = bfd1.add_session(addr2)
            sess2: BFDSession = bfd2.add_session(addr1)
            cb11, cb12, cb21, cb22 = (partial(_callback, fut) for fut in (fut11, fut12, fut21, fut22))
            # act
            logging.warning("act1")
            bfd1.add_sess_callback(addr2, cb11)
            bfd1.add_sess_callback(addr2, cb12)
            bfd2.add_sess_callback(addr1, cb21)
            bfd2.add_sess_callback(addr1, cb22)
            logging.warning("act2")
            logging.info(bfd1._stwaiters)
            logging.info(bfd2._stwaiters)
            fut11_res, fut12_res, fut21_res, fut22_res = await wait_for(gather(fut11, fut12, fut21, fut22), timeout=10)
            logging.warning("act3")
            bfd1.del_sess_callback(addr2, cb11)
            bfd2.del_sess_callback(addr1, cb21)
            await sleep(1)
            assert len(bfd1._stwaiters) == 1
            assert len(bfd2._stwaiters) == 1
            bfd1.del_sess_callback(addr2, cb12)
            bfd2.del_sess_callback(addr1, cb22)
            await gather(*(task for task, handlers in bfd1._stwaiters.values()),
                         *(task for task, handlers in bfd2._stwaiters.values()), return_exceptions=True)
            # assert
            assert not bfd1._stwaiters
            assert not bfd2._stwaiters
            assert fut11_res == (sess1, SessionState.Up)
            assert fut12_res == (sess1, SessionState.Up)
            assert fut21_res == (sess2, SessionState.Up)
            assert fut22_res == (sess2, SessionState.Up)
            assert sess1.counters.chstate_down == sess2.counters.chstate_down == 0
        logging.info("EOT")

    @pytest.mark.asyncio
    async def test_migrate(self):
        # arrange
        addr1: str = '127.0.0.2'
        addr2: str = '127.0.0.3'
        addr_new: str = '127.0.0.4'
        config1: BFDConfig = BFDConfig(addr1)
        config2: BFDConfig = BFDConfig(addr2)
        async with BFD(config1) as bfd1, BFD(config2) as bfd2:
            sess1: BFDSession = bfd1.add_session(addr2, local_discr=1)
            sess2: BFDSession = bfd2.add_session(addr1, local_discr=2)
            await wait_for(gather(sess1.wait_state(SessionState.Up), sess2.wait_state(SessionState.Up)), timeout=10)
            logging.info("Change local ip address %s => %s for session %s" % (addr1, addr_new, sess1))
            config1.listen_addr = addr_new
            await bfd1.open()
            await sleep(1)
            await wait_for(gather(sess1.wait_state(SessionState.Up), sess2.wait_state(SessionState.Up)), timeout=100)
            # assert
            assert sess1.counters.chstate_down == sess2.counters.chstate_down == 0
        logging.info("EOT")

    @pytest.mark.asyncio
    async def test_ttl(self):
        # arrange
        addr1: str = '127.0.0.2'
        config1: BFDConfig = BFDConfig(addr1, ttl_rfc_check=True)
        addr2: str = '127.0.0.3'
        config2: BFDConfig = BFDConfig(addr2, ttl_rfc_check=True)
        # act
        async with BFD(config1) as bfd1, BFD(config2) as bfd2:
            logging.warning("Set TTL to 100")
            bfd2._sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 100)
            sess1: BFDSession = bfd1.add_session(addr2)
            sess2: BFDSession = bfd2.add_session(addr1)
            await sleep(1)
            # assert
            assert bfd1.counters.pkts_drop_bad_ttl > 0
            logging.info("All session up")
        logging.info("EOT")