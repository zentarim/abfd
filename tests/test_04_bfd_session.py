import pytest
try:
    # noinspection PyUnresolvedReferences
    from contextlib import asynccontextmanager
except ImportError:     # py3.6 compatible
    # noinspection PyUnresolvedReferences
    from async_generator import asynccontextmanager
from bfd import *
from typing import List, Awaitable, Any, Union, Optional
from asyncio import Task, get_event_loop ,Event, AbstractEventLoop, gather, wait, gather, sleep, CancelledError, \
    TimeoutError as AsyncTimeoutError
import logging
from itertools import chain


Numeric = Union[int, float]


class MultipleError(Exception):

    def __init__(self, exceptions: List[BaseException], msg: str = ''):
        self.exceptions: List[BaseException] = exceptions
        self.msg: str = msg

    def __str__(self):
        if self.msg:
            return "%s: %s" % (self.msg, str(self.exceptions))
        return str(self.exceptions)

    def __len__(self):
        return len(self.exceptions)


async def _ensure_run(coro: Awaitable[Any], event: Event) -> Any:
    event.set()
    logging.debug("Ensure of start coro %s" % coro)
    return await coro


@asynccontextmanager
async def ensure_task(*coros: Awaitable[Any], timeout: Optional[Numeric] = None) -> List[Task]:
    loop: AbstractEventLoop = get_event_loop()
    events: List[Event] = [Event() for _ in range(len(coros))]
    tasks: List[Task] = [loop.create_task(_ensure_run(coro, event)) for event, coro in zip(events, coros)]
    try:
        await gather(*map(Event.wait, events))
        yield tasks
    finally:
        done, pending = await wait(tasks, timeout=timeout)
        for task in pending:
            task.cancel()
        exceptions: List[BaseException] = [task.exception() for task in done if task.exception() is not None]
        if len(exceptions) == 1:
            raise exceptions[0]
        elif len(exceptions) == 2:
            raise MultipleError(exceptions)
        elif pending:
            raise AsyncTimeoutError(pending)


class TestCounters:

    def test_session_counters(self):
        # arrange
        obj: SessCounters = SessCounters()
        # act
        logging.info(obj.pkts_recv)
        logging.info(obj.pkts_sent)
        logging.info(obj.pkts_proceed)
        logging.info(obj.pkts_bad_auth)
        logging.info(obj.pkts_discard)
        obj.pkts_recv += 1
        obj.pkts_sent += 2
        obj.pkts_proceed += 3
        obj.pkts_bad_auth += 4
        obj.pkts_discard += 5
        logging.info(obj)
        # assert
        assert obj.pkts_recv == 1
        assert obj.pkts_sent == 2
        assert obj.pkts_proceed == 3
        assert obj.pkts_bad_auth == 4
        assert obj.pkts_discard == 5
        for name, value in obj:
            logging.info("%s = %s" % (name, value))

    def test_session_counters_clear(self):
        # arrange
        obj: SessCounters = SessCounters()
        logging.info(obj.pkts_recv)
        logging.info(obj.pkts_sent)
        logging.info(obj.pkts_proceed)
        logging.info(obj.pkts_bad_auth)
        logging.info(obj.pkts_discard)
        obj.pkts_recv += 1
        obj.pkts_sent += 2
        obj.pkts_proceed += 3
        obj.pkts_bad_auth += 4
        obj.pkts_discard += 5
        logging.info(obj)
        # act
        obj.clear()
        # assert
        assert obj.pkts_recv == obj.pkts_sent == obj.pkts_proceed == obj.pkts_bad_auth == obj.pkts_discard == 0
        for name, value in obj:
            logging.info("%s = %s" % (name, value))


class TestState:

    @pytest.mark.asyncio
    async def test_waitstate(self, event_loop: AbstractEventLoop):
        # arrange
        def setstate(sess: BFDSession, state: int):
            logging.info("Set state: %s" % SessionState(state))
            sess.SessionState = state

        session: BFDSession = BFDSession('127.0.0.1', 100)
        # act
        async with ensure_task(session.wait_state(SessionState.Up), session.wait_state(SessionState.Down)):
            event_loop.call_later(0.2, setstate, session, SessionState.Down)
            event_loop.call_later(0.4, setstate, session, SessionState.Init)
            event_loop.call_later(0.6, setstate, session, SessionState.Up)
            event_loop.call_later(0.8, setstate, session, SessionState.AdminDown)
        # assert
        await session.wait_state(SessionState.AdminDown)
        assert session.SessionState == SessionState.AdminDown
        assert not tuple(chain(*session._StateFutures.values()))
        logging.info("EOT")

    @pytest.mark.asyncio
    async def test_waitstate_stop(self, event_loop: AbstractEventLoop):
        # arrange
        session: BFDSession = BFDSession('127.0.0.1', 100)
        session.enable()
        # act
        with pytest.raises(RuntimeError):
            async with ensure_task(session.wait_state(SessionState.Up)):
                await sleep(0.5)
                logging.info("Closing sess. Wait for CancelledError in tasks")
                # session._close()
                session.disable()
        logging.info("EOT")


@pytest.mark.asyncio
async def test_session_role_act():
    # arrange
    addr: str = '127.0.0.1'
    local_discr: int = 100
    role: str = SessionRole.Active
    # act
    async with BFDSession(addr, local_discr, role=role) as sess:
        await sleep(2)
        logging.info(sess)
        logging.info(sess.counters)
        # assert
        assert sess.counters.pkts_sent > 0
        assert sess.counters.chstate_down == 0


@pytest.mark.asyncio
async def test_session_role_pasv():
    # arrange
    # act
    addr: str = '127.0.0.1'
    local_discr: int = 100
    role: str = SessionRole.Passive
    async with BFDSession(addr, local_discr, role=role) as sess:
        await sleep(2)
        logging.info(sess)
        logging.info(sess.counters)
        # assert
        assert sess.counters.pkts_sent == 0
        assert sess.counters.chstate_down == 0


@pytest.mark.asyncio
async def test_session_change_role():
    # arrange
    # act
    addr: str = '127.0.0.1'
    local_discr: int = 100
    role: str = SessionRole.Passive
    async with BFDSession(addr, local_discr, role=role) as sess:
        await sleep(2)
        logging.info(sess)
        logging.info(sess.counters)
        # assert
        assert sess.counters.pkts_sent == 0
        sess.Role = SessionRole.Active
        await sleep(2)
        assert sess.counters.pkts_sent > 0
        assert sess.counters.chstate_down == 0


@pytest.mark.asyncio
async def test_session_context_change_rd():
    # arrange
    # act
    addr: str = '127.0.0.1'
    local_discr: int = 100
    role: str = SessionRole.Passive
    async with BFDSession(addr, local_discr, role=role) as sess:
        await sleep(2)
        logging.info(sess)
        logging.info(sess.counters)
        # assert
        assert sess.counters.pkts_sent == 0
        sess.RemoteDiscr = 200
        await sleep(2)
        assert sess.counters.pkts_sent > 0
        assert sess.counters.chstate_down == 0


@pytest.mark.asyncio
async def test_session_change_minrx():
    # arrange
    # act
    addr: str = '127.0.0.1'
    local_discr: int = 100
    role: str = SessionRole.Active
    async with BFDSession(addr, local_discr, role=role) as sess:
        sess.RemoteMinRxInterval = 0
        await sleep(2)
        logging.info(sess)
        logging.info(sess.counters)
        # assert
        assert sess.counters.pkts_sent == 0
        sess.RemoteMinRxInterval = 1
        await sleep(2)
        assert sess.counters.pkts_sent > 0
        assert sess.counters.chstate_down == 0


class TestMultipleSessions:

    @pytest.mark.asyncio
    async def test_msess(self):
        # arrange
        addr: str = '127.0.0.1'
        async with BFDSession(addr, 100) as s100, BFDSession(addr, 200) as s200:
            s100.send_callable, s200.send_callable = s200.put, s100.put
            await sleep(2)
            # act
            logging.info("Change RX/TX")
            s100.RequiredMinRxInterval = 200_000
            s200.RequiredMinRxInterval = 100_000
            s200.DesiredMinTxInterval = 600_000
            await sleep(2)
            # assert
            assert s100.counters.chstate_down == s200.counters.chstate_down == 0

    @pytest.mark.asyncio
    async def test_sess_disable_enable(self):
        addr: str = '127.0.0.1'
        async with BFDSession(addr, 100) as s100, BFDSession(addr, 200) as s200:
            s100.send_callable, s200.send_callable = s200.put, s100.put
            await sleep(1)
            logging.warning("Disable sess 200")
            s200.disable()
            await sleep(2)
            logging.warning("Enable sess 200")
            s200.enable()
            await sleep(2)
            logging.warning("Disable sess 100")
            s100.disable()
            await sleep(2)
            logging.warning("Enable sess 100")
            s100.enable()
            await sleep(2)
            assert s100.counters.chstate_down == s200.counters.chstate_down == 1


class TestChangeRemoteState:

    @pytest.mark.asyncio
    async def test_ch_state_disable(self):
        # arrange
        addr: str = '127.0.0.1'
        async with BFDSession(addr, 100) as s100, BFDSession(addr, 200) as s200:
            s100.send_callable, s200.send_callable = s200.put, s100.put
            await sleep(2)
            s100_admindown = s100.counters.chstate_admindown
            s200_down = s200.counters.chstate_down
            # act
            logging.warning("Disable Session 100")
            s100.disable()
            await sleep(2)
            # assert
            assert s100_admindown + 1 == s100.counters.chstate_admindown
            assert s200_down + 1 == s200.counters.chstate_down
            assert s100.SessionState == SessionState.AdminDown
            assert s100.RemoteSessionState == SessionState.Down
            assert s200.RemoteSessionState == s200.SessionState == SessionState.Down


class TestChangeLocalDiscr:

    @pytest.mark.asyncio
    async def test_ch_discr1(self):
        # arrange
        discr: int = 0xFF
        addr: str = '127.0.0.1'
        async with BFDSession(addr, 100) as s100, BFDSession(addr, 200) as s200:
            s100.send_callable, s200.send_callable = s200.put, s100.put
            await sleep(2)
            # act
            logging.warning("Change local discr to %s" % discr)
            s100.LocalDiscr = discr
            await sleep(2)
            # assert
            assert s100.LocalDiscr == s200.RemoteDiscr == discr
            assert s100.counters.chstate_down == s200.counters.chstate_down == 0


class TestChangeRemoteMinRx:

    @pytest.mark.asyncio
    async def test_ch_minRx(self):
        # arrange
        min_rx: int = 1_000_000
        addr: str = '127.0.0.1'
        async with BFDSession(addr, 100) as s100, BFDSession(addr, 200) as s200:
            s100.send_callable, s200.send_callable = s200.put, s100.put
            await sleep(2)
            # act
            logging.warning("Change min_rx to %s" % min_rx)
            s100.RequiredMinRxInterval = min_rx
            await sleep(2)
            # assert
            assert s100.RequiredMinRxInterval == s200.RemoteMinRxInterval == min_rx
            assert s100.counters.chstate_down == s200.counters.chstate_down == 0


class TestChangeDetectMult:

    @pytest.mark.asyncio
    async def test_ch_dm1(self):
        # arrange
        detect_mult: int = 2
        addr: str = '127.0.0.1'
        async with BFDSession(addr, 100) as s100, BFDSession(addr, 200) as s200:
            s100.send_callable, s200.send_callable = s200.put, s100.put
            await sleep(2)
            # act
            logging.warning("Change detect_mult to %s" % detect_mult)
            s100.DetectMult = detect_mult
            await sleep(2)
            # assert
            assert s100.DetectMult == s200.RemoteDetectMult == detect_mult
            assert s100.counters.chstate_down == s200.counters.chstate_down == 0


class TestChangeRequiredMinRxInterval:

    @pytest.mark.asyncio
    async def test_ch_minrx1(self):
        # arrange
        RequiredMinRxInterval: int = 2_000_000
        addr: str = '127.0.0.1'
        async with BFDSession(addr, 100) as s100, BFDSession(addr, 200) as s200:
            s100.send_callable, s200.send_callable = s200.put, s100.put
            await sleep(2)
            # act
            logging.warning("Change RequiredMinRxInterval to %s" % RequiredMinRxInterval)
            s100.RequiredMinRxInterval = RequiredMinRxInterval
            await sleep(2)
            # assert
            assert s100.RequiredMinRxInterval == s200.RemoteMinRxInterval == RequiredMinRxInterval
            assert s100.counters.chstate_down == s200.counters.chstate_down == 0


class TestChangeDesiredMinTxInterval:

    @pytest.mark.asyncio
    async def test_ch_mintx1(self):
        # arrange
        DesiredMinTxInterval: int = 2_000_000
        addr: str = '127.0.0.1'
        async with BFDSession(addr, 100) as s100, BFDSession(addr, 200) as s200:
            s100.send_callable, s200.send_callable = s200.put, s100.put
            await sleep(2)
            # act
            logging.warning("Change DesiredMinTxInterval to %s" % DesiredMinTxInterval)
            s100.DesiredMinTxInterval = DesiredMinTxInterval
            await sleep(2)
            # assert
            assert s100.counters.chstate_down == s200.counters.chstate_down == 0


class TestPassiveRole:

    @pytest.mark.asyncio
    async def test_role1(self):
        # arrange
        role: str = SessionRole.Passive
        addr: str = '127.0.0.1'
        async with BFDSession(addr, 100, role=role) as s100, BFDSession(addr, 200, role=role) as s200:
            s100.send_callable, s200.send_callable = s200.put, s100.put
            await sleep(2)
            # act
            logging.warning("Change Role to Active for sess 100")
            s100.Role = SessionRole.Active
            await sleep(2)
            # assert
            assert s100.SessionState == s100.RemoteSessionState == \
                   s200.SessionState == s200.RemoteSessionState == SessionState.Up
            assert s100.counters.chstate_down == s200.counters.chstate_down == 0

    @pytest.mark.asyncio
    async def test_role2(self):
        # arrange
        role: str = SessionRole.Passive
        addr: str = '127.0.0.1'
        async with BFDSession(addr, 100, role=role) as s100, BFDSession(addr, 200, role=role) as s200:
            s100.send_callable, s200.send_callable = s200.put, s100.put
            await sleep(2)
            # act
            logging.warning("Change Role to Active for sess 100")
            s100.Role = SessionRole.Active
            await sleep(2)
            # assert
            assert s100.counters.chstate_down == s200.counters.chstate_down == 0
            assert s100.SessionState == s100.RemoteSessionState == \
                   s200.SessionState == s200.RemoteSessionState == SessionState.Up
            s200.disable()
            await sleep(2)
            assert s200.SessionState == SessionState.AdminDown
            assert s200.RemoteSessionState == SessionState.Down
            assert s100.SessionState == SessionState.Down
            assert s100.RemoteSessionState == SessionState.Down
            s200.enable()
            await sleep(3)
            assert s100.SessionState == s100.RemoteSessionState == \
                   s200.SessionState == s200.RemoteSessionState == SessionState.Up
            assert s100.counters.chstate_down == 1
            assert s200.counters.chstate_down == 0


class TestDemand:

    @pytest.mark.asyncio
    async def test_demand1(self):
        # arrange
        addr: str = '127.0.0.1'
        async with BFDSession(addr, 100) as s100, BFDSession(addr, 200) as s200:
            s100.send_callable, s200.send_callable = s200.put, s100.put
            await sleep(2)
            # act
            logging.warning("Change DemandMode for sess 100")
            s100.DemandMode = True
            await sleep(2)
            await s100.poll()
            await sleep(2)
            # assert
            assert s100.counters.chstate_down == s200.counters.chstate_down == 0
            assert s100.SessionState == s100.RemoteSessionState == \
                   s200.SessionState == s200.RemoteSessionState == SessionState.Up

    @pytest.mark.asyncio
    async def test_demand2(self):
        # arrange
        addr: str = '127.0.0.1'
        async with BFDSession(addr, 100) as s100, BFDSession(addr, 200) as s200:
            s100.send_callable, s200.send_callable = s200.put, s100.put
            await sleep(2)
            # act
            logging.warning("Change DemandMode for sess 100")
            s100.DemandMode = True
            await sleep(2)
            await s100.poll()
            await sleep(2)
            s100.DesiredMinTxInterval = 2_000_000
            await sleep(2)
            # assert
            assert s100.counters.chstate_down == s200.counters.chstate_down == 0
            assert s100.SessionState == s100.RemoteSessionState == \
                   s200.SessionState == s200.RemoteSessionState == SessionState.Up

    @pytest.mark.asyncio
    async def test_demand3(self):
        # arrange
        addr: str = '127.0.0.1'
        async with BFDSession(addr, 100) as s100, BFDSession(addr, 200) as s200:
            s100.send_callable, s200.send_callable = s200.put, s100.put
            await sleep(2)
            # act
            logging.warning("Enable DemandMode for sess 100")
            s100.DemandMode = True
            logging.warning("Enable DemandMode for sess 200")
            s200.DemandMode = True
            await sleep(2)
            await gather(s100.poll(), s200.poll())
            await sleep(2)
            logging.warning("Disable DemandMode for sess 100")
            s100.DemandMode = False
            logging.warning("Disable DemandMode for sess 200")
            s200.DemandMode = False
            await sleep(2)
            # assert
            assert s100.counters.chstate_down == s200.counters.chstate_down == 0
            assert s100.SessionState == s100.RemoteSessionState == \
                   s200.SessionState == s200.RemoteSessionState == SessionState.Up

    @pytest.mark.asyncio
    async def test_demand4(self):
        # arrange
        addr: str = '127.0.0.1'
        async with BFDSession(addr, 100) as s100, BFDSession(addr, 200) as s200:
            s100.send_callable, s200.send_callable = s200.put, s100.put
            await sleep(2)
            # act
            logging.warning("Enable DemandMode for sess 100")
            s100.DemandMode = True
            logging.warning("Enable DemandMode for sess 200")
            s200.DemandMode = True
            await sleep(2)
            s100.RequiredMinRxInterval = 1_000_000
            s200.RequiredMinRxInterval = 1_000_000
            await sleep(2)
            logging.warning("Disable DemandMode for sess 100")
            s100.DemandMode = False
            logging.warning("Disable DemandMode for sess 200")
            s200.DemandMode = False
            await sleep(6)
            # assert
            assert s100.counters.chstate_down == s200.counters.chstate_down == 0
            assert s100.SessionState == s100.RemoteSessionState == \
                   s200.SessionState == s200.RemoteSessionState == SessionState.Up


class TestAsyncGetState:

    @pytest.mark.asyncio
    async def test_asyncgen_state(self):
        # arrange
        async def waiter(sess: BFDSession, arr_len: int) -> List[int]:
            retval: List[int] = []
            while len(retval) != arr_len:
                state: int = await sess.wait_state()
                retval.append(state)
            return retval

        addr: str = '127.0.0.1'
        async with BFDSession(addr, 100) as s100, BFDSession(addr, 200) as s200:
            s100.send_callable, s200.send_callable = s200.put, s100.put
            # act
            await sleep(2)
            task: Task = Task(waiter(s100, 3))
            s200.disable()
            await sleep(1)
            s200.enable()
            result: List[int] = await task

        assert result == [1, 2, 3]
