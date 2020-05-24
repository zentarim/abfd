"""
Main idea of BFD session implementation is a having two tasks:
1) Send task, which periodically sends BFD messages. It stores in `_send_task`
This task consider the Event `_periodical_send_event` and sends Control Packet every `_local_send_intvl`

Also the realtime changes of values `_RemoteMinRxInterval`, `_DesiredMinTxInterval` or `_SessionState`
can trigger sending of Control Packet immediately by setting `_immediate_send_event`

2) Receive task, which is waiting Control packets from Queue `_recv_queue`. It stores in `_recv_task`
The task is waiting for a Control packet endlessly if `DemandMode` is True
or for `self._DetectionTime` / 1_000_000 if `DemandMode` is False

In case of timeout `SessionState` is setting to SessionDown. Awaiting process can be reset at `DemandMode` change
by queuing the None into `_recv_queue`

Both tasks start when setting the `SessionState` to `SessionState.Down`
Both tasks stops when setting the `SessionState` to `SessionState.AdminDown`

TODO:
    https://tools.ietf.org/html/rfc5880#section-6.8.16 isn't fully implemented. It
    For now if the local session goes down administratively, the remote site won't warned about it.

"""
from .misc import WrapInt
from .proto import *
from .const import *
from random import randint
from typing import Dict, Any, List, Optional, Set, Callable, Awaitable, Coroutine, Tuple
from asyncio import Future, Queue, Task, wait_for, gather, Event, AbstractEventLoop, get_event_loop, \
    TimeoutError as AsyncTimeoutError
from contextlib import suppress
from functools import partial
from itertools import filterfalse
from logging import Logger, getLogger


__all__ = ['BFDSession', 'SessCounters']

CbSend = Callable[[CtlPacket or bytes, str], None]


class SessCounters:

    pkts_recv = WrapInt(MAX64)
    pkts_sent = WrapInt(MAX64)
    pkts_proceed = WrapInt(MAX64)
    pkts_bad_auth = WrapInt(MAX64)
    pkts_discard = WrapInt(MAX64)
    poll_recv = WrapInt(MAX64)
    poll_sent = WrapInt(MAX64)
    final_recv = WrapInt(MAX64)
    final_sent = WrapInt(MAX64)
    expires = WrapInt(MAX64)
    chstate_admindown = WrapInt(MAX64)
    chstate_down = WrapInt(MAX64)
    chstate_init = WrapInt(MAX64)
    chstate_up = WrapInt(MAX64)
    _counters: Tuple[str, ...] = tuple(_ for _ in dir() if not _.startswith('_'))  # MUST be after all counters

    def __init__(self):
        self._iter: List[str] = []

    def __getitem__(self, item):
        return getattr(self, item)

    def __str__(self):
        return "Conters: RCV\\SNT\\PROC\\BADAUTH\\DSCRD: %s\\%s\\%s\\%s\\%s" % \
               (self.pkts_recv, self.pkts_sent, self.pkts_proceed, self.pkts_bad_auth, self.pkts_discard)

    def __iter__(self):
        self._iter = list(self._counters)
        return self

    def __next__(self) -> Tuple[str, int]:
        if not self._iter:
            raise StopIteration
        name: str = self._iter.pop()
        value: int = self[name]
        return name, value

    def clear(self):
        for countername in self._counters:
            setattr(self, countername, 0)


class BFDSession:
    """
    Attributes which are intended to be modified by the user in real time:
        `LocalDiscr`
        `DemandMode`
        `DetectMult`
        `RequiredMinRxInterval`
        `DesiredMinTxInterval`
        `Role`
        `SessionState`
        `addr`  Remote IP address

    Attributes which are intended to be modified by the remote side in real time:
        `RemoteSessionState`
        `RemoteDiscr`
        `RemoteDemandMode`
        `RemoteMinRxInterval`
        `RemoteDetectMult`
        `RemoteMinTxInterval`
        `RcvAuthSeq`
        `AuthSeqKnown`
        `LocalDiag`
        `DetectionTime`

    Most of all these attributes implemented as read/write properties to ensure call specific functions at changes.
    Actual values store in private variables prepended with suffix '_'.
    Example: `_RemoteSessionState`, `_RemoteDiscr`, etc...

    Specific Attributes:
        `counters` (SessCounters). Session counters objects.
        `_periodical_send_event` (Event) This event enables or disabled periodical dispatch of Control packets.
        It is always set when `_Role` == `Role.Active` and `_RemoteDemandMode` is False
            Otherwise it sets only if packet dispatch is necessary
        `_immediate_send_event` (Event) This event allows immediate sending of the CtlPacket
        `_StateFutures` (Dict). This dict holds Futures to work and await
        specific session state (AdminDown, Down, Init, Up)
        `_recv_queue` (Queue). BFD daemon puts packets into this queue. This queue is handled by recv loop
        `send_callable` (Callable). This callable is used to the packet sending.
        `_recv_task` (Task). Receive task
        `_send_task` (Task). Send task
        `_poll_result` (Future). This future is intended to store the result of the poll sequence
        `_local_send_intvl` (Int). Agreed frequency of sending ControlPackets
        `RequiredMinEchoInterval` (int). Not implemented, Not used
        `_tasks` (Set). Set of all tasks for this object at the moment
        `_DetectionTime`. Agreed detection time
    """
    _default_min_rx: int = 100_000    # (0.1 sec)
    _default_detect_mult: int = 3

    def __init__(self, remote_addr: str, local_discr: int, min_rx: Optional[int] = None, role: Optional[str] = None,
                 logger: Optional[Logger] = None):
        self._logger: Logger = logger or getLogger()
        self._loop: AbstractEventLoop = get_event_loop()
        self.counters: SessCounters = SessCounters()
        self._LocalDiscr: int = local_discr
        self.name: str = str(local_discr)
        self._min_rx_arg: int = min_rx or self._default_min_rx
        self._role_arg: str = role or SessionRole.Active
        self._Role: str = self._role_arg
        self.AuthSeqKnown: bool = False
        self.RcvAuthSeq: int = 0
        self.addr: str = remote_addr
        self._SessionState: int = SessionState.AdminDown
        self._StateFutures: Dict[int, Set[Future]] = {}
        self._RemoteSessionState: int = SessionState.Down
        self._RemoteDiscr: int = 0
        self.LocalDiag: int = Diag.NoDiag
        self._DesiredMinTxInterval: int = self._min_rx_arg
        self._RequiredMinRxInterval: int = self._min_rx_arg
        self._RemoteMinRxInterval: int = 1
        self._RemoteMinTxInterval: int = 1
        self._DemandMode: bool = False
        self._RemoteDemandMode: bool = False
        self._DetectMult: int = self._default_detect_mult
        self._RemoteDetectMult: int = 0
        self._recv_queue: Queue[Optional[CtlPacket]] = Queue(32)
        self.send_callable: Optional[CbSend] = None
        self._recv_task: Optional[Task] = None
        self._send_task: Optional[Task] = None
        self._poll_result: Optional[Future] = None
        self._local_send_intvl: int = self._DesiredMinTxInterval
        self._immediate_send_event: Event = Event()
        self._periodical_send_event: Event = Event()
        self._DetectionTime: int = 1_000_000
        self.RequiredMinEchoInterval: int = 0   # TODO: Not implemented. should be 0
        self._tasks: Set[Task] = set()

    @property
    def DetectionTime(self) -> int: return self._DetectionTime

    def _set_LocalDiscr(self, value: int):
        if self._LocalDiscr != value:
            self._LocalDiscr = value
            self._logger.info("%s LocalDiscr changed to %s" % (repr(self), value))
            self._schedule_task(self.poll())

    LocalDiscr: int = property(fset=_set_LocalDiscr, fget=lambda self: self._LocalDiscr)

    def _set_RemoteSessionState(self, value: int):
        if self._RemoteSessionState is not value:
            self._RemoteSessionState = value
            self._logger.info("%s RemoteSessionState changed to %s" % (repr(self), SessionState(value)))
            self._update_permission_to_send()

    RemoteSessionState: int = property(fset=_set_RemoteSessionState, fget=lambda self: self._RemoteSessionState)

    def _set_RemoteDiscr(self, value: int):
        if self._RemoteDiscr != value:
            self._RemoteDiscr = value
            self._logger.info("%s RemoteDiscr changed to %s" % (repr(self), value))
            self._update_permission_to_send()

    RemoteDiscr: int = property(fset=_set_RemoteDiscr, fget=lambda self: self._RemoteDiscr)

    def _set_DemandMode(self, value: bool):
        if self._DemandMode is not value:
            self._DemandMode = value
            self._logger.info("%s DemandMode changed to %s." % (repr(self), value))
            self._recalc_detect_time()
            self._update_permission_to_send()
            if value:
                self._recv_queue.put_nowait(None)     # TODO: should be await put somewhere
            self._schedule_task(self.poll())

    DemandMode: bool = property(fset=_set_DemandMode, fget=lambda self: self._DemandMode)

    def _set_RemoteDemandMode(self, value: bool):
        if self._RemoteDemandMode != value:
            self._RemoteDemandMode = value
            if value:
                self._logger.info("%s RemoteDemandMode changed to True. Cease packets transmission" % repr(self))
            else:
                self._logger.info("%s RemoteDemandMode changed to False. Resume packets transmission" % repr(self))
            self._update_permission_to_send()

    RemoteDemandMode: bool = property(fset=_set_RemoteDemandMode, fget=lambda self: self._RemoteDemandMode)

    def _set_RemoteMinRxInterval(self, value: int):
        if self._RemoteMinRxInterval != value:
            if value:
                self._logger.info("%s RemoteMinRxInterval changed to %s" % (repr(self), value))
            else:
                self._logger.info("%s Remote request to cease packet transmission" % repr(self))
            self._RemoteMinRxInterval = value
            self._recalc_tx_intvl()
            self._recalc_detect_time()
            self._update_permission_to_send()

    RemoteMinRxInterval: int = property(fset=_set_RemoteMinRxInterval, fget=lambda self: self._RemoteMinRxInterval)

    def _set_DetectMult(self, value: int):
        if self._DetectMult != value:
            self._logger.info("%s DetectMult changed to %s" % (repr(self), value))
            self._DetectMult = value

    DetectMult: int = property(fset=_set_DetectMult, fget=lambda self: self._DetectMult)

    def _set_RemoteDetectMult(self, value: int):
        if self._RemoteDetectMult != value:
            self._logger.info("%s RemoteDetectMult changed to %s" % (repr(self), value))
            self._RemoteDetectMult = value
            self._recalc_detect_time()

    RemoteDetectMult: int = property(fset=_set_RemoteDetectMult, fget=lambda self: self._RemoteDetectMult)

    def _set_RequiredMinRxInterval(self, value: int):
        if self._RequiredMinRxInterval != value:
            self._logger.info("%s RequiredMinRxInterval changed to %s" % (repr(self), value))
            self._RequiredMinRxInterval = value
            self._recalc_detect_time()

    RequiredMinRxInterval: int = property(fset=_set_RequiredMinRxInterval, fget=lambda self: self._RequiredMinRxInterval)

    def _set_DesiredMinTxInterval(self, value: int):
        if self._DesiredMinTxInterval != value:
            self._logger.info("%s DesiredMinTxInterval changed to %s" % (repr(self), value))
            self._DesiredMinTxInterval = value
            self._recalc_tx_intvl()
            self._recalc_detect_time()

    DesiredMinTxInterval: int = property(fset=_set_DesiredMinTxInterval, fget=lambda self: self._DesiredMinTxInterval)

    def _set_RemoteMinTxInterval(self, value: int):
        if self._RemoteMinTxInterval != value:
            self._logger.info("%s RemoteMinTxInterval changed to %s" % (repr(self), value))
            self._RemoteMinTxInterval = value
            self._recalc_tx_intvl()
            self._recalc_detect_time()

    RemoteMinTxInterval: int = property(fset=_set_RemoteMinTxInterval, fget=lambda self: self._RemoteMinTxInterval)

    def _set_Role(self, value: str):
        if self._Role != value:
            self._logger.debug("%s Role changed to %s" % (repr(self), value))
            self._Role = value
            self._update_permission_to_send()

    Role: str = property(fset=_set_Role, fget=lambda self: self._Role)

    def _set_SessionState(self, state: int):
        if self._SessionState == SessionState.AdminDown and state not in (SessionState.Down, SessionState.AdminDown):
            raise ValueError("Session state 'AdminDown' can be changed only to 'Down'")
        elif self._SessionState != state:
            self._logger.info("%s SessionState %s => %s" %
                         (repr(self), SessionState(self._SessionState), SessionState(state)))
            if state == SessionState.Down and self._SessionState != SessionState.AdminDown:
                # Do not increase 'Down' counter at session enabling (AdminDown => Down)
                self.counters.chstate_down += 1
            self._SessionState = state
            for future in filterfalse(Future.done, self._StateFutures.setdefault(state, set())):    # type: Future
                self._logger.debug("%s Someone waited for state %s" % (repr(self), SessionState(state)))
                future.set_result(state)
            if state == SessionState.Down:
                self._clear_remote_vars()
                self._start_send_task()
                self._start_recv_task()
            elif state == SessionState.AdminDown:
                self.counters.chstate_admindown += 1
                self._disable_session()
            elif state == SessionState.Init:
                self.counters.chstate_init += 1
                self.LocalDiag = Diag.NoDiag
                self._immediate_send_event.set()
            else:   # Up:
                self.counters.chstate_up += 1
                self.LocalDiag = Diag.NoDiag
                self._immediate_send_event.set()
            self._recalc_tx_intvl()
            self._recalc_detect_time()
            self._update_permission_to_send()

    SessionState = property(fset=_set_SessionState, fget=lambda self: self._SessionState)

    def _schedule_task(self, coro: Coroutine[Any, Any, Any]):
        """
        All tasks in scope of this object should be scheduled through this method. At exit these tasks will be
        awaited in the `wait_closed` method. They accompanied by the done callback, which removes task from `_tasks`
        :param coro:
            Coroutine to wrapping into task
        :return:
        """
        task: Task = Task(coro)
        task.add_done_callback(partial(lambda _self, _task: _self._tasks.discard(_task), self))
        self._tasks.add(task)

    def _clear_remote_vars(self):
        self._logger.debug("%s Сlear remote vars" % repr(self))
        self._RemoteMinRxInterval = 1
        self._RemoteDemandMode = False
        self._RemoteDiscr = 0
        self._RemoteSessionState = SessionState.Down
        self._RemoteDetectMult = 0
        self._RemoteMinTxInterval = 1

    async def _apply_detect_time(self, detection_time: int):
        await self.poll()
        self._logger.info("%s: Apply Detection Time value: %s" % (repr(self), detection_time))
        self._DetectionTime = detection_time

    async def _apply_tx_intvl(self, tx_intvl: int):
        await self.poll()
        self._logger.info("%s: Apply TX interval value: %s" % (repr(self), tx_intvl))
        self._local_send_intvl: int = tx_intvl

    def _update_permission_to_send(self):
        """
        Calls when `_periodical_send_event`, `_Role`, `_RemoteMinRxInterval`, `_RemoteDemandMode`, `_SessionState` or
        `_RemoteSession_state` is changed. That gives ability to send a Control packet even if `_Role` is Passive
        :return:
        """
        prev: bool = self._periodical_send_event.is_set()
        if self._Role == SessionRole.Passive and not self._RemoteDiscr:
            self._periodical_send_event.clear()
        elif not self._RemoteMinRxInterval:
            self._periodical_send_event.clear()
        elif self._RemoteDemandMode and self._SessionState == self._RemoteSessionState == SessionState.Up:
            self._periodical_send_event.clear()
        else:
            self._periodical_send_event.set()
        if prev is not self._periodical_send_event.is_set():
            self._logger.debug("%s: role_send_event is: %s" % (repr(self), self._periodical_send_event.is_set()))

    def _recalc_tx_intvl(self):
        """
        Compute and set new send interval. Calls when `RemoteMinRxInterval`, `DesiredMinTxInterval`,
        `RemoteMinTxInterval` or `SessionState` are changed.
        If the new send interval value more than the old one and SessionState is active
        then accept it only after a poll sequence.
        :return:
        """
        self._logger.debug("%s: Recalc TX intvl" % repr(self))
        transmit_intvl = max(self._RemoteMinRxInterval, self._DesiredMinTxInterval) \
            if self._SessionState != SessionState.Down else 1_000_000
        if transmit_intvl != self._local_send_intvl:
            if self._SessionState == SessionState.Up and transmit_intvl > self._local_send_intvl:
                self._logger.debug("%s Add poll task TX intvl %s => %s" %
                              (repr(self), self._local_send_intvl, transmit_intvl))
                self._schedule_task(self._apply_tx_intvl(transmit_intvl))
            else:
                self._logger.info("%s change TX intvl: %s => %s" % (repr(self), self._local_send_intvl, transmit_intvl))
                self._local_send_intvl = transmit_intvl
                self._immediate_send_event.set()

    def _recalc_detect_time(self):
        """
        Compute and set the `DetectionTime`. Calls when `DemandMode`, `RemoteMinRxInterval`, `RemoteDetectMult`,
        `RequiredMinRxInterval`, `DesiredMinTxInterval` , `RemoteMinTxInterval` or `SessionState` are changed.
        If the new detection time value less then current one and SessionState is active
        then accept it only after a poll sequence.
        :return:
        """
        self._logger.debug("%s: Recalc Detect time" % repr(self))
        if self._SessionState not in (SessionState.Up, SessionState.Init):
            detection_time: int = 1_000_000
        elif self._DemandMode:
            detection_time: int = max(self._RemoteMinRxInterval, self._DesiredMinTxInterval) * self._DetectMult
        else:
            detection_time: int = max(self._RequiredMinRxInterval, self._RemoteMinTxInterval) * self._RemoteDetectMult
        if detection_time != self._DetectionTime:
            if self._SessionState == SessionState.Up and detection_time < self._DetectionTime:
                self._logger.debug("%s Add poll task DetectionTime %s => %s" %
                              (repr(self), self._DetectionTime, detection_time))
                self._schedule_task(self._apply_detect_time(detection_time))
            else:
                self._logger.info("%s change DetectionTime: %s => %s" % (repr(self), self._DetectionTime, detection_time))
                self._DetectionTime = detection_time

    def _stop_send_task(self):
        if self._send_task:
            self._logger.info("%s Cease packets transmit" % repr(self))
            self._send_task.cancel()

    def _start_send_task(self):
        if not self._send_task:
            self._logger.debug("%s Start SEND task" % repr(self))
            self._send_task: Task = self._loop.create_task(self._send_coro())
            self._send_task.add_done_callback(self._send_task_finalizer)

    def _stop_recv_task(self):
        if self._recv_task:
            self._logger.debug("%s Close recv loop" % repr(self))
            self._recv_task.cancel()

    def _start_recv_task(self):
        if not self._recv_task:
            self._logger.debug("%s Start RECV task" % repr(self))
            self._recv_task: Task = self._loop.create_task(self._coro_recv_task())
            self._recv_task.add_done_callback(self._recv_task_finalizer)

    async def _transmit_delay(self):
        """
        Wait for variable delay https://tools.ietf.org/html/rfc5880#section-6.8.7
        or return immediately after setting of the `_immediate_send_event`
        :return:
        """
        msg_delay: int = (self._local_send_intvl * (randint(75, 100) / 100)) / 1_000_000
        with suppress(AsyncTimeoutError):
            await wait_for(self._immediate_send_event.wait(), timeout=msg_delay)
        self._immediate_send_event.clear()

    async def _send_coro(self):
        """
        The main send loop coroutine. It starts when SessionState goes from AdminDown to Down
        :return:
        """
        while True:
            await self._periodical_send_event.wait()
            if self._RemoteDemandMode:
                self._periodical_send_event.clear()
            msg: CtlPacket = self._mk_msg()
            if self._poll_result:
                self._logger.debug("%s Send poll" % repr(self))
                msg.poll = True
                self.counters.poll_sent += 1
            self._send_msg(msg)
            self.counters.pkts_sent += 1
            await self._transmit_delay()

    def _set_sess_expired(self):
        if self._SessionState != SessionState.Down:
            self._logger.warning("%s: Session expired" % repr(self))
            self.SessionState = SessionState.Down
            self.LocalDiag = Diag.Expired
            self.counters.expires += 1

    async def _coro_recv_task(self):
        while True:
            timeout: Optional[int] = None if self._DemandMode else self._DetectionTime / 1_000_000
            self._logger.debug("%s Detect timeout: %s" % (repr(self), timeout or "infinity (Demand Mode)"))
            try:
                msg: Optional[CtlPacket] = await wait_for(self._recv_queue.get(), timeout=timeout)
                if msg:
                    self._process_msg(msg)
                    self.counters.pkts_proceed += 1
            except AsyncTimeoutError as e:
                self._set_sess_expired()

    def _update_sess_fields(self, msg: CtlPacket):  # DesiredMinTxInterval
        self.RemoteDiscr = msg.my_discr
        self.RemoteSessionState = msg.state
        self.RemoteDemandMode = msg.demand
        self.RemoteMinRxInterval = msg.min_rx_intvl
        self.RemoteMinTxInterval = msg.min_tx_intvl
        self.RemoteDetectMult = msg.detect_mult
        self.RequiredMinEchoInterval = 0   # TODO: Not implemented. should be 0

    def _process_msg(self, msg: CtlPacket):
        self._update_sess_fields(msg)
        if msg.state == SessionState.AdminDown:
            if self._SessionState != SessionState.Down:
                self._logger.info("%s Remote sess sent: AdminDown" % repr(self))
                self.LocalDiag = Diag.NeighborDown
                self.SessionState = SessionState.Down
        else:
            if self._SessionState == SessionState.Down:
                if msg.state == SessionState.Down:
                    self.SessionState = SessionState.Init
                elif msg.state == SessionState.Init:
                    self.SessionState = SessionState.Up
            elif self.SessionState == SessionState.Init:
                if msg.state in (SessionState.Init, SessionState.Up):
                    self.SessionState = SessionState.Up
            else:   # self.SessionState == SessionState.Up
                if msg.state == SessionState.Down:
                    self._logger.info("%s Remote sess sent: Down" % repr(self))
                    self.LocalDiag = Diag.NeighborDown
                    self.SessionState = SessionState.Down

        if msg.final and self._poll_result:
            self._logger.debug("%s poll answer received" % repr(self))
            self.counters.final_recv += 1
            self._poll_result.set_result(True)
        elif msg.poll:
            self._logger.debug("%s poll request received" % repr(self))
            self.counters.poll_recv += 1
            self._send_final()

    def _send_final(self):
        self._logger.debug("%s Send poll answer packet" % repr(self))
        msg: CtlPacket = self._mk_msg()
        msg.poll = False
        msg.final = True
        self._send_msg(msg)
        self.counters.final_sent += 1

    async def poll(self):
        """
        Run a poll sequence. Multiple calls can be executed simultaneously
        :return:
        """
        self._logger.debug("%s Run poll sequence" % repr(self))
        if not self._poll_result:
            self._logger.debug("%s Create poll future" % repr(self))
            self._poll_result = Future()
        if self._RemoteDemandMode:
            self._logger.debug("%s Send poll (demand)" % repr(self))
            self._periodical_send_event.set()
        try:
            await wait_for(self._poll_result, self._DetectionTime)
        except AsyncTimeoutError as err:
            self._logger.warning("%s Poll sequence timeout after %s" % (repr(self), self._DetectionTime))
            self.SessionState = SessionState.Down
        finally:
            self._poll_result = None

    def put(self, msg: CtlPacket, addr: Optional[str] = None):
        """
        A Control packet must be inserted through this method
        :param msg:
            Control packet object
        :param addr:
            Address (added solely for use in tests-tests)
        :return:
        """
        self._recv_queue.put_nowait(msg)
        self.counters.pkts_recv += 1

    async def wait_state(self, state: Optional[int] = None) -> int:
        """
        This coroutine allows to wait specific state of this session or returns at next session change.
        Multiple calls can be executed simultaneously.
        :param state:
            Awaitable state
        :return:
            Current state
        """
        if state is None:
            future: Future = Future()
            try:
                for stname, stvalue in SessionState.items():
                    self._StateFutures.setdefault(stvalue, set()).add(future)
                return await future
            finally:
                for stname, stvalue in SessionState.items():
                    self._StateFutures.setdefault(stvalue, set()).discard(future)
        elif state != self._SessionState:
            future: Future = Future()
            fset: Set[Future] = self._StateFutures.setdefault(state, set())
            try:
                fset.add(future)
                return await future
            finally:
                fset.discard(future)

    def _disable_session(self):
        self._clear_local()
        self._clear_remote_vars()
        err: RuntimeError = RuntimeError("Session: %s now is AdminStop" % self.name)
        for state, futset in self._StateFutures.items():
            for future in filterfalse(Future.done, futset):
                self._logger.debug("Cancel future: %s for state %s" % (future, state))
                future.set_exception(err)
        self._StateFutures.clear()
        if self._poll_result:
            self._poll_result.set_exception(err)
        self._stop_send_task()
        self._stop_recv_task()

    async def wait_closed(self):
        self._logger.debug("%s waiting for all tasks completion ..." % repr(self))
        waitlist: List[Optional[Awaitable[Any]]] = [self._recv_task, self._send_task, *self._tasks]
        if any(waitlist):
            await gather(*filter(None, waitlist), return_exceptions=True)

    def disable(self):
        """
        This is just shortcut to self.SessionState = SessionState.AdminDown
        :return:
        """
        self._logger.info("Disable sess: %s" % repr(self))
        self.SessionState = SessionState.AdminDown

    def enable(self):
        """
        This is entrypoint. Just shortcut for self.SessionState = SessionState.Down
        :return:
        """
        self._logger.info("Enable sess: %s" % repr(self))
        # self._update_permission_to_send()
        self.SessionState = SessionState.Down

    def _clear_local(self):
        self._logger.debug("%s Cleaning up local variables" % repr(self))
        self.AuthSeqKnown = False
        self.RcvAuthSeq = 0
        self._Role = self._role_arg
        self._SessionState = SessionState.AdminDown
        self.LocalDiag = Diag.NoDiag
        self._DesiredMinTxInterval = self._min_rx_arg
        self._RequiredMinRxInterval = self._min_rx_arg
        self._DetectMult = self._default_detect_mult
        # noinspection PyUnresolvedReferences
        self._recv_queue._queue.clear()
        self._local_send_intvl = self._DesiredMinTxInterval
        self._DetectionTime = 1_000_000
        self.RequiredMinEchoInterval = 0   # TODO: Not implemented. Always sould be 0

    def _mk_msg(self) -> CtlPacket:
        msg: CtlPacket = CtlPacket()
        msg.diag = self.LocalDiag
        msg.my_discr = self._LocalDiscr
        msg.your_discr = self._RemoteDiscr
        msg.state = self._SessionState
        msg.min_tx_intvl = self._DesiredMinTxInterval
        msg.min_rx_intvl = self._RequiredMinRxInterval
        msg.min_echo_rx_intvl = 0   # not implemented. Always 0
        msg.detect_mult = self._DetectMult
        msg.demand = self._DemandMode
        return msg

    def _send_msg(self, msg: CtlPacket):
        if self.send_callable is not None:
            self._logger.debug("%s sent: %s (%s)%s%s%s" % (repr(self), msg, Diag(msg.diag),
                " P" if msg.poll else "", " F" if msg.final else "", " D" if msg.demand else ""))
            self.send_callable(msg, self.addr)
        else:
            self._logger.error("%s Unable to send msg: %s. send_callable is empty" % (repr(self), msg))

    def __hash__(self):
        return hash((self.__class__, self.addr))

    def __eq__(self, other):
        return hash(self) == hash(other)

    def __ne__(self, other):
        return not hash(self) == hash(other)

    def __repr__(self):
        return "<Sess %s>" % self.name

    def __str__(self):
        return "Sess [%s] %s LD\RD: %s\\%s S\R: %s\\%s" % \
            (self.name, self.addr, self._LocalDiscr, self._RemoteDiscr, SessionState(self._SessionState), self._Role)

    def _recv_task_finalizer(self, task: Task):
        self._logger.debug("%s Recv task closed" % repr(self))
        self._recv_task = None
        # noinspection PyUnresolvedReferences
        self._recv_queue._queue.clear()     # By some reason this method isn't exposed. Not sure if it is a good idea.
        if not task.cancelled() and task.exception():
            self._logger.error("%s: RECV err %s" % (repr(self), task.exception()))

    def _send_task_finalizer(self, task: Task):
        self._logger.info("%s Packets transmission ceased" % repr(self))
        self._send_task = None
        if not task.cancelled() and task.exception():
            self._logger.error("%s: SEND err %s" % (repr(self), task.exception()))

    async def __aenter__(self):
        self.enable()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.disable()
        await self.wait_closed()

    def __call__(self):  # pragma: no cover
        self.enable()
