from asyncio import CancelledError, gather, get_event_loop, AbstractEventLoop, Task, Queue
from typing import Optional, Dict, List, Tuple, Generator, Set, Callable, Any, ByteString, Coroutine, AnyStr
from logging import Logger, getLogger
from .proto import *
from .bfd_config import *
from .bfd_session import *
from .misc import *
from .const import *
from .exceptions import *
from .auth_handlers import *
import socket
from datetime import datetime
from functools import partial
from ctypes import sizeof, c_size_t, c_int, c_uint32
from contextlib import suppress


__all__ = ['BFD']

StateCallback = Callable[[BFDSession, int], None]
_AuthHandler = Callable[[CtlPacket, BFDSession, memoryview], str]
IP_RECVTTL = 12     # Couldn't find that const in socket module


async def msg_gen(sock: socket.socket, maxsize: int = 65536, qsize: int = 32) -> \
        Generator[Tuple[bytes, Tuple[str, int], int], Any, None]:
    """
    This thing is really ugly, but it does the job.
    Generate message bytes and TTL out of 'recvmsg' from a DGRAM socket
    :param sock:
        socket object
    :param maxsize:
        recvmsg maxsize
    :param qsize:
        Async queue size
    :return:
        Generates tuple with message bytes and ttl value.
    """
    loop: AbstractEventLoop = get_event_loop()
    queue: Queue = Queue(qsize)
    # http://man7.org/linux/man-pages/man7/ip.7.html
    # http://man7.org/linux/man-pages/man3/cmsg.3.html
    #                         cmsg_len,    cmsg_level,     cmsg_type,      cmsg_data (TTL, uint32)
    cmsghdr_len: int = sizeof(c_size_t) + sizeof(c_int) + sizeof(c_int) + sizeof(c_uint32)

    def _recvmsg_callback():
        try:
            retval = sock.recvmsg(maxsize, cmsghdr_len)
            queue.put_nowait(retval)
        except BaseException:
            queue.put_nowait(None)

    loop.add_reader(sock, _recvmsg_callback)
    try:
        while True:
            retval = await queue.get()
            if retval is None:
                return
            data, [(cmsg_level, cmsg_type, b_ttl)], flags, (ip, port) = retval
            if flags:
                raise OSError("Flags are non-zero: %s" % flags)
            yield data, (ip, port), int.from_bytes(b_ttl, byteorder='little', signed=False)
    finally:
        loop.remove_reader(sock)


def msg_factory(data: ByteString) -> Tuple[CtlPacket, Optional[AuthObj]]:
    """
    Receives a data (bytes, bytearray, memoryview) and returns a packet object and auth data
    :param data:
        data (bytes, bytearray, memoryview)
    :return:
        Packet object and auth data if present
    """
    try:
        if len(data) > CTL_LEN:
            msg: CtlPacket = CtlPacket.frombytes(data[:CTL_LEN])
            auth: AuthObj = AuthFactory(data[CTL_LEN:])
            return msg, auth
        return CtlPacket.frombytes(data), None
    except BaseException as err:
        raise DecodeError(str(err))


class BFDCounters:

    def __init__(self):
        self.start: datetime = datetime.now()
        self._iter: List[str] = []

    internal_errors = WrapInt(MAX64)
    pkts_recv = WrapInt(MAX64)
    pkts_decode_err = WrapInt(MAX64)
    pkts_drop_no_sess = WrapInt(MAX64)
    pkts_drop_bad_ttl = WrapInt(MAX64)
    _counters: Tuple[str, ...] = tuple(_ for _ in dir() if not _.startswith('_'))  # MUST be after all counters

    def __getitem__(self, item):
        return getattr(self, item)

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

    def __str__(self):
        return "Uptime: %s" % (datetime.now() - self.start)


class BFD:
    """
    Possible worklow:
    1) Open UDP server                                                                          open()
    2) Add some sessions                                                                        add_session()
    3) Add callbacks to session                                                                 add_sess_callback()
    4) <do some async stuff>
    5) Close UDP server, close daemon                                                           disconnect()
    6) Wait correct tasks completion                                                            wait_closed()
    """

    def __init__(self, config: BFDConfig, logger: Optional[Logger] = None):
        self._loop: AbstractEventLoop = get_event_loop()
        self._logger: Logger = logger or getLogger(__name__)
        self.config: BFDConfig = config
        self.counters: BFDCounters = BFDCounters()
        self._sessions_by_addr: Dict[str, BFDSession] = {}
        self._sessions_by_ld: Dict[int, BFDSession] = {}
        self._tasks: Set[Task] = set()
        self._auth_by_addr: Dict[str, AuthHandlerObj] = {}
        self._auth_by_keyid: Dict[int, AuthHandlerObj] = {}
        self._stwaiters: Dict[str, List[Task, Set[StateCallback]]] = {}
        self._read_task: Optional[Task] = None
        self._sock: Optional[socket.socket] = None

    def add_sess_callback(self, addr: str, callback: StateCallback):
        """
        Add callback to the session
        :param addr:
            Remote IP addr
        :param callback:
            Callback to run at the BFD session state changes
        :return:
        """
        if addr not in self._sessions_by_addr:
            raise SessionNotExists("Session for addr %s doesn't exist" % addr)
        elif callable(callback):
            self._logger.info("Add state callback %s to addr %s" % (callback, addr))
            task, statehandlers = self._stwaiters.get(addr, (None, set()))  # type: Optional[Task], Set[StateCallback]
            if not task:
                task: Task = self._schedule_task(self._state_waiter(addr, statehandlers))
                task.add_done_callback(partial(lambda _self, _addr, t: _self._stwaiters.pop(_addr, None), self, addr))
                self._stwaiters[addr] = [task, statehandlers]
            statehandlers.add(callback)
        else:
            raise RuntimeError("Callback %s is non-empty and not callable" % callback)

    def del_sess_callback(self, addr: str, callback: Optional[StateCallback] = None):
        """
        Remove callback from specific session
        :param addr:
            Remote IP addr
        :param callback:
            Callback to remove.
            If callback is None all callbacks will be removed
        :return:
        """
        task, statehandlers = self._stwaiters.get(addr, (None, set()))  # type: Optional[Task], Set[StateCallback]
        if not task:
            raise ValueError("No callbacks registered for addr %s" % addr)
        statehandlers.clear() if callback is None else statehandlers.discard(callback)
        if not statehandlers:
            self._logger.debug("StateHandlers is empty. Close callback task")
            task.cancel()

    async def _state_waiter(self, addr: str, callbacks: Set[StateCallback]):
        """
        This coro wraps in task. It waits for ANY session state changes in BFDsession and schedules callbacks into loop
        :param addr:
            remote ip addr
        :param callbacks:
            Set with callbacks.
            WARNING: By design this set could be changed during this task.
        :return:
        """
        sess: Optional[BFDSession] = self._sessions_by_addr.get(addr)
        if not sess:
            raise SessionNotExists("Session for addr %s not exists" % addr)
        try:
            while True:
                session_state: int = await sess.wait_state()
                [self._loop.call_soon(callback, sess, session_state) for callback in callbacks]
        except SessionCancelled as err:
            self._logger.debug("Session %s closed. Close waiter task")
        except CancelledError as err:
            self._logger.debug("State waiter task for addr %s closed" % addr)

    def send_msg(self, msg: CtlPacket, addr: str):
        """
        All BFD session call this callback with their args. BFD sessions don't have an info about authentication
        Try to find auth handler and add the auth info.
        :param msg:
            Control packet objects
        :param addr:
            IP address to send packet
        :return:
        """
        _auth: Optional[AuthHandlerObj] = self._auth_by_addr.get(addr)
        tobytes = _auth.add_auth if _auth else bytes
        self._send_raw(tobytes(msg), addr)

    def _send_raw(self, data: bytes, addr: str):
        if self._sock:
            self._logger.debug("Send %s bytes to %s:%s" % (len(data), addr, BFD_PORT))
            self._sock.sendto(data, (addr, BFD_PORT))
        else:
            self._logger.warning("Socket closed. drop %s bytes for %s:%s" % (len(data), addr, BFD_PORT))

    def _get_free_local_discr(self) -> int:
        return next((ld for ld in range(1, MAX32) if ld not in self._sessions_by_ld))

    def _get_free_key_id(self) -> int:
        return next((keyid for keyid in range(1, MAX8) if keyid not in self._auth_by_keyid))

    def add_session(self, addr: str, min_rx: Optional[int] = None, role: Optional[str] = None,
                    local_discr: Optional[int] = None) -> BFDSession:
        """
        Add session for remote IP addr
        :param addr:
            Remote IP addr
        :param min_rx:
            min_rx time  0.1 sec by default
        :param role:
            BFD role (Active/Passive). Active by default
        :param local_discr:
            Local discriminator
        :return:
            BFDSession object
        """
        local_discr: int = local_discr or self._get_free_local_discr()
        sess: BFDSession = BFDSession(addr, local_discr, min_rx, role)
        self._add_session(sess)
        return sess

    def _add_session(self, sess: BFDSession, auth_handler: Optional[AuthHandlerObj] = None):
        self._logger.debug("Add sess: %s" % sess)
        self._sessions_by_addr[sess.addr] = sess
        self._sessions_by_ld[sess.LocalDiscr] = sess
        if auth_handler:
            self._logger.debug("Add auth_handler %s for sess %s" % (AuthType(auth_handler.type), sess))
            self._auth_by_addr[sess.addr] = auth_handler
        sess.send_callable = self.send_msg
        sess.enable()

    def del_session_by_addr(self, addr: str) -> Optional[BFDSession]:
        """
        Remove session by remote IP
        :param addr:
            Remote IP
        :return:
            Disabled and closed BFD session object (to obtain final counters for example)
        """
        session: Optional[BFDSession] = self._sessions_by_addr.get(addr)
        if session:
            return self.del_session(session)

    def del_sess_byld(self, ld: int) -> Optional[BFDSession]:
        """
        Remove session by Local Discriminator
        :param ld:
            Local Discriminator
        :return:
            Disabled and closed BFD session object (to obtain final counters for example)
        """
        session: Optional[BFDSession] = self._sessions_by_ld.get(ld)
        if session:
            return self.del_session(session)

    def del_session(self, session: BFDSession) -> BFDSession:
        """
        Remove session by the object
        :param session:
            BFD session object
        :return:
            Disabled and closed BFD session object (to obtain final counters for example)
        """
        self._logger.debug("Del sess: %s" % session)
        session.disable()
        session.send_callable = None
        self._sessions_by_addr.pop(session.addr)
        self._sessions_by_ld.pop(session.LocalDiscr)
        self._auth_by_addr.pop(session.addr, None)
        self._schedule_task(session.wait_closed())
        return session

    def add_auth(self, addr: str, auth_cls: AuthHandlerCls, password: AnyStr) -> AuthHandlerObj:
        """
        Add auth info for the specfic remote IP addr
        :param addr:
            Remote IP
        :param auth_cls:
            Auth handler class (from bfd.auth_handlers.py)
        :param password:
            Password (str, bytes)
        :return:
            Auth handler object
        """
        if auth_cls not in tuple(AuthHandlerFactory.cls_mapping.values()):
            raise BadAuth("Incorrect Auth cls %s. Possible values: %s " %
                          (auth_cls, list(AuthHandlerFactory.cls_mapping.values())))
        key_id: int = self._get_free_key_id()
        if type(password) is str:
            password = password.encode('utf-8')
        auth: AuthHandlerObj = auth_cls(key_id, password)
        self._logger.debug("Add auth: %s" % auth)
        self._auth_by_addr[addr] = auth
        self._auth_by_keyid[key_id] = auth
        return auth

    def del_auth(self, addr: str) -> Optional[AuthHandlerObj]:
        """
        Del auth for the specific remote addr
        :param addr:
            IP addr
        :return:
            AuthHandler obj
        """
        auth: Optional[AuthHandlerObj] = self._auth_by_addr.pop(addr)
        if auth:
            return self._auth_by_keyid.pop(auth.key_id)

    def _check_auth(self, sess: BFDSession, auth: Optional[AuthObj],
                    auth_handler: Optional[AuthHandlerObj], mdata: memoryview):
        if not auth_handler and not auth:
            pass    # No auth in packet and no auth required.
        elif auth_handler and not auth:
            raise BadAuth("Empty auth. %s is required" % AuthType(auth_handler.type))
        elif not auth_handler and auth:
            raise BadAuth("%s auth received, but no auth is required" % AuthType(auth.type))
        elif auth_handler.type != auth.type:
            raise BadAuth("%s is required but %s auth received" %
                          (AuthType(auth_handler.type), AuthType(auth.type)))
        elif auth_handler:
            auth_handler.check_auth(auth, mdata, sess)
        else:
            raise Exception("Logic error in _check_auth")

    def _get_sess(self, msg: CtlPacket, addr: str) -> BFDSession:
        sess_by_ld: Optional[BFDSession] = self._sessions_by_ld.get(msg.your_discr)
        sess_by_addr: Optional[BFDSession] = self._sessions_by_addr.get(addr)
        if sess_by_ld is sess_by_addr and all((sess_by_ld, sess_by_addr)):
            return sess_by_ld   # remote_addr correct, ld correct
        elif not sess_by_ld and sess_by_addr:  # initial packet. Your discr still is 0
            return sess_by_addr
        elif sess_by_ld and not sess_by_addr:   # session with correct LD and auth, but IP unknown
            return self._migrate_sess_ip(sess_by_ld, addr)
        else:
            raise SessionNotExists("No sess for remote_addr %s and Local discr %s" % (addr, msg.your_discr))

    def _migrate_sess_ip(self, sess: BFDSession, new_ip: str) -> BFDSession:
        old_ip: str = sess.addr
        self._logger.debug("Migrate remote ip %s => %s for session %s" % (old_ip, new_ip, sess))
        sess.addr = new_ip
        self._sessions_by_addr.pop(old_ip, None)
        self._sessions_by_addr[new_ip] = sess
        return sess

    def datagram_received(self, data: bytes, addr: Tuple[str, int], ttl: int):
        """
        Calls at datagram receive.
        1) Make memoryview from datagram.
        2) if auth present - check auth
        3) send datagram to appropriate session

        If exception is raises, an appropriate counter increase
        :param data:
            Datagram bytes
        :param addr:
            Source ip address + udp port
        :param ttl:
            TTL of the packet
        :return:
        """
        try:
            if self.config.ttl_rfc_check and ttl != 0xFF:
                raise BadTTL("Got incorrect TTL: %s" % ttl)
            mdata: memoryview = memoryview(bytearray(data))
            # noinspection PyTypeChecker
            msg, _auth = msg_factory(mdata)      # type: CtlPacket, Optional[AuthObj]
            session: BFDSession = self._get_sess(msg, addr[0])
        except DecodeError as e:
            self.counters.pkts_decode_err += 1
            self._logger.error("Decode error: %s " % e)
        except SessionNotExists as e:
            self.counters.pkts_drop_no_sess += 1
            self._logger.error(str(e))
        except BadTTL as e:
            self.counters.pkts_drop_bad_ttl += 1
            self._logger.error(str(e))
        except BaseException as e:
            self.counters.internal_errors += 1
            self._logger.error("Internal error: %s " % e)
        else:
            auth_handler: Optional[AuthHandlerObj] = self._auth_by_addr.get(addr[0])
            try:
                if session.SessionState == SessionState.AdminDown:
                    # A sess in AdminDown state doesn't accept messages. Increase counter and do noting
                    session.counters.pkts_discard += 1
                else:
                    self._check_auth(session, _auth, auth_handler, mdata)
                    session.put(msg)
            except BadAuth as e:
                session.counters.pkts_bad_auth += 1
                self._logger.error("Bad auth %s" % e)
                session.SessionState = SessionState.Down
            except BaseException as e:
                self.counters.internal_errors += 1
                self._logger.error("Internal error occurred: %s " % e)

    def _task_finalizer(self, task: Task):
        """
        Runs at task finalization and removes task from self._tasks.
        :param task:
            Task to remove
        :return:
        """
        self._tasks.discard(task)
        with suppress(CancelledError):
            exception: Optional[BaseException] = task.exception()
            if exception:
                self._logger.error("Exception at task finalizer: %s" % exception)
                self.counters.internal_errors += 1

    def _open_socket(self):
        """
        Create UDP server manually due to necessity to set TTL
        :return:
            Socket object which is prepared for asyncio usage
        """
        self._sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if self.config.ttl_rfc_set:
            self._sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 0xFF)
        else:
            self._logger.warning("config.ttl_rfc_set is disabled. TTL is not RFC compatible now")
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, False)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        self._sock.setsockopt(socket.IPPROTO_IP, IP_RECVTTL, True)
        self._sock.bind((self.config.listen_addr, self.config.listen_port))
        self._logger.info("Open BFD on %s:%s" % self._sock.getsockname())
        self._sock.setblocking(False)

    async def _readloop(self):
        self._logger.debug("Enter readloop")
        with suppress(CancelledError):
            async for msg, source, ttl in msg_gen(self._sock):
                self._logger.debug("Recv %s bytes from %s:%s" % (len(msg), *source))
                self.datagram_received(msg, source, ttl)

    def _readtask_finalizer(self, task: Task): self._read_task = self._sock = None

    async def open(self):
        if self._read_task:
            self._logger.info("Restart BFD socket")
            self._close_read_task()
            await self._read_task
        self._open_socket()
        self._read_task = self._schedule_task(self._readloop())
        self._read_task.add_done_callback(self._readtask_finalizer)

    def _schedule_task(self, coro: Coroutine[Any, Any, Any]) -> Task:
        """
        Schedules task into running loop and adds it to self._task.
        self._tasks will be awaited at exit.
        :param coro:
            Coroutine to wrap into task
        :return:
            Task
        """
        task: Task = Task(coro)
        task.add_done_callback(self._task_finalizer)
        self._tasks.add(task)
        return task

    def _close_sessions(self):
        for session in list(self._sessions_by_addr.values()):
            self.del_session(session)

    def _close_read_task(self):
        if self._read_task and self._sock:
            self._logger.debug("Close sock %s:%s" % self._sock.getsockname())
            self._sock.close()
            self._read_task.cancel()    # By some reason recvmsg sometimes hangs on closed socket. Cancel task anyway

    def _cancel_waiters_tasks(self):
        for task, handlers in self._stwaiters.values():
            task.cancel()

    def close(self):
        self._logger.info("Close BFD")
        self._cancel_waiters_tasks()
        self._close_sessions()
        self._close_read_task()
        self.counters.clear()

    async def __aenter__(self):
        await self.open()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        self.close()
        await self.wait_closed()

    def __await__(self): return self.__aenter__().__await__()   # pragma: no cover

    async def wait_closed(self):
        if self._tasks:
            await gather(*list(self._tasks), return_exceptions=True)

    def __str__(self):
        return "%s process listening on %s (%s sessions)" % \
               (clname(self), self.config.listen_addr, len(self._sessions_by_addr))

