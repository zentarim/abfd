abfd: [Yet] Another BFD Daemon
=================
This project is intended to provide python BFD module designed for embedding.

Highlights:
* Based upon the [AsyncIO](https://www.python.org/dev/peps/pep-3156) framework
* Compatible with [RFC5880](https://tools.ietf.org/html/rfc5880)
* Implemented TTL setting and verification according to [RFC5881](https://tools.ietf.org/html/rfc5881)
* Has implemented Authentication mechanisms, Demand mode and Active\passive roles
* Has runtime sessions variables
* Compatible with a Juniper and Mikrotik BFD implementations
* Has compatibility with Python 3.6, 3.7, 3.8
* Can be embedded into another asyncio-based modules through callbacks
* Uses Py3 typing according to [PEP0484](https://www.python.org/dev/peps/pep-0484) as much as possible
* Checked by [Pytest](https://pypi.org/project/pytest) and [Coverage](https://pypi.org/project/coverage)

Usage
-----------------
Module intended to use like that:
```python
from asyncio import run
import logging
from bfd import SessionState, BFDSession, BFD, BFDConfig


def _callback(sess: BFDSession, state: int):
    logging.warning("Callback with %s, %s" % (sess, SessionState(state)))
    if state == SessionState.Up:
        logging.info("Session is UP")
    elif state == SessionState.Down:
        logging.info("Session is DOWN")


async def main():
    local_addr: str = "127.0.0.1"
    remote_addr: str = "127.0.0.2"
    config: BFDConfig = BFDConfig(local_addr)
    async with BFD(config) as bfd:
        sess: BFDSession = bfd.add_session(remote_addr)
        bfd.add_sess_callback(remote_addr, _callback)
        await sess.wait_state(SessionState.Up)
        logging.info("Doing some stuff here")


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    run(main())
```
For other examples please consider tests from file: ```tests/test_05_bfd.py```


Installation
-----------------
There is no installation packages provided. Sorry. 
Just place the ```bfd``` package wherever you need and import classes from it.

