"""
Separate object to store config values.

I avoided usage of the 'dataclasses' module to ensure of Python 3.6 compatibility
"""
from .const import BFD_PORT

__all__ = ['BFDConfig']


class BFDConfig:
    """
    Attrubutes:
        `listen_addr`   IP address to listen on (default 0.0.0.0)
        `listen_port`   Listen port (default 3784)
        `ttl_rfc_set`   Whether or not set TTL to 255 at Control packet send
        `ttl_rfc_set`   Whether or not check ttl == 255 at Control packet receive
    """

    def __init__(self, listen_addr: str = '0.0.0.0', listen_port: int = BFD_PORT, ttl_rfc_set: bool = True,
                 ttl_rfc_check: bool = False):
        self.listen_addr: str = listen_addr
        self.listen_port: int = listen_port
        self.ttl_rfc_set: bool = ttl_rfc_set
        self.ttl_rfc_check: bool = ttl_rfc_check
