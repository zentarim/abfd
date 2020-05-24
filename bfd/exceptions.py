class SessionCancelled(Exception):  # pragma: no cover
    """
    If session is cancelled, all wait_state are cancelled with this exception.
    """


class DecodeError(Exception):  # pragma: no cover
    """
    Raises if an error is occurred at a packet decoding
    """


class SessionNotExists(Exception):  # pragma: no cover
    """
    Raises at recv Control packet from unexpected addr, with unexpected LD, etc...
    """


class BadAuth(Exception):  # pragma: no cover
    """
    Raises at authentication errors
    """


class BadTTL(Exception):  # pragma: no cover
    """
    Raises if recv TTL != 255
    """