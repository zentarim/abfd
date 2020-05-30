#!/usr/bin/env python3
from sys import version_info
if version_info < (3, 6, 0):
    raise RuntimeError("Not intended to run on the Python less than '3.6.0' Got version: '%s.%s.%s'" % version_info[:3])

if version_info < (3, 7, 0):
    try:
        import async_generator
    except ImportError:
        raise ImportError("You should install 'async_generator' package to run tests in Python %s.%s.%s"
                          % version_info[:3])

try:
    import pytest
except ImportError:
    raise ImportError("You should install 'pytest' package to run tests in Python %s.%s.%s" % version_info[:3])

try:
    import pytest_asyncio
except ImportError:
    raise ImportError("You should install 'pytest_asyncio' package to run tests in Python %s.%s.%s" % version_info[:3])

try:
    import pytest_cov
except ImportError:
    raise ImportError("You should install 'pytest-cov' package to run tests in Python %s.%s.%s" % version_info[:3])