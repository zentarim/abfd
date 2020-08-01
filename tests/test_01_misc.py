from bfd.misc import *
from bfd.const import *
import logging
import pytest
from asyncio import sleep
# from typing import List
import gc


def test_enum():
    # arrange
    val: int = 5
    # act
    # noinspection PyArgumentList
    logging.info(AuthType(val))
    logging.info(AuthType)
    # assert
    assert 10 == (AuthType.MKeySha1 + val)
    assert AuthType.MKeySha1 == val


def test_hr_bytes():
    # arrange
    bytedata: bytes = b'\x01\x02\x03\xff'
    strdata: str = '01 02 03 ff'
    # act
    retval: str = hr_bytes(bytedata)
    # assert
    assert strdata == retval


class TestWrap:

    _max_int = (MAX32, MAX64)

    @pytest.mark.parametrize("max_int", _max_int)
    def test_wrap_max(self, max_int: int):
        # arrange
        class Stub:
            attr = WrapInt(max_int)

            def __del__(self):
                logging.info("Del instance %s" % self)

            def __str__(self):
                return "%s: attr: %s" % (clname(self), self.attr)

        logging.info("Maxval now: %s (just under threshold)" % max_int)
        obj: Stub = Stub()
        obj.attr = max_int - 1
        logging.info(obj)
        assert obj.attr == max_int - 1
        # act
        logging.info("Increase by 1")
        obj.attr += 1
        # assert
        logging.info(obj)
        assert obj.attr == 0

    @pytest.mark.parametrize("max_int", _max_int)
    def test_wrap_min(self, max_int: int):
        # arrange
        class Stub:
            attr = WrapInt(max_int)

            def __del__(self):
                logging.info("Del instance %s" % self)

            def __str__(self):
                return "%s: attr: %s" % (clname(self), self.attr)

        logging.info("Maxval now: %s (just under threshold)" % max_int)
        obj: Stub = Stub()
        obj.attr = 1
        logging.info(obj)
        assert obj.attr == 1
        # act
        logging.info("Decrease by 1")
        obj.attr -= 1
        logging.info(obj)
        assert obj.attr == 0
        logging.info("Decrease by 1")
        obj.attr -= 1
        logging.info(obj)
        assert obj.attr == max_int - 1
        # assert

    @pytest.mark.parametrize("max_int", _max_int)
    def test_wrap_negative(self, max_int: int):
        # arrange
        class Stub:
            attr1 = WrapInt(max_int)
            attr2 = WrapInt(max_int)

            def __del__(self):
                logging.info("Del instance %s" % self)

            def __str__(self):
                return "%s: attr1: %s, attr2: %s" % (clname(self), self.attr1, self.attr2)

        obj1: Stub = Stub()
        obj2: Stub = Stub()
        # act
        obj1.attr1 = -2
        obj1.attr2 -= max_int
        obj2.attr1 = -5
        obj2.attr2 -= (max_int * 2)
        # assert
        logging.info(obj1)
        logging.info(obj2)
        assert obj1.attr1 == (max_int - 2)
        assert obj1.attr2 == 0
        assert obj2.attr1 == (max_int - 5)
        assert obj2.attr2 == 0

    @pytest.mark.parametrize("max_int", _max_int)
    def test_wrap_independency(self, max_int: int):
        # arrange
        class Stub:
            attr1 = WrapInt(MAX64)
            attr2 = WrapInt(MAX64)

            def __del__(self):
                logging.info("Del instance %s" % self)

            def __str__(self):
                return "%s: attr1: %s, attr2: %s" % (clname(self), self.attr1, self.attr2)

        class Stub2:
            attr1 = WrapInt(max_int)
            attr2 = WrapInt(max_int)

            def __del__(self):
                logging.info("Del instance %s" % self)

            def __str__(self):
                return "%s: attr1: %s, attr2: %s" % (clname(self), self.attr1, self.attr2)

        obj1: Stub = Stub()
        obj2: Stub2 = Stub2()
        obj3: Stub = Stub()
        obj4: Stub2 = Stub2()
        # act
        obj1.attr1 += 2
        obj1.attr2 += 3
        obj2.attr1 += 5
        obj2.attr2 += 7
        obj3.attr1 += 11
        obj3.attr2 += 13
        obj4.attr1 += 17
        obj4.attr2 += 19
        # assert
        logging.info(obj1)
        logging.info(obj2)
        logging.info(obj3)
        logging.info(obj4)
        assert obj1.attr1 == 2
        assert obj1.attr2 == 3
        assert obj2.attr1 == 5
        assert obj2.attr2 == 7
        assert obj3.attr1 == 11
        assert obj3.attr2 == 13
        assert obj4.attr1 == 17
        assert obj4.attr2 == 19

    @pytest.mark.parametrize("max_int", _max_int)
    def test_wrap_weakref(self, max_int: int):
        # arrange
        class Stub:
            attr = WrapInt(max_int)

            def __del__(self):
                logging.info("Del instance %s" % self)

            def __str__(self):
                return "%s: attr: %s" % (clname(self), self.attr)

        # act
        obj: Stub = Stub()
        obj.attr = 0
        obj2: Stub = Stub()
        obj2.attr = 0
        assert type(Stub.attr) is WrapInt
        # noinspection PyUnresolvedReferences
        assert len(Stub.attr._vault) == 2
        del obj
        del obj2
        gc.collect()
        # noinspection PyUnresolvedReferences
        assert not len(Stub.attr._vault)
