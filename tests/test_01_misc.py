from bfd.misc import *
from bfd.const import *
import logging
import pytest
from asyncio import sleep
from typing import List
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
        # for i in range(10):
        #     obj.attr += 1
        #     logging.error(obj.attr)
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

    @pytest.mark.asyncio
    async def test_wrap3(self):
        # arrange
        class Stub:
            attr = WrapInt(MAX32)

            def __del__(self):
                logging.info("Del instance %s" % self)

        _list: List[Stub] = [Stub(), Stub()]
        # act
        _list[0].attr = 100
        _list[1].attr = 200
        _list[1].attr += 2000000000000000
        logging.info(_list[1].attr)
        logging.info("wait 1")
        await sleep(0.5)
        logging.info("clearing out")
        _list.clear()
        gc.collect()
        await sleep(0.5)
        gc.collect()
        await sleep(0.5)
        _list: List[Stub] = [Stub(), Stub()]
        _list[0].attr = 10000
        gc.collect()
        await sleep(0.5)
        _list.pop(0)
        gc.collect()
        gc.collect()
        logging.info("Dropping class")
        del _list
        instances: int = len(WrapInt._instances)
        del Stub
        gc.collect()
        assert len(WrapInt._instances) == (instances - 1)   # Class Stub is removed. WrapInt._instances must decrease
        await sleep(1)
        # assert
        logging.info('EOT')

    def test_wrap_negative(self):
        # arrange
        class Stub:
            attr1 = WrapInt(MAX64)
            attr2 = WrapInt(MAX64)

            def __del__(self):
                logging.info("Del instance %s" % self)

            def __str__(self):
                return "%s: attr1: %s, attr2: %s" % (clname(self), self.attr1, self.attr2)


        obj1: Stub = Stub()
        obj2: Stub = Stub()
        # act
        obj1.attr1 = -2
        obj1.attr2 -= MAX64
        obj2.attr1 = -5
        obj2.attr2 -= (MAX64 * 2)

        logging.info(obj1)
        logging.info(obj2)

        assert obj1.attr1 == (MAX64 - 2)
        assert obj1.attr2 == 0
        assert obj2.attr1 == (MAX64 - 5)
        assert obj2.attr2 == 0

    def test_wrap_independency(self):
        # arrange
        class Stub:
            attr1 = WrapInt(MAX64)
            attr2 = WrapInt(MAX64)

            def __del__(self):
                logging.info("Del instance %s" % self)

            def __str__(self):
                return "%s: attr1: %s, attr2: %s" % (clname(self), self.attr1, self.attr2)

        class Stub2:
            attr1 = WrapInt(MAX64)
            attr2 = WrapInt(MAX64)

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
