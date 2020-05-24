from typing import Union, Dict, Any, Optional, Iterator, Tuple
from itertools import chain

__all__ = ['T_Enum']

MetaVals = Union[int, str, float, None]


class EnumMeta(type):

    def __contains__(cls, item: MetaVals) -> bool:
        return item in cls.__reverse_map

    def __init__(cls, clname: str, *args):
        cls.__reverse_map: Dict[Any, str] = {value: key for key, value in
             chain(*(parent.__dict__.items() for parent in cls.__mro__))
             if isinstance(value, (str, int, float, type(None))) and not key.startswith('_')}
        super().__init__(clname, *args)

    def __call__(cls, value: MetaVals) -> Optional[str]:
        return cls.__reverse_map.get(value)

    def __str__(cls):
        return "Enum %s: [%s]" % (cls.__name__, ', '.join(("0x%02X" % value) if isinstance(value, int) else value
                                                          for value in cls.__reverse_map.keys()))

    def items(cls) -> Iterator[Tuple[str, Any]]:
        return ((value, key) for key, value in cls.__reverse_map.items())


class T_Enum(metaclass=EnumMeta):
    """
    Implements C-like enums through the metaclass EnumMeta
    """

    def __init__(self, value: MetaVals):
        """
        A workaround for pycharm, which wants to have the __init__ in this class regardless of
        the reimplemented __call__ in metaclass. It  allows to avoid of usage
            # noinspection PyArgumentList
        before sentences like this:
        T_enum(somevalue)

        It won't be actually called. This just a stub.
        :param value:
        """