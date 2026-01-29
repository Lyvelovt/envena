import logging
import math
from time import sleep
from typing import Any, Callable, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, field_validator

from src.envena.core.logger import ROOT_LOGGER_NAME


class BaseProtocol(BaseModel):
    model_config = ConfigDict(extra="ignore", arbitrary_types_allowed=True)

    iface: str
    # send_func: Callable
    send_func: Optional[Callable] = lambda: ...
    count: Union[int, float] = 1
    timeout: float = 0.0

    _word_sending: str = "sending"
    _dot_timer: int = 0
    _word_timer: int = 0
    logger: Any = None

    def __init__(self, **data):
        super().__init__(**data)
        self.logger = logging.getLogger(
            f"{ROOT_LOGGER_NAME}.{self.__class__.__name__}/{self.iface}"
        )

    @field_validator("count")
    @classmethod
    def check_count(cls, v):
        if not (isinstance(v, int) or v == math.inf):
            raise ValueError("count must be 'int' or 'math.inf'")
        return v

    def _print_animated_sending(self, word: str, dot_timer: int, word_timer: int):
        word = "sending"
        animated_word = (
            word[:word_timer] + word[word_timer].upper() + word[word_timer + 1 :]
        )
        print(f"{animated_word}{'.' * dot_timer}", end="\r")
        self._dot_timer = (dot_timer + 1) % 4
        self._word_timer = (word_timer + 1) % len(word)

    def send_packet(self, verbose=True):
        sent_packets = 0
        first_send = True
        while sent_packets < self.count:
            if self.send_func(param=self, verbose=first_send and verbose):
                sent_packets += 1
            if first_send:
                first_send = False
            if verbose:
                self._print_animated_sending(
                    self._word_sending, self._dot_timer, self._word_timer
                )
            sleep(self.timeout)
        if verbose:
            print()
            self.logger.info(f"Successfully sent {sent_packets} packet(s)")
