import math
import logging
from time import sleep
from src.envena.config import ROOT_LOGGER_NAME

class BaseProtocol:
    __slots__ = ('iface','count','timeout','send_func', '_word_sending', '_dot_timer', '_word_timer')
    
    def __init__(self, iface, count, timeout, send_func):
        self.send_func = None
        self._word_sending = 'sending'
        self._dot_timer = 0
        self._word_timer = 0

        if isinstance(iface, str):
            self.iface = iface
        else:
            raise TypeError("iface must be 'str'")
        
        self.logger = logging.getLogger(f'{ROOT_LOGGER_NAME}.{__class__.__name__}/{self.iface}')
        
        if isinstance(count, int) or count is math.inf:
            self.count = count
        else:
            TypeError("count must be 'int' or 'math.inf'")
        
        if isinstance(timeout, float) or isinstance(timeout, int):
            self.timeout = timeout
        else:
            raise TypeError("timeout must be 'float' or 'int'")
        
        if not callable(send_func):
            raise TypeError('send function must be callable')
        else:
            self.send_func = send_func
        
    def _print_animated_sending(self, word: str, dot_timer: int, word_timer: int):
        word = 'sending'
        # Логика анимации, перенесенная из оригинальной функции
        animated_word = word[:word_timer] + word[word_timer].upper() + word[word_timer+1:]
        
        # Печатаем текущее состояние анимации
        print(f"{animated_word}{'.' * dot_timer}", end='\r')

        # Обновляем таймеры
        self._dot_timer = (dot_timer + 1) % 4  # Цикл 0-3
        self._word_timer = (word_timer + 1) % len(word) # Цикл по длине слова
        
    def send_packet(self, printed=True):
        sent_packets = 0
        first_send = True
        try:
            while sent_packets <= self.count:
                if self.send_func(param=self, printed=first_send and printed):
                    sent_packets += 1
                if first_send:
                    first_send = False
                if printed:
                    self._print_animated_sending(self._word_sending, self._dot_timer, self._word_timer)
                sleep(self.timeout)
            if printed:
                print()
                self.logger.info(f'Successfully sent {sent_packets} packet(s)')
        except KeyboardInterrupt:
            if printed:
                self.logger.info(f'Successfully sent {sent_packets} packet(s)')