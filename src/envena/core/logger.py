import logging
import sys

ROOT_LOGGER_NAME = "envena"
# LOG_LEVEL = logging.INFO
LOG_LEVEL = logging.DEBUG
LOG_FORMAT = "[%(name)s] [%(levelname)s] %(message)s"


def setup_root_logger():
    logger = logging.getLogger(ROOT_LOGGER_NAME)
    logger.setLevel(LOG_LEVEL)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setLevel(LOG_LEVEL)

        formatter = logging.Formatter(LOG_FORMAT)
        handler.setFormatter(formatter)

        logger.addHandler(handler)

    return logger


ROOT_LOGGER = setup_root_logger()
