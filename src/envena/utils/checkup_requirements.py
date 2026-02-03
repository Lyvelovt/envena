if __name__ == "__main__":
    import argparse
    import logging

    from src.envena.core.logger import ROOT_LOGGER_NAME

    logger = logging.getLogger(f"{ROOT_LOGGER_NAME}.checkup_requirements")

    parser = argparse.ArgumentParser(
        description=f"Start this module to check up installed requirements"
    )
    parser.add_argument(
        "--i-am-too-stupid",
        help="use this flag if you don't know how to use pip",
        action="store_true",
    )

    cli_args = parser.parse_args()

    if cli_args.i_am_too_stupid:
        try:
            OK_INSTALLED = False
            import subprocess

            result = subprocess.run(
                ["pip", "install", "-r", "requirements.txt"], capture_output=1, text=1
            )
            if not "ERROR" in result.stderr.upper():
                OK_INSTALLED = True

            else:
                logger.error(
                    'Failed to install requirements using "requirements.txt", retrying without it...'
                )
                result = subprocess.run(
                    [
                        "pip",
                        "install",
                        "scapy>=2.6.1",
                        "colorama",
                        "rich",
                        "netaddr",
                        "ipaddress",
                        "numpy",
                        "cmd2",
                        "python-nmap",
                        "pydantic",
                    ],
                    capture_output=1,
                    text=1,
                )

                if "ERROR" in result.stderr:
                    logger.critical("Failed to install requirements. Bailing out")

                elif (
                    "satisfied" in result.stdout.lower()
                    or "successfully" in result.stdout.lower()
                ):
                    OK_INSTALLED = True

            if OK_INSTALLED:
                logger.info("Succesfully installed all requirements")

        except KeyboardInterrupt as e:
            logger.critical(f"Failed to install requirements. Details: {e}")
        exit()

    NOT_INSTALLED_LIBS = []

    try:
        import scapy
    except Exception as e:
        logger.critical(f"Scapy lib is not installed. Details: {e}")
        NOT_INSTALLED_LIBS.append("scapy>=2.6.1")

    try:
        import colorama
    except Exception as e:
        logger.warning(f"Colorama lib is not installed. Details: {e}")
        NOT_INSTALLED_LIBS.append("colorama")

    try:
        import numpy
    except Exception as e:
        logger.error(f"Numpy lib is not installed. Details: {e}")
        NOT_INSTALLED_LIBS.append("numpy")

    try:
        import rich
    except Exception as e:
        logger.error(f"Rich lib is not installed. Details: {e}")
        NOT_INSTALLED_LIBS.append("rich")

    try:
        import netaddr
    except Exception as e:
        logger.error(f"Netaddr lib is not installed. Details: {e}")
        NOT_INSTALLED_LIBS.append("netaddr")

    try:
        import ipaddress
    except Exception as e:
        logger.error(f"Ipaddress lib is not installed. Details: {e}")
        NOT_INSTALLED_LIBS.append("ipaddress")

    try:
        import cmd2
    except Exception as e:
        logger.error(f"Cmd2 lib is not installed. Details: {e}")
        NOT_INSTALLED_LIBS.append("cmd2")

    try:
        import nmap
    except Exception as e:
        logger.error(f"Nmap lib is not installed. Details: {e}")
        NOT_INSTALLED_LIBS.append("nmap")

    try:
        import pydantic
    except Exception as e:
        logger.error(f"Pydantic lib is not installed. Details: {e}")
        NOT_INSTALLED_LIBS.append("pydantic")

    try:
        from src.envena.utils.searchsploit import Searchsploit

        Searchsploit.find("openssh")
    except Exception as e:
        logger.error(f"Searchsploit module is unavailable. Details: {e}")

    if NOT_INSTALLED_LIBS != []:
        logger.info(
            f'Try "pip install -r requirements" or "pip install {" ".join(NOT_INSTALLED_LIBS)}"'
        )
        logger.info('Or try to start this module with "--i-am-too-stupid" flag')

    else:
        logger.info("Succesfully installed all requirements")
