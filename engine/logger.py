"""
engine/logger.py
Centralised coloured console logger for the PCAP engine.
"""

import logging
import sys
from colorama import Fore, Style, init

init(autoreset=True)

class ColouredFormatter(logging.Formatter):
    COLOURS = {
        logging.DEBUG:    Fore.CYAN,
        logging.INFO:     Fore.GREEN,
        logging.WARNING:  Fore.YELLOW,
        logging.ERROR:    Fore.RED,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }

    def format(self, record):
        colour = self.COLOURS.get(record.levelno, "")
        prefix = {
            logging.DEBUG:    "[~]",
            logging.INFO:     "[+]",
            logging.WARNING:  "[!]",
            logging.ERROR:    "[✗]",
            logging.CRITICAL: "[✗✗]",
        }.get(record.levelno, "[?]")
        msg = super().format(record)
        return f"{colour}{prefix} {msg}{Style.RESET_ALL}"


def get_logger(name: str, level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(ColouredFormatter("%(message)s"))
        logger.addHandler(handler)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    return logger
