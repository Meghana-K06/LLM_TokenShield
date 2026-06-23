import logging
import sys

class TwinLogger:
    def __init__(self):
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            handlers=[logging.StreamHandler(sys.stdout)]
        )
        self.logger = logging.getLogger("TwinShield")

    def info(self, msg):  self.logger.info(msg)
    def error(self, msg): self.logger.error(msg)
    def warn(self, msg):  self.logger.warning(msg)
