import logging, os
from logging import handlers


class ConsoleLogging:

    def __init__(self):
        self.level = logging.INFO
        self.log = None


    def setLevel(self,mode):
        if mode == "DEBUG":
            self.level = logging.DEBUG
    def configure_logging(self):

        logger = logging.getLogger("Akamai GCS")

        logger.setLevel(self.level)


        # Format for our loglines
        formatter = logging.Formatter("[%(asctime)s] - %(name)s - %(levelname)s - %(message)s")
        # Setup console logging
        ch = logging.StreamHandler()
        

        ch.setLevel(self.level)
        ch.setFormatter(formatter)
        logger.addHandler(ch)

        ## Set Log Location
        # try:
        #     os.stat('Logs/')
        # except:
        #     os.mkdir('Logs/')
        # fh = handlers.RotatingFileHandler('Logs/audit.log', mode='a', maxBytes=5*1024*1024, 
        #                         backupCount=2, encoding=None, delay=0)
        # if mode == "DEBUG":
        #     fh.setLevel(logging.DEBUG)
        # else:
        #     fh.setLevel(logging.INFO)
        # fh.setFormatter(formatter)
        # logger.addHandler(fh)
        self.log = logger