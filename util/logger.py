import logging
from datetime import datetime
from flask import request
import logging
import os
import warnings

def setup_logging(app=None):
    log_file = "server.log"  # 👈 Just the filename, no directory

    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s')

    # File handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(formatter)

    # Stream handler (console)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(stream_handler)

    # Attach to Flask's app.logger too, if given
    if app:
        app.logger.handlers = []
        app.logger.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.addHandler(stream_handler)

    logging.info("Logging is set up.")