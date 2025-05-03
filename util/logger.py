import logging
from datetime import datetime
from flask import request
import logging
import os
import warnings

# does docker volume generate that file upon requests
# do i used frameworks for this
# aws acess log??
# flask has @app.before_request can i use that
#  root directory of your project outside the docker container
# root directory is it in where the util stuff are
# docker volume handles the file outside docker container
# flask has things that get ip address using .remote_addr can i use that to get ip or some other way or will that get the wrong ip
# how would you recommend getting the ip address

# log.txt - Your main application log containing:
# General server events
# Authentication attempts (logins/logouts)
# Error messages with stack traces
# Formatted with your existing timestamp format

# http_log.txt - Raw HTTP traffic log containing:
# Every incoming request (method + path)
# Response status codes
# Basic auth attempts (just usernames, no passwords)
# Simple IP-based format

def setup_logging(app=None):
    log_dir = "log"
    log_file = os.path.join(log_dir, "log.txt")
    os.makedirs(log_dir, exist_ok=True)

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

    # Also attach to Flask app.logger if available
    if app:
        app.logger.handlers = []
        app.logger.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.addHandler(stream_handler)

    logging.info("Logging is set up.")

def get_raw_logger():
    """Returns a logger that writes only raw HTTP request/response logs to log/http_log.txt."""
    raw_log_path = os.path.join("log", "http_log.txt")
    raw_logger = logging.getLogger("raw_http")
    if not raw_logger.handlers:
        raw_logger.setLevel(logging.INFO)
        handler = logging.FileHandler(raw_log_path)
        formatter = logging.Formatter('%(asctime)s: %(message)s')
        handler.setFormatter(formatter)
        raw_logger.addHandler(handler)
    raw_logger.propagate = False
    return raw_logger


