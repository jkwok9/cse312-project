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


def setup_logging(app=None):
    log_dir = "log"
    log_file = os.path.join(log_dir, "server.log")
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



# def setup_logging():
#     log_dir = "log"
#     log_file = os.path.join(log_dir, "server.log")
#
#     os.makedirs(log_dir, exist_ok=True)  # Make sure log directory exists
#
#     logging.basicConfig(
#         level=logging.INFO,
#         format='%(asctime)s %(levelname)s: %(message)s',
#         handlers=[
#             logging.FileHandler(log_file),
#             logging.StreamHandler()  # Optional: also log to console
#         ]
#     )
#
#     logging.info("Logging is set up.")


    # add this to main script for this to work setup_logging(app)
    #getting enginx ip address  but works if testing locally