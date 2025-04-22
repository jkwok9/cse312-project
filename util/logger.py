import logging
from datetime import datetime
from flask import request


def setup_logging(root):
    logging.basicConfig(
        filename='logs/root.log',
        level=logging.INFO,
        format='%(asctime)s - %(message)s'
    )
    @root.before_request
    def log_request_info():
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        ip_address = request.remote_addr
        method = request.method
        path = request.path
        logging.info(f"{timestamp} - {ip_address} - {method} {path}")

    # add this to main script for this to work setup_logging(app)
    #getting enginx ip address  but works if testing locally