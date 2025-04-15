# Import the Flask class and other necessary functions
from flask import Flask, render_template, request, redirect, url_for, flash
import secrets
import os
import logging
from util.register import handle_register


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create an instance of the Flask class
app = Flask(__name__)  # Flask will look for templates in a 'templates' folder

# Set a secret key for session management and flash messages
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Ensure session is secure
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Define a route for the application's root URL ("/")
@app.route("/")
def index():
    """
    This function is the view function for the "/" route.
    It renders the index.html template.
    """
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Route for user registration
    Uses the registration logic from register.py
    """
    return handle_register()


if __name__ == "__main__":
    logger.info("Starting Flask application...")
    # Run the Flask development server
    # debug=True enables auto-reloading and error pages (disable in production)
    # host='0.0.0.0' makes it accessible on your network
    app.run(debug=True, host='0.0.0.0', port=8080)