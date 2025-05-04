from flask import render_template, request, redirect, url_for, flash, jsonify, make_response
from util.database import db
import hashlib
import logging
from util.auth_utli import create_session, set_auth_cookie

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# We'll store users in the 'users' collection in MongoDB
users_collection = db["users"]

def verify_password(stored_password, provided_password):
    """
    Verify if the provided password matches the stored hashed password
    """
    # Extract the salt and key from the stored password
    salt = stored_password['salt']
    stored_key = stored_password['key']
    
    # Hash the provided password with the same salt
    key = hashlib.pbkdf2_hmac(
        'sha256',
        provided_password.encode('utf-8'),
        salt,
        100000,
        dklen=128
    )
    
    # Compare the generated key with the stored key
    return key == stored_key

def authenticate_user(username, password):
    """
    Authenticate a user with username and password
    """
    logger.info(f"Attempting to authenticate user: {username}")
    
    # Find the user by username
    user = users_collection.find_one({"username": username})
    
    if not user:
        logger.warning(f"User not found: {username}")
        return False, "Invalid username or password", None
    
    # Verify the password
    if not verify_password(user['password'], password):
        logger.warning(f"Invalid password for user: {username}")
        return False, "Invalid username or password", None
    
    # Create authentication session
    auth_token = create_session(user["_id"])
    
    if not auth_token:
        logger.error(f"Failed to create session for user: {username}")
        return False, "Authentication failed - could not create session", None
    
    logger.info(f"User authenticated successfully: {username}")
    return True, "Authentication successful", auth_token

def handle_login():
    """
    Handle user login - to be called from server.py
    Supports both regular form submissions and AJAX requests
    """
    logger.info(f"Login route accessed with method: {request.method}")
    
    # For GET requests, just display the login form
    if request.method == 'GET':
        return render_template('login.html')
    
    # Process POST requests for login
    elif request.method == 'POST':
        # Get form data
        username = request.form.get('Username')
        password = request.form.get('Password')
        color = request.form.get('color')
        
        # Log login attempt (without password)
        logger.info(f"Login attempt - Username: {username}")
        
        # Initialize errors dictionary for AJAX responses
        errors = {}
        
        # Step 1: Basic form validation - check for empty fields
        if not username or not password:
            message = 'Username and password are required'
            
            if not username:
                errors['username'] = 'Username is required'
                logging.info(f"Username is required")
            if not password:
                errors['password'] = 'Password is required'
                logging.info(f"Password is required")
            
            # Handle response based on request type
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'success': False,
                    'message': message,
                    'errors': errors
                }), 400
            else:
                flash(message, 'error')
                return render_template('login.html')
        
        # Step 2: Authenticate the user
        success, message, auth_token = authenticate_user(username, password)
        
        # In login.py, update the AJAX success handler:
        if success:
            logger.info(f"User logged in successfully: {username}")
            
            # Handle response based on request type
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                response = jsonify({
                    'success': True,
                    'message': 'Login successful!',
                    'redirect': url_for('index')  # Add this line
                })
                
                # Set authentication cookie
                response = set_auth_cookie(response, auth_token)
                
                logger.info(f"Auth cookie set for user: {username}")
                logger.info(f"Successfull Login Welcome!: {username}")
                return response
            else:
                flash('Login successful!', 'success')
                response = make_response(redirect(url_for('index')))
                
                # Set authentication cookie
                response = set_auth_cookie(response, auth_token)
                
                logger.info(f"Auth cookie set for user: {username}")
                logger.info(f"Successfull Login Welcome!: {username}")
                return response
        else:
            logger.warning(f"Login failed: {message}")
            
            # Handle response based on request type
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'success': False,
                    'message': message
                }), 401
            else:
                flash(message, 'error')
                return render_template('login.html')