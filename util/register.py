from flask import render_template, request, redirect, url_for, flash, jsonify, make_response
from util.database import db
import re
import os
import hashlib
import secrets
import uuid
from datetime import datetime
import logging
from util.auth_utli import create_session, set_auth_cookie

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# We'll store users in the 'users' collection in MongoDB
users_collection = db["users"]

def validate_password(password):
    """
    Validate password meets requirements:
    - At least 8 characters
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 number
    - At least 1 special character from !@#$%^&*(),.?":{}|<>
    """
    # Log validation attempt
    logger.info(f"Validating password of length {len(password) if password else 0}")
    
    # Empty password check
    if not password:
        logger.warning("Empty password submitted")
        return False, "Password cannot be empty"
        
    # Check length
    if len(password) < 8:
        logger.warning(f"Password too short: {len(password)} chars")
        return False, "Password must be at least 8 characters long"
    
    # Check for uppercase letter
    if not re.search(r'[A-Z]', password):
        logger.warning("Password missing uppercase letter")
        return False, "Password must contain at least one uppercase letter"
    
    # Check for lowercase letter
    if not re.search(r'[a-z]', password):
        logger.warning("Password missing lowercase letter")
        return False, "Password must contain at least one lowercase letter"
    
    # Check for number
    if not re.search(r'[0-9]', password):
        logger.warning("Password missing number")
        return False, "Password must contain at least one number"
    
    # Check for special character
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        logger.warning("Password missing special character")
        return False, "Password must contain at least one special character"
    
    logger.info("Password validation passed")
    return True, "Password valid"

def hash_password(password):
    """
    Generate a salted hash for the password
    """
    salt = os.urandom(32)  # 32 bytes of random data for the salt
    
    # Use SHA-256 for hashing
    key = hashlib.pbkdf2_hmac(
        'sha256',  # Hash algorithm
        password.encode('utf-8'),  # Convert password to bytes
        salt,  # Provide the salt
        100000,  # Number of iterations (higher is more secure but slower)
        dklen=128  # Length of the key
    )
    
    # Return salt and key as a dictionary for storage
    return {
        'salt': salt,
        'key': key
    }

def register_user(username, email, password):
    """
    Register a new user if the username is not already taken
    and password requirements are met
    """
    logger.info(f"Attempting to register user: {username}, email: {email}")
    
    # Check if username already exists
    existing_user = users_collection.find_one({"username": username})
    if existing_user:
        logger.warning(f"Username already exists: {username}")
        return False, "Username already taken", None
    
    # Check if email already exists
    existing_email = users_collection.find_one({"email": email})
    if existing_email:
        logger.warning(f"Email already registered: {email}")
        return False, "Email already registered", None
    
    # Validate password - CRITICAL SECURITY CHECK
    is_valid, message = validate_password(password)
    if not is_valid:
        logger.warning(f"Password validation failed: {message}")
        return False, message, None
    
    # Only if we get here, validation passed
    try:
        # Generate a unique user ID
        user_id = str(uuid.uuid4())
        
        # Hash the password with salt
        password_hash = hash_password(password)
        
        # Create user document
        user = {
            "_id": user_id,
            "username": username,
            "email": email,
            "password": {
                'salt': password_hash['salt'],
                'key': password_hash['key']
            },
            "created_at": datetime.utcnow()
        }
        
        # Insert the user into the database
        result = users_collection.insert_one(user)
        logger.info(f"User registered successfully: {username}, ID: {user_id}")
        
        # Create an authentication session and get the token
        auth_token = create_session(user_id)
        if not auth_token:
            logger.warning(f"Failed to create session for new user: {user_id}")
            # Still return success for registration but note session creation failed
            return True, "Registration successful but session creation failed", None
            
        return True, "Registration successful", auth_token
        
    except Exception as e:
        logger.error(f"Database error during registration: {str(e)}")
        return False, "Database error occurred", None

def handle_register():
    """
    Handle user registration - to be called from server.py
    Supports both regular form submissions and AJAX requests
    """
    logger.info(f"Registration route accessed with method: {request.method}")
    
    # Only process POST requests (GET requests just show the form)
    if request.method == 'POST':
        # Get form data
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Log registration attempt (without password)
        logger.info(f"Registration attempt - Username: {username}, Email: {email}")
        
        # Initialize errors dictionary for AJAX responses
        errors = {}
        
        # Step 1: Basic form validation - check for empty fields
        if not username or not email or not password or not confirm_password:
            message = 'All fields are required'
            if not username:
                errors['username'] = 'Username is required'
            if not email:
                errors['email'] = 'Email is required'
            if not password:
                errors['password'] = 'Password is required'
            if not confirm_password:
                errors['confirm_password'] = 'Please confirm your password'
            
            # Handle response based on request type
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'success': False,
                    'message': message,
                    'errors': errors
                }), 400
            else:
                flash(message, 'error')
                return render_template('register.html')
        
        # Step 2: Check if passwords match
        if password != confirm_password:
            message = 'Passwords do not match'
            errors['confirm_password'] = message
            
            # Handle response based on request type
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'success': False, 
                    'message': message,
                    'errors': errors
                }), 400
            else:
                flash(message, 'error')
                return render_template('register.html')
        
        # Step 3: Validate the password requirements
        is_valid, message = validate_password(password)
        if not is_valid:
            errors['password'] = message
            
            # Handle response based on request type
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'success': False,
                    'message': message,
                    'errors': errors
                }), 400
            else:
                flash(message, 'error')
                return render_template('register.html')
        
        # Step 4: Try to register the user (includes duplicate username check)
        success, message, auth_token = register_user(username, email, password)
        
        if success:
            logger.info(f"User registered successfully: {username}")
            
            # Handle response based on request type
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                response = jsonify({
                    'success': True,
                    'message': 'Registration successful!',
                    'redirect': url_for('index')  # Add this line
                })
                
                # Set authentication cookie if token was generated
                if auth_token:
                    response = set_auth_cookie(response, auth_token)
                    logger.info(f"Auth cookie set for user: {username}")
                
                return response, 201
            else:
                flash('Registration successful!', 'success')
                # Modified: redirect to index (game) instead of back to register
                response = make_response(redirect(url_for('index')))
                
                # Set authentication cookie if token was generated
                if auth_token:
                    response = set_auth_cookie(response, auth_token)
                    logger.info(f"Auth cookie set for user: {username}")
                
                return response
        else:
            logger.warning(f"Registration failed: {message}")
            
            # Determine which field the error is for (for AJAX responses)
            if "Username already taken" in message:
                errors['username'] = message
            elif "Email already registered" in message:
                errors['email'] = message
            elif "Password" in message:
                errors['password'] = message
            
            # Handle response based on request type
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    'success': False,
                    'message': message,
                    'errors': errors
                }), 400
            else:
                flash(message, 'error')
                return render_template('register.html')
    
    # For GET requests, just display the form
    return render_template('register.html')