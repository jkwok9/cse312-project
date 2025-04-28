import os
import hashlib
import secrets
from datetime import datetime, timedelta
import logging
from util.database import db

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# MongoDB collections
sessions_collection = db["sessions"]

def generate_auth_token():
    """
    Generate a secure random token for authentication
    """
    return secrets.token_hex(32)  # 64 characters / 32 bytes of randomness

def hash_token(token):
    """
    Create a hash of the authentication token for storage
    No salting required as per requirements
    """
    return hashlib.sha256(token.encode('utf-8')).hexdigest()

def create_session(user_id, expiry_days=30):
    """
    Create a new authentication session for a user
    Returns the token (to be set as cookie) and stores only the hash in the database
    """
    # Generate a random authentication token
    token = generate_auth_token()
    
    # Hash the token for secure storage
    token_hash = hash_token(token)
    
    # Calculate expiry date
    expires_at = datetime.utcnow() + timedelta(days=expiry_days)
    
    # Create session document with the token hash (not the actual token)
    session = {
        "user_id": user_id,
        "token_hash": token_hash,
        "created_at": datetime.utcnow(),
        "expires_at": expires_at,
        "last_activity": datetime.utcnow()
    }
    
    # Store the session in the database
    try:
        sessions_collection.insert_one(session)
        logger.info(f"Created new session for user {user_id}, expires: {expires_at}")
    except Exception as e:
        logger.error(f"Error creating session: {str(e)}")
        return None

    # Return the token (not the hash) to be set as a cookie
    return token

def get_user_by_token(token):
    """
    Get a user by their authentication token
    """
    if not token:
        return None
    
    # Hash the token to look it up in the database
    token_hash = hash_token(token)
    
    # Find the session and make sure it's not expired
    try:
        session = sessions_collection.find_one({
            "token_hash": token_hash,
            "expires_at": {"$gt": datetime.utcnow()}
        })
        
        if not session:
            logger.info("No valid session found for token")
            return None
        
        # Update the last activity timestamp
        sessions_collection.update_one(
            {"token_hash": token_hash},
            {"$set": {"last_activity": datetime.utcnow()}}
        )
        
        # Get the user from the users collection
        user = db["users"].find_one({"_id": session["user_id"]})
        return user
    except Exception as e:
        logger.error(f"Error retrieving user by token: {str(e)}")
        return None

def set_auth_cookie(response, token, expiry_days=30):
    """
    Set an HTTP-only cookie with the authentication token
    """
    # Calculate expiry in seconds
    max_age = expiry_days * 24 * 60 * 60
    
    # Set the cookie with HttpOnly flag and other security directives
    response.set_cookie(
        'auth_token',          # Cookie name
        token,                 # Cookie value (the actual token, not the hash)
        max_age=max_age,       # Cookie expiration in seconds
        httponly=True,         # Prevents JavaScript access (HttpOnly flag)
        secure=False,          # Set to False for local development (no HTTPS)
        samesite='Lax'         # Prevents CSRF attacks
    )
    
    return response

def clear_auth_cookie(response):
    """
    Clear the authentication cookie
    """
    response.delete_cookie('auth_token')
    return response

def invalidate_session(token):
    """
    Invalidate a session by token
    """
    if not token:
        return False
    
    # Hash the token to look it up
    token_hash = hash_token(token)
    
    try:
        # Delete the session from the database
        result = sessions_collection.delete_one({"token_hash": token_hash})
        return result.deleted_count > 0
    except Exception as e:
        logger.error(f"Error invalidating session: {str(e)}")
        return False