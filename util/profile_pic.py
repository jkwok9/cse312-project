from flask import render_template, request, redirect, url_for, flash, jsonify, abort, send_from_directory
from util.database import db
from util.auth_utli import get_user_by_token
import os
import uuid
import logging
from PIL import Image
from io import BytesIO
import base64

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Set up upload directory
UPLOAD_FOLDER = 'static/uploads/profile_pics'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
AVATAR_SIZE = (96, 96)  # Size for processed avatars - exactly one grid cell


# Create upload directory if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# MongoDB collection for user profile pictures
profile_pics_collection = db["profile_pics"]

def allowed_file(filename):
    """Check if the file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def process_image(file_data):
    """
    Process the uploaded image to match the CSS preview behavior:
    1. Open with PIL
    2. Apply the same crop/scale as CSS object-fit: cover
    3. Save to a BytesIO object for storage
    """
    try:
        # Open image from file data
        img = Image.open(BytesIO(file_data))
        
        # Convert to RGB if needed
        if img.mode in ('RGBA', 'LA'):
            background = Image.new('RGB', img.size, (255, 255, 255))
            if img.mode == 'RGBA':
                background.paste(img, mask=img.split()[3])
            else:
                background.paste(img, mask=img.split()[1])
            img = background
        elif img.mode != 'RGB':
            img = img.convert('RGB')
        
        # Get current dimensions
        orig_width, orig_height = img.size
        
        # Calculate scale to fill the target size (object-fit: cover behavior)
        target_width, target_height = AVATAR_SIZE
        width_ratio = target_width / orig_width
        height_ratio = target_height / orig_height
        
        # Use the larger ratio to ensure the image covers the entire area
        ratio = max(width_ratio, height_ratio)
        
        # Calculate the new size
        new_width = int(orig_width * ratio)
        new_height = int(orig_height * ratio)
        
        # Resize the image
        img = img.resize((new_width, new_height), Image.LANCZOS)
        
        # Calculate crop position to center the image
        left = (new_width - target_width) // 2
        top = (new_height - target_height) // 2
        right = left + target_width
        bottom = top + target_height
        
        # Crop to final size
        img = img.crop((left, top, right, bottom))
        
        # Save to BytesIO object
        output = BytesIO()
        img.save(output, format='PNG', quality=95)
        output.seek(0)
        
        return output.getvalue()
    
    except Exception as e:
        logger.error(f"Error processing image: {str(e)}")
        return None

def save_profile_pic(user_id, file_data, filename):
    """Save the processed profile picture to the database"""
    try:
        # Process the image
        processed_image = process_image(file_data)
        if not processed_image:
            return False, "Failed to process image"
        
        # Generate a unique filename to avoid collisions
        unique_filename = f"{uuid.uuid4()}.png"
        file_path = os.path.join(UPLOAD_FOLDER, unique_filename)
        
        # Save the processed image to disk
        with open(file_path, 'wb') as f:
            f.write(processed_image)
        
        # Create base64 version for efficient WebSocket transfer
        base64_data = base64.b64encode(processed_image).decode('utf-8')
        
        # Update or insert the profile pic record in the database
        profile_pics_collection.update_one(
            {"user_id": user_id},
            {
                "$set": {
                    "user_id": user_id,
                    "filename": unique_filename,
                    "original_filename": filename,
                    "base64_data": base64_data
                }
            },
            upsert=True
        )
        
        return True, unique_filename
    except Exception as e:
        logger.error(f"Error saving profile picture: {str(e)}")
        return False, str(e)

def get_profile_pic(user_id):
    """Get the profile picture data for a user"""
    try:
        profile_pic = profile_pics_collection.find_one({"user_id": user_id})
        if profile_pic:
            return {
                "filename": profile_pic.get("filename"),
                "base64_data": profile_pic.get("base64_data")
            }
        return None
    except Exception as e:
        logger.error(f"Error retrieving profile picture: {str(e)}")
        return None

def handle_profile_page(user):
    """Handle the profile page display and form submission"""
    if request.method == 'GET':
        # Get the user's current profile pic if it exists
        profile_pic_data = get_profile_pic(user.get('_id'))
        return render_template('profile.html', 
                              username=user.get('username', 'Player'),
                              email=user.get('email', ''),
                              profile_pic=profile_pic_data)
    
    elif request.method == 'POST':
        try:
            # Check if a file was uploaded
            if 'profile_pic' not in request.files:
                flash('No file selected', 'error')
                return redirect(url_for('profile'))
            
            file = request.files['profile_pic']
            
            # Check if the file is empty
            if file.filename == '':
                flash('No file selected', 'error')
                return redirect(url_for('profile'))
            
            # Check file extension
            if not allowed_file(file.filename):
                flash('Invalid file type. Only JPG and PNG files are allowed.', 'error')
                return redirect(url_for('profile'))
            
            # Read file data
            file_data = file.read()
            
            # Save the profile picture
            success, result = save_profile_pic(user.get('_id'), file_data, file.filename)
            
            if success:
                flash('Profile picture updated successfully!', 'success')
            else:
                flash(f'Failed to update profile picture: {result}', 'error')
            
            return redirect(url_for('profile'))
        
        except Exception as e:
            logger.error(f"Error handling profile picture upload: {str(e)}")
            flash(f'An error occurred: {str(e)}', 'error')
            return redirect(url_for('profile'))

def get_profile_pic_api(user_id):
    """API to get a user's profile picture data for WebSocket transmission"""
    try:
        profile_pic = get_profile_pic(user_id)
        if profile_pic:
            return jsonify({
                "success": True,
                "base64_data": profile_pic.get("base64_data")
            })
        return jsonify({
            "success": False,
            "message": "No profile picture found"
        })
    except Exception as e:
        logger.error(f"Error in profile pic API: {str(e)}")
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500

def get_profile_pic_by_username(username):
    """Get a user's profile picture data by username (for game use)"""
    try:
        # Find the user by username
        user = db["users"].find_one({"username": username})
        if not user:
            return None
            
        # Get their profile pic
        return get_profile_pic(user.get('_id'))
    except Exception as e:
        logger.error(f"Error getting profile pic by username: {str(e)}")
        return None

def serve_profile_pic(filename):
    """Serve the profile picture file"""
    try:
        return send_from_directory(UPLOAD_FOLDER, filename)
    except Exception as e:
        logger.error(f"Error serving profile picture: {str(e)}")
        abort(404)