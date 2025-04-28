import select
if hasattr(select, 'kqueue'):
    import sys
    if sys.platform == 'darwin':
        select.kqueue = None

import eventlet
from util.logger import setup_logging
eventlet.monkey_patch()
import os
import time
import threading
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, make_response
from flask_pymongo import PyMongo
from flask_socketio import SocketIO, emit, join_room, leave_room, send
from werkzeug.security import generate_password_hash, check_password_hash
from passlib.hash import pbkdf2_sha256 as sha256 # Using passlib for better hashing options
import random
from collections import defaultdict
import logging
from bson import ObjectId  # Add this import for MongoDB ObjectID handling
from util.auth_util import create_session, get_user_by_token, set_auth_cookie, clear_auth_cookie, invalidate_session

# --- Configuration ---
app = Flask(__name__)
setup_logging(app)
@app.before_request
def log_request_info():
    ip = request.remote_addr
    method = request.method
    url = request.url
    path = request.path
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    logging.info(f"{timestamp} - {ip} - {method} {url} {path}")
# IMPORTANT: Change this secret key in a real application!
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "a_very_secret_key_12345")
# Configure MongoDB - Replace with your connection string if necessary
# Example: app.config["MONGO_URI"] = "mongodb://user:pass@host:port/db_name"
app.config["MONGO_URI"] = os.environ.get("MONGO_URI", "mongodb://localhost:27017/grid_game_db")
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Mitigate CSRF

# Set up logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

# --- Extensions ---
mongo = PyMongo(app)
# Use eventlet for async mode, crucial for WebSocket performance
socketio = SocketIO(app, async_mode='eventlet', logger=True, engineio_logger=True)

# --- Game Constants ---
GRID_WIDTH = 30
GRID_HEIGHT = 20
GAME_DURATION_SECONDS = 30
TEAMS = ['red', 'blue', 'green', 'yellow']
MIN_TEAMS_TO_START = 2

# --- Game State (In-Memory - Use Redis/DB for production scaling) ---
game_state = {
    "active": False,
    "start_time": None,
    "grid": {},  # {(x, y): team_color}
    "players": {}, # {sid: {'username': str, 'team': str, 'position': (x, y)}}
    "scores": defaultdict(int), # {team_color: score}
    "team_counts": defaultdict(int), # {team_color: count}
    "timer": None,
    "winner": None,
    "restart_timer": None,
}
game_lock = threading.Lock() # To protect concurrent access to game_state

# --- Helper Functions ---
def get_balanced_team():
    """Assigns a player to the least populated team."""
    min_count = float('inf')
    best_teams = []
    for team in TEAMS:
        count = game_state["team_counts"][team]
        if count < min_count:
            min_count = count
            best_teams = [team]
        elif count == min_count:
            best_teams.append(team)
    return random.choice(best_teams)

def calculate_scores():
    """Recalculates scores based on the current grid state."""
    new_scores = defaultdict(int)
    for cell_color in game_state["grid"].values():
        if cell_color in TEAMS:
            new_scores[cell_color] += 1
    return new_scores

def reset_game():
    """Resets the game state for a new round."""
    global game_state
    log.info("Resetting game state")
    game_state["active"] = False
    game_state["start_time"] = None
    game_state["grid"] = {}
    # Keep players, but reset scores maybe? Or clear grid? Let's clear grid.
    # Players will need to rejoin a team or have their position reset.
    # For simplicity here, we reset scores based on empty grid.
    game_state["scores"] = defaultdict(int)
    game_state["timer"] = None
    game_state["winner"] = None
    # Recalculate scores based on the (now empty) grid
    game_state["scores"] = calculate_scores()

def end_game():
    """Ends the current game round."""
    with game_lock:
        if not game_state["active"]:
            return # Game already ended or wasn't active

        log.info("Game ending...")
        game_state["active"] = False
        final_scores = calculate_scores() # Ensure scores are final
        game_state["scores"] = final_scores

        winner = None
        max_score = -1
        winners = []
        for team, score in final_scores.items():
             if score > max_score:
                 max_score = score
                 winners = [team]
             elif score == max_score:
                 winners.append(team)

        if winners:
             winner = random.choice(winners) # Pick one winner if tie
             game_state["winner"] = winner
             log.info(f"Game Over! Winner: {winner} with score {max_score}")
        else:
             log.info("Game Over! No winner (no scores).")

        # Notify all clients with restart info
        socketio.emit('game_over', {
            'scores': dict(final_scores),
            'winner': winner,
            'restart_in': 5  # Add restart countdown initial value
        })

        # Set up restart timer emitters
        game_state["restart_timer"] = 5
        # Schedule timers to emit countdown updates
        threading.Timer(1.0, lambda: emit_restart_countdown(4)).start()
        threading.Timer(2.0, lambda: emit_restart_countdown(3)).start()
        threading.Timer(3.0, lambda: emit_restart_countdown(2)).start()
        threading.Timer(4.0, lambda: emit_restart_countdown(1)).start()

        # Schedule a reset after 5 seconds
        threading.Timer(5.0, delayed_reset).start()

# Add this new function to emit restart countdown updates
def emit_restart_countdown(seconds):
    """Emit a restart timer update to all clients."""
    try:
        with game_lock:
            # Only update if we're still in between games (not started a new one yet)
            if not game_state["active"] and game_state["restart_timer"] is not None:
                game_state["restart_timer"] = seconds
                log.info(f"Emitting restart countdown: {seconds}s remaining")
                socketio.emit('restart_timer', {'seconds': seconds})
    except Exception as e:
        log.error(f"Error in emit_restart_countdown: {e}", exc_info=True)

def delayed_reset():
     """Resets the game state after a delay and attempts to start a new game."""
     try: # Good practice to wrap timer callbacks in try/except
         log.info("Executing delayed_reset...")
         with game_lock:
             # Reset the core game variables (grid, active status, scores etc.)
             reset_game() # Your existing reset function call
             log.info("Game reset after delay.")

             # --- ADD THIS SECTION ---
             # Now that the game is reset, check if enough players are
             # still present to start a new round immediately.
             log.info("Calling check_start_game after reset to potentially start new round.")
             check_start_game()
             # --- END OF ADDED SECTION ---

     except Exception as e:
         log.error(f"!!!! EXCEPTION in delayed_reset: {e}", exc_info=True)
     finally:
          log.info("Finished executing delayed_reset.")

def check_start_game():
    # Note: Called while game_lock is held by handle_join_game
    log.info("    Inside check_start_game...")
    try: # Wrap the whole function logic
        if game_state["active"]:
            log.info("    check_start_game: Game already active.")
            return

        teams_with_players = sum(1 for count in game_state["team_counts"].values() if count > 0)
        log.info(f"    check_start_game: Teams with players = {teams_with_players}")

        if teams_with_players >= MIN_TEAMS_TO_START:
            log.info("    check_start_game: Starting game...")
            # ... (rest of the game starting logic: set active, time, grid, scores) ...
            game_state["active"] = True
            game_state["start_time"] = time.time()
            # ... etc ...

            log.info("    check_start_game: Resetting player positions...")
            for sid, player_data in game_state["players"].items():
                 player_data['position'] = (
                     random.randint(0, GRID_WIDTH - 1),
                     random.randint(0, GRID_HEIGHT - 1)
                 )
                 game_state["grid"][player_data['position']] = player_data['team']
                 game_state["scores"][player_data['team']] += 1
            log.info("    check_start_game: Finished player position reset.")

            # ... (start timer logic) ...
            if game_state["timer"]:
                 game_state["timer"].cancel()
            game_state["timer"] = threading.Timer(GAME_DURATION_SECONDS, end_game)
            game_state["timer"].start()
            log.info(f"    check_start_game: Timer started ({GAME_DURATION_SECONDS}s).")

            log.info("    check_start_game: Emitting game_start event.")
            socketio.emit('game_start', get_game_state_payload())
            log.info("    check_start_game: Game started event emitted.")
        else:
            log.info(f"    check_start_game: Not starting game. Need {MIN_TEAMS_TO_START} teams, have {teams_with_players}")

    except Exception as e:
        log.error(f"!!!! EXCEPTION inside check_start_game: {e}", exc_info=True)
        # Rethrow or handle as needed. Since the lock is held outside,
        # the finally block in handle_join_game should still execute.

    finally:
        # Optional: log exit if needed, though less critical than lock release log
        log.info("    Exiting check_start_game function.")

def get_game_state_payload():
     """Creates the payload for game state updates."""
     time_remaining = None
     if game_state["active"] and game_state["start_time"]:
         elapsed = time.time() - game_state["start_time"]
         time_remaining = max(0, GAME_DURATION_SECONDS - elapsed)

     # Convert tuple keys in grid to string "x,y" for JSON serialization
     serializable_grid = {f"{x},{y}": color for (x, y), color in game_state["grid"].items()}
     # Convert player positions to lists for JSON
     serializable_players = {
         sid: {**data, 'position': list(data['position'])}
         for sid, data in game_state["players"].items()
     }

     return {
         'active': game_state["active"],
         'grid': serializable_grid,
         'players': serializable_players,
         'scores': dict(game_state["scores"]),
         'time_remaining': time_remaining,
         'grid_width': GRID_WIDTH,
         'grid_height': GRID_HEIGHT,
         'teams': TEAMS
     }

# --- Helper for auth ---
def get_current_user():
    """Get the current user from the auth token cookie"""
    auth_token = request.cookies.get('auth_token')
    if auth_token:
        user = get_user_by_token(auth_token)
        if user:
            log.info(f"User authenticated via token: {user.get('username')}")
            return user
    
    # Fallback to session-based authentication for compatibility
    if 'username' in session:
        username = session['username']
        user = mongo.db.users.find_one({"username": username})
        if user:
            log.info(f"User authenticated via session: {username}")
            return user
    
    log.info("No authenticated user found")
    return None

# --- Flask Routes ---
@app.route('/')
def index():
    # Check for user auth from token instead of session
    user = get_current_user()
    if user:
        return redirect(url_for('game'))
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        flash("Username and password are required.", "error")
        return redirect(url_for('index'))

    if mongo.db.users.find_one({"username": username}):
        flash("Username already exists.", "error")
        return redirect(url_for('index'))

    # Create user
    hashed_password = sha256.hash(password)
    user_id = mongo.db.users.insert_one({
        "username": username, 
        "password_hash": hashed_password
    }).inserted_id
    
    # Create a session token and get a response object
    auth_token = create_session(user_id)
    if not auth_token:
        flash("Error creating session. Please try again.", "error")
        return redirect(url_for('index'))
    
    # Create response and set session for backward compatibility
    response = make_response(redirect(url_for('game')))
    session['username'] = username  # Keep session for compatibility
    
    # Set the auth cookie in the response
    set_auth_cookie(response, auth_token)
    
    flash("Registration successful! You are now logged in.", "success")
    return response

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    if not username or not password:
        flash("Username and password are required.", "error")
        return redirect(url_for('index'))

    user = mongo.db.users.find_one({"username": username})

    if user and sha256.verify(password, user['password_hash']):
        # Create a session token
        auth_token = create_session(user['_id'])
        if not auth_token:
            flash("Error creating session. Please try again.", "error")
            return redirect(url_for('index'))
        
        # Create response and set session for backward compatibility
        response = make_response(redirect(url_for('game')))
        session['username'] = username  # Keep session for compatibility
        
        # Set the auth cookie in the response
        set_auth_cookie(response, auth_token)
        
        log.info(f"User '{username}' logged in with token.")
        return response
    else:
        flash("Invalid username or password.", "error")
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    # Get username from session for logging
    username = session.pop('username', None)
    
    # Invalidate the token
    auth_token = request.cookies.get('auth_token')
    if auth_token:
        invalidate_session(auth_token)
    
    # Prepare response
    response = make_response(redirect(url_for('index')))
    clear_auth_cookie(response)
    
    if username:
        log.info(f"User '{username}' logged out.")
        # Note: Player removal from game happens on socket disconnect
    
    flash("You have been logged out.", "info")
    return response

@app.route('/game')
def game():
    # Check authentication from token
    user = get_current_user()
    if not user:
        log.warning("Attempted to access /game without authentication")
        flash("Please login to play.", "error")
        return redirect(url_for('index'))
    
    # Ensure username is in session for socket compatibility
    if 'username' not in session:
        session['username'] = user['username']
        log.info(f"Added username '{user['username']}' to session for socket compatibility")
    
    log.info(f"User '{user['username']}' accessing game page")
    return render_template('game.html', username=user['username'])

# --- Debug routes ---
@app.route('/debug/auth')
def debug_auth():
    """Debug route to check authentication status"""
    auth_token = request.cookies.get('auth_token')
    session_username = session.get('username')
    
    user = None
    token_user = None
    session_user = None
    
    if auth_token:
        token_user = get_user_by_token(auth_token)
    
    if session_username:
        session_user = mongo.db.users.find_one({"username": session_username})
    
    user = get_current_user()
    
    return jsonify({
        "has_auth_token": bool(auth_token),
        "token_user": token_user['username'] if token_user else None,
        "session_username": session_username,
        "session_user": session_user['username'] if session_user else None,
        "current_user": user['username'] if user else None
    })

# --- SocketIO Event Handlers ---
@socketio.on('connect')
def handle_connect():
    sid = request.sid
    
    # Get user from token - fallback to session if needed
    user = get_current_user()
    if not user and 'username' not in session:
        log.warning(f"Connection attempt without authentication: {sid}")
        emit('error_msg', {'message': 'Authentication required. Please refresh and login.'})
        return

    # If we have a token-authenticated user but no session, add username to session
    if user and 'username' not in session:
        session['username'] = user['username']
        log.info(f"Added username '{user['username']}' to session for socket")
    
    username = session['username']
    log.info(f"Client connected: {username} ({sid})")
    emit('connection_ack', {'sid': sid})  # Acknowledge connection

# The rest of your socket handlers remain the same...
@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    with game_lock:
        player_info = game_state["players"].pop(sid, None)
        if player_info:
            username = player_info['username']
            team = player_info['team']
            game_state["team_counts"][team] -= 1
            if game_state["team_counts"][team] == 0:
                 del game_state["team_counts"][team] # Clean up if team is empty

            log.info(f"Player disconnected: {username} ({sid}), Team: {team}")
            # Don't clear their painted cells
            socketio.emit('player_left', {'sid': sid, 'username': username})
            socketio.emit('update_players', {'players': get_game_state_payload()['players']}) # Update player list for others
            # Optional: Check if game should stop if too few players/teams remain
            # check_stop_game_condition() # Implement if needed
        else:
            log.info(f"Client disconnected without joining game: {sid}")

@socketio.on('join_game')
def handle_join_game():
    sid = request.sid
    log.info(f"--> handle_join_game called for SID: {sid}")
    log.info(f"    Session contents: {dict(session)}")

    if 'username' not in session:
        emit('error_msg', {'message': 'Cannot join game: Not logged in.'})
        log.warning(f"Join attempt failed (not logged in): {sid}. Session did NOT contain 'username'.")
        return

    username = session['username']
    log.info(f"    Username '{username}' found in session for SID {sid}. Proceeding towards lock...")

    # --- Team Persistence Logic ---
    assigned_team = None
    needs_db_update = False

    try:
        user_data = mongo.db.users.find_one({"username": username})
        if user_data and 'team' in user_data and user_data['team'] in TEAMS:
            assigned_team = user_data['team']
            log.info(f"    Found persistent team '{assigned_team}' for user '{username}' in DB.")
        else:
            log.info(f"    No valid persistent team found for user '{username}'. Assigning balanced team.")
            assigned_team = get_balanced_team() # Assign a new team
            needs_db_update = True # Flag that we need to save this back to the DB
            log.info(f"    Assigned new team '{assigned_team}' to user '{username}'. Will update DB.")

    except Exception as e:
        log.error(f"!!!! EXCEPTION during MongoDB user lookup for SID {sid}: {e}", exc_info=True)
        emit('error_msg', {'message': f'Error retrieving user data: {e}'})
        return # Don't proceed if DB lookup fails

    if not assigned_team:
         log.error(f"!!!! Failed to assign a team for user '{username}' (SID: {sid}).")
         emit('error_msg', {'message': 'Could not assign a team.'})
         return
    # --- End Team Persistence Logic ---

    try:
        log.info(f"    Attempting to acquire game_lock for SID {sid} (Team: {assigned_team})")
        with game_lock:
            log.info(f"    Acquired game_lock for SID {sid}")
            try:
                # --- Update DB if needed (inside lock to potentially avoid race conditions if relevant) ---
                if needs_db_update:
                    try:
                        update_result = mongo.db.users.update_one(
                            {"username": username},
                            {"$set": {"team": assigned_team}}
                        )
                        if update_result.modified_count > 0:
                             log.info(f"    Successfully saved assigned team '{assigned_team}' to DB for user '{username}'.")
                        elif update_result.matched_count == 0:
                             log.warning(f"    Could not find user '{username}' in DB to save team.")
                        else:
                             log.info(f"    Team for user '{username}' was already set to '{assigned_team}' in DB (no modification needed).")

                    except Exception as e_db_update:
                         log.error(f"!!!! EXCEPTION during MongoDB user team update for SID {sid}: {e_db_update}", exc_info=True)
                         # Decide if this is critical - maybe proceed without saving but log warning
                         emit('error_msg', {'message': f'Could not save team preference: {e_db_update}'})
                # --- End DB Update ---

                # --- Main logic inside the lock ---
                if sid in game_state["players"]:
                    log.warning(f"User '{username}' ({sid}) tried to join again (already in players dict).")
                    # Maybe check if team matches? For now, just ignore duplicate join attempt logic.
                    emit('game_state', get_game_state_payload()) # Send current state
                else:
                    # Add player to game state using the determined 'assigned_team'
                    start_pos = (random.randint(0, GRID_WIDTH - 1), random.randint(0, GRID_HEIGHT - 1))
                    game_state["players"][sid] = {
                        'username': username,
                        'team': assigned_team, # Use the persistent or newly assigned team
                        'position': start_pos
                    }
                    game_state["team_counts"][assigned_team] += 1 # Increment count for the correct team
                    log.info(f"Player joined: {username} ({sid}), Team: {assigned_team}") # Log correct team

                    # Emit events
                    log.info(f"    Emitting assign_team ({assigned_team}) to {sid}")
                    emit('assign_team', {'team': assigned_team, 'initial_state': get_game_state_payload()})

                    # These emits remain the same, using the current game state
                    log.info(f"    Emitting player_joined to all")
                    socketio.emit('player_joined', {
                        'sid': sid,
                        'player': get_game_state_payload()['players'][sid]
                    })
                    log.info(f"    Emitting update_players to all")
                    socketio.emit('update_players', {'players': get_game_state_payload()['players']})

                    # Check if game starts
                    log.info(f"    Calling check_start_game for SID {sid}")
                    check_start_game()
                    log.info(f"    Finished check_start_game call for SID {sid}")
                # --- End of main logic ---

            except Exception as e_inner:
                log.error(f"!!!! EXCEPTION INSIDE 'with game_lock' for SID {sid}: {e_inner}", exc_info=True)
                emit('error_msg', {'message': f'Server error during join: {e_inner}'})
            finally:
                log.info(f"    Exiting 'with game_lock' block for SID {sid}. Lock is being released.")

    except Exception as e_outer:
        log.error(f"!!!! EXCEPTION OUTSIDE 'with game_lock' for SID {sid}: {e_outer}", exc_info=True)
        emit('error_msg', {'message': f'Server error before join: {e_outer}'})

@socketio.on('move')
def handle_move(data):
    sid = request.sid
    if 'username' not in session:
         emit('error_msg', {'message': 'Cannot move: Not logged in.'})
         return

    with game_lock:
        if not game_state["active"]:
            # emit('error_msg', {'message': 'Game is not active.'})
            return # Ignore moves if game not running

        if sid not in game_state["players"]:
            emit('error_msg', {'message': 'You are not in the current game.'})
            log.warning(f"Move received from unknown player: {sid}")
            return

        player = game_state["players"][sid]
        direction = data.get('direction')
        x, y = player['position']
        team = player['team']

        new_x, new_y = x, y
        if direction == 'up':
            new_y = max(0, y - 1)
        elif direction == 'down':
            new_y = min(GRID_HEIGHT - 1, y + 1)
        elif direction == 'left':
            new_x = max(0, x - 1)
        elif direction == 'right':
            new_x = min(GRID_WIDTH - 1, x + 1)
        else:
            log.warning(f"Invalid direction from {player['username']}: {direction}")
            return # Invalid direction

        new_pos = (new_x, new_y)

        # Check if position changed
        if new_pos != player['position']:
            player['position'] = new_pos

            # Paint the new cell only if it's different or wasn't owned by this team
            current_cell_color = game_state["grid"].get(new_pos)
            if current_cell_color != team:
                 # If another team owned it, decrement their score
                 if current_cell_color and current_cell_color in game_state["scores"]:
                      game_state["scores"][current_cell_color] -= 1
                 # Paint the cell and increment score
                 game_state["grid"][new_pos] = team
                 game_state["scores"][team] += 1

                 # Emit specific cell update for efficiency
                 socketio.emit('cell_update', {
                     'x': new_x, 'y': new_y, 'color': team,
                     'scores': dict(game_state["scores"]) # Send updated scores too
                 })

            # Emit player position update
            socketio.emit('player_moved', {
                'sid': sid,
                'position': list(new_pos), # Convert tuple to list for JSON
                'username': player['username'] # Include username for display updates
            })

# --- Main Execution ---
if __name__ == '__main__':
     log.info("Starting Flask-SocketIO server...")
     # Keep reloader=False while debugging this
     socketio.run(app, host='0.0.0.0', port=500, debug=True, use_reloader=False)