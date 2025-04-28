import eventlet
eventlet.monkey_patch() # Keep if needed for WebSocket stability

# Standard Library Imports
import os
import time
import threading
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
import random
from collections import defaultdict

# Flask and Extensions Imports
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_pymongo import PyMongo
from flask_socketio import SocketIO, emit, join_room, leave_room, send
from flask_session import Session # Import Flask-Session

# Security Imports
from werkzeug.security import generate_password_hash, check_password_hash
from passlib.hash import pbkdf2_sha256 as sha256


# --- Logging Configuration ---
log_file = 'server.log' # Log file in the project root directory
log_formatter = logging.Formatter(
    '%(asctime)s [%(levelname)s] [%(name)s] [PID:%(process)d] %(message)s'
)
# File Handler (Rotates logs)
file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=3, encoding='utf-8')
file_handler.setFormatter(log_formatter)
file_handler.setLevel(logging.INFO)
# Console Handler (Optional, to still see logs on console)
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(log_formatter)
stream_handler.setLevel(logging.INFO) # Adjust level for console if needed
# Configure Root Logger
root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
root_logger.addHandler(file_handler)
root_logger.addHandler(stream_handler)
# App-specific loggers
log = logging.getLogger(__name__)
request_log = logging.getLogger('requests') # Logger for HTTP requests
log.info("--------------------------------------------------")
log.info("Logging configured. Starting application setup...")
log.info("--------------------------------------------------")


# --- Flask App Initialization ---
app = Flask(__name__)
# !! IMPORTANT !! Change this secret key in a real application and keep it secret!
# Use environment variables for production.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change_this_to_a_strong_random_secret_key")

# Configure MongoDB
app.config["MONGO_URI"] = os.environ.get("MONGO_URI", "mongodb://localhost:27017/grid_game_db")

# --- Flask-Session Configuration ---
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = "./.flask_session" # Ensure this directory exists and is writable
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_USE_SIGNER"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True # Fulfills Req 5
app.config["SESSION_COOKIE_SAMESITE"] = 'Lax'
# Optional: Set session lifetime (default is often 31 days)
# app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)

# Ensure the session directory exists
if not os.path.exists(app.config["SESSION_FILE_DIR"]):
    try:
        os.makedirs(app.config["SESSION_FILE_DIR"])
        log.info(f"Created session directory: {app.config['SESSION_FILE_DIR']}")
    except OSError as e:
        log.error(f"Failed to create session directory {app.config['SESSION_FILE_DIR']}: {e}")


# --- Extensions Initialization ---
mongo = PyMongo(app)
server_session = Session(app) # Initialize Flask-Session AFTER config
# Use app.logger provided by Flask which is configured by our handlers now
# Use specific loggers 'log' and 'request_log' where appropriate
socketio = SocketIO(app, async_mode='eventlet', logger=log, engineio_logger=log.getChild('engineio'))


# --- Game Constants ---
GRID_WIDTH = 30
GRID_HEIGHT = 20
GAME_DURATION_SECONDS = 30 # 30 seconds game time
TEAMS = ['red', 'blue', 'green', 'yellow']
MIN_TEAMS_TO_START = 2
RESET_DELAY_SECONDS = 10 # Show results for 10 seconds


# --- Game State (In-Memory) & Lock ---
game_state = {
    "active": False,
    "start_time": None,
    "grid": {},  # {(x, y): team_color}
    "players": {}, # {sid: {'username': str, 'team': str, 'position': (x, y)}}
    "scores": defaultdict(int), # {team_color: score}
    "team_counts": defaultdict(int), # {team_color: count} - In-memory count of *connected* players
    "timer": None,
    "winner": None,
}
game_lock = threading.Lock() # To protect concurrent access to game_state


# --- Request Logging ---
@app.before_request
def log_request_info():
    """Log information about each incoming HTTP request."""
    ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr)
    # Using the dedicated 'requests' logger
    request_log.info(f'{ip_addr} - "{request.method} {request.path}"')


# --- Helper Functions ---

def get_balanced_team():
    """Assigns a player to the least populated team based on *connected* players."""
    min_count = float('inf')
    best_teams = []
    # Operate on a safe copy of current counts
    with game_lock:
        current_counts = dict(game_state["team_counts"])

    log.debug(f"Calculating balanced team based on current counts: {current_counts}")
    for team in TEAMS:
        count = current_counts.get(team, 0)
        if count < min_count:
            min_count = count
            best_teams = [team]
        elif count == min_count:
            best_teams.append(team)

    if not best_teams: # Fallback if TEAMS is empty or error
        log.error("No teams available in get_balanced_team! Assigning random from TEAMS.")
        return random.choice(TEAMS) if TEAMS else None

    chosen_team = random.choice(best_teams)
    log.info(f"Balanced team choice: {chosen_team} (min_count: {min_count})")
    return chosen_team

def calculate_scores():
    """Recalculates scores based on the current grid state."""
    # Needs lock as it reads game_state["grid"] which can be modified elsewhere
    with game_lock:
        new_scores = defaultdict(int)
        for cell_color in game_state["grid"].values():
            if cell_color in TEAMS:
                new_scores[cell_color] += 1
    return new_scores

def reset_game():
    """Resets the mutable parts of the game state for a new round."""
    # Assumes game_lock is already held by caller (e.g., delayed_reset)
    log.info("Resetting game state (grid, scores, timer, active status)...")
    game_state["active"] = False
    game_state["start_time"] = None
    game_state["grid"] = {}
    game_state["scores"] = defaultdict(int) # Reset scores
    if game_state["timer"]:
        game_state["timer"].cancel() # Cancel any existing timer
        game_state["timer"] = None
    game_state["winner"] = None
    # Player positions will be reset in check_start_game if it starts

def end_game():
    """Ends the current game round."""
    log.info("Attempting to end game...")
    with game_lock:
        if not game_state["active"]:
            log.warning("end_game called but game is not active.")
            return # Game already ended or wasn't active

        log.info("Game ending sequence started...")
        game_state["active"] = False
        final_scores = calculate_scores() # Recalculate final scores safely
        game_state["scores"] = final_scores

        winner = None
        max_score = -1
        winners = []
        log.info(f"Final scores: {dict(final_scores)}")
        for team, score in final_scores.items():
             if score > max_score:
                 max_score = score
                 winners = [team]
             elif score == max_score and score > 0 : # Only tie if score > 0
                 winners.append(team)

        if len(winners) == 1:
            winner = winners[0]
            game_state["winner"] = winner
            log.info(f"Game Over! Winner: {winner} (Score: {max_score})")
        elif len(winners) > 1:
             winner = "Tie" # Indicate a tie
             game_state["winner"] = winner
             log.info(f"Game Over! Tie between: {', '.join(winners)} (Score: {max_score})")
        else:
             winner = "None" # No winner if no scores
             game_state["winner"] = winner
             log.info("Game Over! No scores recorded.")

        # Notify all clients
        socketio.emit('game_over', {
            'scores': dict(final_scores),
            'winner': winner # Send "Tie" or "None" if applicable
        })
        log.info("Game over notification sent to clients.")

        # Schedule the reset (calls delayed_reset)
        log.info(f"Scheduling game reset in {RESET_DELAY_SECONDS} seconds.")
        threading.Timer(RESET_DELAY_SECONDS, delayed_reset).start()

def delayed_reset():
     """Resets the game state after a delay and attempts to start a new game."""
     try:
         log.info("Executing delayed_reset...")
         with game_lock:
             reset_game() # Reset grid, scores, active status, timer
             log.info("Game reset completed.")

             # Attempt to start a new game if conditions are met
             log.info("Calling check_start_game after reset...")
             check_start_game() # Fulfills Req: Auto-start after reset delay
     except Exception as e:
         log.error(f"!!!! EXCEPTION in delayed_reset: {e}", exc_info=True)
     finally:
          log.info("Finished executing delayed_reset.")

def check_start_game():
    """Checks if conditions are met and starts a new game round."""
    # Assumes game_lock is HELD by the caller (handle_join_game or delayed_reset)
    log.info("    Inside check_start_game...")
    try:
        if game_state["active"]:
            log.info("    check_start_game: Game already active.")
            return

        # Check based on *connected* players' teams
        teams_with_players = sum(1 for count in game_state["team_counts"].values() if count > 0)
        log.info(f"    check_start_game: Teams with currently connected players = {teams_with_players}")

        if teams_with_players >= MIN_TEAMS_TO_START:
            log.info("    check_start_game: Conditions met. Starting game...")
            game_state["active"] = True
            game_state["start_time"] = time.time()
            game_state["winner"] = None
            game_state["grid"] = {} # Ensure grid is clear
            game_state["scores"] = defaultdict(int) # Ensure scores are reset

            log.info("    check_start_game: Resetting player positions and painting initial cells.")
            for sid, player_data in list(game_state["players"].items()): # Iterate over copy
                try:
                    player_data['position'] = (
                        random.randint(0, GRID_WIDTH - 1),
                        random.randint(0, GRID_HEIGHT - 1)
                    )
                    # Ensure position is not already taken (optional, simple overwrite ok for now)
                    game_state["grid"][player_data['position']] = player_data['team']
                    game_state["scores"][player_data['team']] += 1
                except Exception as e_player_reset:
                     log.error(f"Error resetting position/score for player {player_data.get('username','unknown')}: {e_player_reset}")

            log.info("    check_start_game: Player positions reset.")

            if game_state["timer"]: # Cancel just in case
                log.warning("    check_start_game: Found existing timer unexpectedly, cancelling.")
                game_state["timer"].cancel()
            log.info(f"    check_start_game: Starting new {GAME_DURATION_SECONDS}s timer.")
            game_state["timer"] = threading.Timer(GAME_DURATION_SECONDS, end_game)
            game_state["timer"].start()

            log.info("    check_start_game: Emitting game_start event.")
            socketio.emit('game_start', get_game_state_payload()) # Send initial state
            log.info("    check_start_game: Game started event emitted.")
        else:
            log.info(f"    check_start_game: Not starting game. Need {MIN_TEAMS_TO_START} teams with players, have {teams_with_players}")

    except Exception as e:
         log.error(f"!!!! EXCEPTION inside check_start_game: {e}", exc_info=True)
    # No finally block needed here as lock is managed outside

def get_game_state_payload():
     """Creates the payload for game state updates. Assumes lock may be needed if called outside."""
     # This function primarily reads game_state, acquire lock if called from non-locked context
     # However, it's usually called right after modifications within a lock, so maybe okay.
     # Let's be safe and acquire lock here if not already held (tricky without context).
     # For simplicity, assume caller holds the lock if modifications just happened.
     # If called asynchronously, it MUST acquire the lock.
     # Let's assume it's called synchronously after modifications for now.

     time_remaining = None
     if game_state["active"] and game_state["start_time"]:
         elapsed = time.time() - game_state["start_time"]
         time_remaining = max(0, GAME_DURATION_SECONDS - elapsed)

     serializable_grid = {f"{x},{y}": color for (x, y), color in game_state["grid"].items()}
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
         'teams': TEAMS,
         'winner': game_state["winner"] # Include winner info if game just ended
     }


# --- Flask Routes ---

@app.route('/')
def index():
    if 'username' in session:
        # User is logged in (persistent session checked)
        log.debug(f"User '{session['username']}' accessing '/' - redirecting to /game")
        return redirect(url_for('game'))
    log.debug("Anonymous user accessing '/' - showing index/login page")
    return render_template('index.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr)
    log.info(f"Registration attempt for username: '{username}' from IP: {ip_addr}")

    if not username or not password:
        flash("Username and password are required.", "error")
        log.warning(f"Registration failed for IP {ip_addr}: Missing fields.")
        return redirect(url_for('index'))
    # Add more validation (e.g., password complexity, username format) here if needed

    if mongo.db.users.find_one({"username": username}):
        flash("Username already exists.", "error")
        log.warning(f"Registration failed for '{username}' from IP {ip_addr}: Username exists.")
        return redirect(url_for('index'))

    hashed_password = sha256.hash(password) # Salted and hashed
    try:
        user_doc = {
            "username": username,
            "password_hash": hashed_password,
            "team": None, # Initialize team field
            "registered_at": datetime.utcnow()
        }
        insert_result = mongo.db.users.insert_one(user_doc)
        if insert_result.inserted_id:
            flash("Registration successful! Please login.", "success")
            log.info(f"Registration successful for '{username}' (ID: {insert_result.inserted_id}) from IP {ip_addr}.")
        else:
             raise Exception("User insertion failed silently.") # Should not happen
    except Exception as e:
        log.error(f"Database error during registration for '{username}': {e}", exc_info=True)
        flash("An internal error occurred during registration.", "error")

    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr)
    log.info(f"Login attempt for username: '{username}' from IP: {ip_addr}")

    if not username or not password:
        flash("Username and password are required.", "error")
        log.warning(f"Login failed for IP {ip_addr}: Missing fields.")
        return redirect(url_for('index'))

    try:
        user = mongo.db.users.find_one({"username": username})
        if user and sha256.verify(password, user['password_hash']):
            session['username'] = username # Store in persistent session
            session['user_id'] = str(user['_id']) # Store user ID too if useful
            log.info(f"User '{username}' (ID: {session['user_id']}) logged in successfully from IP {ip_addr}.")
            return redirect(url_for('game'))
        else:
            flash("Invalid username or password.", "error")
            log.warning(f"Login failed for '{username}' from IP {ip_addr}: Invalid credentials.")
            return redirect(url_for('index'))
    except Exception as e:
        log.error(f"Error during login for '{username}': {e}", exc_info=True)
        flash("An internal error occurred during login.", "error")
        return redirect(url_for('index'))


@app.route('/logout')
def logout():
    username = session.get('username', 'Unknown')
    user_id = session.get('user_id', 'N/A')
    ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr)

    log.info(f"Logout request from user '{username}' (ID: {user_id}) from IP {ip_addr}.")
    # Clear the persistent session server-side
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('index'))

@app.route('/game')
def game():
    # Check persistent session
    if 'username' not in session:
        ip_addr = request.headers.get('X-Forwarded-For', request.remote_addr)
        log.warning(f"Unauthorized access attempt to /game from IP {ip_addr} - redirecting to login.")
        flash("Please login to play.", "error")
        return redirect(url_for('index'))

    username = session['username']
    log.info(f"User '{username}' accessing /game.")
    return render_template('game.html', username=username)


# --- SocketIO Event Handlers ---

@socketio.on('connect')
def handle_connect():
    sid = request.sid
    # Session should be available here due to Flask-Session integration
    if 'username' in session:
        username = session['username']
        log.info(f"Socket connected: User '{username}' (SID: {sid})")
        emit('connection_ack', {'sid': sid}) # Acknowledge connection
    else:
        # This ideally shouldn't happen if /game requires login,
        # but handle defensively.
        log.warning(f"Socket connection attempt from unauthenticated session (SID: {sid}). Disallowing join.")
        # Optionally disconnect the user if they shouldn't be here at all
        # emit('error_msg', {'message': 'Authentication error. Please login again.'})
        # return False # Returning False disconnects the client
        emit('connection_ack', {'sid': sid, 'error': 'Not Authenticated'}) # Acknowledge but indicate error


@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    # Remove player from in-memory game state
    with game_lock:
        player_info = game_state["players"].pop(sid, None)
        if player_info:
            username = player_info['username']
            team = player_info['team']
            log.info(f"Player disconnected: {username} ({sid}), Team: {team}")

            # Decrement in-memory team count for balancing new players
            if team in game_state["team_counts"]:
                 game_state["team_counts"][team] -= 1
                 if game_state["team_counts"][team] <= 0:
                      del game_state["team_counts"][team] # Clean up empty team count
            log.info(f"Updated team counts: {dict(game_state['team_counts'])}")

            # Don't clear their painted cells from the grid
            # Notify remaining players
            socketio.emit('player_left', {'sid': sid, 'username': username})
            socketio.emit('update_players', {'players': get_game_state_payload()['players']})
            # Optional: Check if game needs to stop if too few players remain
            # check_stop_game() # Implement if needed
        else:
            log.info(f"Client disconnected without being in active game state (SID: {sid})")


@socketio.on('join_game')
def handle_join_game():
    """Handles player joining, assigns persistent or new team, adds to game."""
    sid = request.sid
    log.info(f"--> handle_join_game called for SID: {sid}")
    # Use dict(session) for logging as session object itself isn't directly serializable
    log.info(f"    Session contents: {dict(session)}")

    if 'username' not in session:
        emit('error_msg', {'message': 'Cannot join game: Not logged in.'})
        log.warning(f"Join attempt failed (not logged in): {sid}. Session did NOT contain 'username'.")
        return

    username = session['username']
    log.info(f"    User '{username}' found in session for SID {sid}. Proceeding...")

    # --- Team Persistence Logic ---
    assigned_team = None
    needs_db_update = False
    try:
        user_data = mongo.db.users.find_one({"username": username})
        if user_data and 'team' in user_data and user_data['team'] in TEAMS:
            assigned_team = user_data['team']
            log.info(f"    Found persistent team '{assigned_team}' for user '{username}' in DB.")
        else:
            log.info(f"    No valid persistent team found for '{username}'. Assigning balanced team.")
            assigned_team = get_balanced_team()
            if assigned_team:
                needs_db_update = True
                log.info(f"    Assigned new team '{assigned_team}' to user '{username}'. Will update DB.")
            else:
                log.error(f"    Failed to get a balanced team for '{username}'. Cannot join.")
                emit('error_msg', {'message': 'Error assigning team. No teams available?'})
                return

    except Exception as e:
        log.error(f"!!!! EXCEPTION during MongoDB user lookup for SID {sid}, User '{username}': {e}", exc_info=True)
        emit('error_msg', {'message': f'Error retrieving user data: {e}'})
        return

    if not assigned_team: # Should be caught above, but double check
         log.error(f"!!!! Failed to assign a team for user '{username}' (SID: {sid}).")
         emit('error_msg', {'message': 'Could not assign a team.'})
         return
    # --- End Team Persistence Logic ---

    # --- Lock and Modify Game State ---
    try:
        log.info(f"    Attempting to acquire game_lock for SID {sid} (User: {username}, Team: {assigned_team})")
        with game_lock:
            log.info(f"    Acquired game_lock for SID {sid}")
            try:
                # Update DB if needed
                if needs_db_update:
                    try:
                        update_result = mongo.db.users.update_one(
                            {"username": username},
                            {"$set": {"team": assigned_team}}
                        )
                        log.info(f"    DB update result for user '{username}', team '{assigned_team}': Matched={update_result.matched_count}, Modified={update_result.modified_count}")
                    except Exception as e_db_update:
                         log.error(f"!!!! EXCEPTION during MongoDB user team update for SID {sid}, User '{username}': {e_db_update}", exc_info=True)
                         # Non-critical, proceed but log
                         flash("Could not save team preference.", "warning") # Flash might not show well here

                # Add player to in-memory game state
                if sid in game_state["players"]:
                    log.warning(f"User '{username}' ({sid}) tried to join again (already in players dict). Sending current state.")
                    emit('game_state', get_game_state_payload())
                else:
                    start_pos = (random.randint(0, GRID_WIDTH - 1), random.randint(0, GRID_HEIGHT - 1))
                    game_state["players"][sid] = {
                        'username': username,
                        'team': assigned_team, # Use the determined team
                        'position': start_pos
                    }
                    game_state["team_counts"][assigned_team] = game_state["team_counts"].get(assigned_team, 0) + 1
                    log.info(f"Player added to game state: {username} ({sid}), Team: {assigned_team}. New Counts: {dict(game_state['team_counts'])}")

                    # Emit events
                    log.info(f"    Emitting assign_team ({assigned_team}) to {sid}")
                    emit('assign_team', {'team': assigned_team, 'initial_state': get_game_state_payload()})

                    payload_players = get_game_state_payload()['players'] # Get updated player list once

                    log.info(f"    Emitting player_joined ({username}) to all")
                    socketio.emit('player_joined', {
                        'sid': sid,
                        'player': payload_players.get(sid) # Send specific new player data safely
                    })
                    log.info(f"    Emitting update_players to all")
                    socketio.emit('update_players', {'players': payload_players})

                    # Check if game starts
                    log.info(f"    Calling check_start_game from handle_join_game for SID {sid}")
                    check_start_game()

            except Exception as e_inner:
                log.error(f"!!!! EXCEPTION INSIDE 'with game_lock' for SID {sid}, User '{username}': {e_inner}", exc_info=True)
                emit('error_msg', {'message': f'Server error during join processing: {e_inner}'})
            finally:
                log.info(f"    Exiting 'with game_lock' block for SID {sid}. Lock released.")

    except Exception as e_outer:
        log.error(f"!!!! EXCEPTION OUTSIDE 'with game_lock' acquire for SID {sid}, User '{username}': {e_outer}", exc_info=True)
        emit('error_msg', {'message': f'Server error before processing join: {e_outer}'})

@socketio.on('move')
def handle_move(data):
    """Handles player movement and grid painting."""
    sid = request.sid
    if 'username' not in session:
         log.warning(f"Move received from unauthenticated session (SID: {sid}). Ignoring.")
         # emit('error_msg', {'message': 'Cannot move: Not logged in.'}) # Avoid flooding client
         return

    with game_lock:
        if not game_state["active"]:
            # log.debug(f"Move ignored from SID {sid}: Game not active.") # Can be noisy
            return # Ignore moves if game not running

        player = game_state["players"].get(sid)
        if not player:
            log.warning(f"Move received from SID {sid} but player not found in game state. Ignoring.")
            # emit('error_msg', {'message': 'You are not in the current game.'})
            return

        username = player['username']
        direction = data.get('direction')
        x, y = player['position']
        team = player['team']

        new_x, new_y = x, y
        if direction == 'up': new_y = max(0, y - 1)
        elif direction == 'down': new_y = min(GRID_HEIGHT - 1, y + 1)
        elif direction == 'left': new_x = max(0, x - 1)
        elif direction == 'right': new_x = min(GRID_WIDTH - 1, x + 1)
        else:
            log.warning(f"Invalid move direction '{direction}' from {username} ({sid}).")
            return

        new_pos = (new_x, new_y)

        if new_pos != player['position']:
            log.debug(f"Processing move: {username} ({sid}) from {player['position']} to {new_pos}")
            player['position'] = new_pos
            current_cell_color = game_state["grid"].get(new_pos)

            cell_updated = False
            if current_cell_color != team:
                 cell_updated = True
                 if current_cell_color and current_cell_color in game_state["scores"]:
                      game_state["scores"][current_cell_color] -= 1
                 game_state["grid"][new_pos] = team
                 game_state["scores"][team] = game_state["scores"].get(team, 0) + 1

                 # Emit specific cell update
                 socketio.emit('cell_update', {
                     'x': new_x, 'y': new_y, 'color': team,
                     'scores': dict(game_state["scores"])
                 })

            # Emit player position update regardless of cell paint
            socketio.emit('player_moved', {
                'sid': sid,
                'position': list(new_pos),
                'username': username
            })
            # Log move completion
            # log.debug(f"Move processed for {username}. Cell updated: {cell_updated}. New Scores: {dict(game_state['scores'])}")


# --- Main Execution ---
if __name__ == '__main__':
    log.info("===================================================")
    log.info(f"Starting Flask-SocketIO server (PID: {os.getpid()})...")
    log.info(f"Flask App Name: {app.name}")
    log.info(f"Debug mode: {app.debug}")
    # Recommended settings for running directly (adjust host/port as needed)
    # Set debug=False and use_reloader=False for stability, especially with logging/timers/sessions
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, use_reloader=False)
    log.info("Flask-SocketIO server has shut down.")
    log.info("===================================================")