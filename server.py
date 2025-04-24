import select

if hasattr(select, 'kqueue'):
    import sys
    if sys.platform == 'darwin':
        select.kqueue = None

# Then your existing imports
import eventlet
eventlet.monkey_patch()
import eventlet.wsgi
from flask import Flask, flash, jsonify, make_response, render_template, request, session, redirect, url_for
from flask_socketio import SocketIO, emit, join_room, leave_room, send
from util.leaderboard import handle_leaderboard_page, handle_territory_leaderboard_api, handle_wins_leaderboard_api
from util.logger import setup_logging

import time
import threading
import secrets
import os
import logging
from flask_socketio import disconnect

from util.register import handle_register
from util.login import handle_login
from util.auth_utli import get_user_by_token

# --- Game Configuration ---
GRID_SIZE = 25
GAME_DURATION = 30  # Seconds
PLAYER_COLORS = ['#ff4136', '#0074d9', '#2ecc40', '#ffdc00'] # Red, Blue, Green, Yellow
MAX_PLAYERS = 4

# --- NEW: Map hex colors to names ---
COLOR_NAMES = {
    '#ff4136': 'Red',
    '#0074d9': 'Blue',
    '#2ecc40': 'Green',
    '#ffdc00': 'Yellow'
}

# --- Flask App Setup ---
app = Flask(__name__)
setup_logging(app)
@app.before_request
def log_request_info():
    logging.info(request)
    # ip = request.remote_addr
    # method = request.method
    # path = request.path
    # timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    #
    # logging.info(f"{timestamp} - {ip} - {method} {path}")

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'


socketio = SocketIO(app,
                    async_mode='eventlet',
                    cors_allowed_origins="*") # RESTRICT IN PRODUCTION

# --- Game State (Server-Side) ---
game_state = {
    "grid": [[-1 for _ in range(GRID_SIZE)] for _ in range(GRID_SIZE)],
    "players": {}, # Dictionary: {sid: player_data}
    "scores": [0] * MAX_PLAYERS,
    "remaining_time": GAME_DURATION,
    "game_active": False,
    "timer_thread": None,
    "assigned_ids": [False] * MAX_PLAYERS # Track which player IDs (0-3) are taken
}
game_state_lock = threading.Lock() # Using threading Lock

# --- Helper Functions ---
def get_available_player_id():
    # Finds the first available player ID (0 to MAX_PLAYERS-1)
    with game_state_lock:
        for i in range(MAX_PLAYERS):
            if not game_state["assigned_ids"][i]:
                game_state["assigned_ids"][i] = True
                return i
    return -1 # No ID available

def release_player_id(player_id):
    # Marks a player ID as available again
    if 0 <= player_id < MAX_PLAYERS:
        with game_state_lock:
             # Check if the ID is actually assigned before releasing
             if game_state["assigned_ids"][player_id]:
                 game_state["assigned_ids"][player_id] = False

def reset_game_state():
    # Resets the game to its initial state
    with game_state_lock:
        game_state["grid"] = [[-1 for _ in range(GRID_SIZE)] for _ in range(GRID_SIZE)]
        game_state["players"] = {}
        game_state["scores"] = [0] * MAX_PLAYERS # Reset scores
        game_state["remaining_time"] = GAME_DURATION
        game_state["game_active"] = False
        game_state["assigned_ids"] = [False] * MAX_PLAYERS # Reset assignments
        # Stop any existing timer greenlet
        timer = game_state.get("timer_thread")
        if timer:
            try:
                timer.kill()
            except Exception:
                pass # Ignore errors if killing fails
        game_state["timer_thread"] = None

def get_state_for_client():
    # Creates a snapshot of the current game state suitable for sending to clients
    with game_state_lock:
        # Create a list copy of player data to avoid sending internal details like SID
        players_list = list(game_state["players"].values())
        # Create a copy of the state to send
        state = {
            "grid": game_state["grid"],
            "players": players_list,
            "scores": game_state["scores"],
            "remaining_time": game_state["remaining_time"],
            "game_active": game_state["game_active"]
        }
        return state

def game_timer():
    # Background task (greenlet) that decrements the game timer
    while True:
        with game_state_lock:
            is_active = game_state["game_active"]
            time_left = game_state["remaining_time"]

        if not is_active:
            break # Stop timer if game becomes inactive

        if time_left <= 0:
            end_game() # End the game if time runs out
            break

        # Decrement time inside the lock
        with game_state_lock:
            if game_state["remaining_time"] > 0:
                game_state["remaining_time"] -= 1
            current_time = game_state["remaining_time"]

        # Broadcast the update AFTER releasing the lock for decrementing
        socketio.emit('game_update', get_state_for_client())

        if current_time <= 0:
             # We already called end_game() above if time_left was <= 0 initially,
             # but this catches the case where it hits 0 during the decrement.
             # end_game() is idempotent due to the game_active check inside it.
             end_game()
             break

        # Yield control cooperatively for 1 second
        socketio.sleep(1)

    # Clean up timer reference when the loop finishes
    with game_state_lock:
        game_state["timer_thread"] = None

def start_game_if_ready():
    # Checks if enough players have joined and starts the game
    should_start = False
    with game_state_lock:
        num_players = len(game_state["players"])
        # Start only if game isn't already active and we have the max number of players
        if not game_state["game_active"] and num_players >= MAX_PLAYERS:
            game_state["game_active"] = True
            game_state["remaining_time"] = GAME_DURATION # Reset timer
            should_start = True
            # Start the timer greenlet only if it's not already running
            if game_state["timer_thread"] is None:
                game_state["timer_thread"] = socketio.start_background_task(target=game_timer)

    # Emit updates outside the lock
    if should_start:
        socketio.emit('game_update', get_state_for_client()) # Send initial active state
        socketio.emit('game_event', {'message': 'Game Started!'})

def end_game():
    # Ends the current game, calculates the winner, and notifies clients
    winners = []
    max_score = -1
    was_active = False # Flag to check if the game was actually active when ended

    with game_state_lock:
        if game_state["game_active"]: # Only proceed if the game is currently active
            game_state["game_active"] = False # Mark game as inactive
            was_active = True

            # Stop the timer greenlet
            timer = game_state.get("timer_thread")
            if timer:
                try:
                    timer.kill()
                except Exception:
                    pass # Ignore errors
                game_state["timer_thread"] = None # Clear reference

            # Determine winner(s) based on final scores
            scores = game_state["scores"] # Use the final scores
            for i, score in enumerate(scores):
                if score > max_score:
                    max_score = score
                    winners = [i] # New highest score
                elif score == max_score and score > 0: # Tie for the highest score (and score > 0)
                    winners.append(i)
        # else: Game was already inactive, do nothing

    # Announce winner(s) only if the game was active when end_game was called
    if was_active:
        winner_message = "Game Over! "
        if not winners or max_score <= 0:
            winner_message += "No winner!"
        elif len(winners) == 1:
            winner_idx = winners[0]
            # Safely get hex color
            winner_hex = PLAYER_COLORS[winner_idx] if 0 <= winner_idx < len(PLAYER_COLORS) else '#ffffff'
            # *** CHANGE: Look up color name, fallback to hex ***
            winner_color_name = COLOR_NAMES.get(winner_hex, winner_hex)
            winner_message += f"Player {winner_idx + 1} ({winner_color_name}) Wins!"
        else:
            winner_message += "It's a tie between Players: "
            winner_strs = []
            for w_idx in winners:
                # Safely get hex color
                w_hex = PLAYER_COLORS[w_idx] if 0 <= w_idx < len(PLAYER_COLORS) else '#ffffff'
                # *** CHANGE: Look up color name, fallback to hex ***
                w_color_name = COLOR_NAMES.get(w_hex, w_hex)
                winner_strs.append(f"{w_idx + 1} ({w_color_name})")
            winner_message += ", ".join(winner_strs)

        # Broadcast final state and game over message
        socketio.emit('game_update', get_state_for_client()) # Send final scores/state
        socketio.emit('game_event', {'message': winner_message, 'isGameOver': True})

# --- NEW: Authentication Middleware ---
def check_auth():
    """
    Check if user is authenticated by verifying auth_token cookie
    Returns user object if authenticated, None otherwise
    """
    auth_token = request.cookies.get('auth_token')
    if not auth_token:
        app.logger.warning("No auth_token cookie found")
        return None

    # Verify token and get user
    user = get_user_by_token(auth_token)
    if user:
        app.logger.info(f"User authenticated: {user.get('username', 'unknown')}")
    else:
        app.logger.warning(f"Invalid auth_token: {auth_token[:10]}...")
    return user

def auth_required(f):
    """
    Decorator to require authentication for routes
    Redirects to login page if not authenticated
    """
    def decorated(*args, **kwargs):
        user = check_auth()
        if not user:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__  # Preserve the original function name
    return decorated

def no_auth_required(f):
    """
    Decorator for routes that should only be accessible when NOT authenticated
    Redirects to game/index if already authenticated
    Uses a 302 redirect to ensure no connection to WebSocket occurs
    """
    def decorated(*args, **kwargs):
        user = check_auth()
        if user:
            # Use 302 redirect to ensure immediate redirect before any WebSocket connection
            return redirect(url_for('index'), 302)
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__  # Preserve the original function name
    return decorated

# --- Modified Flask Routes ---
@app.route('/')
def index():
    """
    Serves the main game page or redirects to login if not authenticated
    """
    user = check_auth()
    if not user:
        return redirect(url_for('login'))

    # User is authenticated, serve the game page
    return render_template('game.html')

@app.route('/login', methods=['GET', 'POST'])
@no_auth_required
def login():
    """
    Route for user login - only accessible when not logged in
    GET: Serves the login page
    POST: Authenticates user credentials and redirects to game
    """
    return handle_login()

@app.route('/register', methods=['GET', 'POST'])
@no_auth_required
def register():
    """
    Route for user registration - only accessible when not logged in
    Uses the registration logic from register.py
    """
    return handle_register()

@app.route('/logout')
def logout():
    """
    Route for user logout
    Clears the auth_token cookie and redirects to login
    """
    from util.auth_utli import clear_auth_cookie

    response = make_response(redirect(url_for('login')))
    clear_auth_cookie(response)
    flash('You have been logged out.', 'success')
    return response


@app.route('/debug')
def debug_auth():
    """
    Debug route to check authentication status
    """
    user = check_auth()
    cookies = request.cookies

    if user:
        return jsonify({
            "authenticated": True,
            "username": user.get('username'),
            "cookies": {k: v[:10] + "..." if k == "auth_token" else v for k, v in cookies.items()}
        })
    else:
        return jsonify({
            "authenticated": False,
            "cookies": dict(cookies)
        })
@app.route('/leaderboard')
@auth_required
def leaderboard():
    """
    Serves the leaderboard page
    """
    return handle_leaderboard_page()

@app.route('/api/leaderboard/wins')
@auth_required
def leaderboard_wins_api():
    """
    API endpoint for the wins leaderboard data
    """
    return handle_wins_leaderboard_api()

@app.route('/api/leaderboard/territory')
@auth_required
def leaderboard_territory_api():
    """
    API endpoint for the territory score leaderboard data
    """
    return handle_territory_leaderboard_api()

# --- Default route to handle initial page load ---
@app.route('/_init')
def initial_route():
    """
    Initial route that redirects based on authentication status
    If authenticated -> game page, otherwise -> login page
    """
    user = check_auth()
    if user:
        return redirect(url_for('index'))
    else:
        return redirect(url_for('login'))

# --- SocketIO Event Handlers ---
@socketio.on('connect')
def handle_connect():
    """
    Handles new client connections with improved authentication
    """
    # First verify the user is authenticated
    user = check_auth()
    if not user:
        # Reject connection if not authenticated
        emit('connect_error', {'message': 'Authentication required'})
        # Disconnect immediately to prevent pending connections
        disconnect()
        return


    sid = request.sid
    player_id = get_available_player_id() # Try to get an ID

    with game_state_lock:
        is_game_active = game_state["game_active"]
        num_current_players = len(game_state["players"])

    # Reject connection if no ID available, game is full, or game is in progress
    if player_id == -1 or num_current_players >= MAX_PLAYERS or is_game_active:
        reject_reason = "Game full or unavailable" if player_id == -1 else "Game already in progress"
        emit('connect_error', {'message': f'Sorry, {reject_reason}!'})
        # Release the ID if it was tentatively assigned but rejected due to other conditions
        if player_id != -1:
             release_player_id(player_id)
        disconnect()
        return # Stop processing connection

    # Assign starting position based on player ID
    potential_starts = [(1, 1), (GRID_SIZE - 2, 1), (1, GRID_SIZE - 2), (GRID_SIZE - 2, GRID_SIZE - 2)]
    # Ensure player_id is valid index for starts and colors
    if not (0 <= player_id < len(potential_starts) and 0 <= player_id < len(PLAYER_COLORS)):
         # This should ideally not happen if MAX_PLAYERS matches array sizes
         emit('connect_error', {'message': 'Internal server error: player configuration mismatch.'})
         release_player_id(player_id)
         disconnect()
         return

    start_x, start_y = potential_starts[player_id]
    player_color = PLAYER_COLORS[player_id]

    # Add user info to player data
    player_data = {
        'id': player_id,
        'sid': sid,
        'x': start_x,
        'y': start_y,
        'color': player_color,
        'username': user['username']  # Include username from auth
    }

    with game_state_lock:
        # Store player data
        game_state["players"][sid] = player_data
        # Claim initial cell and update score (only if cell is empty)
        if game_state["grid"][start_y][start_x] == -1:
            game_state["grid"][start_y][start_x] = player_id
            game_state["scores"][player_id] += 1 # Increment score for initial claim

    # --- Operations outside the lock ---
    # Send player assignment info to the connecting client
    assign_payload = {'playerId': player_id}
    emit('assign_player', assign_payload, room=sid)

    # Send the current game state to the new client
    current_client_state = get_state_for_client()
    emit('game_update', current_client_state, room=sid)

    # Notify existing clients about the new player and update their state
    socketio.emit('game_update', current_client_state, skip_sid=sid) # Send to others
    socketio.emit('game_event', {'message': f'Player {player_id + 1} ({COLOR_NAMES.get(player_color, player_color)}) has joined!'}) # Use color name here too!

    # Check if the game can start now
    start_game_if_ready()

@socketio.on('disconnect')
def handle_disconnect():
    # Handles client disconnections
    sid = request.sid
    player_id = -1
    player_color_name = "Unknown" # Default
    was_game_active = False
    num_players_after_disconnect = 0

    # Remove player data and release ID under lock
    with game_state_lock:
        was_game_active = game_state["game_active"] # Check status before removing player
        player_data = game_state["players"].pop(sid, None) # Remove player by SID
        if player_data:
            player_id = player_data['id']
            hex_color = player_data.get('color', '#ffffff')
            player_color_name = COLOR_NAMES.get(hex_color, hex_color) # Get name for disconnect message
            release_player_id(player_id) # Make the ID available again
        num_players_after_disconnect = len(game_state["players"]) # Count remaining players

    # --- Operations outside the lock ---
    if player_id != -1: # If a known player disconnected
        # Notify remaining clients
        socketio.emit('game_update', get_state_for_client()) # Update state for others
        socketio.emit('game_event', {'message': f'Player {player_id + 1} ({player_color_name}) has left.'}) # Use name

        # End the game if it was active and player count drops below minimum
        if was_game_active and num_players_after_disconnect < MAX_PLAYERS:
            end_game() # End the game prematurely

@socketio.on('player_move')
def handle_player_move(data):
    # Handles player movement requests
    sid = request.sid
    should_broadcast = False # Flag to indicate if an update needs to be sent

    with game_state_lock:
        # 1. Check if game is active and player exists
        if not game_state["game_active"]: return
        player = game_state["players"].get(sid)
        if not player: return

        # 2. Validate input data
        if not isinstance(data, dict) or 'dx' not in data or 'dy' not in data: return
        dx = data.get('dx', 0); dy = data.get('dy', 0)
        # Ensure movement is only 1 step horizontally or vertically
        if abs(dx) + abs(dy) != 1: return

        # 3. Calculate new position
        current_x = player['x']; current_y = player['y']
        next_x = current_x + dx; next_y = current_y + dy

        # 4. Check if new position is within grid bounds
        if 0 <= next_x < GRID_SIZE and 0 <= next_y < GRID_SIZE:
            # 5. Get current owner of the target cell *before* changing it
            old_owner_id = game_state["grid"][next_y][next_x]
            new_owner_id = player['id'] # The player making the move

            # 6. Update player's position state
            player['x'] = next_x
            player['y'] = next_y

            # 7. Update grid cell ownership
            game_state["grid"][next_y][next_x] = new_owner_id

            # 8. *** Incremental Score Update ***
            # Only update scores if the owner actually changed to someone new
            if old_owner_id != new_owner_id:
                # Decrement score of the old owner (if there was one)
                if old_owner_id != -1 and 0 <= old_owner_id < MAX_PLAYERS:
                    game_state["scores"][old_owner_id] -= 1
                # Increment score of the new owner
                if 0 <= new_owner_id < MAX_PLAYERS:
                     game_state["scores"][new_owner_id] += 1

            # 9. Set flag to broadcast the update
            should_broadcast = True
        # else: Move was out of bounds, do nothing

    # 10. Broadcast updated state AFTER releasing lock (if a valid move occurred)
    if should_broadcast:
        socketio.emit('game_update', get_state_for_client())

@socketio.on('request_reset')
def handle_reset_request():
    # Handles requests from clients to reset the game (only allowed when inactive)
    sid = request.sid # Could potentially track who requested, but not currently used
    can_reset = False
    with game_state_lock:
        # Only allow reset if the game is NOT currently active
        if not game_state["game_active"]:
            can_reset = True
            reset_game_state() # Perform the reset logic

    # --- Operations outside the lock ---
    if can_reset:
        # Notify all clients that the game has been reset
        socketio.emit('game_reset', get_state_for_client()) # Send the fresh state
        socketio.emit('game_event', {'message': 'Game Reset! Waiting for players...'})
    else:
        # Notify the requesting client that reset is not allowed
        emit('game_event', {'message': 'Cannot reset: Game in progress!'}, room=sid)

# --- Main Execution ---
if __name__ == '__main__':
    print("Initializing Flask-SocketIO server with eventlet WSGI...")
    try:
        print(f"Starting eventlet WSGI server on http://0.0.0.0:5001")
        # Start the server using eventlet's WSGI server
        eventlet.wsgi.server(eventlet.listen(('', 5001)), app)
    except Exception as e:
        # Use print for critical startup errors since logging might be minimal/removed
        print(f"Failed to start eventlet WSGI server: {e}")