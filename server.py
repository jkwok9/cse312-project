# *** CHANGE: Move eventlet import and monkey_patch to the VERY TOP ***
import eventlet
# If using eventlet, monkey patching is often necessary for standard libraries
# to work correctly with its concurrency model. Do this BEFORE other imports.
eventlet.monkey_patch()

# Import necessary libraries AFTER monkey patching
# Make sure to install Flask-SocketIO and eventlet: pip install Flask-SocketIO eventlet
from flask import Flask, render_template, request, session
from flask_socketio import SocketIO, emit, join_room, leave_room, send
import time
import threading # Keep for Lock if preferred, though eventlet has its own primitives
# *** CHANGE: Import eventlet.wsgi for direct server usage ***
import eventlet.wsgi


# --- Game Configuration ---
GRID_SIZE = 25
GAME_DURATION = 30  # Seconds (Adjusted comment)
PLAYER_COLORS = ['#ff4136', '#0074d9', '#2ecc40', '#ffdc00'] # Red, Blue, Green, Yellow
MAX_PLAYERS = 4

# --- NEW: Map hex colors to names ---
COLOR_NAMES = {
    '#ff4136': 'Red',
    '#0074d9': 'Blue',
    '#2ecc40': 'Green',
    '#ffdc00': 'Yellow'
}
# --- End New ---

# --- Flask App Setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_very_secret_key_here!' # CHANGE FOR PRODUCTION
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
# (get_available_player_id, release_player_id, reset_game_state unchanged)
# ... (Keep existing helper functions here) ...
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

# (game_timer, start_game_if_ready functions unchanged)
# ... (Keep existing game_timer and start_game_if_ready functions here) ...
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


# --- MODIFIED end_game Function ---
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
# --- End MODIFIED end_game Function ---


# --- Flask Routes ---
# (@app.route('/') unchanged)
# ... (Keep existing Flask routes here) ...
@app.route('/')
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
    # Serves the main HTML page
    return render_template('game.html')

# --- SocketIO Event Handlers ---
# (handle_connect, handle_disconnect, handle_player_move, handle_reset_request unchanged)
# ... (Keep existing SocketIO handlers here) ...
@socketio.on('connect')
def handle_connect():
    # Handles new client connections
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
        return # Stop processing connection

    # Assign starting position based on player ID
    potential_starts = [(1, 1), (GRID_SIZE - 2, 1), (1, GRID_SIZE - 2), (GRID_SIZE - 2, GRID_SIZE - 2)]
    # Ensure player_id is valid index for starts and colors
    if not (0 <= player_id < len(potential_starts) and 0 <= player_id < len(PLAYER_COLORS)):
         # This should ideally not happen if MAX_PLAYERS matches array sizes
         emit('connect_error', {'message': 'Internal server error: player configuration mismatch.'})
         release_player_id(player_id)
         return

    start_x, start_y = potential_starts[player_id]
    player_color = PLAYER_COLORS[player_id]
    player_data = { 'id': player_id, 'sid': sid, 'x': start_x, 'y': start_y, 'color': player_color }

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
        print(f"Starting eventlet WSGI server on http://0.0.0.0:5000")
        # Start the server using eventlet's WSGI server
        eventlet.wsgi.server(eventlet.listen(('', 5000)), app)
    except Exception as e:
        # Use print for critical startup errors since logging might be minimal/removed
        print(f"Failed to start eventlet WSGI server: {e}")
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