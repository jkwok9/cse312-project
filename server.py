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

import time
import threading
import secrets
import os
import logging
import random
from flask_socketio import disconnect

from util.register import handle_register
from util.login import handle_login
from util.auth_utli import get_user_by_token

# --- Game Configuration ---
GRID_SIZE = 40  # Larger grid
GAME_DURATION = 60  # Increased duration (seconds)
MAX_PLAYERS = 999  # No practical limit on players

# --- Flask App Setup ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
# Replace the existing socketio initialization
socketio = SocketIO(app,
                    async_mode='eventlet',
                    cors_allowed_origins="*",
                    ping_timeout=20,
                    ping_interval=25,
                    max_http_buffer_size=1e8,
                    engineio_logger=True)  # Add logging to debug issues # RESTRICT IN PRODUCTION

# --- Game State (Server-Side) ---
game_state = {
    "grid": [[-1 for _ in range(GRID_SIZE)] for _ in range(GRID_SIZE)],
    "players": {}, # Dictionary: {sid: player_data}
    "remaining_time": GAME_DURATION,
    "game_active": False,
    "timer_thread": None,
    "next_player_id": 0  # Counter for assigning unique player IDs
}
game_state_lock = threading.Lock() # Using threading Lock

# --- Helper Functions ---
def generate_random_color():
    """
    Generate a random bright color in hexadecimal format.
    Makes sure colors are bright enough to be visible on dark background.
    """
    # Generate higher values for brighter colors (128-255 range for each RGB component)
    r = random.randint(128, 255)
    g = random.randint(128, 255)
    b = random.randint(128, 255)
    
    # Convert to hex format
    return f'#{r:02x}{g:02x}{b:02x}'

def get_random_empty_position():
    """
    Find a random empty position on the grid for a new player to spawn.
    Returns tuple (x, y) of an empty cell.
    """
    with game_state_lock:
        empty_cells = []
        
        # Find all empty cells
        for y in range(GRID_SIZE):
            for x in range(GRID_SIZE):
                if game_state["grid"][y][x] == -1:
                    empty_cells.append((x, y))
        
        # If there are no empty cells, just return a random position
        # (not ideal but prevents errors if grid is full)
        if not empty_cells:
            return (random.randint(0, GRID_SIZE - 1), random.randint(0, GRID_SIZE - 1))
        
        # Return a random empty cell
        return random.choice(empty_cells)

def get_next_player_id():
    """
    Get the next available unique player ID
    """
    with game_state_lock:
        player_id = game_state["next_player_id"]
        game_state["next_player_id"] += 1
        return player_id

def reset_game_state():
    # Resets the game to its initial state
    with game_state_lock:
        game_state["grid"] = [[-1 for _ in range(GRID_SIZE)] for _ in range(GRID_SIZE)]
        # Keep the players but reset their positions and scores
        for sid, player in game_state["players"].items():
            x, y = get_random_empty_position()
            player['x'] = x
            player['y'] = y
            player['score'] = 0
            # Mark their initial position as claimed
            game_state["grid"][y][x] = player['id']
        
        game_state["remaining_time"] = GAME_DURATION
        game_state["game_active"] = False
        
        # Stop any existing timer greenlet
        timer = game_state.get("timer_thread")
        if timer:
            try:
                timer.kill()
            except Exception:
                pass # Ignore errors if killing fails
        game_state["timer_thread"] = None

def calculate_scores():
    """
    Calculate scores for all players by counting their claimed cells
    """
    with game_state_lock:
        # Initialize score counter for each player
        scores = {player['id']: 0 for player in game_state["players"].values()}
        
        # Count cells for each player
        for y in range(GRID_SIZE):
            for x in range(GRID_SIZE):
                owner_id = game_state["grid"][y][x]
                if owner_id != -1:
                    if owner_id in scores:
                        scores[owner_id] += 1
        
        # Update player scores
        for sid, player in game_state["players"].items():
            player['score'] = scores.get(player['id'], 0)

def get_state_for_client():
    # Creates a snapshot of the current game state suitable for sending to clients
    with game_state_lock:
        # Create a list copy of player data to avoid sending internal details like SID
        players_list = []
        for sid, player_data in game_state["players"].items():
            # Create a copy without the sid
            player_copy = {
                'id': player_data['id'],
                'x': player_data['x'],
                'y': player_data['y'],
                'color': player_data['color'],
                'username': player_data.get('username', f'Player {player_data["id"]}'),
                'score': player_data.get('score', 0)
            }
            players_list.append(player_copy)
        
        # Create a copy of the state to send
        state = {
            "grid": game_state["grid"],
            "players": players_list,
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

        # Recalculate scores before broadcasting
        calculate_scores()
            
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
    # Starts the game if there are enough players (at least 2)
    should_start = False
    with game_state_lock:
        num_players = len(game_state["players"])
        # Start if game isn't already active and we have at least 2 players
        if not game_state["game_active"] and num_players >= 2:
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

            # Calculate final scores
            calculate_scores()
            
            # Determine winner(s) based on final scores
            for sid, player in game_state["players"].items():
                score = player.get('score', 0)
                if score > max_score:
                    max_score = score
                    winners = [player] # New highest score
                elif score == max_score and score > 0: # Tie for the highest score (and score > 0)
                    winners.append(player)
        # else: Game was already inactive, do nothing

    # Announce winner(s) only if the game was active when end_game was called
    if was_active:
        winner_message = "Game Over! "
        if not winners or max_score <= 0:
            winner_message += "No winner!"
        elif len(winners) == 1:
            winner = winners[0]
            winner_message += f"Player {winner['username']} Wins with {max_score} cells!"
        else:
            winner_message += "It's a tie between: "
            winner_strs = []
            for winner in winners:
                winner_strs.append(f"{winner['username']} ({max_score} cells)")
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
            # Add a Cache-Control header to prevent caching
            response = make_response(redirect(url_for('index'), 302))
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            return response
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
    # Track connection attempts for debugging
    print(f"WebSocket connection attempt from {request.remote_addr}")
    
    # First verify the user is authenticated
    auth_token = request.cookies.get('auth_token')
    if not auth_token:
        print(f"Connection rejected: No auth token present")
        # Immediately reject connection if no auth token
        emit('redirect', {'url': '/login'})
        disconnect()
        return
    
    # Then verify the token is valid
    user = get_user_by_token(auth_token)
    if not user:
        print(f"Connection rejected: Invalid auth token")
        # Reject connection if invalid token
        emit('redirect', {'url': '/login'})
        disconnect()
        return
    
    # Get the session ID
    sid = request.sid
    
    # Check for existing connections from this user and clean them up
    with game_state_lock:
        existing_sid = None
        for s, player in list(game_state["players"].items()):
            if player.get('username') == user['username'] and s != sid:
                existing_sid = s
                break
        
        # If there was an existing connection, clean it up
        if existing_sid:
            print(f"Found existing connection for user {user['username']} with SID {existing_sid}")
            game_state["players"].pop(existing_sid, None)
    
    # Get next available player ID
    player_id = get_next_player_id()
    
    # Generate a random color for the player
    player_color = generate_random_color()
    
    # Find a random empty position for the new player
    start_x, start_y = get_random_empty_position()
    
    # Create player data structure
    player_data = { 
        'id': player_id, 
        'sid': sid, 
        'x': start_x, 
        'y': start_y, 
        'color': player_color,
        'username': user['username'],
        'score': 0  # Initial score
    }

    with game_state_lock:
        # Store player data
        game_state["players"][sid] = player_data
        # Claim initial cell
        game_state["grid"][start_y][start_x] = player_id
        # Update player's score
        player_data['score'] = 1  # For the initial cell

    # --- Operations outside the lock ---
    # Send player assignment info to the connecting client
    assign_payload = {'playerId': player_id}
    emit('assign_player', assign_payload, room=sid)

    # Send the current game state to the new client
    current_client_state = get_state_for_client()
    emit('game_update', current_client_state, room=sid)

    # Notify all clients about the new player and update their state
    socketio.emit('game_update', current_client_state)
    socketio.emit('game_event', {'message': f'Player {user["username"]} has joined!'})

    # Check if the game can start now
    start_game_if_ready()

@socketio.on('disconnect')
def handle_disconnect():
    # Handles client disconnections
    sid = request.sid
    username = "Unknown"
    
    # Remove player data under lock
    with game_state_lock:
        player_data = game_state["players"].pop(sid, None) # Remove player by SID
        
        if player_data:
            username = player_data.get('username', f"Player {player_data['id']}")
        
        # Check remaining players to decide if we need to end the game
        num_players_after_disconnect = len(game_state["players"])

    # --- Operations outside the lock ---
    if player_data: # If a known player disconnected
        # Notify remaining clients
        socketio.emit('game_update', get_state_for_client()) # Update state for others
        socketio.emit('game_event', {'message': f'Player {username} has left.'})

        # End the game if active and less than 2 players remain
        if game_state["game_active"] and num_players_after_disconnect < 2:
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

            # 8. Calculate scores - simplified incremental update
            if old_owner_id != new_owner_id:
                # If old owner exists, decrement their score
                if old_owner_id != -1:
                    for p in game_state["players"].values():
                        if p['id'] == old_owner_id:
                            p['score'] = max(0, p.get('score', 0) - 1)
                            break
                
                # Increment current player's score
                player['score'] = player.get('score', 0) + 1

            # 9. Set flag to broadcast the update
            should_broadcast = True

    # 10. Broadcast updated state AFTER releasing lock (if a valid move occurred)
    if should_broadcast:
        socketio.emit('game_update', get_state_for_client())

@socketio.on('request_reset')
def handle_reset_request():
    # Handles requests from clients to reset the game (only allowed when inactive)
    sid = request.sid
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
        # Check if we can start immediately with the players we have
        start_game_if_ready()
    else:
        # Notify the requesting client that reset is not allowed
        emit('game_event', {'message': 'Cannot reset: Game in progress!'}, room=sid)

# --- Main Execution ---
if __name__ == '__main__':
    print("Initializing Flask-SocketIO server with eventlet WSGI...")
    try:
        print(f"Starting eventlet WSGI server on http://0.0.0.0:5002")
        # Start the server using eventlet's WSGI server
        eventlet.wsgi.server(eventlet.listen(('', 5002)), app)
    except Exception as e:
        # Use print for critical startup errors since logging might be minimal/removed
        print(f"Failed to start eventlet WSGI server: {e}")