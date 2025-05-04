import select


# Compatibility check for kqueue on older macOS with eventlet
if hasattr(select, 'kqueue'):
    import sys
    if sys.platform == 'darwin':
        select.kqueue = None # pragma: no cover darwin

import eventlet
eventlet.monkey_patch() # Make standard libraries cooperative
import eventlet.wsgi
from flask import Flask, flash, jsonify, make_response, render_template, request, session, redirect, url_for
from flask_socketio import SocketIO, emit, join_room, leave_room, send, disconnect
from util.leaderboard import handle_leaderboard_page, handle_territory_leaderboard_api, handle_wins_leaderboard_api
from util.logger import setup_logging

import time
import threading
import secrets
import os
import logging
import random
from util.profile_pic import get_profile_pic_by_username, handle_profile_page, serve_profile_pic

from util.register import handle_register
from util.login import handle_login
from util.auth_utli import get_user_by_token

# --- Game Configuration ---
GRID_SIZE = 60 # Example: Kept the larger grid size
GAME_DURATION = 10 # Seconds
MAX_PLAYERS = 999 # Theoretical max
MIN_PLAYERS_TO_START = 2 # Minimum active players required to *enable* start button

# --- Team Configuration ---
NUM_TEAMS = 4
TEAM_COLORS = {
    0: '#FF0000', # Red
    1: '#0000FF', # Blue
    2: '#00FF00', # Green
    3: '#FFFF00'  # Yellow
}
TEAM_NAMES = { # Optional names for display
    0: 'Red',
    1: 'Blue',
    2: 'Green',
    3: 'Yellow'
}


# --- Flask App Setup ---
app = Flask(__name__)
setup_logging(app)
@app.before_request
def log_request_info():
    logging.info(request)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

socketio = SocketIO(app,
                    async_mode='eventlet',
                    cors_allowed_origins="*",
                    ping_timeout=20,
                    ping_interval=25,
                    max_http_buffer_size=1e8,
                    engineio_logger=False) # Turn off detailed engine logging for production

# --- Game State (Server-Side) ---
game_state = {
    "grid": [[-1 for _ in range(GRID_SIZE)] for _ in range(GRID_SIZE)], # Stores team_id (-1 for empty)
    "players": {}, # Dictionary: {sid: player_data}
    "teams": { # Team information and scores
        tid: {"color": color, "score": 0, "name": TEAM_NAMES.get(tid, f"Team {tid+1}")}
        for tid, color in TEAM_COLORS.items()
    },
    "remaining_time": GAME_DURATION,
    "game_active": False,
    "timer_thread": None,
    "next_player_id_counter": 0 # Counter for assigning unique player IDs (internal)
}
game_state_lock = threading.Lock() # Using threading Lock

# Stores the last known team ID for reconnecting players (in-memory)
username_to_last_team = {}
username_to_last_team_lock = threading.Lock() # Separate lock for this dict

# --- Helper Functions ---

def get_active_players_count():
    """ Counts non-spectator players """
    # Assumes game_state_lock is held by caller or access is safe
    count = 0
    for player in game_state["players"].values():
        if not player.get('is_spectator', False):
            count += 1
    return count

def get_team_player_counts():
    """ Counts active players per team """
    # Assumes game_state_lock is held by caller or access is safe
    counts = {tid: 0 for tid in range(NUM_TEAMS)}
    for player in game_state["players"].values():
        if not player.get('is_spectator', False) and player.get('team_id') is not None:
            counts[player['team_id']] += 1
    return counts

def assign_team():
    """ Assigns the team with the fewest active players """
    # Assumes game_state_lock is held by caller or access is safe
    team_counts = get_team_player_counts()
    min_count = float('inf')
    for tid in range(NUM_TEAMS):
        min_count = min(min_count, team_counts.get(tid, 0))
    min_teams = [tid for tid, count in team_counts.items() if count == min_count]
    return random.choice(min_teams) if min_teams else 0 # Default to team 0

def get_random_empty_position():
    """ Find a random empty position on the grid """
    # Assumes game_state_lock is held by caller
    empty_cells = []
    for y in range(GRID_SIZE):
        for x in range(GRID_SIZE):
            if game_state["grid"][y][x] == -1:
                empty_cells.append((x, y))
    if not empty_cells:
        return (random.randint(0, GRID_SIZE - 1), random.randint(0, GRID_SIZE - 1))
    return random.choice(empty_cells)

def get_next_player_id():
    """ Get the next available unique player ID (internal server ID) """
    # Assumes game_state_lock is held by caller
    player_id = game_state["next_player_id_counter"]
    game_state["next_player_id_counter"] += 1
    return player_id

def calculate_team_scores():
    """ Calculate scores for all teams by counting their claimed cells """
    # Assumes game_state_lock is held by caller
    for tid in game_state["teams"]:
        game_state["teams"][tid]["score"] = 0
    for y in range(GRID_SIZE):
        for x in range(GRID_SIZE):
            owner_team_id = game_state["grid"][y][x]
            if owner_team_id != -1 and owner_team_id in game_state["teams"]:
                game_state["teams"][owner_team_id]["score"] += 1

def reset_game_state():
    """ Resets the game to its initial state, reassigning all players """
    # Assumes game_state_lock is held by caller
    logging.info("Resetting game state...")
    game_state["grid"] = [[-1 for _ in range(GRID_SIZE)] for _ in range(GRID_SIZE)]
    game_state["remaining_time"] = GAME_DURATION
    game_state["game_active"] = False

    for tid in game_state["teams"]:
        game_state["teams"][tid]["score"] = 0

    timer = game_state.get("timer_thread")
    if timer:
        try: timer.kill()
        except Exception: pass
    game_state["timer_thread"] = None

    connected_sids = list(game_state["players"].keys())
    logging.info(f"Reassigning {len(connected_sids)} players for new game.")
    temp_team_counts = {tid: 0 for tid in range(NUM_TEAMS)}

    for sid in connected_sids:
        player = game_state["players"][sid]
        min_count = float('inf')
        for tid in range(NUM_TEAMS):
             min_count = min(min_count, temp_team_counts.get(tid, 0))
        min_teams = [tid for tid, count in temp_team_counts.items() if count == min_count]
        assigned_team_id = random.choice(min_teams) if min_teams else 0

        # Preserve profile pic data if present
        profile_pic = player.get('profile_pic')
        
        player['team_id'] = assigned_team_id
        player['is_spectator'] = False # No longer spectating
        player['score'] = 0
        x, y = get_random_empty_position()
        player['x'] = x
        player['y'] = y
        game_state["grid"][y][x] = player['team_id']
        temp_team_counts[assigned_team_id] += 1
        
        # Make sure profile_pic is still present
        if profile_pic:
            player['profile_pic'] = profile_pic
            
        logging.debug(f"Player {player['username']} (SID: {sid[:5]}) assigned to Team {assigned_team_id} at ({x},{y})")
        # Store new team assignment for persistence
        with username_to_last_team_lock:
             username_to_last_team[player['username']] = assigned_team_id

    calculate_team_scores()
    logging.info("Game state reset complete.")


def get_state_for_client():
    """ Creates a snapshot of the current game state suitable for sending to clients """
    # Assumes game_state_lock is held by caller
    players_list = []
    for sid, player_data in game_state["players"].items():
        player_copy = {
            'id': player_data['id'],
            'x': player_data.get('x', -1),
            'y': player_data.get('y', -1),
            'team_id': player_data.get('team_id', None),
            'color': TEAM_COLORS.get(player_data.get('team_id'), '#888888'),
            'username': player_data.get('username', f'Player {player_data["id"]}'),
            'score': player_data.get('score', 0),
            'is_spectator': player_data.get('is_spectator', False),
            'profile_pic': player_data.get('profile_pic', None)  # Include profile pic data
        }
        players_list.append(player_copy)

    teams_copy = {tid: dict(data) for tid, data in game_state["teams"].items()}
    active_count = get_active_players_count() # Get current active count

    state = {
        "grid": game_state["grid"],
        "players": players_list,
        "teams": teams_copy,
        "remaining_time": game_state["remaining_time"],
        "game_active": game_state["game_active"],
        "active_players_count": active_count, # <-- ADDED for client button logic
        "min_players_to_start": MIN_PLAYERS_TO_START # <-- ADDED for client button logic
    }
    return state

def game_timer():
    """ Background task (greenlet) that decrements the game timer """
    logging.info("Game timer started.")
    while True:
        time_left = -1
        is_active = False
        should_broadcast = False
        with game_state_lock:
            is_active = game_state["game_active"]
            if is_active:
                if game_state["remaining_time"] > 0:
                    game_state["remaining_time"] -= 1
                    calculate_team_scores() # Calculate scores each second
                    should_broadcast = True
                time_left = game_state["remaining_time"]

        if not is_active:
            logging.info("Timer stopping: Game became inactive.")
            break

        if time_left <= 0:
            logging.info("Timer stopping: Time ran out.")
            end_game() # End the game (handles lock internally)
            break

        # Broadcast the update AFTER releasing the lock
        if should_broadcast:
            current_client_state = get_state_for_client() # Get state outside lock if possible
            socketio.emit('game_update', current_client_state)

        socketio.sleep(1) # Yield control cooperatively

    with game_state_lock:
        # Check if this greenlet is still the active timer before clearing
        # (prevents race condition if end_game/reset clears it first)
        if game_state.get("timer_thread") == eventlet.getcurrent(): # <--- ADDED CHECK
            game_state["timer_thread"] = None
    logging.info("Game timer finished.")

# REMOVED start_game_if_ready() function as start is now manual


def end_game():
    """ Ends the current game, calculates the winning team, and notifies clients """
    winners = []
    max_score = -1
    was_active = False

    with game_state_lock:
        if game_state["game_active"]:
            logging.info("Ending game...")
            game_state["game_active"] = False
            was_active = True

            timer = game_state.get("timer_thread")
            if timer:
                try: timer.kill()
                except Exception: pass
                game_state["timer_thread"] = None

            calculate_team_scores()

            for tid, team_data in game_state["teams"].items():
                score = team_data.get('score', 0)
                if score > max_score:
                    max_score = score
                    winners = [tid]
                elif score == max_score and score >= 0:
                    winners.append(tid)
            logging.info(f"Game ended. Max score: {max_score}, Winning teams: {winners}")

    if was_active:
        winner_message = "Game Over! "
        if not winners or max_score < 0 :
             winner_message += "No winner!?"
        elif len(winners) == 1:
            winner_tid = winners[0]
            team_info = game_state["teams"].get(winner_tid, {})
            winner_message += f"Team {team_info.get('name', winner_tid+1)} ({team_info.get('color','#?')}) Wins with {max_score} cells!"
        else:
            winner_message += "It's a tie between Teams: "
            winner_strs = []
            for tid in winners:
                 team_info = game_state["teams"].get(tid, {})
                 winner_strs.append(f"{team_info.get('name', tid+1)} ({team_info.get('color','#?')}, {max_score} cells)")
            winner_message += ", ".join(winner_strs)

        # Need lock to get final state accurately
        with game_state_lock:
            final_state = get_state_for_client()
        socketio.emit('game_update', final_state) # Send final scores/state
        socketio.emit('game_event', {'message': winner_message, 'isGameOver': True})
        logging.info(f"Sent game over event: {winner_message}")

# --- Authentication Middleware ---
def check_auth():
    auth_token = request.cookies.get('auth_token')
    if not auth_token: return None
    return get_user_by_token(auth_token)

def auth_required(f):
    def decorated(*args, **kwargs):
        user = check_auth()
        if not user:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(user, *args, **kwargs) # Pass user object to route
    decorated.__name__ = f.__name__
    return decorated

def no_auth_required(f):
    def decorated(*args, **kwargs):
        user = check_auth()
        if user:
            response = make_response(redirect(url_for('index'), 302))
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            return response
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

# --- Flask Routes ---
@app.route('/')
@auth_required
def index(user):
    return render_template('game.html', username=user.get('username', 'Player'))

@app.route('/login', methods=['GET', 'POST'])
@no_auth_required
def login():
    return handle_login()

@app.route('/register', methods=['GET', 'POST'])
@no_auth_required
def register():
    return handle_register()

@app.route('/logout')
def logout():
    from util.auth_utli import clear_auth_cookie
    response = make_response(redirect(url_for('login')))
    clear_auth_cookie(response)
    flash('You have been logged out.', 'success')
    return response

@app.route('/debug')
@auth_required
def debug_auth(user):
    cookies = request.cookies
    # Access game state safely
    with game_state_lock:
        state_summary = {
            "game_active": game_state.get("game_active"),
            "players_count": len(game_state.get("players", {})),
            "active_players_count": get_active_players_count(),
            "team_scores": {t: d.get("score") for t, d in game_state.get("teams", {}).items()}
        }
    return jsonify({
        "authenticated": True,
        "username": user.get('username'),
        "cookies": {k: v[:10] + "..." if k == "auth_token" else v for k, v in cookies.items()},
        "current_game_state_summary": state_summary
    })

@app.route('/profile', methods=['GET', 'POST'])
@auth_required
def profile(user):
    return handle_profile_page(user)

@app.route('/profile_pic/<filename>')
def profile_pic(filename):
    return serve_profile_pic(filename)

@app.route('/leaderboard')
@auth_required
def leaderboard(user):
    return handle_leaderboard_page()

@app.route('/api/leaderboard/wins')
@auth_required
def leaderboard_wins_api(user):
    return handle_wins_leaderboard_api()

@app.route('/api/leaderboard/territory')
@auth_required
def leaderboard_territory_api(user):
    return handle_territory_leaderboard_api()


# --- SocketIO Event Handlers ---
@socketio.on('connect')
def handle_connect():
    sid = request.sid
    logging.info(f"Connection attempt from SID: {sid[:5]}...")

    auth_token = request.cookies.get('auth_token')
    if not auth_token:
        logging.warning(f"Connection {sid[:5]} rejected: No auth token.")
        emit('redirect', {'url': url_for('login')})
        disconnect(sid)
        return

    user = get_user_by_token(auth_token)
    if not user:
        logging.error(f"User object became invalid? SID: {sid[:5]}")
        emit('redirect', {'url': url_for('login')}) # Redirect if token invalid
        disconnect(sid)
        return
    username = user['username']
    logging.info(f"User '{username}' (SID: {sid[:5]}) authenticated successfully.")

    # Get user's profile picture if available
    profile_pic_data = get_profile_pic_by_username(username)
    profile_pic_base64 = profile_pic_data.get('base64_data') if profile_pic_data else None

    player_id = -1 # Will be assigned inside lock
    player_data = None
    assigned_team_id = None
    is_spectator_join = False
    initial_state_for_client = None
    join_message = f"Player {username} has joined"

    with game_state_lock:
        player_id = get_next_player_id() # Get ID first

        player_data = {
            'id': player_id, 
            'sid': sid, 
            'username': username, 
            'score': 0,
            'x': -1, 
            'y': -1, 
            'team_id': None, 
            'is_spectator': False,
            'profile_pic': profile_pic_base64  # Add profile pic to player data
        }

        is_active = game_state["game_active"]

        if is_active:
            # Game in progress, join as spectator
            player_data['is_spectator'] = True
            is_spectator_join = True
            logging.info(f"User '{username}' (SID: {sid[:5]}) joining as spectator.")
            join_message += " as a spectator."
        else:
            # Game not active, assign team and position
            player_data['is_spectator'] = False
            team_assigned = False

            with username_to_last_team_lock:
                last_team = username_to_last_team.get(username)
                if last_team is not None:
                    # Check if team exists (in case NUM_TEAMS changed)
                    if last_team in TEAM_COLORS:
                        assigned_team_id = last_team
                        player_data['team_id'] = assigned_team_id
                        team_assigned = True
                        logging.info(f"User '{username}' (SID: {sid[:5]}) rejoining last known Team {assigned_team_id}.")
                    else:
                         logging.warning(f"User '{username}' last known team {last_team} is invalid. Reassigning.")
                         # Remove invalid team from memory
                         del username_to_last_team[username]


            if not team_assigned:
                assigned_team_id = assign_team()
                player_data['team_id'] = assigned_team_id
                with username_to_last_team_lock:
                    username_to_last_team[username] = assigned_team_id
                logging.info(f"User '{username}' (SID: {sid[:5]}) assigned balanced Team {assigned_team_id}.")

            x, y = get_random_empty_position()
            player_data['x'] = x
            player_data['y'] = y
            if assigned_team_id is not None:
                game_state["grid"][y][x] = assigned_team_id
                team_info = game_state['teams'].get(assigned_team_id,{})
                join_message += f" and joined Team {team_info.get('name', assigned_team_id+1)} ({team_info.get('color','#?')})!"
            else:
                logging.error(f"Failed to assign team ID for active player {username}!")
                join_message += "." # Fallback

            calculate_team_scores() # Recalculate scores after adding player

        game_state["players"][sid] = player_data
        initial_state_for_client = get_state_for_client() # Get state AFTER adding player

    # --- Operations outside the lock ---
    emit('assign_player', {'playerId': player_id, 'isSpectator': player_data['is_spectator']}, room=sid)
    emit('game_update', initial_state_for_client, room=sid) # Send initial state to new client

    # Notify all clients about the new player and update their state
    # (Send state again to ensure everyone has the latest active player count etc.)
    socketio.emit('game_update', initial_state_for_client)
    socketio.emit('game_event', {'message': join_message})

@socketio.on('disconnect')
def handle_disconnect():
    sid = request.sid
    username = "Unknown"
    player_was_active = False
    last_team_id = None
    should_emit_update = False
    should_check_end = False
    num_active_after = 0

    with game_state_lock:
        player_data = game_state["players"].pop(sid, None)

        if player_data:
            should_emit_update = True
            username = player_data.get('username', f"PID {player_data.get('id', '???')}")
            last_team_id = player_data.get('team_id')
            logging.info(f"Player {username} (SID: {sid[:5]}) disconnected from Team {last_team_id}.")

            if not player_data.get('is_spectator', False):
                player_was_active = True
                # If game active, check if player count drops below minimum
                num_active_after = get_active_players_count()
                if game_state["game_active"] and num_active_after < MIN_PLAYERS_TO_START:
                     should_check_end = True # Flag to call end_game outside lock

            # Store last team ID regardless of spectator status
            if username != "Unknown" and last_team_id is not None:
                 with username_to_last_team_lock:
                     username_to_last_team[username] = last_team_id
                     logging.debug(f"Stored last team {last_team_id} for user {username}")

            # Get updated state for broadcast after removing player
            current_client_state = get_state_for_client()

    # --- Operations outside the lock ---
    if player_data:
        socketio.emit('game_update', current_client_state) # Update state for others
        socketio.emit('game_event', {'message': f'Player {username} has left.'})

        if should_check_end:
            logging.info(f"Game may end: Only {num_active_after} active players left.")
            end_game() # end_game checks game_active itself and handles lock


@socketio.on('player_move')
def handle_player_move(data):
    sid = request.sid
    should_broadcast = False
    p_username = "Unknown" # For logging
    player_team_id = None

    with game_state_lock:
        if not game_state["game_active"]: return # Ignore if game not active
        player = game_state["players"].get(sid)
        if not player: return # Ignore if player not found

        p_username = player.get('username', 'Unknown') # Get username for logging
        if player.get('is_spectator', False): return # Ignore spectators

        if not isinstance(data, dict) or 'dx' not in data or 'dy' not in data: return
        dx = data.get('dx', 0); dy = data.get('dy', 0)
        if abs(dx) + abs(dy) != 1: return # Invalid move step

        player_team_id = player.get('team_id')
        if player_team_id is None:
            logging.warning(f"Active player {p_username} has no team_id! SID: {sid[:5]}")
            return

        current_x = player['x']; current_y = player['y']
        next_x = current_x + dx; next_y = current_y + dy

        if 0 <= next_x < GRID_SIZE and 0 <= next_y < GRID_SIZE:
            player['x'] = next_x
            player['y'] = next_y
            game_state["grid"][next_y][next_x] = player_team_id
            should_broadcast = True # Flag to broadcast state update (score is updated by timer)
            # Don't log excessively here, score recalc/broadcast happens in timer or after move
            # logging.debug(f"Player {p_username} moved to ({next_x},{next_y}), claimed for Team {player_team_id}.")

    if should_broadcast:
        # Broadcast minimal update? Or full state? Full state easier for now.
        # Score update happens in timer, but position update needs broadcast.
        with game_state_lock:
             current_client_state = get_state_for_client()
        socketio.emit('game_update', current_client_state)


# --- NEW: Handler for manual game start request ---
@socketio.on('request_start')
def handle_start_request():
    """ Handles requests from clients to start the game. Resets state first. """
    sid = request.sid
    start_successful = False
    player_username = "Unknown"
    state_after_start = None # Store state to broadcast

    with game_state_lock:
        player = game_state["players"].get(sid)
        if player: player_username = player.get('username', 'Unknown')
        else: logging.warning(f"Start req from unknown SID: {sid[:5]}"); return

        num_active_players = get_active_players_count()
        logging.debug(f"Start req from {player_username}. Active: {game_state['game_active']}, Players: {num_active_players}/{MIN_PLAYERS_TO_START}")

        # Conditions: Not active AND enough players
        if not game_state["game_active"] and num_active_players >= MIN_PLAYERS_TO_START:
            # Ensure timer thread isn't somehow running
            if game_state.get("timer_thread") is not None:
                logging.warning(f"Start req from {player_username}: Timer thread exists while inactive? Killing.")
                try: game_state["timer_thread"].kill(); game_state["timer_thread"] = None
                except Exception: pass

            logging.info(f"Start request approved from {player_username}. Resetting and starting game...")

            # --- RESET THE GAME STATE FIRST --- # <--- ADDED COMMENT
            reset_game_state() # Clears grid, scores, reassigns players, sets game_active=False # <--- ADDED CALL

            # --- NOW START THE GAME --- # <--- ADDED COMMENT
            game_state["game_active"] = True # Set game to active *after* reset # <--- ENSURED THIS HAPPENS AFTER RESET
            game_state["remaining_time"] = GAME_DURATION # Set timer duration

            # Start the timer greenlet
            game_state["timer_thread"] = socketio.start_background_task(target=game_timer)
            start_successful = True
            state_after_start = get_state_for_client() # Get the state *after* reset and activation

        elif game_state["game_active"]:
            logging.debug(f"Start req from {player_username} ignored: Game already active.")
            # Optionally notify requester
            emit('game_event', {'message': 'Game is already running!'}, room=sid)
        else: # Not enough players
            logging.debug(f"Start req from {player_username} ignored: Not enough active players ({num_active_players}/{MIN_PLAYERS_TO_START}).")
            emit('game_event', {'message': f'Need {MIN_PLAYERS_TO_START} players to start! ({num_active_players} ready)'}, room=sid)

    # --- Operations outside the lock ---
    if start_successful:
        # Broadcast updated state (reflecting the reset) and start message
        socketio.emit('game_update', state_after_start)
        socketio.emit('game_event', {'message': f'Game Started by {player_username}!'})


@socketio.on('request_reset')
def handle_reset_request():
    """ Handles requests from clients to reset the game (only allowed when inactive) """
    sid = request.sid
    can_reset = False
    player_username = "Unknown"
    reset_state_after = None

    with game_state_lock:
        player = game_state["players"].get(sid)
        if player:
            player_username = player.get('username', 'Unknown')

        if not game_state["game_active"]:
             logging.info(f"Reset requested by {player_username} (SID: {sid[:5]}) - Game inactive. Performing reset.")
             can_reset = True
             reset_game_state() # Perform the reset logic (holds lock)
             reset_state_after = get_state_for_client() # Get state after reset
        else:
             logging.warning(f"Reset requested by {player_username} (SID: {sid[:5]}) - Denied (Game Active).")

    # --- Operations outside the lock ---
    if can_reset:
        socketio.emit('game_reset', reset_state_after) # Send the fresh state
        socketio.emit('game_event', {'message': f'Game Reset by {player_username}! Waiting for players...'})
        # No automatic start check needed here anymore
    else:
        # Notify the requesting client that reset is not allowed
        emit('game_event', {'message': 'Cannot reset: Game in progress!'}, room=sid)


# --- Main Execution ---
if __name__ == '__main__':
    print("Initializing Flask-SocketIO server with eventlet WSGI...")
    print(f"Grid Size: {GRID_SIZE}")
    print(f"Team Colors: {TEAM_COLORS}")
    print(f"Min Players to Start: {MIN_PLAYERS_TO_START}")
    try:
        host = '0.0.0.0'
        port = int(os.environ.get('PORT', 8080))
        print(f"Starting eventlet WSGI server on http://{host}:{port}")
        socketio.run(app, host=host, port=port, use_reloader=False)
    except Exception as e:
        logging.exception(f"Failed to start server: {e}")
        print(f"Failed to start server: {e}")