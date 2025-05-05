from flask import jsonify, render_template
from util.database import db
import logging
from datetime import datetime
from bson.objectid import ObjectId

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Collections
users_collection = db["users"]
games_collection = db["games"]
leaderboard_collection = db["leaderboard_stats"]


def update_leaderboard_stats(game_result):
    """
    Update leaderboard statistics for team-based wins
    """
    try:
        player_ids = list(game_result['player_scores'].keys())
        winner_ids = game_result.get('winner_ids', [])  # Now a list

        for player_id in player_ids:
            player_stats = leaderboard_collection.find_one({'user_id': player_id})
            territory_score = game_result['player_scores'].get(player_id, 0)

            if player_stats:
                update_data = {
                    '$inc': {'games_played': 1},
                    '$set': {'last_played': game_result['timestamp']}
                }

                # Add win if player is in winner list
                if player_id in winner_ids:
                    update_data['$inc']['wins'] = 1

                # Update best territory score
                if territory_score > player_stats.get('best_territory_score', 0):
                    update_data['$set'].update({
                        'best_territory_score': territory_score,
                        'best_score_date': game_result['timestamp']
                    })

                leaderboard_collection.update_one(
                    {'user_id': player_id},
                    update_data
                )
            else:
                new_stats = {
                    'user_id': player_id,
                    'games_played': 1,
                    'wins': 1 if player_id in winner_ids else 0,
                    'best_territory_score': territory_score,
                    'best_score_date': game_result['timestamp'],
                    'last_played': game_result['timestamp']
                }
                leaderboard_collection.insert_one(new_stats)

        logger.info(f"Updated team-based leaderboard for game")
        return True
    except Exception as e:
        logger.error(f"Error updating leaderboard: {str(e)}")
        return False

def get_wins_leaderboard(limit=20):
    """
    Get the leaderboard sorted by number of wins
    """
    try:
        # Pipeline for MongoDB aggregation
        pipeline = [
            # Join with users collection to get usernames
            {
                '$lookup': {
                    'from': 'users',
                    'localField': 'user_id',
                    'foreignField': 'username',
                    'as': 'user_info'
                }
            },
            # Unwind the user_info array
            {
                '$unwind': {
                    'path': '$user_info',
                    'preserveNullAndEmptyArrays': False
                }
            },
            # Project only the fields we need
            {
                '$project': {
                    '_id': 0,
                    'username': '$user_info.username',
                    'wins': 1,
                    'gamesPlayed': '$games_played',
                    'winRate': {
                        '$cond': [
                            {'$eq': ['$games_played', 0]},
                            0,
                            {'$multiply': [{'$divide': ['$wins', '$games_played']}, 100]}
                        ]
                    }
                }
            },
            # Sort by wins (descending)
            {
                '$sort': {
                    'wins': -1,
                    'winRate': -1,
                    'username': 1  # Alphabetical tiebreaker
                }
            },
            # Limit results
            {
                '$limit': limit
            }
        ]
        
        # Execute the aggregation
        results = list(leaderboard_collection.aggregate(pipeline))
        return results
    except Exception as e:
        logger.error(f"Error fetching wins leaderboard: {str(e)}")
        return []

def get_territory_leaderboard(limit=20):
    """
    Get the leaderboard sorted by best territory score
    """
    try:
        # Pipeline for MongoDB aggregation
        pipeline = [
            # Join with users collection to get usernames
            {
                '$lookup': {
                    'from': 'users',
                    'localField': 'user_id',
                    'foreignField': '_id',
                    'as': 'user_info'
                }
            },
            # Unwind the user_info array
            {
                '$unwind': {
                    'path': '$user_info',
                    'preserveNullAndEmptyArrays': False
                }
            },
            # Project only the fields we need
            {
                '$project': {
                    '_id': 0,
                    'username': '$user_info.username',
                    'bestScore': '$best_territory_score',
                    'dateAchieved': '$best_score_date'
                }
            },
            # Sort by best territory score (descending)
            {
                '$sort': {
                    'bestScore': -1,
                    'username': 1  # Alphabetical tiebreaker
                }
            },
            # Limit results
            {
                '$limit': limit
            }
        ]
        
        # Execute the aggregation
        results = list(leaderboard_collection.aggregate(pipeline))
        return results
    except Exception as e:
        logger.error(f"Error fetching territory leaderboard: {str(e)}")
        return []

def handle_leaderboard_page():
    """
    Render the leaderboard page
    """
    return render_template('leaderboard.html')

def handle_wins_leaderboard_api():
    """
    API endpoint to get wins leaderboard data
    """
    try:
        wins_data = get_wins_leaderboard()
        return jsonify(wins_data)
    except Exception as e:
        logger.error(f"Error in wins leaderboard API: {str(e)}")
        return jsonify({"error": "Failed to fetch leaderboard data"}), 500

def handle_territory_leaderboard_api():
    """
    API endpoint to get territory leaderboard data
    """
    try:
        territory_data = get_territory_leaderboard()
        return jsonify(territory_data)
    except Exception as e:
        logger.error(f"Error in territory leaderboard API: {str(e)}")
        return jsonify({"error": "Failed to fetch leaderboard data"}), 500

# Function to record game results when a game ends
def record_game_result(winner_ids, player_scores, players_info):
    """
    Modified to accept multiple winner IDs
    """
    try:
        game_record = {
            'timestamp': datetime.utcnow(),
            'winner_ids': winner_ids,
            'player_scores': player_scores,
            'players_info': players_info
        }

        games_collection.insert_one(game_record)
        update_leaderboard_stats(game_record)

        logger.info(f"Recorded team game result with {len(winner_ids)} winners")
        return True
    except Exception as e:
        logger.error(f"Error recording game result: {str(e)}")
        return False