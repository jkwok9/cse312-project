document.addEventListener('DOMContentLoaded', () => {
    const canvas = document.getElementById('grid-canvas');
    const ctx = canvas.getContext('2d');
    const statusDiv = document.getElementById('status');
    const timerDiv = document.getElementById('timer');
    const teamInfoSpan = document.getElementById('player-team');
    const teamInfoDiv = document.getElementById('team-info');
    const scoresList = document.getElementById('scores-list');
    const playersList = document.getElementById('players-list');
    const canvasWrapper = document.getElementById('canvas-wrapper'); // For player markers
    const usernameDisplay = document.getElementById('username-display'); // Get username from HTML


    // --- State Variables ---
    let gridWidth = 30; // Default, will be updated from server
    let gridHeight = 20; // Default
    let cellWidth = canvas.width / gridWidth;
    let cellHeight = canvas.height / gridHeight;
    let mySid = null;
    let myTeam = null;
    let players = {}; // { sid: { username: 'name', team: 'color', position: [x, y] } }
    let gridData = {}; // { "x,y": "color" } - Keys are strings now
    let gameActive = false;
    let gameTimerInterval = null;
    const teamColors = { // Map team names to display colors
        red: '#dc3545',
        blue: '#007bff',
        green: '#28a745',
        yellow: '#ffc107',
        default: '#d3d3d3' // Color for empty cells
    };

    // --- WebSocket Connection ---
    // Connect to the Socket.IO server
    // Use window.location.origin for flexibility (http/https, port)
    const socket = io(window.location.origin);

    socket.on('connect', () => {
        console.log('Connected to server with SID:', socket.id);
        mySid = socket.id;
        // Tell the server we are ready to join the game room/logic
        socket.emit('join_game');
        statusDiv.textContent = "Connected. Waiting for team assignment...";
    });

    socket.on('disconnect', () => {
        console.log('Disconnected from server.');
        statusDiv.textContent = "Disconnected. Please refresh.";
        gameActive = false;
        clearInterval(gameTimerInterval);
        timerDiv.textContent = "Time Left: --";
        // Maybe clear the grid or show a disconnected message
    });

    socket.on('error_msg', (data) => {
        console.error('Server Error:', data.message);
        statusDiv.textContent = `Error: ${data.message}`;
        // Could add flashing message bar here
    });

    socket.on('connection_ack', (data) => {
        console.log("Connection acknowledged by server", data);
        // mySid = data.sid; // Already have socket.id, but good to confirm
    });

    // --- Game State Updates ---

    socket.on('assign_team', (data) => {
        console.log('Assigned to team:', data.team);
        myTeam = data.team;
        teamInfoSpan.textContent = myTeam.charAt(0).toUpperCase() + myTeam.slice(1);
        teamInfoDiv.style.backgroundColor = teamColors[myTeam] || 'grey';
        statusDiv.textContent = "Joined game! Waiting for start...";
        // Initial state is sent with assignment
        updateGameState(data.initial_state);
    });

    socket.on('game_state', (data) => {
        console.log('Received full game state update');
        updateGameState(data);
    });

     socket.on('game_start', (data) => {
        console.log('Game started!');
        statusDiv.textContent = "Game Active!";
        updateGameState(data); // Ensure latest state on start
        startClientTimer(data.time_remaining);
    });

    socket.on('game_over', (data) => {
        console.log('Game Over!', data);
        gameActive = false;
        clearInterval(gameTimerInterval);
        timerDiv.textContent = "Game Over!";
        const winner = data.winner;
        if (winner) {
            statusDiv.textContent = `Game Over! Winner: ${winner.charAt(0).toUpperCase() + winner.slice(1)} Team!`;
        } else {
            statusDiv.textContent = "Game Over! It's a tie or no scores!";
        }
        updateScores(data.scores);
        // Optionally clear player markers or show final positions
        // Wait for potential reset
        setTimeout(() => {
             if (!gameActive) statusDiv.textContent = "Waiting for next game...";
        }, 10000); // Match server delay
    });

    socket.on('cell_update', (data) => {
        // console.log('Cell update:', data);
        gridData[`${data.x},${data.y}`] = data.color;
        drawCell(data.x, data.y, data.color);
        updateScores(data.scores); // Update scores based on server calculation
    });

     socket.on('player_moved', (data) => {
        if (players[data.sid]) {
             players[data.sid].position = data.position;
             // Redraw player markers efficiently
             drawPlayers();
        } else {
            console.warn("Moved event for unknown player:", data.sid);
        }
    });

     socket.on('player_joined', (data) => {
         console.log("Player joined:", data.player.username);
         players[data.sid] = data.player;
         updatePlayersList();
         drawPlayers(); // Redraw markers including the new one
     });

     socket.on('player_left', (data) => {
        console.log("Player left:", data.username);
        if (players[data.sid]) {
            delete players[data.sid];
            updatePlayersList();
            drawPlayers(); // Remove marker by not drawing it
        }
     });

     socket.on('update_players', (data) => {
        console.log("Updating full player list");
        players = data.players;
        updatePlayersList();
        drawPlayers(); // Redraw all markers based on the new list
     });


    // --- Game Logic and Drawing ---

    function updateGameState(state) {
        console.log("Updating local state from server data");
        gameActive = state.active;
        gridWidth = state.grid_width;
        gridHeight = state.grid_height;
        canvas.width = Math.max(600, gridWidth * 15); // Adjust canvas size maybe? Or cell size
        canvas.height = Math.max(400, gridHeight * 15);
        cellWidth = canvas.width / gridWidth;
        cellHeight = canvas.height / gridHeight;

        gridData = state.grid; // {"x,y": color}
        players = state.players; // {sid: {username, team, position:[x,y]}}

        updateScores(state.scores);
        updatePlayersList();

        if (gameActive) {
            statusDiv.textContent = "Game Active!";
            startClientTimer(state.time_remaining);
        } else if (state.winner) {
             statusDiv.textContent = `Game Over! Winner: ${state.winner.charAt(0).toUpperCase() + state.winner.slice(1)} Team!`;
             timerDiv.textContent = "Game Over!";
        }
         else {
            statusDiv.textContent = "Waiting for game to start...";
             timerDiv.textContent = "Time Left: --";
             clearInterval(gameTimerInterval); // Ensure timer stops if game becomes inactive
        }

        drawGrid();
        drawPlayers();
    }


    function drawGrid() {
        // Clear canvas
        ctx.fillStyle = teamColors.default; // Background color
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        // Draw colored cells
        for (const key in gridData) {
            const [x, y] = key.split(',').map(Number);
            const color = gridData[key];
            drawCell(x, y, color);
        }

        // Optional: Draw grid lines
        // ctx.strokeStyle = '#ccc';
        // ctx.lineWidth = 0.5;
        // for (let x = 0; x <= gridWidth; x++) {
        //     ctx.beginPath();
        //     ctx.moveTo(x * cellWidth, 0);
        //     ctx.lineTo(x * cellWidth, canvas.height);
        //     ctx.stroke();
        // }
        // for (let y = 0; y <= gridHeight; y++) {
        //      ctx.beginPath();
        //      ctx.moveTo(0, y * cellHeight);
        //      ctx.lineTo(canvas.width, y * cellHeight);
        //      ctx.stroke();
        // }
    }

    function drawCell(x, y, colorName) {
        ctx.fillStyle = teamColors[colorName] || teamColors.default;
        ctx.fillRect(x * cellWidth, y * cellHeight, cellWidth, cellHeight);
         // Add a slight border to cells for definition
         ctx.strokeStyle = 'rgba(0,0,0,0.1)';
         ctx.strokeRect(x * cellWidth, y * cellHeight, cellWidth, cellHeight);
    }

     function drawPlayers() {
         // Clear existing markers
         canvasWrapper.querySelectorAll('.player-marker').forEach(marker => marker.remove());

         // Draw current players
         for (const sid in players) {
             const player = players[sid];
             const [x, y] = player.position;
             const teamColor = teamColors[player.team] || 'grey';

             // --- Option 1: Draw on Canvas (simpler, might obscure grid) ---
             /*
             const centerX = (x + 0.5) * cellWidth;
             const centerY = (y + 0.5) * cellHeight;
             const radius = Math.min(cellWidth, cellHeight) * 0.3;

             ctx.beginPath();
             ctx.arc(centerX, centerY, radius, 0, 2 * Math.PI, false);
             ctx.fillStyle = 'white'; // Inner color
             ctx.fill();
             ctx.lineWidth = 2;
             ctx.strokeStyle = teamColor; // Outline with team color
             ctx.stroke();

             // Draw username above
             ctx.fillStyle = 'black';
             ctx.font = '10px sans-serif';
             ctx.textAlign = 'center';
             ctx.fillText(player.username, centerX, y * cellHeight - 5);
             */

             // --- Option 2: Use HTML Elements (better for text overlay) ---
             const marker = document.createElement('div');
             marker.className = 'player-marker';
             marker.textContent = player.username;
             marker.style.left = `${(x + 0.5) * cellWidth}px`;
             marker.style.top = `${(y + 0.5) * cellHeight}px`; // Adjust vertical position slightly
             marker.style.backgroundColor = teamColor;
             marker.style.borderColor = `darken(${teamColor}, 10%)`; // Slightly darker border
             marker.dataset.sid = sid; // Store sid if needed later
             canvasWrapper.appendChild(marker);
         }
     }


    function updateScores(scores) {
        for (const team in teamColors) {
             if (team === 'default') continue;
             const scoreSpan = document.getElementById(`score-${team}`);
             if (scoreSpan) {
                scoreSpan.textContent = scores[team] || 0;
             }
        }
    }

     function updatePlayersList() {
        playersList.innerHTML = ''; // Clear current list
        let teamPlayerCounts = {}; // {team: count}
        for (const team of ['red', 'blue', 'green', 'yellow']){ teamPlayerCounts[team] = 0; } // Init

        Object.values(players).forEach(p => {
             const li = document.createElement('li');
             li.textContent = `${p.username} (${p.team})`;
             li.style.color = teamColors[p.team] || 'black';
             playersList.appendChild(li);
             if(teamPlayerCounts.hasOwnProperty(p.team)) {
                 teamPlayerCounts[p.team]++;
             }
        });
        // Could also display team counts if desired
    }


    function startClientTimer(startTime) {
        clearInterval(gameTimerInterval); // Clear any existing timer
        let timeLeft = Math.max(0, Math.floor(startTime));
        timerDiv.textContent = `Time Left: ${timeLeft}s`;

        gameTimerInterval = setInterval(() => {
            timeLeft--;
            if (timeLeft >= 0) {
                timerDiv.textContent = `Time Left: ${timeLeft}s`;
            } else {
                timerDiv.textContent = `Time Left: 0s`;
                clearInterval(gameTimerInterval);
                // Server will send 'game_over', no need to guess state here
            }
        }, 1000);
    }


    // --- Input Handling ---
    document.addEventListener('keydown', (event) => {
        if (!gameActive || !mySid || !players[mySid]) {
             // console.log("Ignoring input: Game not active or player not ready.");
             return; // Ignore input if game not active or player not initialized
        }

        let direction = null;
        switch (event.key) {
            case 'ArrowUp':
            case 'w':
                direction = 'up';
                break;
            case 'ArrowDown':
            case 's':
                direction = 'down';
                break;
            case 'ArrowLeft':
            case 'a':
                direction = 'left';
                break;
            case 'ArrowRight':
            case 'd':
                direction = 'right';
                break;
            default:
                return; // Ignore other keys
        }

        event.preventDefault(); // Prevent arrow keys from scrolling the page
        // console.log('Sending move:', direction);
        socket.emit('move', { direction: direction });
    });

    // Initial draw (empty grid)
    drawGrid();
});