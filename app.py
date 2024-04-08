from flask import Flask, render_template, request, redirect, url_for, session, flash
from passlib.hash import sha256_crypt
import pymysql
import os
from libraries.elo import Elo

# App Instantiation
app = Flask(__name__)
app.secret_key = "secret123!"

# Connection to the database
def get_db_connection():
    connection = pymysql.connect(
        host = os.environ.get('DB_HOST'),
        user = os.environ.get('DB_USER'),
        password = os.environ.get('DB_PASSWORD'),
        database = os.environ.get('DB_NAME'),
        unix_socket = os.environ.get('SOCKET_PATH'),
        cursorclass = pymysql.cursors.DictCursor
    )
    return connection


# Root Route
# Publicly accessible; used to display the scores for each game if they exist
@app.route('/')
def home():
    # Establish a connection to the database
    conn = get_db_connection()
    cur = conn.cursor()

    # Fetch the latest scores with usernames and game names
    cur.execute("""
        SELECT g.game_name, u.username, MAX(s.score) AS score
        FROM scores s
        JOIN users u ON s.user_id = u.user_id
        JOIN games g ON s.game_id = g.game_id
        GROUP BY g.game_name, u.user_id
        ORDER BY g.game_name, score DESC
    """)

    # Fetch all the latest scores
    scores = cur.fetchall()

    # Close the connection to the DB
    cur.close()
    conn.close()

    # Group the scores by game name
    scores_by_game = {}
    for score in scores:
        game_name = score['game_name']
        if game_name not in scores_by_game:
            scores_by_game[game_name] = []
        scores_by_game[game_name].append(score)

    return render_template('home.html', scores_by_game=scores_by_game)

# Registration Route
# Publicly accessible
@app.route('/register', methods=['GET', 'POST'])
def register():
    # Render the registration form on a GET request
    if request.method == 'GET':
        return render_template('register.html')
    else:
        # Extract the form data from the POST request
        firstname = request.form['Firstname']
        lastname = request.form['Lastname']
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm']

        # Check if the password and confirm password fields match
        if password != confirm:
            flash("Passwords don't match", "danger")
            return render_template('register.html')

        # Encrypt the password using SHA-256
        secure_password = sha256_crypt.encrypt(str(password))
        
        # Establish a connection to the database
        conn = get_db_connection()
        cur = conn.cursor()

        # Check if the username or email already exists in the database
        cur.execute("SELECT * FROM users WHERE username=%s OR email=%s", (username, email))
        existing_user = cur.fetchone()

        if existing_user:
            # If a user with the same username or email already exists, flash an error message
            flash("Username or email already exists", "danger")
            cur.close()
            conn.close()
            return render_template('register.html')
        else:
            # Insert user into the 'users' table
            cur.execute("INSERT INTO users (username, email, password, first_name, last_name) VALUES (%s, %s, %s, %s, %s)", (username, email, secure_password, firstname, lastname))
            user_id = cur.lastrowid  # Get the ID of the newly inserted user

            # Assign the 'user' role to the newly registered user
            cur.execute("SELECT role_id FROM roles WHERE role_name = 'user'")
            user_role_id = cur.fetchone()['role_id']
            cur.execute("INSERT INTO user_roles (user_id, role_id) VALUES (%s, %s)", (user_id, user_role_id))

            # Commit the transaction and close the connection
            conn.commit()
            cur.close()
            conn.close()

            # Flash a success message and redirect to the home page
            flash("You are registered!", "success")
            session['username'] = username
            return redirect(url_for('home'))
            
# Login Route
# Publicly accessible
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Render the login form on a GET request
    if request.method == 'GET':
        return render_template('login.html')
    else:
        # Extract the form data
        username = request.form['username']
        password = request.form['password']

        # Establish a connection to the database
        conn = get_db_connection()
        cur = conn.cursor()

        # Check if the user exists in the database
        cur.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = cur.fetchone()

        # Close the connection to the DB
        cur.close()
        conn.close()

        # If the user exists and the password is correct, log the user in
        # Otherwise, flash an error message and redirect to the login page
        if user and sha256_crypt.verify(password, user['password']):
            session['username'] = user['username']
            flash("You logged in successfully", "success")
            return redirect(url_for('home'))
        else:
            flash("Incorrect login details", "danger")
            return render_template("login.html")

# Dashboard Route
# Requires the user to be logged in    
@app.route('/dashboard')
def dashboard():
    # Check if the user is logged in
    # If not, flash an error message and redirect to the login page
    if 'username' not in session:
        flash("You need to login first", "danger")
        return redirect(url_for('login'))
    else:
        # Establish a connection to the database
        conn = get_db_connection()
        cur = conn.cursor()

        # Fetch games from the 'games' table
        cur.execute("SELECT game_id, game_name FROM games")
        games = cur.fetchall()

        # Fetch pending game requests for the logged-in user
        cur.execute("""
            SELECT pg.pending_game_id, u.username AS requester_username, g.game_name
            FROM pending_games pg
            JOIN users u ON pg.requester_id = u.user_id
            JOIN games g ON pg.game_id = g.game_id
            WHERE pg.requested_user_id = (SELECT user_id FROM users WHERE username = %s)
        """, (session['username'],))
        pending_requests = cur.fetchall()

        # Close the connection to the DB
        cur.close()
        conn.close()

    return render_template('dashboard.html', games=games, pending_requests=pending_requests)

# Record Game Route
# Requires the user to be logged in
@app.route('/create_game_request', methods=['POST'])
def create_game_request():
    # Check if the user is logged in
    # If not, flash an error message and redirect to the login page
    if 'username' not in session:
        flash("You need to login first", "danger")
        return redirect(url_for('login'))
    else:
        # Extract the form data
        opponent_username = request.form['opponent_username']
        game_id = request.form['game_id']
        result = request.form.get('result', 0)  # Get the result checkbox value (0 or 1)

        # Establish a connection to the database
        conn = get_db_connection()
        cur = conn.cursor()

        # Get the user ID of the logged-in user
        cur.execute("SELECT user_id FROM users WHERE username = %s", (session['username'],))
        requester_id = cur.fetchone()['user_id']

        # Get the user ID of the opponent
        cur.execute("SELECT user_id FROM users WHERE username = %s", (opponent_username,))
        opponent_user_id = cur.fetchone()['user_id']

        # Insert the game request into the 'pending_games' table
        cur.execute("""
            INSERT INTO pending_games (requester_id, requested_user_id, game_id, result)
            VALUES (%s, %s, %s, %s)
        """, (requester_id, opponent_user_id, game_id, result))
        conn.commit()

        # Close the connection to the DB
        cur.close()
        conn.close()

        flash(f"Game request sent to {opponent_username}", "success")
        return redirect(url_for('dashboard'))

# Accept Game Request Route
# Requires the user to be logged in
@app.route('/accept_game_request/<int:request_id>', methods=['GET'])
def accept_game_request(request_id):
    # Check if the user is logged in
    # If not, flash an error message and redirect to the login page
    if 'username' not in session:
        flash("You need to login first", "danger")
        return redirect(url_for('login'))
    else:
        # Establish a connection to the database
        conn = get_db_connection()
        cur = conn.cursor()

        # Retrieve the pending game request details
        cur.execute("""
            SELECT pg.requester_id, pg.requested_user_id, pg.game_id, pg.result,
                   u1.username AS requester_username, u2.username AS requested_username
            FROM pending_games pg
            JOIN users u1 ON pg.requester_id = u1.user_id
            JOIN users u2 ON pg.requested_user_id = u2.user_id
            WHERE pg.pending_game_id = %s
        """, (request_id,))
        request_details = cur.fetchone()

        # If the request exists, update the scores for both players
        if request_details:
            # Extract the request details from the query
            requester_id = request_details['requester_id']
            requested_user_id = request_details['requested_user_id']
            game_id = request_details['game_id']
            result = request_details['result']

            # Validate input parameters of the game result
            if not isinstance(result, int) or result not in [0, 1]:
                print(requester_id, requested_user_id, game_id, result)
                flash("Invalid game result", "danger")
                return redirect(url_for('dashboard'))

            # Retrieve the current Elo ratings for both players
            # If the player doesn't have a rating (first time), default to 1000
            cur.execute("""
                SELECT score_id, score FROM scores
                WHERE user_id = %s AND game_id = %s
                ORDER BY score DESC
                LIMIT 1
            """, (requester_id, game_id))
            requester_rating_result = cur.fetchone()
            if requester_rating_result:
                requester_rating = requester_rating_result['score']
                requester_score_id = requester_rating_result['score_id']
            else:
                requester_rating = 1000
                requester_score_id = None

            cur.execute("""
                SELECT score_id, score FROM scores
                WHERE user_id = %s AND game_id = %s
                ORDER BY score DESC
                LIMIT 1
            """, (requested_user_id, game_id))
            requested_user_rating_result = cur.fetchone()
            if requested_user_rating_result:
                requested_user_rating = requested_user_rating_result['score']
                requested_user_score_id = requested_user_rating_result['score_id']
            else:
                requested_user_rating = 1000
                requested_user_score_id = None

            # Calculate the new Elo ratings
            elo = Elo()
            new_requester_rating, new_requested_user_rating = elo.expectedScore(requester_rating, requested_user_rating, result)

            # Update the scores for both players
            if requester_score_id:
                cur.execute("""
                    UPDATE scores
                    SET score = %s
                    WHERE score_id = %s
                """, (new_requester_rating, requester_score_id))
            else:
                cur.execute("""
                    INSERT INTO scores (user_id, game_id, score)
                    VALUES (%s, %s, %s)
                """, (requester_id, game_id, new_requester_rating))

            if requested_user_score_id:
                cur.execute("""
                    UPDATE scores
                    SET score = %s
                    WHERE score_id = %s
                """, (new_requested_user_rating, requested_user_score_id))
            else:
                cur.execute("""
                    INSERT INTO scores (user_id, game_id, score)
                    VALUES (%s, %s, %s)
                """, (requested_user_id, game_id, new_requested_user_rating))

            # Remove the request from the 'pending_games' table
            cur.execute("""
                DELETE FROM pending_games
                WHERE pending_game_id = %s
            """, (request_id,))

            # Commit the transaction and close the connection
            conn.commit()
            cur.close()
            conn.close()

            flash(f"Game request between {request_details['requester_username']} and {request_details['requested_username']} accepted and scores updated.", "success")
        else:
            flash("Invalid game request", "danger")

        return redirect(url_for('dashboard'))

# Decline Game Request Route
# Requires the user to be logged in
@app.route('/decline_game_request/<int:request_id>', methods=['GET'])
def decline_game_request(request_id):
    # Check if the user is logged in
    # If not, flash an error message and redirect to the login page
    if 'username' not in session:
        flash("You need to login first", "danger")
        return redirect(url_for('login'))
    
    # Establish a connection to the database
    conn = get_db_connection()
    cur = conn.cursor()

    # Remove the request from the 'pending_games' table
    cur.execute("""
        DELETE FROM pending_games
        WHERE pending_game_id = %s
    """, (request_id,))
    conn.commit()

    # Close the connection to the DB
    cur.close()
    conn.close()

    flash("Game request declined", "success")
    return redirect(url_for('dashboard'))

# Admin Route
# Requires the user to be logged in and have the 'admin' role
@app.route('/admin', methods=['GET'])
def admin():
    # Check if the user is logged in to prevent needless queries
    # If not, flash an error message and redirect to the login page
    if 'username' not in session:
        flash("You need to login first", "danger")
        return redirect(url_for('login'))
    
    # Establish a connection to the database
    conn = get_db_connection()
    cur = conn.cursor()

    # Check if the logged-in user is an admin
    cur.execute("""
        SELECT COUNT(*) AS is_admin
        FROM user_roles ur
        JOIN users u ON ur.user_id = u.user_id
        JOIN roles r ON ur.role_id = r.role_id
        WHERE u.username = %s AND r.role_name = 'admin'
    """, (session['username'],))
    result = cur.fetchone()
    is_admin = result['is_admin'] > 0

    # Close the connection to the DB
    cur.close()
    conn.close()

    # If the user is an admin, render the admin page
    # Else, flash an error message and redirect to the home page
    if is_admin:
        return render_template('admin.html')
    else:
        flash("You don't have permission to access this page", "danger")
        return redirect(url_for('home'))

# Create Game Route
# Requires the user to be logged in and have the 'admin' role
@app.route('/create_game', methods=['POST'])
def create_game():
    # Check if the user is logged in to prevent needless queries
    # If not, flash an error message and redirect to the login page
    if 'username' not in session:
        flash("You need to login first", "danger")
        return redirect(url_for('login'))
    
    # Establish a connection to the database
    conn = get_db_connection()
    cur = conn.cursor()

    # Check if the logged-in user is an admin
    cur.execute("""
        SELECT COUNT(*) AS is_admin
        FROM user_roles ur
        JOIN users u ON ur.user_id = u.user_id
        JOIN roles r ON ur.role_id = r.role_id
        WHERE u.username = %s AND r.role_name = 'admin'
    """, (session['username'],))
    result = cur.fetchone()
    is_admin = result['is_admin'] > 0

    if is_admin:
        # Extract the form data
        game_name = request.form['game_name']

        # Insert the new game into the 'games' table
        cur.execute("""
            INSERT INTO games (game_name)
            VALUES (%s)
        """, (game_name))
        conn.commit()

        # Close the connection to the DB
        cur.close()
        conn.close()

        # Flash a success message and redirect to the admin page
        # Else, flash an error message and redirect to the home page
        flash(f"Game '{game_name}' created successfully", "success")
        return redirect(url_for('admin'))
    else:
        flash("You don't have permission to create games", "danger")
        return redirect(url_for('home'))

# Upgrade User Route
# Requires the user to be logged in and have the 'admin' role
@app.route('/upgrade_user', methods=['POST'])
def upgrade_user():
    # Check if the user is logged in to prevent needless queries
    # If not, flash an error message and redirect to the login page
    if 'username' not in session:
        flash("You need to login first", "danger")
        return redirect(url_for('login'))
    
    # Establish a connection to the database
    conn = get_db_connection()
    cur = conn.cursor()

    # Check if the logged-in user is an admin
    cur.execute("""
        SELECT COUNT(*) AS is_admin
        FROM user_roles ur
        JOIN users u ON ur.user_id = u.user_id
        JOIN roles r ON ur.role_id = r.role_id
        WHERE u.username = %s AND r.role_name = 'admin'
    """, (session['username'],))
    result = cur.fetchone()
    is_admin = result['is_admin'] > 0

    if is_admin:
        # Extract the form data
        username = request.form['username']

        # Get the user ID of the user to be upgraded
        cur.execute("SELECT user_id FROM users WHERE username = %s", (username,))
        user = cur.fetchone()

        # If the user exists, assign the 'admin' role to the user
        # Else, flash an error message
        if user:
            user_id = user['user_id']

            # Check if the user already has the 'admin' role
            cur.execute("""
                SELECT COUNT(*) AS is_admin
                FROM user_roles
                WHERE user_id = %s AND role_id = (SELECT role_id FROM roles WHERE role_name = 'admin' LIMIT 1)
            """, (user_id,))
            result = cur.fetchone()
            is_already_admin = result['is_admin'] > 0

            if not is_already_admin:
                # Assign the 'admin' role to the user
                cur.execute("""
                    INSERT INTO user_roles (user_id, role_id)
                    VALUES (%s, (SELECT role_id FROM roles WHERE role_name = 'admin' LIMIT 1))
                """, (user_id,))
                conn.commit()
                flash(f"User '{username}' upgraded to admin successfully", "success")
            else:
                flash(f"User '{username}' is already an admin", "warning")
        else:
            flash(f"User '{username}' not found", "danger")

        cur.close()
        conn.close()

        return redirect(url_for('admin'))
    else:
        flash("You don't have permission to upgrade users", "danger")
        return redirect(url_for('home'))

# Logout Route    
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)


