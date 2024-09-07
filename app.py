from flask import Flask, request, jsonify
import bcrypt
import json
import os
from datetime import timedelta, datetime
from flask import session

app = Flask(__name__)

# Set a secret key for the session
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # 30 minutes session timeout

# Path to the JSON file
JSON_FILE_PATH = 'users.json'

# Load or create the JSON file if it doesn't exist
def load_users():
    if not os.path.exists(JSON_FILE_PATH):
        with open(JSON_FILE_PATH, 'w') as file:
            json.dump({"users": []}, file)
    with open(JSON_FILE_PATH, 'r') as file:
        return json.load(file)

def save_users(data):
    with open(JSON_FILE_PATH, 'w') as file:
        json.dump(data, file, indent=4)

# Input validation function
def validate_input(username, password):
    if not username or not password:
        return False
    if len(password) < 6:
        return False  # Example: Password must be at least 6 characters
    return True

# Registration route
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()

    username = data.get('username')
    password = data.get('password')

    # Validate inputs
    if not validate_input(username, password):
        return jsonify({"error": "Invalid input!"}), 400

    # Load users from JSON file
    users = load_users()

    # Check if username already exists
    for user in users['users']:
        if user['username'] == username:
            return jsonify({"error": "Username already exists!"}), 400

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Add new user to the JSON file
    new_user = {
        "username": username,
        "password": hashed_password
    }
    users['users'].append(new_user)
    save_users(users)

    return jsonify({"message": "User registered successfully!"}), 201

# Login route
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    username = data.get('username')
    password = data.get('password')

    # Validate inputs
    if not validate_input(username, password):
        return jsonify({"error": "Invalid input!"}), 400

    # Load users from JSON file
    users = load_users()

    # Check if username exists and validate password
    for user in users['users']:
        if user['username'] == username:
            if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                # Set session for the logged-in user
                session.permanent = True  # Set session to expire after the specified time
                session['username'] = username
                session['last_active'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                return jsonify({"message": "Login successful!"}), 200
            else:
                return jsonify({"error": "Invalid password!"}), 400

    return jsonify({"error": "Username not found!"}), 404

# Check session expiration and lockout mechanism
@app.before_request
def check_session_timeout():
    username = session.get('username')
    last_active = session.get('last_active')
    
    if username and last_active:
        now = datetime.now()
        last_active_time = datetime.strptime(last_active, '%Y-%m-%d %H:%M:%S')
        time_difference = now - last_active_time

        if time_difference > app.config['PERMANENT_SESSION_LIFETIME']:
            session.clear()
            return jsonify({"error": "Session expired, please log in again!"}), 401
        else:
            session['last_active'] = now.strftime('%Y-%m-%d %H:%M:%S')

# Logout route
@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully!"}), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

