from flask import Flask, render_template, redirect, url_for, flash, session
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, validators
from flask_wtf.csrf import CSRFProtect
from datetime import timedelta, datetime
import os,re
import json

app = Flask(__name__)
app.secret_key = 'strong_secret_key'
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

# Lockout mechanism
failed_attempts = {}
LOCKOUT_THRESHOLD = 3  # After 3 failed attempts
LOCKOUT_TIME = 300  # Lockout time in seconds (5 minutes)

USERS_JSON = 'users.json'

def load_users():
    if os.path.exists(USERS_JSON):
        with open(USERS_JSON, 'r') as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_JSON, 'w') as f:
        json.dump(users, f, indent=4)
def validate_email_format(form, field):
    email = field.data
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    if not re.match(email_regex, email):
        raise validators.ValidationError('Invalid email format')


# Registration form class
class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', [validators.InputRequired(), validators.Length(min=2, max=25)])
    last_name = StringField('Last Name', [validators.InputRequired(), validators.Length(min=2, max=25)])
    email = StringField('Email', [validators.InputRequired(), validate_email_format])
    username = StringField('Username', [validators.InputRequired(), validators.Length(min=4, max=25)])
    password = PasswordField('Password', [validators.InputRequired(), validators.Length(min=6)])
    confirm_password = PasswordField('Confirm Password', [validators.InputRequired(), validators.EqualTo('password')])

# Login form class
class LoginForm(FlaskForm):
    username = StringField('Username', [validators.InputRequired(), validators.Length(min=4, max=25)])
    password = PasswordField('Password', [validators.InputRequired()])

@app.route('/')
def index():
    form = LoginForm()
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    users_db = load_users()
        # Proceed only on validation success
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        first_name = form.first_name.data
        last_name = form.last_name.data

        if username in users_db:
            flash("Username already exists. Try a different one.")
            return redirect(url_for('register'))

        # Hash the password and store user info in JSON
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        users_db[username] = {
            'first_name': first_name,
            'last_name': last_name,
            'username': username,
            'email': email,
            'password': hashed_password
        }

        save_users(users_db)
        flash("Registration successful! You can now log in.")
        return redirect(url_for('index'))

    return render_template('register.html', form=form)

@app.route('/login', methods=['POST'])
def login():
    form = LoginForm()
    users_db = load_users()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        if username in failed_attempts and failed_attempts[username]['count'] >= LOCKOUT_THRESHOLD:
            lockout_end_time = failed_attempts[username]['time'] + timedelta(seconds=LOCKOUT_TIME)
            if datetime.now() < lockout_end_time:
                flash(f"Account locked. Try again later.")
                return redirect(url_for('index'))
            else:
                failed_attempts[username]['count'] = 0  # Reset failed attempts after lockout

        # Check if user exists and password matches
        if username in users_db and bcrypt.check_password_hash(users_db[username]['password'], password):
            session['user'] = username
            session.permanent = True
            app.permanent_session_lifetime = timedelta(minutes=30)  # Set session expiration
            flash("Login successful!")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid credentials. Please try again.")
            if username not in failed_attempts:
                failed_attempts[username] = {'count': 1, 'time': datetime.now()}
            else:
                failed_attempts[username]['count'] += 1
                failed_attempts[username]['time'] = datetime.now()
            return redirect(url_for('index'))

    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    if 'user' in session:
        users_db = load_users()
        user_info = users_db.get(session['user'], {})
        return f"Welcome {user_info['first_name']} {user_info['last_name']} to Failsafe!"
    else:
        flash("Please log in first.")
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("Logged out successfully!")
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
