from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, validators
from flask_wtf.csrf import CSRFProtect
from datetime import timedelta, datetime
import os
app = Flask(__name__)
app.secret_key = os.urandom(24)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

# Dummy user database for demonstration
users_db = {}

# Lockout mechanism
failed_attempts = {}
LOCKOUT_THRESHOLD = 3  # After 3 failed attempts
LOCKOUT_TIME = 300  # Lockout time in seconds (5 minutes)


class RegistrationForm(FlaskForm):
    username = StringField('Username', [validators.InputRequired(), validators.Length(min=4, max=25)])
    password = PasswordField('Password', [validators.InputRequired(), validators.Length(min=6)])
    confirm_password = PasswordField('Confirm Password', [validators.InputRequired(), validators.EqualTo('password')])


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
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        if username in users_db:
            flash("Username already exists. Try a different one.")
            return redirect(url_for('register'))

        # Hash the password and store it
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        users_db[username] = hashed_password

        flash("Registration successful! You can now log in.")
        return redirect(url_for('index'))

    return render_template('register.html', form=form)


@app.route('/login', methods=['POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Lockout check
        if username in failed_attempts and failed_attempts[username]['count'] >= LOCKOUT_THRESHOLD:
            lockout_end_time = failed_attempts[username]['time'] + timedelta(seconds=LOCKOUT_TIME)
            if datetime.now() < lockout_end_time:
                flash(f"Account locked. Try again later.")
                return redirect(url_for('index'))
            else:
                failed_attempts[username]['count'] = 0  # Reset failed attempts after lockout

        # Check if user exists and password matches
        if username in users_db and bcrypt.check_password_hash(users_db[username], password):
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
        return f"Welcome {session['user']} to your dashboard!"
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
