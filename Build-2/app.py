from flask import Flask, request, render_template, redirect, url_for, session
import random
import mysql.connector
import os
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail


load_dotenv()

EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
DB_PASSWORD = os.getenv("DB_PASSWORD")
FLASK_KEY = os.getenv("FLASK_KEY")
EMAIL_ADDRESS = "shiragh.4@gmail.com"

app = Flask(__name__)
app.secret_key = FLASK_KEY

db = mysql.connector.connect(
    host=os.getenv("MYSQLHOST"),
    user=os.getenv("MYSQLUSER"),
    password=os.getenv("MYSQLPASSWORD"),
    database=os.getenv("MYSQLDATABASE"),
    port=int(os.getenv("MYSQLPORT"))
)

cursor = db.cursor(dictionary=True)
otp_store = {}
reset_otp_store = {}

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        query = "SELECT * FROM users WHERE email=%s"
        cursor.execute(query, (email,))
        user = cursor.fetchone()

        if user and check_password_hash(user['password'], password):

            otp = random.randint(100000, 999999)
            otp_store[email] = otp

            message = Mail(
                from_email=EMAIL_ADDRESS,
                to_emails=email,
                subject='OTP Verification',
                html_content=f'<strong>Your login OTP is: {otp}</strong>'
            )

            try:
                sg = SendGridAPIClient(os.getenv("SENDGRID_API_KEY"))
                sg.send(message)
                print("OTP email sent")
            except Exception as e:
                print("SendGrid failed:", e)
                print("OTP:", otp)

            return render_template('login.html', show_otp=True, email=email)

        return render_template('login.html', error="Either Email or Password is Wrong")

    return render_template('login.html')

@app.route('/verify-otp', methods=['POST'])
def verify_otp():

    email = request.form['email']
    user_otp = request.form['otp']

    if email in otp_store and str(otp_store[email]) == user_otp:

        otp_store.pop(email)
        session['user_email'] = email

        # Get user name from database
        query = "SELECT name FROM users WHERE email=%s"
        cursor.execute(query, (email,))
        user = cursor.fetchone()
        session['user_name'] = user['name'] if user else 'User'

        return redirect(url_for("dashboard"))

    return render_template(
        'login.html',
        show_otp=True,
        email=email,
        error="Wrong OTP, Try Again"
    )

@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':

        name = request.form['name']
        email = request.form['email'].lower()
        password = request.form['password']

        if len(password) < 6:
            return render_template('register.html', error='Password must be at least 6 characters long')
        
        if not any(char.isdigit() for char in password):
            return render_template('register.html', error='Password must contain at least one number')

        check_query = "SELECT * FROM users WHERE email=%s"
        cursor.execute(check_query, (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            return render_template('register.html', error='Email is already registered. Please use a different email or login.')

        hash_pass = generate_password_hash(password)
        query = "INSERT INTO users(name, email, password) VALUES (%s,%s,%s)"
        cursor.execute(query, (name, email, hash_pass))
        db.commit()

        return render_template(
            'login.html',
            success="Registration successful! You can now login."
        )

    return render_template('register.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    
    if request.method == 'POST':
        email = request.form['email'].lower()
        
        query = "SELECT * FROM users WHERE email=%s"
        cursor.execute(query, (email,))
        user = cursor.fetchone()
        
        if not user:
            return render_template('forgot-password.html', error='Email not found. Please register first.')
        
        otp = random.randint(100000, 999999)
        reset_otp_store[email] = otp
        
        message = Mail(
            from_email=EMAIL_ADDRESS,
            to_emails=email,
            subject='Password Reset OTP',
            html_content=f'<strong>Your password reset OTP is: {otp}</strong>'
        )

        try:
            sg = SendGridAPIClient(os.getenv("SENDGRID_API_KEY"))
            sg.send(message)
            return render_template('forgot-password.html', show_otp=True, email=email, success='OTP sent to your email')
        except Exception as e:
            print("SendGrid failed:", e)
            print("Reset OTP:", otp)
            return render_template('forgot-password.html', show_otp=True, email=email)

    
    return render_template('forgot-password.html')

@app.route('/verify-reset-otp', methods=['POST'])
def verify_reset_otp():
    
    email = request.form['email']
    user_otp = request.form['otp']
    
    if email in reset_otp_store and str(reset_otp_store[email]) == user_otp:
        return render_template('forgot-password.html', show_reset=True, email=email)
    
    return render_template(
        'forgot-password.html',
        show_otp=True,
        email=email,
        error='Invalid OTP. Please try again.'
    )

@app.route('/reset-password', methods=['POST'])
def reset_password():
    
    email = request.form['email']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']
    
    if len(new_password) < 6:
        return render_template('forgot-password.html', show_reset=True, email=email, error='Password must be at least 6 characters long')
    
    if not any(char.isdigit() for char in new_password):
        return render_template('forgot-password.html', show_reset=True, email=email, error='Password must contain at least one number')
    
    if new_password != confirm_password:
        return render_template('forgot-password.html', show_reset=True, email=email, error='Passwords do not match')
    
    hash_pass = generate_password_hash(new_password)
    query = "UPDATE users SET password=%s WHERE email=%s"
    cursor.execute(query, (hash_pass, email))
    db.commit()
    
    if email in reset_otp_store:
        reset_otp_store.pop(email)
    
    return render_template('login.html', success='Password reset successful! Please login with your new password.')

@app.route('/dashboard')
def dashboard():

    if 'user_email' not in session:
        return redirect(url_for("login"))

    return render_template('dashboard.html', 
                         user_email=session.get('user_email'),
                         user_name=session.get('user_name', 'User'))

@app.route('/todo')
def todo():

    if 'user_email' not in session:
        return redirect(url_for("login"))

    return render_template('11-todo-list.html')

@app.route('/rps_game')
def rps_game():

    if 'user_email' not in session:
        return redirect(url_for("login"))

    return render_template('rock-paper-scissor-game.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5002)
