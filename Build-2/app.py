from flask import Flask, request, render_template, redirect, url_for, session, jsonify
import random
import mysql.connector
import os
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from openai import OpenAI

load_dotenv()

EMAIL_ADDRESS = "shiragh.4@gmail.com"
FLASK_KEY = os.getenv("FLASK_KEY")

app = Flask(__name__)
app.secret_key = FLASK_KEY

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

def get_db():
    return mysql.connector.connect(
        host=os.getenv("MYSQLHOST"),
        user=os.getenv("MYSQLUSER"),
        password=os.getenv("MYSQLPASSWORD"),
        database=os.getenv("MYSQLDATABASE"),
        port=int(os.getenv("MYSQLPORT"))
    )

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

        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        db.close()

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

        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT name FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        db.close()

        session['user_name'] = user['name'] if user else 'User'
        return redirect(url_for("dashboard"))

    return render_template('login.html', show_otp=True, email=email, error="Wrong OTP, Try Again")

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

        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            cursor.close()
            db.close()
            return render_template('register.html', error='Email already registered')

        hash_pass = generate_password_hash(password)
        cursor.execute("INSERT INTO users(name, email, password) VALUES (%s,%s,%s)", (name, email, hash_pass))
        db.commit()
        cursor.close()
        db.close()

        return render_template('login.html', success="Registration successful! You can now login.")

    return render_template('register.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].lower()

        db = get_db()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        db.close()

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

    return render_template('forgot-password.html', show_otp=True, email=email, error='Invalid OTP')

@app.route('/reset-password', methods=['POST'])
def reset_password():
    email = request.form['email']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']

    if new_password != confirm_password:
        return render_template('forgot-password.html', show_reset=True, email=email, error='Passwords do not match')

    hash_pass = generate_password_hash(new_password)

    db = get_db()
    cursor = db.cursor()
    cursor.execute("UPDATE users SET password=%s WHERE email=%s", (hash_pass, email))
    db.commit()
    cursor.close()
    db.close()

    reset_otp_store.pop(email, None)

    return render_template('login.html', success='Password reset successful!')

@app.route('/dashboard')
def dashboard():
    if 'user_email' not in session:
        return redirect(url_for("login"))

    return render_template(
        'dashboard.html',
        user_email=session.get('user_email'),
        user_name=session.get('user_name', 'User')
    )

@app.route('/chatbot')
def chatbot_page():
    if 'user_email' not in session:
        return redirect(url_for("login"))
    return render_template('chatbot.html')

@app.route('/chat', methods=['POST'])
def chat():
    if 'user_email' not in session:
        return jsonify({"reply": "Please login first."}), 401

    user_message = request.json.get("message")

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are an AI assistant for a productivity dashboard web app. Be concise and helpful."},
                {"role": "user", "content": user_message}
            ]
        )

        reply = response.choices[0].message.content
        return jsonify({"reply": reply})

    except Exception as e:
        print("OpenAI Error:", e)
        return jsonify({"reply": "AI service temporarily unavailable."}), 500

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
