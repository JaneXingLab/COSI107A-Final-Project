import os
import random
import time
from flask import Flask, request, redirect, url_for, render_template, flash, session
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Mail, Message

from werkzeug.security import generate_password_hash, check_password_hash

users = {
    "user1@gmail.com": {
        "hashed_password": "user1_hashed_password",
        "verified": False,
    }
}

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

mail = Mail(app)


def send_email(to, subject, body):
    msg = Message(subject, recipients=[to], body=body)
    mail.send(msg)

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        print(f"Attempting sign in with email: {email}")  
        user = users.get(email)
        print(f"Found user: {user}") 
        if user and check_password_hash(user['hashed_password'], password):
            print("Password check passed!")  
            # Password is correct, proceed to 2FA
            code = str(random.randint(100000, 999999))
            user['code'] = code
            user['code_timestamp'] = time.time()
            send_email(email, 'Your 2FA Code', f'Your 2FA code is: {code}')
            session['pending_email'] = email
            flash('A 2FA code has been sent to your email!')
            return redirect(url_for('verify_2fa'))
        else:
            print("Password check failed!")  
            flash('Invalid email or password')
    return render_template('signin.html')

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    email = session.get('pending_email')
    if not email:
        flash('No email to verify. Please sign up first.')
        return redirect(url_for('signup'))
    if request.method == 'POST':
        code_entered = request.form['code']
        if users[email]['code'] == code_entered:
            users[email]['verified'] = True
            session.pop('pending_email', None)
            return '2FA successful! Your email is verified.'
        else:
            flash('Incorrect code. Please try again.')
    return render_template('verify_2fa.html', email=email)

@app.route('/status/<email>')
def status(email):
    user = users.get(email)
    if not user:
        return 'User not found.'
    return f"Verified: {user['verified']}"

@app.route('/test-email')
def test_email():
    msg = Message("Test Email", recipients=["bearlee0245@gmail.com"], body="This is a test.")
    mail.send(msg)
    return "Test email sent!"

if __name__ == '__main__':
    app.run(debug=True, port=5003)
