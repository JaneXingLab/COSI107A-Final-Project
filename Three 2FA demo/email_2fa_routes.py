import os
import random
import time
from flask import Blueprint, request, redirect, url_for, render_template, flash, session
from flask_mail import Message
from werkzeug.security import generate_password_hash, check_password_hash

# --- User Data (Replace with DB in real app) ---
# Generate a hash for the password 'emailpass'
hashed_password = generate_password_hash('emailpass', method='pbkdf2:sha256')
email_users = {
    "test@mail.com": {
        "hashed_password": hashed_password,
        "verified": False,
        "code": None,
        "code_timestamp": None,
    }
}
# --- End User Data ---

# Need a factory function to accept the 'mail' object
def email_bp_factory(mail):
    email_bp = Blueprint('email_2fa', __name__,
                         template_folder='templates/email_2fa',
                         url_prefix='/email')

    def send_email(to, subject, body):
        """Helper function to send emails."""
        try:
            msg = Message(subject, recipients=[to], body=body, sender=os.environ.get('MAIL_USERNAME'))
            mail.send(msg)
            return True
        except Exception as e:
            import traceback
            error_details = traceback.format_exc()
            print(f"Error sending email: {e}\nDetails: {error_details}")  # Log detailed error
            flash('Failed to send verification email. Please check server configuration.')
            return False

    @email_bp.route('/signin', methods=['GET', 'POST'])
    def signin():
        if request.method == 'POST':
            email = request.form['email']
            password = request.form['password']
            user = email_users.get(email)

            if user and check_password_hash(user['hashed_password'], password):
                # Password is correct, proceed to 2FA
                code = str(random.randint(100000, 999999))
                user['code'] = code
                user['code_timestamp'] = time.time() # Store timestamp

                if send_email(email, 'Your 2FA Code', f'Your 2FA code is: {code}'):
                    session['email_pending_verification'] = email
                    flash('A 2FA code has been sent to your email.')
                    return redirect(url_for('email_2fa.verify_2fa'))
                else:
                    # Error already flashed in send_email
                    return redirect(url_for('email_2fa.signin'))
            else:
                flash('Invalid email or password')
        return render_template('signin.html')

    @email_bp.route('/verify', methods=['GET', 'POST'])
    def verify_2fa():
        email = session.get('email_pending_verification')
        if not email or email not in email_users:
            flash('Verification process not started or invalid. Please sign in again.')
            return redirect(url_for('email_2fa.signin'))

        user = email_users[email]

        if request.method == 'POST':
            code_entered = request.form['code']
            # Check if code exists and is not expired (e.g., 5 minutes validity)
            if user.get('code') and user.get('code_timestamp'):
                time_elapsed = time.time() - user['code_timestamp']
                if time_elapsed > 300: # 5 minutes
                    flash('Verification code has expired. Please sign in again.')
                    # Clear expired code details
                    user['code'] = None
                    user['code_timestamp'] = None
                    session.pop('email_pending_verification', None)
                    return redirect(url_for('email_2fa.signin'))

                if user['code'] == code_entered:
                    user['verified'] = True
                    user['code'] = None # Clear code after use
                    user['code_timestamp'] = None
                    session.pop('email_pending_verification', None)
                    session['email_verified_user'] = email # Mark as fully verified
                    flash('2FA successful! You are logged in.')
                    return redirect(url_for('email_2fa.success'))
                else:
                    flash('Incorrect code. Please try again.')
            else:
                 flash('Verification code not found or expired. Please sign in again.')
                 session.pop('email_pending_verification', None)
                 return redirect(url_for('email_2fa.signin'))

        # Pass email to template for display
        return render_template('verify_2fa.html', email=email)

    @email_bp.route('/success')
    def success():
        if 'email_verified_user' not in session:
            flash('You are not logged in.')
            return redirect(url_for('email_2fa.signin'))
        # Clear user verification status if needed for demo purposes
        # email_users[session['email_verified_user']]['verified'] = False
        return render_template('success.html', user=session['email_verified_user'], method="Email")

    @email_bp.route('/logout')
    def logout():
        email = session.pop('email_verified_user', None)
        if email and email in email_users:
             email_users[email]['verified'] = False # Reset status on logout
        session.pop('email_pending_verification', None)
        flash('You have been logged out.')
        return redirect(url_for('home')) # Redirect to main home

    return email_bp
