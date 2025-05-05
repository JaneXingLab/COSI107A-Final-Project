import os
import re
import logging
from flask import Blueprint, render_template, request, redirect, url_for, session, flash
from twilio.rest import Client
from werkzeug.security import generate_password_hash, check_password_hash

# Logger setup
logger = logging.getLogger('sms_2fa')
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# --- User Data (Replace with DB in real app) ---
sms_users = {
    'smsuser': {
        'password': generate_password_hash('smspass', method='pbkdf2:sha256'),
        # Store phone number in international format E.164 for Twilio
        'phone': '+14155552671' # Example US number - REPLACE if testing
                                # Or use '+86...' for China etc.
    }
}
# --- End User Data ---

# Initialize Twilio client
TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
VERIFY_SERVICE_SID = os.getenv('VERIFY_SERVICE_SID')

if not all([TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, VERIFY_SERVICE_SID]):
    print("WARNING: Twilio environment variables not fully set. SMS 2FA might fail.")
    twilio_client = None
else:
    twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

sms_bp = Blueprint('sms_2fa', __name__,
                   template_folder='templates/sms_2fa')
                   # url_prefix is defined in app.py

def format_phone_number_e164(phone):
    """Basic formatting to E.164, assumes US/Canada if no '+'."""
    phone = re.sub(r'\D', '', phone) # Remove non-digits
    if not phone.startswith('+'):
        if len(phone) == 10: # Assume US/Canada if 10 digits
           phone = '+1' + phone
        # Add more specific country code logic if needed here
        # Example for +86 (China) might need prefix checks
        # elif phone.startswith('86') and len(phone) > 10:
        #     phone = '+' + phone
        else:
            # Cannot determine country code, return original with '+' attempt
            phone = '+' + phone # Might fail in Twilio if not E.164
    return phone

@sms_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = sms_users.get(username)

        if user and check_password_hash(user['password'], password):
            session['sms_pre_verify_user'] = username
            logger.info(f"User {username} logged in and redirected to SMS verification.")
            phone_to_verify = user.get('phone')
            if not phone_to_verify:
                flash('No phone number registered for this user.')
                logger.warning(f"User {username} has no registered phone number.")
                return render_template('login.html')

            if not twilio_client or not VERIFY_SERVICE_SID:
                flash('Twilio service is not configured correctly.')
                logger.error("Twilio service configuration is missing.")
                return render_template('login.html')

            try:
                verification = twilio_client.verify.v2.services(VERIFY_SERVICE_SID) \
                    .verifications \
                    .create(to=phone_to_verify, channel='sms')

                if verification.status == 'pending':
                    session['sms_phone_being_verified'] = phone_to_verify
                    flash(f'Verification code sent to {phone_to_verify[-4:]}.')
                    logger.info(f"Verification code sent to {phone_to_verify[-4:]}. Redirecting to verify page.")
                    return redirect(url_for('sms_2fa.verify_code'))
                else:
                    flash(f'Failed to send verification code: {verification.status}')
                    logger.error(f"Failed to send verification code for {phone_to_verify}: {verification.status}")
            except Exception as e:
                flash(f'Error sending SMS: {e}')
                logger.error(f"Twilio error while sending SMS: {e}")

        else:
            flash('Invalid username or password.')
            logger.warning(f"Failed login attempt for username: {username}")

    return render_template('login.html')

@sms_bp.route('/verify', methods=['GET', 'POST'])
def verify_code():
    if 'sms_pre_verify_user' not in session or 'sms_phone_being_verified' not in session:
        flash('Please log in first.')
        logger.warning("Session keys 'sms_pre_verify_user' or 'sms_phone_being_verified' are missing. Redirecting to login.")
        return redirect(url_for('sms_2fa.login'))

    phone_number = session['sms_phone_being_verified']

    if request.method == 'POST':
        code = request.form['code']
        if not twilio_client or not VERIFY_SERVICE_SID:
            flash('Twilio service is not configured correctly.')
            logger.error("Twilio service configuration is missing during verification.")
            return render_template('verify.html', phone_last_4=phone_number[-4:])

        try:
            verification_check = twilio_client.verify.v2.services(VERIFY_SERVICE_SID) \
                .verification_checks \
                .create(to=phone_number, code=code)

            if verification_check.status == 'approved':
                username = session.pop('sms_pre_verify_user')
                session.pop('sms_phone_being_verified')
                session['sms_verified_user'] = username
                flash('SMS verification successful! You are logged in.')
                logger.info(f"User {username} successfully verified SMS.")
                return redirect(url_for('sms_2fa.success'))
            else:
                flash('Invalid verification code. Please try again.')
                logger.warning(f"Invalid verification code entered for {phone_number[-4:]}.")
        except Exception as e:
            flash(f'Error verifying code: {e}')
            logger.error(f"Twilio error during verification: {e}")

    return render_template('verify.html', phone_last_4=phone_number[-4:])

@sms_bp.route('/success')
def success():
    if 'sms_verified_user' not in session:
        flash('You are not logged in.')
        logger.warning("Session key 'sms_verified_user' is missing. Redirecting to login.")
        return redirect(url_for('sms_2fa.login'))
    return render_template('success.html', user=session['sms_verified_user'], method="SMS")

@sms_bp.route('/logout')
def logout():
    session.pop('sms_verified_user', None)
    session.pop('sms_pre_verify_user', None)
    session.pop('sms_phone_being_verified', None)
    flash('You have been logged out.')
    logger.info("User logged out.")
    return redirect(url_for('home'))
