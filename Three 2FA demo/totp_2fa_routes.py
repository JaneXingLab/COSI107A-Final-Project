import io
import base64
import logging
from flask import Blueprint, render_template, request, redirect, session, url_for, flash
import pyotp
import qrcode
from werkzeug.security import generate_password_hash, check_password_hash

# Logger setup
logger = logging.getLogger('totp_2fa')
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

# --- User Data (Replace with DB in real app) ---
# Generate secrets securely and store them associated with the user
totp_users = {
    'totpuser': {
        'password': generate_password_hash('totppass', method='pbkdf2:sha256'),
        'totp_secret': pyotp.random_base32(), # Generate a unique secret per user
        'is_totp_setup': False # Flag to track if user scanned QR
    }
}
# --- End User Data ---


def generate_qr_code_base64(secret, username, issuer_name="MyFlaskApp"):
    """Generate a base64-encoded QR code for the TOTP secret."""
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=username, issuer_name=issuer_name)
    # Create QR code image
    qr_img = qrcode.make(uri, box_size=10, border=4)
    # Save image to a bytes buffer
    buf = io.BytesIO()
    qr_img.save(buf, format='PNG')
    buf.seek(0)
    # Encode buffer to base64
    base64_img = base64.b64encode(buf.read()).decode('utf-8')
    return f"data:image/png;base64,{base64_img}"

totp_bp = Blueprint('totp_2fa', __name__,
                    template_folder='templates/totp_2fa')
                    # url_prefix defined in app.py

# Add detailed logging to track session state and route resolution
@totp_bp.route('/login_totp', methods=['GET', 'POST'])
def login():
    print(totp_bp.name, "Login route accessed")
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = totp_users.get(username)

        # IMPORTANT: Use check_password_hash for security
        if user and check_password_hash(user['password'], password):
            session['totp_pre_verify_user'] = username
            return redirect(url_for('totp_2fa.verify'))
        else:
            flash('Invalid username or password.')
            logger.warning(f"Failed login attempt for username: {username}")
    return render_template('login_totp.html')

@totp_bp.route('/verify_totp', methods=['GET', 'POST'])
def verify():
    logger.info(f"Session state at verify start: {session}")
    if 'totp_pre_verify_user' not in session:
        logger.warning("Session key 'totp_pre_verify_user' is missing. Redirecting to login.")
        return redirect(url_for('totp_2fa.login'))

    username = session['totp_pre_verify_user']
    user = totp_users.get(username)

    if not user:
        session.pop('totp_pre_verify_user', None)
        flash('User not found.')
        logger.error(f"User {username} not found during TOTP verification.")
        return redirect(url_for('totp_2fa.login'))

    secret = user['totp_secret']
    totp = pyotp.TOTP(secret)
    qr_code_data = None

    show_qr = not user.get('is_totp_setup', False)
    if show_qr:
        qr_code_data = generate_qr_code_base64(secret, username, issuer_name="TOTP Demo App")

    logger.info(f"Data passed to template: username={username}, show_qr={show_qr}, qr_code={'present' if qr_code_data else 'absent'}")

    if request.method == 'POST':
        otp = request.form['otp']
        if totp.verify(otp):
            if not user.get('is_totp_setup'):
                user['is_totp_setup'] = True

            session.pop('totp_pre_verify_user')
            session['totp_verified_user'] = username
            logger.info(f"Session state after successful TOTP verification: {session}")
            return redirect(url_for('totp_2fa.success'))
        else:
            flash('Invalid TOTP code. Please try again.')
            logger.warning(f"Invalid TOTP code entered for user {username}.")

    return render_template('verify_totp.html', username=username, qr_code=qr_code_data, show_qr=show_qr)


@totp_bp.route('/success')
def success():
    logger.info(f"Session state at success: {session}")
    if 'totp_verified_user' not in session:
        logger.warning("Session key 'totp_verified_user' is missing. Redirecting to login.")
        flash('You are not logged in.')
        return redirect(url_for('totp_2fa.login'))
    return render_template('success.html', user=session['totp_verified_user'], method="TOTP")

@totp_bp.route('/logout')
def logout():
    session.pop('totp_verified_user', None)
    session.pop('totp_pre_verify_user', None)
    # We don't reset the 'is_totp_setup' flag on logout
    flash('You have been logged out.')
    logger.info("User logged out.")
    return redirect(url_for('home'))
