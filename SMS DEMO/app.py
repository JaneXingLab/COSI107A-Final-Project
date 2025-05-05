from flask import Flask, render_template, request, redirect, url_for, session
from twilio.rest import Client
from dotenv import load_dotenv
import os
import re
from werkzeug.security import generate_password_hash, check_password_hash

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For session encryption

# Twilio configuration
TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
VERIFY_SERVICE_SID = os.getenv('VERIFY_SERVICE_SID')

# Initialize Twilio client
client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

# Simulated user database (should use a real database in production)
USERS = {
    'admin': {
        'password': generate_password_hash('admin123'),
        'phone': '+8613812345678'
    }
}

def format_phone_number(phone):
    """Format phone number"""
    # Remove all spaces and special characters
    phone = re.sub(r'[^\d+]', '', phone)
    # Ensure it starts with +
    if not phone.startswith('+'):
        # If it starts with 0, replace with +86
        if phone.startswith('0'):
            phone = '+86' + phone[1:]
        else:
            phone = '+86' + phone
    return phone

def validate_phone_number(phone):
    """Validate phone number format"""
    if not phone:
        return False
    # Format phone number
    phone = format_phone_number(phone)
    # Validate format
    pattern = r'^\+\d{1,15}$'
    return re.match(pattern, phone) is not None

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('sms'))
    return render_template('index.html', show_login_form=True)

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username in USERS and check_password_hash(USERS[username]['password'], password):
        session['username'] = username
        return redirect(url_for('sms'))
    else:
        return render_template('index.html',
                             message='Invalid username or password',
                             message_type='error',
                             show_login_form=True)

@app.route('/sms', methods=['GET', 'POST'])
def sms():
    if 'username' not in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        phone_number = request.form.get('phone')
        
        # Validate phone number format
        if not validate_phone_number(phone_number):
            return render_template('index.html', 
                                 message='Please enter a valid phone number (format: +8613812345678)',
                                 message_type='error',
                                 show_sms_form=True)
        
        # Format phone number
        formatted_phone = format_phone_number(phone_number)
        
        try:
            # Send verification code using Twilio Verify
            verification = client.verify.v2.services(VERIFY_SERVICE_SID) \
                .verifications \
                .create(to=formatted_phone, channel='sms')
            
            session['phone'] = formatted_phone
            return redirect(url_for('verify'))
        
        except Exception as e:
            error_message = str(e)
            if 'Invalid parameter `To`' in error_message:
                return render_template('index.html',
                                     message='Invalid phone number format. Please use format: +8613812345678',
                                     message_type='error',
                                     show_sms_form=True)
            return render_template('index.html',
                                 message=f'Sending failed: {error_message}',
                                 message_type='error',
                                 show_sms_form=True)
    return render_template('index.html', show_sms_form=True)

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if 'username' not in session or 'phone' not in session:
        return redirect(url_for('index'))
        
    phone_number = session['phone']
    if request.method == 'POST':
        code = request.form.get('code')
        
        # Verify phone number
        if not validate_phone_number(phone_number):
            return render_template('index.html', 
                                 message='Invalid phone number format. Please use format: +8613812345678',
                                 message_type='error',
                                 show_verify_form=True,
                                 phone=phone_number)
        
        # Format phone number
        formatted_phone = format_phone_number(phone_number)
        
        try:
            # Verify the code
            verification_check = client.verify.v2.services(VERIFY_SERVICE_SID) \
                .verification_checks \
                .create(to=formatted_phone, code=code)
            
            if verification_check.status == 'approved':
                session['verified'] = True
                return render_template('index.html',
                                     message='Two-step verification completed successfully!',
                                     message_type='success')
            else:
                return render_template('index.html',
                                     message='Invalid verification code. Please try again.',
                                     message_type='error',
                                     show_verify_form=True,
                                     phone=phone_number)
        
        except Exception as e:
            error_message = str(e)
            if 'Invalid parameter `To`' in error_message:
                return render_template('index.html',
                                     message='Invalid phone number format. Please use format: +8613812345678',
                                     message_type='error',
                                     show_verify_form=True,
                                     phone=phone_number)
            return render_template('index.html',
                                 message=f'Verification failed: {error_message}',
                                 message_type='error',
                                 show_verify_form=True,
                                 phone=phone_number)
    return render_template('index.html', show_verify_form=True, phone=phone_number)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True) 