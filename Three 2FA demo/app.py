import os
from flask import Flask, render_template
from dotenv import load_dotenv
from flask_mail import Mail

# Load environment variables from .env file
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24) # Needed for session management

# Configure Flask-Mail
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')

# Initialize Flask-Mail
mail = Mail(app)

# Import and register blueprints
# We import here to avoid circular dependencies, and pass 'mail' object to email blueprint
from email_2fa_routes import email_bp_factory
from sms_2fa_routes import sms_bp
from totp_2fa_routes import totp_bp

app.register_blueprint(email_bp_factory(mail)) # Pass the initialized mail object
app.register_blueprint(sms_bp, url_prefix='/sms')
app.register_blueprint(totp_bp, url_prefix='/totp')

# Home route
@app.route('/')
def home():
    """Renders the main home page with links to the demos."""
    return render_template('home.html')

if __name__ == '__main__':
    # Ensure debug is False in production
    app.run(debug=True, port=5000)
