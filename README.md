# 2FA Demo Application

This is a demonstration project for implementing three types of Two-Factor Authentication (2FA) mechanisms using Flask:
1. **Email-Based 2FA**
2. **SMS-Based 2FA**
3. **TOTP-Based 2FA** (Time-based One-Time Password)

The project is designed for educational purposes as part of the Brandeis COSI 107A course on Introduction to Computer Security.

---

## Features

- **Email-Based 2FA**: Sends a 6-digit verification code to the user's email address.
- **SMS-Based 2FA**: Sends a 6-digit verification code to the user's phone number using Twilio.
- **TOTP-Based 2FA**: Generates a QR code for users to scan with an authenticator app (e.g., Google Authenticator, Authy) and verify using a 6-digit code.
- **Session Management**: Tracks user login and verification states using Flask sessions.
- **Demo Credentials**: Predefined users for testing each 2FA mechanism.

---

## Project Structure

```
.
├── app.py                     # Main Flask application
├── email_2fa_routes.py        # Routes for Email-Based 2FA
├── sms_2fa_routes.py          # Routes for SMS-Based 2FA
├── totp_2fa_routes.py         # Routes for TOTP-Based 2FA
├── templates/                 # HTML templates for the application
│   ├── home.html              # Home page
│   ├── email_2fa/             # Email 2FA templates
│   │   ├── signin.html
│   │   ├── success.html
│   │   └── verify_2fa.html
│   ├── sms_2fa/               # SMS 2FA templates
│   │   ├── login.html
│   │   ├── success.html
│   │   └── verify.html
│   ├── totp_2fa/              # TOTP 2FA templates
│       ├── login_totp.html
│       ├── success.html
│       └── verify_totp.html
├── requirements.txt           # Python dependencies
```

---

## Prerequisites

1. **Python**: Ensure Python 3.7+ is installed.
2. **Dependencies**: Install the required Python packages listed in `requirements.txt`:
   ```bash
   pip install -r requirements.txt
   ```
3. **Environment Variables**: Configure the `.env` file with the following:
   - Email server credentials for Flask-Mail:
     ```
     MAIL_SERVER=smtp.gmail.com
     MAIL_PORT=587
     MAIL_USE_TLS=True
     MAIL_USERNAME=your_email@gmail.com
     MAIL_PASSWORD=your_email_password
     ```
   - Twilio credentials for SMS-based 2FA:
     ```
     TWILIO_ACCOUNT_SID=your_twilio_account_sid
     TWILIO_AUTH_TOKEN=your_twilio_auth_token
     VERIFY_SERVICE_SID=your_twilio_verify_service_sid
     ```

---

## How to Run

1. Clone the repository and navigate to the project directory:
   ```bash
   git clone <repository_url>
   cd <project_directory>
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up the `.env` file with your email and Twilio credentials.

4. Run the Flask application:
   ```bash
   python app.py
   ```

5. Open your browser and navigate to `http://localhost:5000`.

---

## Demo Credentials

Use the following credentials to test the application:

| 2FA Type       | Username/Email       | Password   |
|----------------|----------------------|------------|
| Email-Based    | `test@mail.com`      | `emailpass`|
| SMS-Based      | `smsuser`            | `smspass`  |
| TOTP-Based     | `totpuser`           | `totppass` |

---

## Notes

- **Email-Based 2FA**: Ensure the email credentials in `.env` are valid. Use an app-specific password if using Gmail.
- **SMS-Based 2FA**: Requires a valid Twilio account and a phone number in E.164 format.
- **TOTP-Based 2FA**: Use an authenticator app to scan the QR code and generate the 6-digit code.

---

## License

This project is for educational purposes and is not intended for production use. Modify and use at your own risk.

---

## Acknowledgments

- Flask documentation: [https://flask.palletsprojects.com/](https://flask.palletsprojects.com/)
- Twilio API: [https://www.twilio.com/docs/verify](https://www.twilio.com/docs/verify)
- PyOTP library: [https://pyauth.github.io/pyotp/](https://pyauth.github.io/pyotp/)