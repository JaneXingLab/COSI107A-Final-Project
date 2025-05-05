from flask import Flask, render_template, request, redirect, session, url_for
import pyotp
import qrcode
import io
import base64

app = Flask(__name__)
app.secret_key = 'super-secret-key'

# 模拟数据库
USER_DB = {
    'user1': {
        'password': '123456',
        'totp_secret': pyotp.random_base32()
    }
}

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = USER_DB.get(username)
        if user and user['password'] == password:
            session['pre_2fa_user'] = username
            return redirect('/verify')
        # Pass error message to the template
        return render_template('index.html', error='Invalid username or password.')
    return render_template('index.html')

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if 'pre_2fa_user' not in session:
        return redirect('/')

    username = session['pre_2fa_user']
    secret = USER_DB[username]['totp_secret']
    totp = pyotp.TOTP(secret)

    if request.method == 'POST':
        otp = request.form['otp']
        if totp.verify(otp):
            session['username'] = username
            session.pop('pre_2fa_user')
            return render_template('success.html', username=username)
        return render_template('verify.html', qr_code=generate_qr_code(secret), error='Invalid OTP. Please try again.')

    return render_template('verify.html', qr_code=generate_qr_code(secret))

def generate_qr_code(secret):
    """Generate a base64-encoded QR code for the TOTP secret."""
    uri = pyotp.TOTP(secret).provisioning_uri(name=session['pre_2fa_user'], issuer_name="FlaskApp")
    qr_img = qrcode.make(uri)
    buf = io.BytesIO()
    qr_img.save(buf, format='PNG')
    return base64.b64encode(buf.getvalue()).decode()

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
