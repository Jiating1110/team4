import os

import pathlib
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
import requests
import secrets
from flask_mail import Mail
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import jwt
import time
from datetime import date, timedelta, datetime
import qrcode

import random
import stripe


from Forms import RegisterForm, LoginForm, UpdateProfileForm, VerifyPassword, VerifyEmail, ChangePassword,OTPVerifyForm
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, jsonify,send_from_directory

from flask_limiter import Limiter

from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_bcrypt import Bcrypt  # buy the blender

bcrypt = Bcrypt()  # initializing the blender

import pyotp
from cryptography.fernet import Fernet,InvalidToken
from functools import wraps
from twilio.rest import Client
from werkzeug.utils import secure_filename
import random
import pyotp
import time

import re

bbb=0
app = Flask(__name__, static_folder='static')

# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = 'your secret key'
# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
# Password below must be changed to match root password specified at server installation
# Lab computers use the root password `mysql`
app.config['MYSQL_PASSWORD'] = 'mysql'
app.config['MYSQL_DB'] = 'pythonlogin'
# DO NOTE THAT THE MYSQL SERVER INSTANCE IN THE LAB IS RUNNING ON PORT 3360.
# Please make necessary change to the above MYSQL_PORT config
app.config['MYSQL_PORT'] = 3306
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=120)
# Intialize MySQL
mysql = MySQL(app)

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
google_client_id = "494648185587-331iamoak392u2o7bl1h2ornokj4qmse.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")
flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email",
            "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)

# Configure Flask-Mail with your email settings
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Use your SMTP email server details
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = '345ting678ting@gmail.com'
app.config['MAIL_PASSWORD'] = 'niny ehgu sanf vizj'
# app.config['MAIL_USE_TLS'] = True
# app.config['MAIL_USE_SSL'] = False
mail = Mail(app)

# Stripe secret key
stripe.api_key = 'sk_test_51PZuEKCYAKRWJ1BCjBB79DUIVW2tKvR7cqCtcSb2rvJn2aN0enF4PrXZjXmrewiBJVlSKbrOwxUo6yiYVteEFy4700JG6HFGzD'
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LeaSwUqAAAAAJQ-YP7y_seOSo9YvqjdPAzxEWzy'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LeaSwUqAAAAALrtgi3HJTwYRQsrOsfbmU_LjgQF'
app.config['UPLOAD_FOLDER'] = 'secure_uploads/'
app.config['MAX_CONTENT_LENGTH'] = 800*1024
extensions_allowed = {'pdf', 'jpg', 'jpeg', 'png'}

def generate_totp_key():
    return pyotp.random_base32()
def get_session_username():
    # Default to 'anonymous' if the user is not logged in
    return session.get('username', 'anonymous')
limiter=Limiter(app=app,key_func=get_session_username)

@app.errorhandler(429)
def rate_limit_error(e):
    # Render the custom 404 error page
    flash('You have reached the maximum number of allowed requests for today. Please try again tomorrow')
    return redirect(url_for('profile'))

# determine action based on sesion state
@app.before_request
def log_session():
    if 'username' in session:
        user_id = session.get('id')
        username = session.get('username')
        action = 'login' if 'loggedin' in session else 'timeout'  # Determine action based on session state
        log_session_activity(user_id, username, action)


def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'loggedin' in session:
            return f(*args, **kwargs)
        else:
            flash('You need to login first')
            return redirect(url_for('login'))
    return wrap
def super_admin():
    if 'role' in session and session['role'] == 'super_admin':
        return True
    return False


def admin_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'loggedin' in session and session.get('role') in ['admin', 'super_admin']:
            return func(*args, **kwargs)
        else:
            flash('Unauthorised Access! Only admins can access this page')
            return redirect(url_for('login'))
    return wrapper

#amd
def generate_totp_key():
    return pyotp.random_base32()
def generate_totp_token(secret):
    totp_key = pyotp.TOTP(secret, interval=30)
    return totp_key.now()

def verification_code(phone_number, totp_key):
    if 'loggedin' in session:
        username = session['username']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT phone_number FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()

        if account:
            otp = generate_totp_token(totp_key)
            print(otp)
            session['otp'] = otp

            # account_sid = 'AC7a1d687ad3fe859ad6636ed450197fea'
            # auth_token = 'e617c93c6aded91e0c11de0b3e5c228c'
            account_sid = 'AC7a1d687ad3fe859ad6636ed450197fea'
            auth_token = 'bd86cda8a775c285c234321129722b5e'
            client = Client(account_sid, auth_token)
            message = client.messages.create(
                    body=f'Time-Based OTP verification code: {otp} ',
                    from_='+19787552616',  # Your Twilio Singapore number
                    to=phone_number      # Recipient’s Singapore phone number
                )
            if message.status == "queued" or message.status == 'sent':
                print("Message sent successfully.")
                return otp
            else:
                print(f"Message failed with error")
                return None
        else:
            print('Error in finding phone_number')
            return None

def session_timeout_required(f):
    @wraps(f)
    def decorated_func(*args, **kwargs):
        if 'session_time' in session:
            print("Checking session timeout")
            print(int(time.time()))
            print("Session TIme:" + str(session['session_time']))
            session_time = session['session_time']
            if int(time.time()) - session_time > 120:
                return redirect(url_for('logout'))
            session['session_time'] = int(time.time())
        else:
            return redirect(url_for('logout'))
        return f(*args, **kwargs)

    return decorated_func


def save_event(title, description, date, image_url):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('INSERT INTO events (title, description, date, image_url) VALUES (%s, %s, %s, %s)',
                   (title, description, date, image_url))
    mysql.connection.commit()
    cursor.close()


def load_events():
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM events')
    events = cursor.fetchall()
    cursor.close()
    return events


def generate_random_password(length=12):
    """Generate a random password with the specified length."""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+="
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password


@app.route("/google")
def google_login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@app.route("/callback")
def callback():
    try:
        flow.fetch_token(authorization_response=request.url)
    except:
        print("Access denied error")
        flash("Failed to login with Google")
        return redirect(url_for('login'))

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=google_client_id
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    session['email'] = id_info.get("email")
    print('google try', session["google_id"], session["name"], session['email'])

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    # cursor.execute('SELECT google_id FROM accounts ')
    cursor.execute('SELECT * FROM accounts WHERE google_id = %s', (session['google_id'],))
    account = cursor.fetchone()

    if account is None:
        # no account in database
        role = 'customer'
        username = session['name']
        pwd_type = 'random'
        password = generate_random_password()
        hashpwd = bcrypt.generate_password_hash(password)
        email = session['email']
        google_id = session['google_id']
        last_pwd_change = date.today()
        totp_key=generate_totp_token
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute(
            'INSERT INTO accounts (role, username, pwd_type, password, last_pwd_change, email,phone_number, google_id, is_verified, verification_token, totp_key) '
            'VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
            (role, username, pwd_type, hashpwd, last_pwd_change, email, '+6586751352', google_id, True, None,
             totp_key)
        )

        # cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        # cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s,%s, %s, %s,%s, %s)',
        #                (role, username, pwd_type, hashpwd, last_pwd_change, email, google_id,))
        mysql.connection.commit()
        print('google create acc,successfully')

        session['loggedin'] = True
        session['id'] = cursor.lastrowid
        session['username'] = session['name']
        session['role'] = 'customer'
        session['session_time'] = int(time.time())
    else:
        # if database have account

        session['loggedin'] = True
        session['id'] = account['id']
        session['username'] = account['username']
        session['role'] = 'customer'
        session['session_time'] = int(time.time())

    return redirect(url_for('home'))


def log_session_activity(user_id, username, action):
    with mysql.connection.cursor() as cursor:
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        cursor.execute('INSERT INTO session_logs (user_id, username, action, timestamp) VALUES (%s, %s, %s, %s)',
                       (user_id, username, action, timestamp))
        mysql.connection.commit()


@app.route('/extend_session', methods=['POST'])
def extend_session():
    session.permanent = True
    return '', 200

MAX_ATTEMPTS = 2

@app.route('/', methods=['GET', 'POST'])
def login():
    msg = ''
    login_form=LoginForm(request.form)
    if request.method == 'POST' and login_form.validate():
        username = login_form.username.data
        password = login_form.password.data
        totp_code = login_form.totp_code.data
        user_ip = request.remote_addr

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)


        cursor.execute('SELECT COUNT(*) as ip_count FROM failed_login_attempts WHERE ip_addr = %s', (user_ip,))
        result = cursor.fetchone()
        ip_count = result['ip_count']

        if ip_count > 2:
            print('block')
            flash('Your IP address has been blocked due to unusual activity. Please contact support for assistance.')
            cursor.close()
            return render_template('login.html', msg=msg, form=login_form)

        #check the fail attempts
        cursor.execute('SELECT * FROM failed_login_attempts WHERE ip_addr = %s and username=%s', (user_ip,username,))
        record = cursor.fetchone()
        if record:
            print('got record')
            attempts = record['attempts']
            block_time = record['block_time']
            block_num = record['block_num']
            last_attempt = record['attempt_time']
            time_elapsed = (datetime.now() - last_attempt).total_seconds()

            # Check if the IP is currently blocked
            if attempts > MAX_ATTEMPTS:
                if time_elapsed < block_time:
                    remaining_time = block_time - time_elapsed
                    flash(f'Too many failed attempts. Please try again after {int(remaining_time)} seconds.')
                    cursor.close()
                    return render_template('login.html', msg=msg, form=login_form)
                else:
                    attempts=0
                    cursor.execute(
                        'UPDATE failed_login_attempts SET attempt_time = NULL, attempts = %s, block_time = %s, block_num = %s WHERE ip_addr = %s and username=%s',
                        (attempts, block_time, block_num, user_ip,username))

        cursor.execute('SELECT * FROM accounts WHERE username = %s or email=%s', (username,username))
        # Fetch one record and return result
        account = cursor.fetchone() #if account dont exist in db, return 0

        if account:
            user_hashpwd = account['password']
            if bcrypt.check_password_hash(user_hashpwd, password):
                if account.get('totp_secret'):
                    if not totp_code:
                        flash('TOTP code is required.')
                        return redirect(url_for('login'))

                    otp = pyotp.TOTP(account['totp_secret'])
                    if not otp.verify(totp_code):
                        flash('Invalid TOTP code.')
                        return redirect(url_for('login'))
                if not account['is_verified']:
                    flash('Please verify your email address before logging in.', 'warning')
                    return redirect(url_for('login'))

                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']
                session['role'] = account['role']
                session['session_time'] = int(time.time())
                #
                # encrypted_email = account['email'].encode()
                # key_file_name = f"{username}_symmetric.key"
                # if not os.path.exists(key_file_name):
                #     return "Symmetric key file not found."
                #
                # # Open and read the symmetric key file
                # file = open(key_file_name, 'rb')
                # key = file.read()
                # file.close()
                # # Load he Symmetric key
                # f = Fernet(key)
                #
                # # Decrypt the Encrypted Email address
                # decrypted_email = f.decrypt(encrypted_email)
                # email = decrypted_email.decode()


                last_pwd_change=account['last_pwd_change']
                date_difference=date.today()-last_pwd_change
                print('login check date difference',date_difference)

                if date_difference >= timedelta(days=3):
                    flash('Your password is older than 3 days. Please change your password.')
                    return redirect(url_for('change_password'))

                else:
                    if account['role']=='admin' or account['role']=='super_admin':
                        cursor.execute('DELETE FROM failed_login_attempts WHERE ip_addr = %s and username=%s', (user_ip,username,))
                        mysql.connection.commit()
                        # return redirect(url_for('admin_home'))
                        return redirect(url_for('verify_phone_otp'))

                    else:
                        flash('You successfully log in ')
                        cursor.execute('DELETE FROM failed_login_attempts WHERE ip_addr = %s and username=%s', (user_ip,username,))
                        mysql.connection.commit()
                        # return redirect(url_for('home'))
                        return redirect(url_for('verify_phone_otp'))

            else:
                msg = 'Incorrect username/password!'
                print('fail')

                attempt_time = datetime.now()
                if record:
                    attempts = record['attempts'] + 1
                    block_time = record['block_time']
                    block_num = record['block_num']
                    if attempts>MAX_ATTEMPTS:
                        attempts=0
                        block_num=record['block_num']+1
                        if block_num>1:
                            block_time=record['block_time']*2
                        else:
                            block_time = record['block_time']
                        last_attempt=record['attempt_time']
                        time_elapsed = (datetime.now() - last_attempt).total_seconds()
                        print('block time:', block_time)
                        cursor.execute('UPDATE failed_login_attempts SET attempt_time = %s, attempts = %s, block_time = %s, block_num = %s WHERE ip_addr = %s and username=%s',
                            (attempt_time, attempts, block_time, block_num, user_ip,username))
                        if time_elapsed < block_time:
                            remaining_time = block_time - time_elapsed
                            flash(f'Too many failed attempts. Please try again after {int(remaining_time)} seconds.')
                            return render_template('login.html', msg=msg, form=login_form)

                    cursor.execute(
                        'UPDATE failed_login_attempts SET attempt_time = %s, attempts = %s, block_time = %s, block_num = %s WHERE ip_addr = %s and username=%s',
                        (attempt_time, attempts, block_time, block_num, user_ip,username))
                else:
                    block_time = 30
                    block_num = 0
                    attempts = 1
                    cursor.execute(
                        'INSERT INTO failed_login_attempts (ip_addr, username,attempt_time, attempts, block_time, block_num) VALUES (%s,%s, %s, %s, %s, %s)',
                        (user_ip,username,attempt_time, attempts, block_time, block_num))
                mysql.connection.commit()
                cursor.close()

        else:
            msg = 'Incorrect username/password!'

    return render_template('login.html', msg=msg, form=login_form)




@app.route('/qr_code')
def qr_code():
    return render_template('totp.html')


def generate_qr_code(provisioning_uri):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    img.show()
    return img


def save_qr_code_image(img, qr_file_path):
    try:
        os.makedirs(os.path.dirname(qr_file_path), exist_ok=True)
        img.save(qr_file_path)
        print(f"QR Code saved at: {qr_file_path}")  # Debugging line
    except Exception as e:
        print(f"Error saving QR code image: {e}")


@app.route('/setup_totp', methods=['GET', 'POST'])
def setup_totp():
    if request.method == 'POST':
        username = request.form.get('username')  # Retrieve username from sql

        if username:
            user = get_user_by_username(username)

            if user:
                if user.get('totp_secret'):
                    flash('TOTP is already enabled.')
                    return redirect(url_for('profile'))

                totp = pyotp.TOTP(pyotp.random_base32())
                secret = totp.secret
                user['totp_secret'] = secret

                # Save the secret to the database
                cursor = mysql.connection.cursor()
                cursor.execute('UPDATE accounts SET totp_secret = %s WHERE username = %s', (secret, username))
                mysql.connection.commit()

                # Generate QR code URL
                provisioning_uri = totp.provisioning_uri(name='iqah', issuer_name="Google")
                print(f"Provisioning URI: {provisioning_uri}")
                qr_code_img = generate_qr_code(provisioning_uri)
                qr_file_path = 'static/qr_code.png'
                save_qr_code_image(qr_code_img, qr_file_path)

                return render_template('totp.html', totp_secret=secret)

            flash('User not found.')
            return redirect(url_for('profile'))

    # Handle GET request
    return render_template('totp.html')


@app.route('/verify_totp', methods=['POST'])
def verify_totp():
    username = request.form['iqah']
    user_input_code = request.form['totp_code']

    user = get_user_by_username(username)

    if user:
        secret = user.get('totp_secret')
        if secret:
            totp = pyotp.TOTP(secret)
            print(f"Secret: {secret}")  # Debugging line
            print(f"User Input Code: {user_input_code}")  # Debugging line
            print(f"Current OTP: {totp.now()}")  # Debugging line
            if totp.verify(user_input_code):
                flash('TOTP code verified successfully.')
                return redirect(url_for('profile'))
            else:
                flash('Invalid TOTP code.')
        else:
            flash('TOTP secret not found for the user.')
    else:
        flash('User not found.')

    return redirect(url_for('setup_totp'))


def simulate_totp_for_time_intervals(secret, intervals, time_step=30):
    otp = pyotp.TOTP(secret)
    current_time = time.time()  # Current time in seconds
    codes = []
    for interval in intervals:
        # Calculate time offset from current time
        timestamp = current_time - (interval * time_step)
        # Generate OTP for that specific time
        otp_code = otp.at(timestamp)
        codes.append((timestamp, otp_code))
    return codes


def get_user_by_username(username):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
    user = cursor.fetchone()
    return user

@app.route('/logout')
@login_required
def logout():
    if 'loggedin' in session:
        user_id = session['id']
        username = session['username']
        role = session['role']
        if role == 'admin' or role == 'super_admin':
            log_session_activity(user_id, username, 'admin_logout')
        else:
            log_session_activity(user_id, username, 'customer_logout')
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    session.clear()

    return redirect(url_for('login'))


@app.route('/webapp/register', methods=['GET', 'POST'])
def register():
    msg = ''
    mssg = ''
    register_form = RegisterForm(request.form)
    otp_sent = False

    if request.method == 'POST':
        if 'send_otp' in request.form:  # If OTP send button is clicked
            email = register_form.email.data
            otp = str(random.randint(100000, 999999))  # Generate a random OTP

            # Send OTP email
            try:
                msg = msg('Your OTP Code', recipients=[email])
                msg.body = f'Your OTP code is {otp}. It will expire in 30 seconds.'
                mail.send(msg)
                flash('OTP has been sent to your email address.')
                otp_sent = True
                session['otp'] = otp  # Store the OTP in the session for verification
            except Exception as e:
                flash(f'Failed to send OTP. Error: {str(e)}')
                return render_template('register.html', msg=msg, form=register_form, otp_sent=otp_sent)

        elif 'register' in request.form and register_form.validate():
            otp_verified = request.form.get('otp_verified') == 'true'
            captcha_verified = request.form.get('verify') == 'true'

            if otp_verified:
                username = register_form.username.data
                password = register_form.password.data
                email = register_form.email.data

                role = 'customer'
                pwd_type = 'user'
                google_id = 'Null'
                last_pwd_change = date.today()

                # Hash the user's password
                hashpwd = bcrypt.generate_password_hash(password).decode('utf-8')

                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
                account = cursor.fetchone()

                #check duplicate acc name
                if account:
                    if account['username'] == username:
                        flash('Username has been taken. Please choose a different username')
                        return render_template('register.html', msg=msg, form=register_form, otp_sent=otp_sent)

                #check captcha
                if not captcha_verified:
                    mssg = ''
                #
                # key = Fernet.generate_key()
                # # Write Symmetric key to file – wb:write and close file
                # key_file_name = f"{username}_symmetric.key"
                # with open(key_file_name, "wb") as fo:
                #     fo.write(key)
                # # Initialize Fernet Class
                # f = Fernet(key)
                #
                # # convert email address to bytes before saving to Database
                # email = email.encode()
                # # Encrypt email address
                # encrypted_email = f.encrypt(email)
                totp_key = generate_totp_key()

                #store pwd

                user_file = f"{username}_pwd"
                try:
                    with open(user_file, 'w') as file:
                        file.write(f"{hashpwd}\n")
                    print(f"Hashed password successfully written to {user_file}")
                except Exception as e:
                    print(f"Error writing hashed password to file: {e}")

                # Insert the new account into the accounts table, including the TOTP secret
                cursor.execute(
                    'INSERT INTO accounts (role, username, pwd_type, password, last_pwd_change, email,phone_number, google_id, is_verified, verification_token, totp_key) '
                    'VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)',
                    (role, username, pwd_type, hashpwd, last_pwd_change,email,'+6586751352', google_id, True, None,totp_key)
                )

                mysql.connection.commit()
                msg = 'You have successfully registered!'
            else:
                flash('Please verify your OTP before registering.')
                # return render_template('register.html', msg=msg, form=register_form, otp_sent=otp_sent)

    return render_template('register.html', msg=msg, form=register_form, otp_sent=otp_sent)





@app.route('/webapp/admin/register', methods=['GET', 'POST'])
@admin_required
@login_required
def admin_register():
    if 'loggedin' in session:

        if not super_admin() == True:
            flash('Unauthorised Access! Only super admins can create admin accounts')
            return redirect(url_for('admin_home'))


        msg = ''
        register_form = RegisterForm(request.form)
        if request.method == 'POST' and register_form.validate():
            username = register_form.username.data
            password = register_form.password.data
            email = register_form.email.data
            role = 'admin'
            pwd_type = 'user'
            google_id = 'Null'
            last_pwd_change = date.today()

            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
            account = cursor.fetchone()

            if account:
                msg = 'Username has been taken. Please choose a different username'
                return render_template('admin_register.html', msg=msg, form=register_form)
            else:
                hashpwd = bcrypt.generate_password_hash(password).decode('utf-8')

                #
                # key = Fernet.generate_key()
                # # Write Symmetric key to file – wb:write and close file
                # key_file_name = f"{username}_symmetric.key"
                # with open(key_file_name, "wb") as fo:
                #     fo.write(key)
                # # Initialize Fernet Class
                # f = Fernet(key)
                #
                # # convert email address to bytes before saving to Database
                # email = email.encode()
                # # Encrypt email address
                # encrypted_email = f.encrypt(email)
                totp_key = generate_totp_key()


                # Generate TOTP secret
                secret = pyotp.random_base32()

                user_file = f"{username}_pwd"
                try:
                    with open(user_file, 'w') as file:
                        file.write("{}\n".format(hashpwd))
                    print(f"Hashed password successfully written to {user_file}")
                except Exception as e:
                    print(f"Error writing hashed password to file: {e}")

                # Insert user into database
                cursor.execute(
                    'INSERT INTO accounts (role, username, pwd_type, password, last_pwd_change,email,phone_number, google_id, is_verified, verification_token,totp_secret, totp_key) VALUES (%s, %s,%s, %s, %s, %s, %s, %s, %s, %s,%s)',
                    (role, username, pwd_type, hashpwd, last_pwd_change, '+6586751352', email, google_id, True,None, totp_key,secret))
                mysql.connection.commit()

                msg = 'You have successfully registered!'
                return render_template('admin_home.html', msg=msg, username=session['username'])
        elif request.method == 'POST':
            msg = 'Please fill out the form!'
        return render_template('admin_register.html', msg=msg, form=register_form)
    return redirect(url_for('login'))

@app.route('/verify_phone_otp', methods=['GET','POST'])
@login_required
def verify_phone_otp():
    msg = ''
    if 'loggedin' not in session:
          return redirect(url_for('login'))
    if 'verify' == False:
         print("CAPTCHA verification is required")
         return redirect(url_for('login'))
    otp_form = OTPVerifyForm(request.form)
    if request.method == 'POST':
        if request.form['resend_otp']:
            resend_otp()
        if request.form['confirm_phone_otp']:
            confirm_phone_otp()
    session['otp_verified'] = False
    username = session['username']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT phone_number, totp_key FROM accounts WHERE username = %s', (username,))
    account = cursor.fetchone()

    if account:
          phone_number = account['phone_number']
          totp_key = account['totp_key']
          if totp_key:
              otp = verification_code(phone_number, totp_key)
              if otp:
                  session['phone_number'] = phone_number
                  session['otp'] = otp
                  session['otp_timestamp'] = time.time()
              else:
                print('Error in sending OTP')
    else:
          print('Error in finding phone_number')
    return render_template('verifyOTP.html', msg=msg, form=otp_form)

@app.route('/confirm_phone_otp', methods=['GET','POST'])
@login_required
def confirm_phone_otp():
    otp_form = OTPVerifyForm(request.form)
    entered_otp = request.form['otp']
    print(session['otp'])
    otp_time = session['otp_timestamp']
    current_time = time.time()

    username = session['username']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT totp_key FROM accounts WHERE username = %s', (username,))
    account = cursor.fetchone()
    if account:
        totp_key = account['totp_key']
        if totp_key:
            otp_expired = current_time-otp_time > pyotp.TOTP(totp_key).interval
            if entered_otp == session['otp']:
                if not otp_expired:
                    session['otp_verified'] = True
                    if session['role'] == 'admin' or session['role'] == 'super_admin':
                        msg = 'Success!'
                        return redirect(url_for('admin_home', msg=msg))
                    else:
                        msg = 'You have successfully logged in'
                        return redirect(url_for('home', msg=msg))
                else:
                    msg = 'OTP has expired.\n Please request a new OTP and try again'
            else:
                msg = 'Incorrect. Please try again'
        else:
            msg = 'Error in finding TOTP Secret Key'
    else:
        msg = 'Error in finding phone number'
    return render_template('verifyOTP.html', msg=msg, form=otp_form)
@app.route('/resend_otp', methods=['GET','POST'])
@login_required
def resend_otp():
    otp_form = OTPVerifyForm(request.form)
    username = session['username']
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT phone_number, totp_key FROM accounts WHERE username = %s', (username,))
    account = cursor.fetchone()
    if account:
        phone_number = account['phone_number']
        totp_key = account['totp_key']
        otp = verification_code(phone_number, totp_key)
        if otp:
            session['phone_number'] = phone_number
            session['otp'] = otp
            session['otp_timestamp'] = time.time()
            msg = 'OTP has been resent. Please try again'
        else:
            msg = 'Error in sending OTP'
    else:
        msg= 'Error in finding phone_number'
    return render_template('verifyOTP.html', msg=msg, form=otp_form)

@app.route('/webapp/home')
@login_required
@session_timeout_required
def home():
    if 'loggedin' in session:
        print(session['session_time'])
        return render_template('home.html', username=session['username'])
    return redirect(url_for('login'))


@app.route('/webapp/admin/home')
@admin_required
@login_required
@session_timeout_required
def admin_home():
    if 'loggedin' in session:
        return render_template('admin_home.html', username=session['username'])
    return redirect(url_for('login'))


# User Profile Route
@app.route('/webapp/profile', methods=['GET', 'POST'])
# @app.route('/profile', methods=['GET', 'POST'])
@login_required
@session_timeout_required
def profile():
    if 'username' in session:
        username = session['username']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()
        email = account['email']

        # # encrypted_email = account['email'].encode()
        # # username = account['username']
        # # key_file_name = f"{username}_symmetric.key"
        # #
        # # if not os.path.exists(key_file_name):
        # #     return "Symmetric key file not found."
        # # with open(key_file_name, 'rb') as key_file:
        # #     key = key_file.read()
        # #
        # # f = Fernet(key)
        # # decrypted_email = f.decrypt(encrypted_email)
        # # email = decrypted_email.decode()
        #
        # Mask the email address
        email_parts = email.split('@')
        masked_email = f"{email_parts[0][0]}***{email_parts[0][-1]}@{email_parts[1]}"

        account['email'] = masked_email

        return render_template('profile.html', account=account)
    else:
        flash('You need to log in first.')
        return redirect(url_for('login'))


# Admin Profile Route
@app.route('/webapp/admin/profile', methods=['GET', 'POST'])
@admin_required
@login_required
@session_timeout_required
def admin_profile():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        email=account['email']

        # encrypted_email = account['email'].encode()
        # username = account['username']
        # key_file_name = f"{username}_symmetric.key"
        #
        # if not os.path.exists(key_file_name):
        #     return "Symmetric key file not found."
        # with open(key_file_name, 'rb') as key_file:
        #     key = key_file.read()
        #
        # f = Fernet(key)
        # decrypted_email = f.decrypt(encrypted_email)
        # email = decrypted_email.decode()
        #
        # Mask the email address
        email_parts = email.split('@')
        masked_email = f"{email_parts[0][0]}***{email_parts[0][-1]}@{email_parts[1]}"

        account['email'] = masked_email

        return render_template('admin_profile.html', account=account)
    return redirect(url_for('login'))


# Update Profile Route
@app.route('/webapp/profile/update', methods=['GET', 'POST'])
@login_required
@session_timeout_required
def update_profile():
    if 'loggedin' in session:
        msg = ''
        update_profile_form = UpdateProfileForm(request.form)
        if request.method == 'POST' and update_profile_form.validate():
            new_username = update_profile_form.username.data
            email = update_profile_form.email.data

            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            
            cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
            account = cursor.fetchone()
            current_username=account['username']

            if new_username !=current_username:
                cursor.execute('SELECT * FROM accounts WHERE username = %s', (new_username,))
                existing_acc = cursor.fetchone()

                if existing_acc:
                    flash('This username or email is already in use. Please choose a different one')
                    return render_template('update_profile.html', msg=msg, form=update_profile_form)
            #
            #
            # old_key_file_name = f"{current_username}_symmetric.key"
            # if not os.path.exists(old_key_file_name):
            #     return "Symmetric key file not found."
            #
            # new_key_file_name = f"{new_username}_symmetric.key"
            # try:
            #     os.rename(old_key_file_name, new_key_file_name)
            # except Exception as e:
            #     flash('Error renaming key file')
            #     return redirect(url_for('update_profile'))
            #
            #     # Open and read the symmetric key file
            #     with open(new_key_file_name, 'rb') as key_file:
            #         key = key_file.read()
            #     f = Fernet(key)
            #     # convert email address to bytes before saving to Database
            #     email = email.encode()
            #     # Encrypt email address
            #     encrypted_email = f.encrypt(email)




            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('UPDATE accounts SET username = %s,email=%s WHERE id = %s',
                           (new_username, email, session['id']))

            mysql.connection.commit()

            msg = 'You have successfully updated your profile!'
            if session.get('role') in ['admin', 'super_admin']:
                return redirect(url_for('admin_profile'))
            else:
                return redirect(url_for('profile'))
        else:
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
            account = cursor.fetchone()
            #
            # encrypted_email = account['email'].encode()
            # username = account['username']
            # key_file_name = f"{username}_symmetric.key"
            #
            # if not os.path.exists(key_file_name):
            #     return "Symmetric key file not found."
            #
            # # Open and read the symmetric key file
            # with open(key_file_name, 'rb') as key_file:
            #     key = key_file.read()
            #
            # f = Fernet(key)
            # decrypted_email = f.decrypt(encrypted_email)
            # # account['email'] = decrypted_email.decode()
            # email = decrypted_email.decode()

            update_profile_form.username.data = account['username']
            update_profile_form.email.data = account['email']
            return render_template('update_profile.html', msg=msg, form=update_profile_form, account=account)
    return redirect(url_for('login'))


def get_reset_token(user, expires=200):
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT username FROM accounts WHERE email = %s', (user,))
        account = cursor.fetchone()
        username = account['username']
        if not account:
            return None
        token = jwt.encode({'reset_password': username, 'exp': time.time() + expires}, key=app.secret_key,
                           algorithm='HS256')
        return token
    except Exception as e:
        print(f"Error: {e}")
        return None


def verify_reset_token(token):
    try:
        decoded_token = jwt.decode(token, key=app.secret_key, algorithms=['HS256'])
        username = decoded_token.get('reset_password')
        if not username:
            return None
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
        account = cursor.fetchone()
        if not account:
            return None

        return account
    except jwt.ExpiredSignatureError:
        return None  # Token has expired
    except jwt.InvalidTokenError:
        return None  # Invalid token
    except Exception as e:
        print(f"Error: {e}")
        return None


def send_mail(user):
    msg = MIMEMultipart()
    msg['From'] = os.getenv('345ting678ting@gmail.com')
    msg['To'] = user
    msg['Subject'] = 'Change Password'
    token = get_reset_token(user)
    reset_url = url_for('reset_password', token=token, _external=True)
    body = f"""To change your password, please follow the link below:
    {reset_url}

    If you didn't send a password reset request, please ignore this message."""
    msg.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
    server.starttls()
    server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
    server.sendmail(app.config['MAIL_USERNAME'], msg['To'], msg.as_string())
    server.quit()

    print('Email sent successfully.')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = verify_reset_token(token)
    print(user['pwd_type'])
    print('token', user)
    if user is None:
        flash('The reset link is invalid or has expired.', 'warning')
        return redirect(url_for('reset_password_request'))
    pwd_form = ChangePassword(request.form)
    email = user['email']
    if request.method == 'POST' and pwd_form.validate():
        newpwd = pwd_form.newpwd.data
        confirm_password = pwd_form.confirmpwd.data

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE pwd_type = %s', (user['pwd_type'],))
        account = cursor.fetchone()
        username = account['username']
        if newpwd == confirm_password:
            hashpwd = bcrypt.generate_password_hash(confirm_password).decode('utf-8')

            user_file = f"{username}_pwd"
            try:
                file = open(user_file, 'w')
                file.write("{}\n".format(hashpwd))
                print(f"Hashed password successfully written to {user_file}")
            except Exception as e:
                print(f"Error writing hashed password to file: {e}")

            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE pwd_type = %s', (user['pwd_type'],))
            account = cursor.fetchone()
            if account['pwd_type'] == 'random':
                pwd_type = 'user'
                cursor.execute('UPDATE accounts SET password = %s, pwd_type=%s  WHERE username = %s',
                               (hashpwd, pwd_type, user['username']))
                mysql.connection.commit()
                print('You have successfully update!')
                return render_template('reset_pwd_successfully.html', email=email)
            else:
                cursor.execute('UPDATE accounts SET password = %s WHERE username = %s', (hashpwd, user['username']))
                mysql.connection.commit()
                print('You have successfully update!')
                return render_template('reset_pwd_successfully.html', email=email)
        else:
            msg = 'Password didnt match.Pls try again'
    return render_template('change_pwd.html', form=pwd_form)


@app.route('/webapp/reset_request',methods=['GET','POST'])
def reset_request():
    msg=''
    verify_form=VerifyEmail(request.form)
    if request.method=='POST' and verify_form.validate():
        email=verify_form.email.data
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE email = %s', (email,))
        account = cursor.fetchone()
        if account:
            database_email = account['email']
            if email==database_email:
                send_mail(email)
                return render_template('reset_pwd.html',email=email)
        else:
            msg='Incorrect email'
    return render_template('verify_email.html',form=verify_form,msg=msg)


@app.route('/webapp/verify_type', methods=['GET', 'POST'])
@login_required
@limiter.limit('2 per day')
def verify_type():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        return render_template('verify_type.html')
    return redirect(url_for('login'))


@app.route('/webapp/verify/password', methods=['GET', 'POST'])
@login_required
def verify_password():
    msg = ''
    if 'loggedin' in session:
        verify_form = VerifyPassword(request.form)
        if request.method == 'POST' and verify_form.validate():
            pwd = verify_form.pwd.data

            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
            account = cursor.fetchone()
            user_hashpwd = account['password']
            print('verify pwd', user_hashpwd)

            if account and bcrypt.check_password_hash(user_hashpwd, pwd):
                return redirect(url_for('change_password'))
            else:
                msg = 'Incorrect password'
        return render_template('verify_pwd.html', form=verify_form, msg=msg)
    return redirect(url_for('login'))


def send_confirm_mail(email, username):
    msg = MIMEMultipart()
    msg['From'] = os.getenv('345ting678ting@gmail.com')
    msg['To'] = email
    msg['Subject'] = 'Your password has been changed'
    formatted_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    body = f"""Hi {username},
    Your password was recently changed on {formatted_time}.

    If you did not initiate this request, please contact our Customer Service Team immediately here

    Cheers,
    xx Team"""
    msg.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
    server.starttls()
    server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
    server.sendmail(app.config['MAIL_USERNAME'], msg['To'], msg.as_string())
    server.quit()

    print('Email sent successfully.')


@app.route('/webapp/profile/change_passowrd', methods=['GET', 'POST'])
@login_required
@session_timeout_required
def change_password():
    if 'loggedin' in session:
        print('hhh')
        msg = ' '
        pwd_form = ChangePassword(request.form)
        if request.method == 'POST' and pwd_form.validate():
            newpwd = pwd_form.newpwd.data
            confirm_password = pwd_form.confirmpwd.data

            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
            account = cursor.fetchone()

            username = account['username']
            role = account['role']




            if newpwd == confirm_password:
                hashpwd = bcrypt.generate_password_hash(confirm_password).decode('utf-8')

                user_file = f"{username}_pwd"
                # check pwd history
                try:
                    file = open(user_file, 'r+')
                    pwd_history = file.readlines()
                    pwd_history = [pwd.strip() for pwd in pwd_history]

                    for old_pwd in pwd_history:
                        if bcrypt.check_password_hash(old_pwd, newpwd):
                            flash('New password cannot be one of the previosly used passwords')
                            return redirect(url_for('change_password'))
                    if len(pwd_history) >= 3:
                        pwd_history = pwd_history[1:]
                    pwd_history.append(hashpwd)
                    print('change pwd line', pwd_history)

                    file.seek(0)
                    file.truncate()  # Clear existing content
                    file.writelines(pwd + '\n' for pwd in pwd_history)
                except FileNotFoundError:
                    file = open(user_file, 'w')
                    file.write("{}\n".format(hashpwd))

                last_pwd_change = date.today()
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('UPDATE accounts SET password = %s,last_pwd_change= %s WHERE id = %s',
                               (hashpwd, last_pwd_change, session['id']))
                mysql.connection.commit()
                msg = 'You have successfully update!'

                encrypted_email = account['email'].encode()
                key_file_name = f"{username}_symmetric.key"
                if not os.path.exists(key_file_name):
                    return "Symmetric key file not found."

                # Open and read the symmetric key file
                file = open(key_file_name, 'rb')
                key = file.read()
                file.close()
                # Load he Symmetric key
                f = Fernet(key)

                # Decrypt the Encrypted Email address
                decrypted_email = f.decrypt(encrypted_email)
                email = decrypted_email.decode()

                send_confirm_mail(email, username)
                return render_template('change_pwd_successfully.html', username=username, role=role)


            else:
                msg = 'Password didnt match.Pls try again'
        return render_template('change_pwd.html', form=pwd_form, msg=msg)
    return redirect(url_for('login'))


@app.route('/webapp/admin/retrieve_users')
@admin_required
@login_required
@session_timeout_required
def retrieve_users():
    if 'loggedin' in session:
        # We need all the account info for the user so we can display it on the profile page
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT COUNT(*) AS users_count FROM accounts')
        count = cursor.fetchone()
        users_count = count['users_count']
        # cursor.execute('SELECT * FROM accounts')
        # users_info = cursor.fetchall()
        cursor.execute('SELECT username, role, email, phone_number FROM accounts')
        users_info = cursor.fetchall()
        for user in users_info:
            username=user['username']
            email=user['email']



        #
        # for user in users_info:
        #     encrypted_email = user['email'].encode()
        #     username = user['username']
        #     key_file_name = f"{username}_symmetric.key"
        #
        #     if not os.path.exists(key_file_name):
        #         return f"Symmetric key file not found for user {username}."
        #
        #     with open(key_file_name, 'rb') as key_file:
        #         key = key_file.read()
        #
        #     f = Fernet(key)
        #     decrypted_email = f.decrypt(encrypted_email)
        #     email = decrypted_email.decode()

            email_parts = email.split('@')
            masked_email = f"{email_parts[0][0]}***{email_parts[0][-1]}@{email_parts[1]}"

            user['email'] = masked_email

            phone_number = user['phone_number']
            masked_phone_no = f"{phone_number[3]}******{phone_number[-2:]}"

            user['phone_number'] = masked_phone_no


        # Show the profile page with account info
        return render_template('admin_retrieve_users.html', users_count=users_count, users_info=users_info)
        # User is not loggedin redirect to login page
    return redirect(url_for('login'))


@app.route('/webapp/admin/event')
@admin_required
@login_required
@session_timeout_required
def admin_event():
    if 'loggedin' in session:
        events = load_events()
        return render_template('admin_event.html', events=events)
    return redirect(url_for('login'))

def files_allowed(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in extensions_allowed
@app.route('/uploaded_file/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.errorhandler(413)
def file_size_exceeded(e):
    flash('File size exceeds the maximum limit of 1MB','error')
    return redirect(url_for('admin_event'))
@app.route('/webapp/admin/create_event', methods=['POST', 'GET'])
@admin_required
@login_required
@session_timeout_required
def create_event():
    if 'loggedin' in session:
        title = request.form['title']
        date = request.form['date']
        description = request.form['description']
        image_url = request.form['image_url']
        file = request.files['file']

        file_url = None
        if file and files_allowed(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            file.save(file_path)
            file_url = url_for('uploaded_file', filename=filename)
        elif file and not files_allowed(file.filename):
            flash('File type not allowed', 'error')
            return redirect(url_for('admin_event'))
        else:
            file_url = image_url

        save_event(title, description, date, file_url)

        return redirect(url_for('admin_event'))
    else:
        return redirect(url_for('login'))


@app.route('/webapp/admin/edit_event/<int:event_id>', methods=['GET', 'POST'])
@admin_required
@login_required
@session_timeout_required
def edit_event(event_id):
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)

        if request.method == 'POST':
            title = request.form['title']
            date = request.form['date']
            description = request.form['description']
            image_url = request.form['image_url']
            cursor.execute('UPDATE events SET title = %s, date = %s, description = %s, image_url = %s WHERE id = %s',
                           (title, date, description, image_url, event_id))
            mysql.connection.commit()
            cursor.close()
            return redirect(url_for('admin_event'))

        cursor.execute('SELECT * FROM events WHERE id = %s', (event_id,))
        event = cursor.fetchone()
        cursor.close()

        return render_template('admin_edit_event.html', event=event)
    else:
        return redirect(url_for('login'))


@app.route('/webapp/admin/delete_event/<event_id>', methods=['POST', 'GET'])
@admin_required
@login_required
@session_timeout_required
def delete_event(event_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('DELETE FROM events WHERE id = %s', (event_id,))
    mysql.connection.commit()
    cursor.close()
    return redirect(url_for('admin_event'))


@app.route('/webapp/events')
@login_required
@session_timeout_required
def retrieve_events():
    if 'loggedin' in session:
        events = load_events()
        return render_template('retrieve_events.html', events=events)
    else:
        return redirect(url_for('login'))


@app.route('/webapp/admin/retrieve_orders')
@admin_required
@login_required
@session_timeout_required
def retrieve_orders():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM orders")
        orders = cursor.fetchall()
        cursor.close()
        return render_template('admin_order.html', orders=orders)
    return redirect(url_for('login'))


@app.route('/webapp/register_event', methods=['POST', 'GET'])
@login_required
def register_event():
    if 'loggedin' in session:
        if request.method == 'POST' and 'name' in request.form and 'email' in request.form and 'event' in request.form and 'payment_method' in request.form:
            name = request.form['name']
            email = request.form['email']
            event = request.form['event']
            payment_method = request.form.get('payment_method')

            if payment_method == 'credit-card':
                token = request.form['stripeToken']
                try:
                    # Create a new Stripe Customer
                    customer = stripe.Customer.create(
                        email=email,
                        source=token
                    )

                    # Charge the Customer instead of the card
                    charge = stripe.Charge.create(
                        customer=customer.id,
                        amount=5000,  # Amount in cents
                        currency='usd',
                        description='Event Registration'
                    )

                    # Get last 4 digits of the card
                    card_last4 = charge.source.last4

                    cust_id = session['id']
                    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                    cursor.execute(
                        "INSERT INTO orders (cust_id, name, email, event, payment_method, card_last4) VALUES (%s, %s, %s, %s, %s, %s)",
                        (cust_id, name, email, event, payment_method, card_last4))
                    mysql.connection.commit()

                    return render_template('event_register_successfully.html')

                except stripe.error.StripeError as e:
                    return str(e), 400

        return render_template('event_register.html')
    return redirect(url_for('login'))


@app.route('/delete/<int:order_id>', methods=['POST'])
@admin_required
@login_required
def delete(order_id):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    try:
        cursor.execute("DELETE FROM orders WHERE id = %s", [order_id])
        mysql.connection.commit()
        cursor.close()
        return redirect(url_for('retrieve_orders'))
    except Exception as e:
        return f"Error deleting order: {str(e)}"

def send_otp_email(user, otp):
    try:
        msg = MIMEMultipart()
        msg['From'] = app.config['MAIL_USERNAME']
        msg['To'] = user
        msg['Subject'] = 'Your OTP Code'

        body = f"""Your OTP code is {otp}. Please enter this code to complete the registration process."""
        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
            server.starttls()
            server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            server.sendmail(msg['From'], msg['To'], msg.as_string())

        print('OTP email sent successfully.')

    except Exception as e:
        print(f"Error sending OTP email: {e}")

@app.route('/send_otp', methods=['POST'])
def send_otp():
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({'success': False, 'message': 'Email is required'})

    otp = str(random.randint(100000, 999999))
    # Store OTP and its expiry time in session or database
    # For simplicity, using a temporary in-memory storage
    session['otp'] = otp
    session['otp_expiry'] = time.time() + 60  # OTP valid for 60 seconds

    send_otp_email(email, otp)
    return jsonify({'success': True})

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    otp = data.get('otp')
    stored_otp = session.get('otp')
    otp_expiry = session.get('otp_expiry')

    print(f"Entered OTP: {otp}")  # Debug
    print(f"Stored OTP: {stored_otp}")  # Debug

    if not otp or stored_otp != otp:
        return jsonify({'success': False, 'message': 'Invalid OTP'})

    if time.time() > otp_expiry:
        return jsonify({'success': False, 'message': 'OTP expired'})

    session.pop('otp', None)  # Remove OTP from session
    session.pop('otp_expiry', None)  # Remove OTP expiry from session
    return jsonify({'success': True})

@app.route('/confirm_email/<token>', methods=['GET'])
def confirm_email(token):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM accounts WHERE verification_token = %s', (token,))
    account = cursor.fetchone()

    if account:
        cursor.execute(
            'UPDATE accounts SET is_verified = TRUE, verification_token = NULL WHERE verification_token = %s', (token,))
        mysql.connection.commit()
        flash('Your email has been verified successfully! You can now log in.')
        return redirect(url_for('login'))
    else:
        flash('Invalid or expired verification link.')
        return redirect(url_for('register'))


if __name__ == '__main__':
    app.run(debug=True)

