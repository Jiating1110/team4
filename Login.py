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
from datetime import date,timedelta,datetime

import stripe

from Forms import RegisterForm,LoginForm,UpdateProfileForm,VerifyPassword,VerifyEmail,ChangePassword
from flask import Flask, render_template, request, redirect, url_for, session,flash,abort

from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_bcrypt import Bcrypt   #buy the blender
bcrypt = Bcrypt()   #initializing the blender

from cryptography.fernet import Fernet
from functools import wraps



import re
app = Flask(__name__)
# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = 'your secret key'
# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
# Password below must be changed to match root password specified at server installation
# Lab computers use the root password `mysql`
app.config['MYSQL_PASSWORD'] = 'mysql'
app.config['MYSQL_DB'] = 'pythonlogin'
#DO NOTE THAT THE MYSQL SERVER INSTANCE IN THE LAB IS RUNNING ON PORT 3360.
#Please make necessary change to the above MYSQL_PORT config
app.config['MYSQL_PORT'] = 3306
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=30)
# Intialize MySQL
mysql = MySQL(app)

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
google_client_id="494648185587-331iamoak392u2o7bl1h2ornokj4qmse.apps.googleusercontent.com"
client_secrets_file=os.path.join(pathlib.Path(__file__).parent,"client_secret.json")
flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
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

#determine action based on sesion state
@app.before_request
def log_session():
    if 'username' in session:
        user_id = session.get('id')
        username = session.get('username')
        action = 'login' if 'loggedin' in session else 'timeout'  # Determine action based on session state
        log_session_activity(user_id, username, action)
def login_required(f):
    @wraps(f)
    def wrap(*args,**kwargs):
        if 'loggedin' in session:
            return f(*args,**kwargs)
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

def session_timeout_required(f):
    @wraps(f)
    def decorated_func(*args, **kwargs):
        if 'session_time' in session:
            print("Checking session timeout")
            print(int(time.time()))
            print("Session TIme:" + str(session['session_time']))
            session_time = session['session_time']
            if int(time.time()) - session_time > 30:
                return redirect(url_for('logout'))
            session['session_time'] = int(time.time())
        else:
            return redirect(url_for('logout'))
        return f(*args, **kwargs)
    return decorated_func


def save_event(title, description, date, image_url):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('INSERT INTO events (title, description, date, image_url) VALUES (%s, %s, %s, %s)', (title, description, date, image_url))
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
    except :
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
    session['email']=id_info.get("email")
    print('google try',session["google_id"],session["name"],session['email'])

    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    # cursor.execute('SELECT google_id FROM accounts ')
    cursor.execute('SELECT * FROM accounts WHERE google_id = %s', (session['google_id'],))
    account = cursor.fetchone()

    if account is None:
        # no account in database
        role='customer'
        username=session['name']
        pwd_type='random'
        password=generate_random_password()
        hashpwd=bcrypt.generate_password_hash(password)
        email = session['email']
        google_id=session['google_id']
        last_pwd_change=date.today()

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s,%s, %s, %s,%s, %s)',(role, username, pwd_type,hashpwd,last_pwd_change,email,google_id,))
        mysql.connection.commit()
        print('google create acc,successfully')

        session['loggedin'] = True
        session['id'] = cursor.lastrowid
        session['username'] = session['name']
        session['role'] = 'customer'
        session['session_time'] = int(time.time())
    else:
        #if database have account

        session['loggedin']=True
        session['id']=account['id']
        session['username']=account['username']
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




@app.route('/', methods=['GET', 'POST'])
def login():
    msg = ''
    login_form=LoginForm(request.form)
    if request.method == 'POST' and login_form.validate():
        username=login_form.username.data
        password=login_form.password.data
        print(password)

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s or email=%s', (username,username))
        # Fetch one record and return result
        account = cursor.fetchone() #if account dont exist in db, return 0
        if account:
            user_hashpwd = account['password']
            if account and bcrypt.check_password_hash(user_hashpwd, password):
                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']
                session['role']=account['role']
                session['session_time'] = int(time.time())


                last_pwd_change=account['last_pwd_change']


                date_difference=date.today()-last_pwd_change
                print('login check date difference',date_difference)
                if date_difference >= timedelta(days=3):
                    flash('Your Password Already 3 days.Please change your password')
                    return redirect(url_for('change_password'))
                else:
                    if account['role']=='admin' or account['role']=='super_admin':
                        return redirect(url_for('admin_home'))
                    else:
                        flash('You successfully log in ')
                        return redirect(url_for('home'))

            else:
                msg = 'Incorrect username/password!'
        else:
            msg = 'Incorrect username/password!'

    return render_template('login.html', msg=msg,form=login_form)


@app.route('/logout')
@login_required
def logout():
    if 'loggedin' in session:
        user_id=session['id']
        username=session['username']
        role=session['role']
        if role=='admin' or role=='super_admin':
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
    register_form=RegisterForm(request.form)
    if request.method == 'POST' and register_form.validate():
        username=register_form.username.data
        password=register_form.password.data
        email=register_form.email.data
        role='customer'
        pwd_type='user'
        google_id='Null'
        last_pwd_change=date.today()
        hashpwd = bcrypt.generate_password_hash(password).decode('utf-8')

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s ', (username,))
        account=cursor.fetchone()
        if account:
            if account['username']==username:
                flash('Username has been taken. Please choose a different username')
                return render_template('register.html', msg=msg, form=register_form)

        user_file = f"{username}_pwd"
        try:
            file=open(user_file,'w')
            file.write("{}\n".format(hashpwd))
            print(f"Hashed password successfully written to {user_file}")
        except Exception as e:
            print(f"Error writing hashed password to file: {e}")

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('INSERT INTO accounts (role, username, pwd_type, password, last_pwd_change, email, google_id) VALUES (%s, %s, %s, %s, %s, %s, %s)', (role, username, pwd_type, hashpwd, last_pwd_change, email, google_id))
        mysql.connection.commit()
        msg = 'You have successfully registered!'

    return render_template('register.html', msg=msg,form=register_form)
@app.route('/webapp/admin/register', methods=['GET', 'POST'])
@admin_required
@login_required
def admin_register():
    if 'loggedin' in session:
        if not super_admin() == True:
            return 'Unauthorised Access! Only super admins can create admin accounts'

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
            # cursor.execute('SELECT * FROM accounts WHERE username = %s OR email = %s', (username, email))
            account = cursor.fetchone()

            if account:
                if account['username'] == username:
                    msg = 'Username has been taken. Please choose a different username'

                return render_template('admin_register.html', msg=msg,form=register_form)
            else:
                # Account doesnt exists and the form data is valid, now insert new account into accounts table
                hashpwd = bcrypt.generate_password_hash(password).decode('utf-8')

                user_file = f"{username}_pwd"
                try:
                    file = open(user_file, 'w')
                    file.write("{}\n".format(hashpwd))
                    print(f"Hashed password successfully written to {user_file}")
                except Exception as e:
                    print(f"Error writing hashed password to file: {e}")

                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s, %s, %s,%s, %s)',(role, username, pwd_type, hashpwd,last_pwd_change, email, google_id,))
                mysql.connection.commit()

                msg = 'You have successfully registered!'
                return render_template('admin_home.html', msg=msg,username=session['username'])
        elif request.method == 'POST': #verify if theres an input
            # Form is empty... (no POST data)
            msg = 'Please fill out the form!'
            # Show registration form with message (if any)
        return render_template('admin_register.html', msg=msg,form=register_form)
    return redirect(url_for('login'))
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


@app.route('/webapp/profile',methods=['GET','POST'])
@login_required
@session_timeout_required
def profile():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        return render_template('profile.html', account=account)
    return redirect(url_for('login'))
@app.route('/webapp/admin/profile',methods=['GET','POST'])
@admin_required
@login_required
@session_timeout_required
def admin_profile():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()

        return render_template('admin_profile.html', account=account)
    return redirect(url_for('login'))

@app.route('/webapp/profile/update',methods=['GET','POST'])
@login_required
@session_timeout_required
def update_profile():
    if 'loggedin' in session:
        msg=' '
        update_profile_form=UpdateProfileForm(request.form)
        if request.method=='POST' and update_profile_form.validate():
            new_username=update_profile_form.username.data
            email=update_profile_form.email.data

            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
            account = cursor.fetchone()


            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('UPDATE accounts SET username = %s,email=%s WHERE id = %s', (new_username,email, session['id']))
            mysql.connection.commit()

            msg='You have successfully update!'
            if account['role'] == 'admin' or account['role']=='super_admin':
                return redirect(url_for('admin_profile'))
            else:
                return redirect(url_for('profile'))
        else:
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            id = session['id']
            cursor.execute('SELECT * FROM accounts WHERE id = %s ', (id,))
            account=cursor.fetchone()
            email=account['email']

            update_profile_form.username.data=account['username']
            update_profile_form.email.data=email
            return render_template('update_profile.html',msg=msg,form=update_profile_form,account=account)
    return redirect(url_for('login'))



def get_reset_token(user,expires=200):
    try:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT username FROM accounts WHERE email = %s', (user,))
        account = cursor.fetchone()
        username=account['username']
        if not account:
            return None
        token=jwt.encode({'reset_password':username,'exp':time.time()+expires},key=app.secret_key,algorithm='HS256')
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
    token=get_reset_token(user)
    reset_url = url_for('reset_password', token=token, _external=True)
    body = f"""To change your password, please follow the link below:
    {reset_url}

    If you didn't send a password reset request, please ignore this message."""
    msg.attach(MIMEText(body, 'plain'))

    server = smtplib.SMTP(app.config['MAIL_SERVER'] ,app.config['MAIL_PORT'])
    server.starttls()
    server.login(app.config['MAIL_USERNAME'],app.config['MAIL_PASSWORD'])
    server.sendmail(app.config['MAIL_USERNAME'], msg['To'], msg.as_string())
    server.quit()

    print('Email sent successfully.')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user=verify_reset_token(token)
    print(user['pwd_type'])
    print('token',user)
    if user is None:
        flash('The reset link is invalid or has expired.', 'warning')
        return redirect(url_for('reset_password_request'))
    pwd_form=ChangePassword(request.form)
    email=user['email']
    if request.method == 'POST' and pwd_form.validate():
        newpwd = pwd_form.newpwd.data
        confirm_password = pwd_form.confirmpwd.data

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE pwd_type = %s', (user['pwd_type'],))
        account = cursor.fetchone()
        username=account['username']
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
                cursor.execute('UPDATE accounts SET password = %s, pwd_type=%s  WHERE username = %s', (hashpwd,pwd_type,user['username']))
                mysql.connection.commit()
                print( 'You have successfully update!')
                return render_template('reset_pwd_successfully.html',email=email)
            else:
                cursor.execute('UPDATE accounts SET password = %s WHERE username = %s',(hashpwd, user['username']))
                mysql.connection.commit()
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


@app.route('/webapp/verify_type',methods=['GET','POST'])
@login_required
def verify_type():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()
        return render_template('verify_type.html')
    return redirect(url_for('login'))

@app.route('/webapp/verify/password',methods=['GET','POST'])
@login_required
def verify_password():
    msg=''
    if 'loggedin' in session:
        verify_form=VerifyPassword(request.form)
        if request.method=='POST' and verify_form.validate():
            pwd=verify_form.pwd.data

            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
            account = cursor.fetchone()
            user_hashpwd=account['password']
            print('verify pwd',user_hashpwd)

            if account and bcrypt.check_password_hash(user_hashpwd,pwd):
                return redirect(url_for('change_password'))
            else:
                msg='Incorrect password'
        return render_template('verify_pwd.html',form=verify_form,msg=msg)
    return redirect(url_for('login'))

@app.route('/webapp/profile/change_passowrd',methods=['GET','POST'])
@login_required
@session_timeout_required
def change_password():
    if 'loggedin' in session:
        print('hhh')
        msg=' '
        pwd_form=ChangePassword(request.form)
        if request.method=='POST' and pwd_form.validate():
            newpwd=pwd_form.newpwd.data
            confirm_password=pwd_form.confirmpwd.data

            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
            account = cursor.fetchone()
            username=account['username']
            role=account['role']

            if newpwd==confirm_password:
                hashpwd = bcrypt.generate_password_hash(confirm_password).decode('utf-8')

                user_file = f"{username}_pwd"
                #check pwd history
                try:
                    file=open(user_file,'r+')
                    pwd_history=file.readlines()
                    pwd_history = [pwd.strip() for pwd in pwd_history]

                    for old_pwd in pwd_history:
                        if bcrypt.check_password_hash(old_pwd,newpwd):
                            flash('New password cannot be one of the previosly used passwords')
                            return redirect(url_for('change_password'))
                    if len(pwd_history)>=3:
                        pwd_history = pwd_history[1:]
                    pwd_history.append(hashpwd)
                    print('change pwd line', pwd_history)

                    file.seek(0)
                    file.truncate()  # Clear existing content
                    file.writelines(pwd + '\n' for pwd in pwd_history)
                except FileNotFoundError:
                    file = open(user_file, 'w')
                    file.write("{}\n".format(hashpwd))

                last_pwd_change=date.today()
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('UPDATE accounts SET password = %s,last_pwd_change= %s WHERE id = %s', (hashpwd,last_pwd_change,session['id']))
                mysql.connection.commit()
                msg = 'You have successfully update!'
                return render_template('change_pwd_successfully.html',username=username,role=role)

            else:
                msg='Password didnt match.Pls try again'
        return render_template('change_pwd.html',form=pwd_form,msg=msg)
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
        cursor.execute('SELECT * FROM accounts')
        users_info = cursor.fetchall()

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
        events= load_events()
        return render_template('admin_event.html', events=events)
    return redirect(url_for('login'))
@app.route('/webapp/admin/create_event', methods=['POST','GET'])
@admin_required
@login_required
@session_timeout_required
def create_event():
    if 'loggedin' in session:
        title = request.form['title']
        date = request.form['date']
        description = request.form['description']
        image_url = request.form['image_url']

        save_event(title, description, date, image_url)

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
@app.route('/webapp/admin/delete_event/<event_id>', methods=['POST','GET'])
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


        


if __name__== '__main__':
    app.run(debug=True)