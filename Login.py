import os
import pathlib
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
import requests

from Forms import RegisterForm,LoginForm,UpdateProfileForm,ChangePassword
from flask import Flask, render_template, request, redirect, url_for, session,flash,abort
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_bcrypt import Bcrypt   #buy the blender
bcrypt = Bcrypt()   #initializing the blender
import cryptography
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


@app.route("/google_login")
def google_login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)

@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

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
    return redirect('/MyWebApp/home')


@app.route('/', methods=['GET', 'POST'])
def login():
    msg = ''
    login_form=LoginForm(request.form)
    if request.method == 'POST' and login_form.validate():
        username=login_form.username.data
        password=login_form.password.data
        print(password)

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = %s ', (username,))
        # Fetch one record and return result
        account = cursor.fetchone() #if account dont exist in db, return 0
        if account:
            user_hashpwd = account['password']
            if account and bcrypt.check_password_hash(user_hashpwd, password):
                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']
                session['role']=account['role']
                print(session['id'])

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
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)

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
        hashpwd = bcrypt.generate_password_hash(password)

        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s, %s)', (role,username, hashpwd, email,))
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
        # Output message if something goes wrong...
        msg = ''
        # Check if "username", "password" and "email" POST requests exist (user submitted form)
        if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
            # Create variables for easy access
            username = request.form['username']
            role = 'admin'
            password = request.form['password']
            email = request.form['email']

            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('SELECT * FROM accounts WHERE username = %s', (username,))
            # cursor.execute('SELECT * FROM accounts WHERE username = %s OR email = %s', (username, email))
            account = cursor.fetchone()

            if account:
                if account['username'] == username:
                    msg = 'Username has been taken. Please choose a different username'
                # elif bcrypt.generate_password_hash(account['password']) == password:
                #     msg = 'Password has been taken. Please choose a different password'
                # elif account['email'] == email:
                #     msg = 'Email has been taken. Please choose a different email'
                return render_template('admin_register.html', msg=msg)
            else:
                # Account doesnt exists and the form data is valid, now insert new account into accounts table
                hashpwd = bcrypt.generate_password_hash(password)


                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('INSERT INTO accounts VALUES (NULL, %s, %s, %s, %s)', (role,username, hashpwd, email))
                mysql.connection.commit()
                msg = 'You have successfully registered!'
                return render_template('admin_home.html', msg=msg)
        elif request.method == 'POST': #verify if theres an input
            # Form is empty... (no POST data)
            msg = 'Please fill out the form!'
            # Show registration form with message (if any)
        return render_template('admin_register.html', msg=msg)
    return redirect(url_for('login'))
@app.route('/webapp/home')
@login_required
def home():
    if 'loggedin' in session:
        return render_template('home.html', username=session['username'])
    return redirect(url_for('login'))
@app.route('/webapp/admin/home')
@admin_required
@login_required
def admin_home():
    if 'loggedin' in session:
        return render_template('admin_home.html', username=session['username'])
    return redirect(url_for('login'))


@app.route('/webapp/profile',methods=['GET','POST'])
@login_required
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
def admin_profile():
    if 'loggedin' in session:
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE id = %s', (session['id'],))
        account = cursor.fetchone()

        return render_template('admin_profile.html', account=account)
    return redirect(url_for('login'))

@app.route('/webapp/profile/update',methods=['GET','POST'])
@login_required
def update_profile():
    if 'loggedin' in session:
        msg=' '
        update_profile_form=UpdateProfileForm(request.form)
        if request.method=='POST' and update_profile_form.validate():
            username=update_profile_form.username.data
            email=update_profile_form.email.data

            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute('UPDATE accounts SET username = %s,email=%s WHERE id = %s', (username,email, session['id']))
            mysql.connection.commit()
            print('update profile',session['id'])
            msg='You have successfully update!'
            return redirect(url_for('profile'))
        else:
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            username=session['username']
            cursor.execute('SELECT * FROM accounts WHERE username = %s ', (username,))
            account=cursor.fetchone()

            update_profile_form.username.data=account['username']
            update_profile_form.email.data=account['email']
            return render_template('update_profile.html',msg=msg,form=update_profile_form,account=account)
    return redirect(url_for('login'))

@app.route('/webapp/profile/change_passowrd',methods=['GET','POST'])
@login_required
def change_password():
    if 'loggedin' in session:
        msg=' '
        pwd_form=ChangePassword(request.form)
        if request.method=='POST' and pwd_form.validate():
            newpwd=pwd_form.newpwd.data
            confirm_password=pwd_form.confirmpwd.data

            if newpwd==confirm_password:
                hashpwd = bcrypt.generate_password_hash(confirm_password)
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute('UPDATE accounts SET password = %s WHERE id = %s', (hashpwd, session['id']))
                mysql.connection.commit()
                msg = 'You have successfully update!'

                return redirect(url_for('profile'))
            else:
                msg='Password didnt match.Pls try again'
        return render_template('change_pwd.html',form=pwd_form,msg=msg)
    return redirect(url_for('login'))

@app.route('/webapp/admin/retrieve_users')
@admin_required
@login_required
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
#ellexys,email verification
@app.route('/forgot_password',methods=['GET','POST'])
@login_required
def forgot_password():
    pass







if __name__== '__main__':
    app.run()