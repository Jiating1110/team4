from wtforms import Form,StringField,PasswordField,validators
from wtforms.validators import DataRequired,ValidationError
import re
from flask_wtf import RecaptchaField

def pwd_dic_check(form,field):
    file=open("wordlist.txt","r")
    for password in file:
        if password.strip().lower() in field.data.lower():
            raise ValidationError('Password contains a common word and is not allowed.')
def pwd_check(form,field):
    pwd=field.data
    pattern=("^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{10,20}$")
    # if len(pwd)<10:
    #     raise ValidationError('Password must have at least 10 characters')
    if re.search(r"(.)\1{2}", pwd):
        raise ValidationError('Not more than 2 identical characters in a row')
    if not re.match(pattern,pwd):
        raise ValidationError('Passoword must be at least 10 characters long,contain'
                              'at least one uppercase and one lowercase characters,'
                              'at least one numerals number'
                              'at least one special characters')
class RegisterForm(Form):
    username=StringField('Username',[validators.DataRequired()])
    password=PasswordField('Password',[validators.DataRequired(),pwd_dic_check])
    email=StringField('Email',[validators.Email(message='Invalid Email format'),validators.DataRequired(message='Email address is required.')])

class LoginForm(Form):
    username=StringField('Username',[validators.DataRequired()])
    password=PasswordField('Password',[validators.DataRequired()])
    recaptcha = RecaptchaField()
    totp_code = StringField('TOTP Code')  # Ensure this field is included

class UpdateProfileForm(Form):
    username = StringField('Username', [validators.DataRequired()])
    email = StringField('Email', [validators.Email(message='Invalid Email format'),
                                  validators.DataRequired(message='Email address is required.')])

class VerifyPassword(Form):
    pwd=PasswordField('Password',[validators.DataRequired()])
class VerifyEmail(Form):
    email = StringField('Email', [validators.Email(message='Invalid Email format'),
                                  validators.DataRequired(message='Email address is required.')])

class ChangePassword(Form):
    newpwd=PasswordField('New Password',[validators.DataRequired()])
    confirmpwd=PasswordField('Confirm Password',[validators.DataRequired(),pwd_dic_check])

class OTPVerifyForm(Form):
    otp = StringField('OTP Code', [validators.Length(min=6, max=6, message='OTP code must be 6 characters long'), validators.DataRequired(message='OTP code is required'), validators.Regexp('^[0-9]*$', message='OTP code must only contain numbers')])