from wtforms import Form,StringField,PasswordField,validators
from wtforms.validators import DataRequired,ValidationError
from flask_wtf import RecaptchaField

class RegisterForm(Form):
    username=StringField('Username',[validators.DataRequired()])
    password=PasswordField('Password',[validators.DataRequired()])
    email=StringField('Email',[validators.Email(message='Invalid Email format'),validators.DataRequired(message='Email address is required.')])
class LoginForm(Form):
    username=StringField('Username',[validators.DataRequired()])
    password=PasswordField('Password',[validators.DataRequired()])
    recaptcha = RecaptchaField()
class UpdateProfileForm(Form):
    username = StringField('Username', [validators.DataRequired()])
    email = StringField('Email', [validators.Email(message='Invalid Email format'),
                                  validators.DataRequired(message='Email address is required.')])

class ChangePassword(Form):
    newpwd=PasswordField('New Password',[validators.DataRequired()])
    confirmpwd=PasswordField('Confirm Password',[validators.DataRequired()])

class OTPVerifyForm(Form):
    otp = StringField('OTP Code', [validators.Length(min=6, max=6, message='OTP code must be 6 characters long'), validators.DataRequired(message='OTP code is required'), validators.Regexp('^[0-9]*$', message='OTP code must only contain numbers')])