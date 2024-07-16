from wtforms import Form,StringField,PasswordField,validators
from wtforms.validators import DataRequired,ValidationError

def pwd_dic_check(form,field):
    file=open("wordlist.txt","r")
    for password in file:
        if password.strip().lower() in field.data.lower():
            raise ValidationError('Password contains a common word and is not allowed.')
class RegisterForm(Form):
    username=StringField('Username',[validators.DataRequired()])
    password=PasswordField('Password',[validators.DataRequired(),pwd_dic_check])
    email=StringField('Email',[validators.Email(message='Invalid Email format'),validators.DataRequired(message='Email address is required.')])

class LoginForm(Form):
    username=StringField('Username',[validators.DataRequired()])
    password=PasswordField('Password',[validators.DataRequired()])
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