from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from testBM.models import User


class SignUpForm(FlaskForm):
    username = StringField('username',
                           validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    passwordConf = PasswordField('Confirm password',
                                 validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    # creating a custom validation for the username
    def validate_username(self, username):
        # check if the username already exists in the database by filtering the queries
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username already exists, please choose another one')

    # creating a custom validation of the email
    def validate_email(self, email):
        # check if the username already exists in the database by filtering the queries
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email already exists, please choose another one')


class LoginForm(FlaskForm):
    email = StringField('email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember me')
    submit = SubmitField('Login')
