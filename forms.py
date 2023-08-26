# forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, IntegerField, SelectField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Optional, StopValidation, ValidationError
from pytz import all_timezones
import re


# Define a custom validator for password strength
def validate_password_strength(form, field):
    password = field.data

    # Define password requirements (at least one lowercase, one uppercase, one digit, one special character, and at least 8 characters)
    if not re.search(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', password):
        raise ValidationError("Password must contain at least one lowercase letter, one uppercase letter, one digit, one special character, and be at least 8 characters long.")

# Define the signup form using Flask-WTF
class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, max=128), validate_password_strength])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Signup')

class ResendVerificationEmailForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Resend Verification Email')
    
# Define the login form using Flask-WTF
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class PasswordResetRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    submit = SubmitField('Send Reset Link')

# Define the password reset form using Flask-WTF
class PasswordResetForm(FlaskForm):
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=8, max=128), validate_password_strength])
    confirm_new_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Reset Password')

    # def __init__(self, *args, **kwargs):
    #     super(PasswordResetForm, self).__init__(*args, **kwargs)

    #     # Get the token expiration time from the configuration
    #     self.token_expiration = config.PASSWORD_RESET_TOKEN_EXPIRATION

    # def validate_token(self, token):
    #     # Custom validation for token expiration
    #     token_info = verify_password_reset_token(token.data)

    #     if not token_info or token_info.expiration < datetime.utcnow():
    #         raise ValidationError('Invalid or expired password reset link.')

# Define the custom validator for the phone_number field
def phone_number_required(form, field):
    if form.phone_number.data.strip() == "":
        raise StopValidation("Phone number is required.")

class UpdateUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=80)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone_number = StringField('Phone Number', validators=[Optional(), phone_number_required])
    
    time_zone = SelectField('Time Zone', choices=[("", 'None')] + [(tz, tz) for tz in all_timezones], validators=[Optional()], default="")
    
    view_access = BooleanField('View Access')
    edit_access = BooleanField('Edit Access')
    delete_restore_access = BooleanField('Delete/Restore Access')
    deleted = BooleanField('Deleted')
    role_id = SelectField('Role', coerce=int, validators=[DataRequired()])  # Add a SelectField for selecting the user role
    
    # Additional fields, such as 'is_admin' and 'access_level', can be included here if needed
    
    submit = SubmitField('Update')

    # Add additional fields and custom validators as needed

    # Define the constructor to set the default choices for the time_zone and role_id fields
    def __init__(self, *args, **kwargs):
        role_choices = kwargs.pop('role_choices', [])
        super(UpdateUserForm, self).__init__(*args, **kwargs)
        # self.time_zone.choices = [(tz, tz) for tz in all_timezones]
        self.role_id.choices = role_choices  # Provide choices for available roles

        # Set the default value for time_zone to "None"
        if not self.time_zone.data:
            self.time_zone.data = None

    # Define any additional methods or custom validation logic as needed

class ConfirmDeleteForm(FlaskForm):
    submit = SubmitField('Confirm Deletion')

class ProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    phone_number = StringField('Phone Number')
    time_zone = SelectField('Time Zone', choices=[("", 'None')] + [(tz, tz) for tz in all_timezones], validators=[Optional()], default="")
    submit = SubmitField('Save Changes')
