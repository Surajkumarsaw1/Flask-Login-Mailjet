# app.py
import secrets
from flask import Flask, jsonify, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from flask_talisman import Talisman
from mailjet_rest import Client
import jwt
from datetime import datetime, timedelta
from pytz import all_timezones
from flask_migrate import Migrate
from password_reset import generate_password_reset_token, verify_password_reset_token
from settings import config
from forms import *
from email_service import send_verification_email, send_password_reset_email
import logging
from flask_limiter.util import get_remote_address
from flask_limiter import Limiter
from flask_limiter.errors import RateLimitExceeded

import redislite
from flask_caching import Cache

# Create a Flask app instance
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = config.SQLALCHEMY_DATABASE_URI
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['MAILJET_API_KEY'] = config.MAILJET_API_KEY
app.config['MAILJET_API_SECRET'] = config.MAILJET_API_SECRET
app.config['MAILJET_SENDER_EMAIL'] = config.MAILJET_SENDER_EMAIL
app.config['MAILJET_SENDER_NAME'] = config.MAILJET_SENDER_NAME
JWT_SECRET_KEY = config.SECRET_KEY

# Configure Flask-Limiter with the app
limiter = Limiter(get_remote_address, app=app, default_limits=["10000 per day", "6000 per hour"])

# Configure Flask-Caching
# app.config['CACHE_TYPE'] = 'simple'  # Use SimpleCache as the caching backend
app.config['CACHE_TYPE'] = 'redis'
app.config['CACHE_REDIS_URL'] = 'redis:///redis.db'
app.config['RATELIMIT_STORAGE_URL'] = "redis:///redis.db"
app.config['CACHE_DEFAULT_TIMEOUT'] = 300  # Set a default timeout for cached items (in seconds)
# Initialize Flask-Caching with the app
cache = Cache(app)

# Define the Content Security Policy rules
# Define the Content Security Policy rules
csp = {
    'default-src': '\'self\'',
    'script-src': ['\'self\'', 'https://cdn.jsdelivr.net', '\'unsafe-inline\'', '\'unsafe-eval\''],  # Add 'unsafe-eval'
    'style-src': ['\'self\'', 'https://cdnjs.cloudflare.com', 'https://127.0.0.1:5000', '\'unsafe-inline\''],  # Add 'unsafe-inline'
    'img-src': '\'self\' https://127.0.0.1:5000',
    'font-src': ['\'self\'', 'https://cdnjs.cloudflare.com', 'https://127.0.0.1:5000'],
    # Add other resource types as needed
}

# Initialize Flask-Talisman with your app (place it after initializing the Flask app)
talisman = Talisman(app, content_security_policy=csp)
# talisman = Talisman(app, content_security_policy=csp, strict_transport_security=True)


db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Define the User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    modified = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    # access_level = db.Column(db.Integer, default=0)
    phone_number = db.Column(db.String(20))
    time_zone = db.Column(db.String(50))
    view_access = db.Column(db.Boolean, default=True, nullable=False)
    edit_access = db.Column(db.Boolean, default=False, nullable=False)
    delete_restore_access = db.Column(db.Boolean, default=False, nullable=False)
    deleted = db.Column(db.Boolean, default=False, nullable=False)
    last_active = db.Column(db.DateTime)
    # is_admin = db.Column(db.Boolean, default=False, nullable=False)

    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    role = db.relationship('Role', backref='users')

    verification_token_info = db.relationship('VerificationToken', uselist=False, back_populates='user')
    
    @classmethod
    def get_by_id(cls, user_id):
        return db.session.get(cls, user_id)  # Use Session.get() to query by primary key
    
    def __repr__(self):
        return f"<User {self.username}>"
    
class VerificationToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(32), unique=True, nullable=False, index=True)
    expiration = db.Column(db.DateTime, nullable=False, index=True)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', back_populates='verification_token_info')

    def __repr__(self):
        return f"<VerificationToken {self.token}>"

    @classmethod
    def cleanup_expired_tokens(cls):
        expired_tokens = cls.query.filter(cls.expiration < datetime.utcnow()).all()
        for token in expired_tokens:
            db.session.delete(token)
        db.session.commit()

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(255))

    def __repr__(self):
        return f"<Role {self.name}>"
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create all tables in the database
with app.app_context():
    db.create_all()

# Error handling: 404 Not Found
# @app.errorhandler(404)
# def page_not_found(e):
#     logger.error(f"404 Not Found: {request.url}")
#     flash("The page you are looking for does not exist.", "error")
#     return redirect(url_for("home"))

# # Error handling: 500 Internal Server Error
# @app.errorhandler(500)
# def internal_server_error(e):
#     logger.error(f"500 Internal Server Error: {e}")
#     flash("An internal server error occurred. Please try again later.", "error")
#     return redirect(url_for("home"))

# Handle RateLimitExceeded exception for error 429
@app.errorhandler(RateLimitExceeded)  # Use the errorhandler decorator to handle RateLimitExceeded exception
def handle_ratelimit_exceeded(e):
    response = jsonify({
        'error': 'Rate limit exceeded. Please try again later.',
        'msg' : str(e)
    })
    response.status_code = 429
    # response.headers.add('Retry-After', limiter.parser.parse([limiter.default_limits])[0][1])
    return response

@app.before_request
def create_default_roles():
    if not app.config.get('ROLES_INITIALIZED', False):
        default_roles = [
            {'name': 'User', 'description': 'Regular user with basic access'},
            {'name': 'Admin', 'description': 'Administrator with full access'}
            # Add more roles as needed
        ]

        for role_data in default_roles:
            role = Role.query.filter_by(name=role_data['name']).first()
            if not role:
                role = Role(**role_data)
                db.session.add(role)

        db.session.commit()
        app.config['ROLES_INITIALIZED'] = True  # Set a flag to avoid creating roles on every request

@app.route('/')
def home():
    logger.info('Home page accessed.')
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('home'))  # Redirect logged-in users to the home page

    form = SignupForm()

    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('Username or email already exists. Please choose a different one.', 'error')
        else:
            hashed_password = generate_password_hash(password)
            is_first_user = User.query.count() == 0
            # new_user = User(username=username, email=email, password_hash=hashed_password, is_admin=is_first_user)
            new_user = User(username=username, email=email, password_hash=hashed_password)

            # Assign the 'User' role to the new user by default
            if is_first_user:
                user_role = Role.query.filter_by(name='Admin').first()
            else:
                user_role = Role.query.filter_by(name='User').first()

            new_user.role = user_role

            db.session.add(new_user)
            db.session.commit()

            # Generate a verification token
            verification_token = secrets.token_hex(16)
            verification_token_expiration = datetime.utcnow() + timedelta(hours=1)

            # Create a new VerificationToken instance and link it to the User
            new_token = VerificationToken(token=verification_token,expiration=verification_token_expiration, user=new_user)
            db.session.add(new_token)

            db.session.commit()

            verification_link = url_for('verify_email', token=verification_token, _external=True)
            send_verification_email(email, verification_link, username=new_user.username)

            flash('Signup successful! Please check your email for verification.', 'success')
            return redirect(url_for('login'))
            
    # Log if form validation fails
    if form.errors:
        logger.error("Form validation failed with errors: %s", form.errors)

    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))  # Redirect logged-in users to the home page

    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            if user.email_verified:
                login_user(user)
                logger.info(f'User {user.username} logged in.')
                flash('Login successful!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Email verification required. Please check your email for the verification link.', 'warning')
        else:
            flash('Invalid username or password. Please try again.', 'error')

    return render_template('login.html', form=form)


@app.route('/logout')
@login_required
def logout():
    logger.info(f'User {current_user.username} logged out.')
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/verify_email/<token>')
@limiter.limit("10 per day")
def verify_email(token):
    VerificationToken.cleanup_expired_tokens()
    token_info = VerificationToken.query.filter_by(token=token).first()

    if token_info and token_info.expiration > datetime.utcnow():
        user = token_info.user
        user.email_verified = True
        db.session.delete(token_info)  # Remove the token after successful verification
        db.session.commit()
        logger.info(f'User {user.username} email verified.')
        flash('Email verification successful. You can now log in.', 'success')
    else:
        flash('Invalid or expired verification link.', 'error')

    return redirect(url_for('login'))

@app.route('/resend_verification_email', methods=['GET', 'POST'])
@limiter.limit("10 per day")
def resend_verification_email():
    if current_user.is_authenticated:
        return redirect(url_for('home'))  # Redirect logged-in users to the home page

    form = ResendVerificationEmailForm()

    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()

        if user and not user.email_verified:
            token = user.verification_token_info.token
            verification_link = url_for('verify_email', token=token, _external=True)
            send_verification_email(email, verification_link, username=user.username)

            flash('Verification email resent. Please check your email for the verification link.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Email not found or already verified. Please enter a valid unverified email address.', 'error')

    return render_template('resend_verification_email.html', form=form)

@app.route('/password_reset_request', methods=['GET', 'POST'])
@limiter.limit("10 per day")
def password_reset_request():
    form = PasswordResetRequestForm()

    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()

        if user:
            token = generate_password_reset_token(user.id, expiration_minutes=10)  # Set expiration to 10 minutes
            reset_link = url_for('password_reset', token=token, _external=True)
            send_password_reset_email(email, reset_link, username=user.username)

            flash('Password reset link sent. Please check your email for the reset link.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Email not found. Please enter a valid email address.', 'error')

    return render_template('password_reset_request.html', form=form)

@app.route('/password_reset/<token>', methods=['GET', 'POST'])
@limiter.limit("10 per day")
def password_reset(token):
    form = PasswordResetForm()

    # Check if the token is valid and not expired
    user_id = verify_password_reset_token(token)
    user = User.query.get(user_id)

    if not user:
        flash('Invalid or expired password reset link.', 'error')
        return redirect(url_for('login'))

    if form.validate_on_submit():
        # Update the user's password
        new_password = form.new_password.data
        hashed_password = generate_password_hash(new_password)
        user.password_hash = hashed_password
        db.session.commit()

        logger.info(f'User {user.username} password reset successfully.')
        flash('Your password has been reset successfully. You can now log in with the new password.', 'success')
        return redirect(url_for('login'))

    return render_template('password_reset.html', form=form, user=user, token=token)  # Pass the user object to the template

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    form = ProfileForm(obj=current_user)  # Pre-populate the form with the current user's data

    if form.validate_on_submit():
        # Update the user's profile
        form.populate_obj(current_user)
        db.session.commit()
        flash('Profile updated successfully.', 'success')
        return redirect(url_for('profile'))

    # Handle form validation errors
    for field, errors in form.errors.items():
        for error in errors:
            flash(f'Error in {getattr(form, field).label.text}: {error}', 'error')

    return render_template('profile.html', form=form)

@app.route('/admin', methods=['GET'])
@login_required
def admin_dashboard():
    if not current_user.role.name == 'Admin':
        logger.warning(f'Non-admin user {current_user.username} attempted to access the admin dashboard.')
        flash('You do not have permission to access the admin dashboard.', 'warning')
        return redirect(url_for('home'))

    # Get the current page number from the request args (default to page 1)
    page = request.args.get('page', 1, type=int)

    # Set the number of users per page (you can adjust this as needed)
    users_per_page = 10

    # Get all users from the database using pagination
    users_pagination = User.query.paginate(page=page, per_page=users_per_page, error_out=False)

    return render_template('admin_dashboard.html', users_pagination=users_pagination)


@app.route('/admin/view_user/<int:user_id>', methods=['GET'])
@login_required
def view_user(user_id):
    if not current_user.role or current_user.role.name != 'Admin':
        logger.warning(f'Non-admin user {current_user.username} attempted to view a user profile.')
        flash('You do not have permission to view users.', 'warning')
        return redirect(url_for('admin_dashboard'))

    # user = User.query.get_or_404(user_id)
    user = User.get_by_id(user_id)  # Use the new get_by_id method
    return render_template('view_user.html', user=user)


@app.route('/admin/update_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def update_user(user_id):
    if not current_user.role or current_user.role.name != 'Admin':
        logger.warning(f'Non-admin user {current_user.username} attempted to update a user profile.')
        flash('You do not have permission to update users.', 'warning')
        return redirect(url_for('admin_dashboard'))

    # user = User.query.get_or_404(user_id)
    user = User.get_by_id(user_id)  # Use the new get_by_id method
    role_choices = [(role.id, role.name) for role in Role.query.all()]  # Create choices for the role_id field
    
    form = UpdateUserForm(obj=user, role_choices=role_choices)

    if form.validate_on_submit():
        form.populate_obj(user)
        db.session.commit()
        logger.info(f'User {user.username} details updated successfully.')
        flash('User details updated successfully.', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('update_user.html', form=form, user=user, time_zones=all_timezones)

@app.route('/admin/delete_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def delete_user(user_id):
    if not current_user.role or current_user.role.name != 'Admin':
        logger.warning(f'Non-admin user {current_user.username} attempted to delete a user.')
        flash('You do not have permission to delete users.', 'warning')
        return redirect(url_for('admin_dashboard'))

    user = User.query.get_or_404(user_id)
    form = ConfirmDeleteForm()

    if form.validate_on_submit():
        db.session.delete(user)
        db.session.commit()
        logger.info(f'User {user.username} deleted successfully.')
        flash('User deleted successfully.', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('confirm_delete_user.html', user=user, form=form)

if __name__ == '__main__':
    app.run("0.0.0.0", debug=True)
    # app.run(debug=True)
