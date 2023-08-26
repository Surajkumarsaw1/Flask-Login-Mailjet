# app.py
import secrets
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo
from mailjet_rest import Client
import jwt
from datetime import datetime, timedelta
from pytz import all_timezones
from flask_migrate import Migrate
from password_reset import generate_password_reset_token, verify_password_reset_token
from settings import config
from forms import *
from email_service import send_verification_email, send_password_reset_email

# Create a Flask app instance
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = config.SQLALCHEMY_DATABASE_URI
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['MAILJET_API_KEY'] = config.MAILJET_API_KEY
app.config['MAILJET_API_SECRET'] = config.MAILJET_API_SECRET
app.config['MAILJET_SENDER_EMAIL'] = config.MAILJET_SENDER_EMAIL
app.config['MAILJET_SENDER_NAME'] = config.MAILJET_SENDER_NAME
JWT_SECRET_KEY = config.SECRET_KEY

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)

# Define the User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    modified = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    access_level = db.Column(db.Integer, default=0)
    phone_number = db.Column(db.String(20))
    time_zone = db.Column(db.String(50))
    view_access = db.Column(db.Boolean, default=True, nullable=False)
    edit_access = db.Column(db.Boolean, default=False, nullable=False)
    delete_restore_access = db.Column(db.Boolean, default=False, nullable=False)
    deleted = db.Column(db.Boolean, default=False, nullable=False)
    last_active = db.Column(db.DateTime)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    verification_token_info = db.relationship('VerificationToken', uselist=False, back_populates='user')
    
    def __repr__(self):
        return f"<User {self.username}>"
    
class VerificationToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(32), unique=True, nullable=False)
    expiration = db.Column(db.DateTime, nullable=False)

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


    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create all tables in the database
with app.app_context():
    db.create_all()

@app.route('/')
def home():
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
            new_user = User(username=username, email=email, password_hash=hashed_password, is_admin=is_first_user)

            # Generate a verification token
            verification_token = secrets.token_hex(16)
            verification_token_expiration = datetime.utcnow() + timedelta(hours=1)

            # Create a new VerificationToken instance
            new_token = VerificationToken(token=verification_token, expiration=verification_token_expiration)
            db.session.add(new_token)

            # Link the VerificationToken to the User
            new_user.verification_token_info = new_token

            db.session.add(new_user)
            db.session.commit()

            verification_link = url_for('verify_email', token=verification_token, _external=True)
            send_verification_email(email, verification_link, username=new_user.username)

            flash('Signup successful! Please check your email for verification.', 'success')
            return redirect(url_for('login'))

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
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/verify_email/<token>')
def verify_email(token):
    VerificationToken.cleanup_expired_tokens()
    token_info = VerificationToken.query.filter_by(token=token).first()

    if token_info and token_info.expiration > datetime.utcnow():
        user = token_info.user
        user.email_verified = True
        db.session.delete(token_info)  # Remove the token after successful verification
        db.session.commit()
        flash('Email verification successful. You can now log in.', 'success')
    else:
        flash('Invalid or expired verification link.', 'error')

    return redirect(url_for('login'))

@app.route('/resend_verification_email', methods=['GET', 'POST'])
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
def password_reset_request():
    form = PasswordResetRequestForm()

    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()

        if user:
            token = generate_password_reset_token(user.id)
            reset_link = url_for('password_reset', token=token, _external=True)
            send_password_reset_email(email, reset_link, username=user.username)

            flash('Password reset link sent. Please check your email for the reset link.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Email not found. Please enter a valid email address.', 'error')

    return render_template('password_reset_request.html', form=form)

@app.route('/password_reset/<token>', methods=['GET', 'POST'])
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

        flash('Your password has been reset successfully. You can now log in with the new password.', 'success')
        return redirect(url_for('login'))

    return render_template('password_reset.html', form=form, token=token)  # Pass 'token' to the template context


@app.route('/admin', methods=['GET'])
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('You do not have permission to access the admin dashboard.', 'warning')
        return redirect(url_for('home'))

    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

@app.route('/admin/view_user/<int:user_id>', methods=['GET'])
@login_required
def view_user(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to view users.', 'warning')
        return redirect(url_for('admin_dashboard'))

    user = User.query.get_or_404(user_id)
    return render_template('view_user.html', user=user)

@app.route('/admin/update_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def update_user(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to update users.', 'warning')
        return redirect(url_for('admin_dashboard'))

    user = User.query.get_or_404(user_id)
    form = UpdateUserForm(obj=user)

    if form.validate_on_submit():
        form.populate_obj(user)
        db.session.commit()
        flash('User details updated successfully.', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('update_user.html', form=form, user=user, time_zones=all_timezones)

@app.route('/admin/delete_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        flash('You do not have permission to delete users.', 'warning')
        return redirect(url_for('admin_dashboard'))

    user = User.query.get_or_404(user_id)
    form = ConfirmDeleteForm()

    if form.validate_on_submit():
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully.', 'success')
        return redirect(url_for('admin_dashboard'))

    return render_template('confirm_delete_user.html', user=user, form=form)

if __name__ == '__main__':
    app.run("0.0.0.0", debug=True)