# password_reset.py
from datetime import datetime, timedelta
import jwt
from itsdangerous import URLSafeTimedSerializer
from settings import config

def generate_password_reset_token(user_id, expiration_minutes=None):
    if expiration_minutes is None:
        expiration_minutes = config.PASSWORD_RESET_TOKEN_EXPIRATION_MINUTES

    expiration = datetime.utcnow() + timedelta(minutes=expiration_minutes)
    payload = {
        'reset_password': user_id,
        'exp': expiration
    }
    token = jwt.encode(payload, config.SECRET_KEY, algorithm='HS256')
    return token

def verify_password_reset_token(token):
    try:
        payload = jwt.decode(token, config.SECRET_KEY, algorithms=['HS256'])
        user_id = payload.get('reset_password')
        expiration = payload.get('exp')

        if datetime.utcnow() > datetime.utcfromtimestamp(expiration):
            # Token has expired
            return None

        return user_id
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

# def generate_password_reset_link(token):
#     return f"http://yourdomain.com/reset_password?token={token}"  # Replace with your actual domain

# def verify_password_reset_link(link):
#     # Extract the token from the link
#     token = link.split('?token=')[-1]
#     return verify_password_reset_token(token)

# def is_valid_password_reset_link(link):
#     return verify_password_reset_link(link) is not None
