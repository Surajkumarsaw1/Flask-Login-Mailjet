# password_reset.py
from flask import url_for
from datetime import datetime, timedelta
import jwt
from itsdangerous import URLSafeTimedSerializer
from settings import config

def generate_password_reset_token(user_id):
    # Move the import statement inside the function to avoid circular import
    from app import app

    expiration = datetime.utcnow() + timedelta(hours=1)
    payload = {
        'reset_password': user_id,
        'exp': expiration
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')
    return token

# def verify_password_reset_token(token):
#     from app import app

#     try:
#         payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
#         user_id = payload.get('reset_password')
#         return user_id
#     except jwt.ExpiredSignatureError:
#         return None
#     except jwt.InvalidTokenError:
#         return None

def verify_password_reset_token(token):
    serializer = URLSafeTimedSerializer(config.SECRET_KEY)
    try:
        user_id = serializer.loads(token, salt='password-reset', max_age=3600)  # Token expires after 1 hour (3600 seconds)
        return user_id
    except:
        return None