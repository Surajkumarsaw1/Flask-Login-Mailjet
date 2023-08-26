# setting.py
import json

def load_config():
    try:
        with open('config.json', 'r') as config_file:
            config = json.load(config_file)

        mailjet_config = config.get('mailjet', {})
        mailjet_api_key = mailjet_config.get('api_key', '')
        mailjet_api_secret = mailjet_config.get('api_secret', '')
        mailjet_sender_email = mailjet_config.get('sender_email', '')
        mailjet_sender_name = mailjet_config.get('sender_name', '')

        app_config = config.get('appsetting', {})
        app_secret_key = app_config.get('secret_key', '')

        if not all([mailjet_api_key, mailjet_api_secret, mailjet_sender_email, mailjet_sender_name]):
            raise ValueError("One or more required fields are missing in the mailjet section of config.json.")

        if not app_secret_key:
            raise ValueError("The secret_key field is missing in the appsetting section of config.json.")

        return {
            'mailjet_api_key': mailjet_api_key,
            'mailjet_api_secret': mailjet_api_secret,
            'mailjet_sender_email': mailjet_sender_email,
            'mailjet_sender_name': mailjet_sender_name,
            'app_secret_key': app_secret_key
        }
    except FileNotFoundError:
        raise FileNotFoundError("config.json not found. Please create the config.json file.")
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON format in config.json. Please check the file.")
    except Exception as e:
        raise Exception(f"Error loading config.json: {str(e)}")

class Config:
    def __init__(self):
        config = load_config()
        self.PASSWORD_RESET_TOKEN_EXPIRATION = 60 * 7  # in seconds
        self.PASSWORD_RESET_TOKEN_EXPIRATION_MINUTES = 7
        self.SQLALCHEMY_DATABASE_URI = 'sqlite:///users.db'
        self.SECRET_KEY = config['app_secret_key']
        self.MAILJET_API_KEY = config['mailjet_api_key']
        self.MAILJET_API_SECRET = config['mailjet_api_secret']
        self.MAILJET_SENDER_EMAIL = config['mailjet_sender_email']
        self.MAILJET_SENDER_NAME = config['mailjet_sender_name']

config = Config()
