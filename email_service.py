from mailjet_rest import Client


def send_verification_email(email, verification_link, username):
    from app import app
    mailjet_api_key = app.config['MAILJET_API_KEY']
    mailjet_api_secret = app.config['MAILJET_API_SECRET']
    sender_email = app.config['MAILJET_SENDER_EMAIL']
    sender_name = app.config['MAILJET_SENDER_NAME']

    mailjet = Client(auth=(mailjet_api_key, mailjet_api_secret), version='v3.1')

    subject = "Email Verification"
    text_part = f"Hello {username},\n\nPlease click the link below to verify your email address:\n{verification_link}\n\nIf you didn't request this verification, you can safely ignore this email."

    html_part = f"<h3>Hello {username},</h3><p>Please click the link below to verify your email address:</p><p><a href='{verification_link}'>{verification_link}</a></p><p>If you didn't request this verification, you can safely ignore this email.</p>"

    data = {
        'Messages': [
            {
                "From": {
                    "Email": sender_email,
                    "Name": sender_name
                },
                "To": [
                    {
                        "Email": email,
                        "Name": ""
                    }
                ],
                "Subject": subject,
                "TextPart": text_part,
                "HTMLPart": html_part
            }
        ]
    }

    return mailjet.send.create(data=data)

def send_password_reset_email(email, reset_link, username):
    from app import app
    mailjet_api_key = app.config['MAILJET_API_KEY']
    mailjet_api_secret = app.config['MAILJET_API_SECRET']
    sender_email = app.config['MAILJET_SENDER_EMAIL']
    sender_name = app.config['MAILJET_SENDER_NAME']

    mailjet = Client(auth=(mailjet_api_key, mailjet_api_secret), version='v3.1')

    subject = "Password Reset Request"
    text_part = f"Hello {username},\n\nYou have requested to reset your password. Please click the link below to reset your password:\n{reset_link}\n\nIf you didn't request this password reset, you can safely ignore this email."

    html_part = f"<h3>Hello {username},</h3><p>You have requested to reset your password. Please click the link below to reset your password:</p><p><a href='{reset_link}'>{reset_link}</a></p><p>If you didn't request this password reset, you can safely ignore this email.</p>"

    data = {
        'Messages': [
            {
                "From": {
                    "Email": sender_email,
                    "Name": sender_name
                },
                "To": [
                    {
                        "Email": email,
                        "Name": ""
                    }
                ],
                "Subject": subject,
                "TextPart": text_part,
                "HTMLPart": html_part
            }
        ]
    }

    return mailjet.send.create(data=data)
