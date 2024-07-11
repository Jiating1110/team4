#try email

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os

SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_USERNAME = '345ting678ting@gmail.com'  # Replace with your Gmail email address
SMTP_PASSWORD = 'niny ehgu sanf vizj'  # Replace with your Gmail password or app password


def send_email():
    try:
        sender_email = SMTP_USERNAME
        recipient_email = 'ting1234ssp@gmail.com'  # Replace with recipient email address

        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = 'Test Email'
        body = 'This is a test email.'
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(sender_email, SMTP_PASSWORD)
        server.sendmail(sender_email, recipient_email, msg.as_string())
        server.quit()

        print('Email sent successfully.')
    except Exception as e:
        print(f'Error sending email: {e}')

if __name__ == '__main__':
    send_email()