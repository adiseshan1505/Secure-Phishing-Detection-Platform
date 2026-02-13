import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
import logging

logger = logging.getLogger(__name__)


class EmailService:
    SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SENDER_EMAIL = os.getenv("SENDER_EMAIL", "noreply@phishing-detection.com")
    SENDER_PASSWORD = os.getenv("SENDER_PASSWORD", "")

    @staticmethod
    def send_otp(email: str, otp: str, username: str = None) -> bool:
        try:
            subject = "🔐 Your One-Time Password (OTP) - Phishing Detection Platform"

            html_body = f"""
            <html>
                <body style="font-family: Arial, sans-serif; background-color: #f5f5f5;">
                    <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                        <h1 style="color: #667eea; text-align: center;">🔐 One-Time Password</h1>
                        <p style="color: #333; font-size: 16px;">Hello{' ' + username if username else ''},</p>
                        <p style="color: #555; margin: 20px 0;">Your One-Time Password for the Phishing Detection Platform is:</p>
                        <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 8px; margin: 30px 0;">
                            <h2 style="color: white; letter-spacing: 8px; margin: 0; font-size: 36px;">{otp}</h2>
                        </div>
                        <p style="color: #666; margin: 20px 0;">
                            <strong>⏱️ Valid for 5 minutes only</strong>
                        </p>
                        <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; border-radius: 4px; margin: 20px 0;">
                            <p style="margin: 0; color: #856404;">
                                🔒 Never share this code with anyone. We will never ask for it.
                            </p>
                        </div>
                        <p style="color: #999; font-size: 12px; text-align: center; margin-top: 30px; border-top: 1px solid #ddd; padding-top: 20px;">
                            Phishing Detection Platform © 2026<br>
                            This is an automated message. Please do not reply to this email.
                        </p>
                    </div>
                </body>
            </html>
            """

            text_body = f"""
Your One-Time Password (OTP)
{'='*50}

Hello{' ' + username if username else ''},

Your OTP is: {otp}

Valid for 5 minutes only

Never share this code with anyone.

Phishing Detection Platform 2026
            """

            message = MIMEMultipart("alternative")
            message["Subject"] = subject
            message["From"] = EmailService.SENDER_EMAIL
            message["To"] = email

            message.attach(MIMEText(text_body, "plain"))
            message.attach(MIMEText(html_body, "html"))

            with smtplib.SMTP(EmailService.SMTP_SERVER, EmailService.SMTP_PORT) as server:
                server.starttls()
                server.login(EmailService.SENDER_EMAIL, EmailService.SENDER_PASSWORD)
                server.send_message(message)

            logger.info(f"OTP email sent successfully to: {email}")
            return True

        except smtplib.SMTPAuthenticationError:
            logger.error("SMTP Authentication failed. Check email/password in .env")
            return False
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error: {str(e)}")
            return False
        except Exception as e:
            logger.error(f"Failed to send OTP email: {str(e)}")
            return False
