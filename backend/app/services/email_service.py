import smtplib
import ssl
from email.message import EmailMessage
from email.utils import formataddr

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("email_service")


class EmailConfigurationError(Exception):
    pass


class EmailDeliveryError(Exception):
    pass


class EmailService:
    @staticmethod
    def is_configured() -> bool:
        return bool(
            settings.SMTP_HOST
            and settings.SMTP_PORT
            and settings.SMTP_FROM_EMAIL
            and (bool(settings.SMTP_USERNAME) == bool(settings.SMTP_PASSWORD))
        )

    @staticmethod
    def send_verification_email(email: str, full_name: str, otp: str) -> None:
        if not EmailService.is_configured():
            raise EmailConfigurationError("Email delivery is not configured.")

        message = EmailMessage()
        message["Subject"] = "Your Cyber Guard verification code"
        message["From"] = formataddr((settings.SMTP_FROM_NAME, settings.SMTP_FROM_EMAIL))
        message["To"] = email
        message.set_content(
            f"Hello {full_name},\n\n"
            f"Your Cyber Guard email verification code is: {otp}\n\n"
            "Enter this code on the verification page within 10 minutes. "
            "The code can only be used once. If you did not create this account, "
            "you can ignore this email."
        )

        try:
            if settings.SMTP_PORT == 465:
                with smtplib.SMTP_SSL(
                    settings.SMTP_HOST,
                    settings.SMTP_PORT,
                    timeout=10,
                    context=ssl.create_default_context(),
                ) as server:
                    if settings.SMTP_USERNAME:
                        server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                    EmailService._deliver(server, message)
            else:
                with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
                    server.starttls(context=ssl.create_default_context())
                    if settings.SMTP_USERNAME:
                        server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
                    EmailService._deliver(server, message)
        except (OSError, smtplib.SMTPException) as exc:
            logger.error("Verification email delivery failed.")
            raise EmailDeliveryError("Verification email could not be delivered.") from exc

    @staticmethod
    def _deliver(server: smtplib.SMTP, message: EmailMessage) -> None:
        refused = server.send_message(message)
        if refused:
            raise EmailDeliveryError("Verification email could not be delivered.")
