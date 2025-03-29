from django.core.mail import EmailMessage
from django.core.mail.backends.smtp import EmailBackend
from django.conf import settings
import logging
from threading import Thread

logger = logging.getLogger(__name__)

class Util:
    @staticmethod
    def send_email(data):
        """
        Sends an email using Django's EmailMessage.
        Supports logging, async execution, and error handling.
        """

        try:
            email = EmailMessage(
                subject=data.get('subject', 'No Subject'),
                body=data.get('body', ''),
                from_email=settings.EMAIL_HOST_USER,  # Uses Django settings
                to=[data['to_email']],
                cc=data.get('cc', []),
                bcc=data.get('bcc', [])
            )

            if 'attachments' in data:
                for attachment in data['attachments']:
                    email.attach(*attachment)  # (filename, content, mimetype)

            # Send email asynchronously
            Thread(target=Util._send_email_thread, args=(email,)).start()

        except Exception as e:
            logger.error(f"Email sending failed: {str(e)}")

    @staticmethod
    def _send_email_thread(email):
        """ Runs email sending in a separate thread to avoid blocking requests. """
        try:
            email.send(fail_silently=False)
            logger.info("Email sent successfully.")
        except Exception as e:
            logger.error(f"Email sending failed: {str(e)}")
