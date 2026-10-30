import smtplib
import ssl
from dataclasses import dataclass
from email.message import EmailMessage


@dataclass(frozen=True)
class SmtpConfig:
    host: str
    port: int
    security: str  # none | starttls | ssl
    username: str
    from_addr: str
    to_addr: str


class MailError(Exception):
    """Fehler beim Versand. Die Meldung ist bewusst fest formuliert und enthält nie Zugangsdaten."""


def send_mail(cfg: SmtpConfig, password: str | None, subject: str, body: str, timeout: float = 10) -> None:
    msg = EmailMessage()
    msg["From"] = cfg.from_addr
    msg["To"] = cfg.to_addr
    msg["Subject"] = subject
    msg.set_content(body)
    try:
        if cfg.security == "ssl":
            smtp = smtplib.SMTP_SSL(cfg.host, cfg.port, timeout=timeout, context=ssl.create_default_context())
        else:
            smtp = smtplib.SMTP(cfg.host, cfg.port, timeout=timeout)
        with smtp:
            if cfg.security == "starttls":
                smtp.starttls(context=ssl.create_default_context())
            if cfg.username and password:
                smtp.login(cfg.username, password)
            smtp.send_message(msg)
    except smtplib.SMTPAuthenticationError as e:
        raise MailError(f"Mail server rejected the login (Code {e.smtp_code})") from None
    except smtplib.SMTPRecipientsRefused:
        raise MailError("Mail server rejected the recipient") from None
    except smtplib.SMTPSenderRefused:
        raise MailError("Mail server rejected the sender") from None
    except ssl.SSLError as e:
        raise MailError(f"TLS error: {e.reason or 'unknown'}") from None
    except smtplib.SMTPNotSupportedError:
        raise MailError("Mail server does not support the selected security or login") from None
    except smtplib.SMTPException as e:
        raise MailError(f"Mail server error ({type(e).__name__})") from None
    except TimeoutError:
        raise MailError("Connection timed out") from None
    except OSError as e:
        raise MailError(f"Connection failed ({e.strerror or type(e).__name__})") from None
