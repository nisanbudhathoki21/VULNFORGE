import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone


EMAIL_RE = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


@dataclass
class User:
    email: str
    first_name: str
    last_name: str
    password_hash: str
    created_at: str
    verified: bool = False
    verification_token: str = ""


USERS = {}


def normalize_email(email):
    return email.strip().lower()


def validate_email(email: str):
    """
    ShopCart email validation.

    Lab policy:
    - Email must contain exactly one @.
    - Username/local-part must contain letters only.
    - Numbers are rejected.
    - Special characters are rejected.
    - Domain must contain valid DNS-style labels.
    - A two-character-or-longer alphabetic TLD is required.

    This validates format only. It does not prove mailbox ownership.
    """

    if not isinstance(email, str):
        return False, "Use a valid email address."

    email = email.strip()

    if not email:
        return False, "Email address is required."

    if len(email) > 254:
        return False, "Use a valid email address."

    if email.count("@") != 1:
        return False, "Use a valid email address."

    local, domain = email.rsplit("@", 1)

    if not local or not domain:
        return False, "Use a valid email address."

    # ShopCart policy:
    # local part must contain letters only.
    if not local.isalpha():
        return False, "Use a valid email address."

    # Keep account usernames reasonably sized.
    if not 2 <= len(local) <= 32:
        return False, "Use a valid email address."

    # Domain must be lowercase-normalized.
    domain = domain.lower()

    if "." not in domain:
        return False, "Use a valid email address."

    if ".." in domain:
        return False, "Use a valid email address."

    if domain.startswith(".") or domain.endswith("."):
        return False, "Use a valid email address."

    labels = domain.split(".")

    if len(labels) < 2:
        return False, "Use a valid email address."

    tld = labels[-1]

    if len(tld) < 2 or not tld.isalpha():
        return False, "Use a valid email address."

    for label in labels:
        if not label:
            return False, "Use a valid email address."

        if len(label) > 63:
            return False, "Use a valid email address."

        if label.startswith("-") or label.endswith("-"):
            return False, "Use a valid email address."

        if not all(ch.isalnum() or ch == "-" for ch in label):
            return False, "Use a valid email address."

    return True, f"{local}@{domain}"
def validate_password(password):
    errors = []

    if not password:
        return ["Password is required."]

    if len(password) < 8:
        errors.append(
            "Password must contain at least 8 characters."
        )

    if len(password) > 128:
        errors.append(
            "Password cannot exceed 128 characters."
        )

    if not re.search(r"[A-Z]", password):
        errors.append(
            "Password must contain an uppercase letter."
        )

    if not re.search(r"[a-z]", password):
        errors.append(
            "Password must contain a lowercase letter."
        )

    if not re.search(r"\d", password):
        errors.append(
            "Password must contain a number."
        )

    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append(
            "Password must contain a special character."
        )

    return errors


def password_score(password):
    score = 0

    if len(password) >= 8:
        score += 1

    if len(password) >= 12:
        score += 1

    if re.search(r"[A-Z]", password):
        score += 1

    if re.search(r"[a-z]", password):
        score += 1

    if re.search(r"\d", password):
        score += 1

    if re.search(r"[^A-Za-z0-9]", password):
        score += 1

    return min(score, 5)


def hash_password(password):
    salt = secrets.token_bytes(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        150_000,
    )

    return salt.hex() + ":" + digest.hex()


def verify_password(password, stored):
    try:
        salt_hex, digest_hex = stored.split(":", 1)

        salt = bytes.fromhex(salt_hex)

        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt,
            150_000,
        )

        return secrets.compare_digest(
            digest.hex(),
            digest_hex,
        )

    except (ValueError, TypeError):
        return False


def create_user(
    email,
    first_name,
    last_name,
    password,
    verified=False,
):
    email = normalize_email(email)

    verification_token = (
        secrets.token_urlsafe(32)
        if not verified
        else ""
    )

    user = User(
        email=email,
        first_name=first_name.strip(),
        last_name=last_name.strip(),
        password_hash=hash_password(password),
        created_at=datetime.now(timezone.utc).isoformat(),
        verified=verified,
        verification_token=verification_token,
    )

    USERS[email] = user

    return user


def verify_user(token):
    if not token:
        return None

    for user in USERS.values():
        if (
            user.verification_token
            and secrets.compare_digest(
                user.verification_token,
                token,
            )
        ):
            user.verified = True
            user.verification_token = ""
            return user

    return None


def get_user_by_email(email):
    return USERS.get(normalize_email(email))


def authenticate(email, password):
    email = normalize_email(email)

    user = USERS.get(email)

    if not user:
        return None

    if not verify_password(
        password,
        user.password_hash,
    ):
        return None

    if not user.verified:
        return None

    return user


def seed_demo_users():
    if "alice@example.com" not in USERS:
        create_user(
            "alice@example.com",
            "Alice",
            "Sharma",
            "Alice@12345!",
            verified=True,
        )

    if "bob@example.com" not in USERS:
        create_user(
            "bob@example.com",
            "Bob",
            "Thapa",
            "Bob@12345!",
            verified=True,
        )
