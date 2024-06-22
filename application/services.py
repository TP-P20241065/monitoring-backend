from sqlalchemy.orm import Session
from domain.models import User
from passlib.context import CryptContext
import random
import string

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def generate_password():
    password_length = 12
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ""

    for index in range(password_length):
        password = password + random.choice(characters)

    return password


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.Email == email).first()


def authenticate_user(db: Session, email: str, password: str):
    user = get_user_by_email(db, email)
    if not user or not verify_password(password, user.HashedPassword):
        return None
    return user
