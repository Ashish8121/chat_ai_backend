from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey, create_engine
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from datetime import datetime
import pytz
import os
from dotenv import load_dotenv

load_dotenv()
SQLALCHEMY_DATABASE_URL = os.getenv("DB_URL")

db_engine = create_engine(SQLALCHEMY_DATABASE_URL, echo=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=db_engine)
Base = declarative_base()

class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(100))
    email = Column(String(100), unique=True, nullable=False)
    password = Column(String(100), nullable=False)
    timezone = Column(String(50), default='Asia/Kolkata')

    sent_messages = relationship('Messages', foreign_keys='Messages.sender_id', backref='sender_user', lazy='joined')
    received_messages = relationship('Messages', foreign_keys='Messages.recipient_id', backref='recipient_user', lazy='joined')


class Messages(Base):
    __tablename__ = 'messages'

    id = Column(Integer, primary_key=True)
    sender_id = Column(Integer, ForeignKey('user.id'), nullable=False, index=True)
    recipient_id = Column(Integer, ForeignKey('user.id'), nullable=False, index=True)
    text = Column(Text, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=datetime.utcnow, index=True)
    is_ai = Column(Boolean, default=False)
    is_ai_replied = Column(Boolean, default=False)

    def to_dict(self):
        try:
            user_timezone = pytz.timezone(self.sender_user.timezone) if self.sender_user and self.sender_user.timezone else pytz.utc
        except pytz.UnknownTimeZoneError:
            user_timezone = pytz.utc

        local_time = self.timestamp.replace(tzinfo=pytz.utc).astimezone(user_timezone) if self.timestamp else None

        return {
            'id': self.id,
            'sender_id': self.sender_id,
            'recipient_id': self.recipient_id,
            'text': self.text,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'is_ai': self.is_ai,
            'is_ai_replied': self.is_ai_replied
        }
