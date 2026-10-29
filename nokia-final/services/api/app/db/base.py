from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


from app.models.command import Command
from app.models.event import Event
from app.models.session import Session
