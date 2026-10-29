from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from shared.db.base import Base


def create_database_engine(
	host: str,
	port: int,
	database: str,
	username: str,
	password: str,
):
	database_url = (
		f"postgresql+psycopg://"
		f"{username}:{password}"
		f"@{host}:{port}"
		f"/{database}"
	)

	return create_engine(
		database_url,
		pool_pre_ping=True,
	)


def create_session_factory(engine):
	return sessionmaker(
		bind=engine,
		autoflush=False,
		autocommit=False,
	)
