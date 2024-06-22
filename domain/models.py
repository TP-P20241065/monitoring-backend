from sqlalchemy import Column, Integer, String, DateTime, JSON, BLOB, ForeignKey
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class User(Base):
    __tablename__ = "user"
    Id = Column(Integer, primary_key=True, index=True)
    Username = Column(String(50), nullable=False)
    FirstName = Column(String(50))
    LastName = Column(String(50))
    Email = Column(String(100), unique=True, nullable=False)
    Headquarter = Column(Integer)
    Permissions = Column(JSON)
    HashedPassword = Column(String(255), nullable=False)


class Unit(Base):
    __tablename__ = "unit"
    Id = Column(Integer, primary_key=True, index=True)
    Driver = Column(String(100))


class Camera(Base):
    __tablename__ = "camera"
    Id = Column(Integer, primary_key=True, index=True)
    Name = Column(String(100))
    Location = Column(String(255))
    UnitId = Column(Integer, ForeignKey("unit.Id"))


class Report(Base):
    __tablename__ = "report"
    Id = Column(Integer, primary_key=True, index=True)
    DateTime = Column(DateTime)
    Address = Column(String(255))
    Incident = Column(String(255))
    TrackingLink = Column(String(255), nullable=True)
    Image = Column(BLOB)
