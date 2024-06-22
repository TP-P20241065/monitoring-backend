from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
from datetime import timedelta, datetime
import jwt
from sqlalchemy.orm import Session
import os

from infrastructure.database import get_db
from application.services import authenticate_user, get_password_hash, generate_password
from domain.models import User, Unit, Camera, Report

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))


# Modelos de Pydantic
class UserModel(BaseModel):
    Id: int
    Username: str
    FirstName: str
    LastName: str
    Email: str
    Headquarter: int
    Permissions: List[int]

    class Config:
        from_attributes = True


class UnitModel(BaseModel):
    Id: int
    Driver: str

    class Config:
        from_attributes = True


class CameraModel(BaseModel):
    Id: int
    Name: str
    Location: str
    UnitId: int

    class Config:
        from_attributes = True


class ReportModel(BaseModel):
    Id: int
    DateTime: datetime
    Address: str
    Incident: str
    TrackingLink: Optional[str] = None
    Image: bytes

    class Config:
        from_attributes = True


class TokenModel(BaseModel):
    access_token: str
    token_type: str


class TokenDataModel(BaseModel):
    Email: Optional[str] = None


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def verify_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token inválido")


def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    email: str = payload.get("sub")
    if email is None:
        raise HTTPException(status_code=401, detail="No se pudieron validar las credenciales")
    user = db.query(User).filter(User.Email == email).first()
    if user is None:
        raise HTTPException(status_code=401, detail="No se pudieron validar las credenciales")
    return user


# Endpoint para generar token de acceso
@app.post("/token", response_model=TokenModel)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Correo y/o contraseña incorrectas",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.Email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


# Endpoint para obtener todos los usuarios
@app.get("/users/", response_model=List[UserModel])
def get_users(db: Session = Depends(get_db)):
    return db.query(User).all()


# Endpoint para obtener el usuario actual
@app.get("/users/me/", response_model=UserModel)
async def read_users_me(current_user: UserModel = Depends(get_current_user)):
    return current_user


# Endpoint para buscar usuarios
@app.get("/users/search/", response_model=List[UserModel])
def search_users(email: Optional[str] = None, db: Session = Depends(get_db)):
    return db.query(User).filter(User.Email.contains(email)).all() if email else db.query(User).all()


# Endpoint para crear un nuevo usuario
@app.post("/users/", response_model=UserModel)
def create_user(user: UserModel, db: Session = Depends(get_db)):
    db_user = User(
        Username=user.Username,
        FirstName=user.FirstName,
        LastName=user.LastName,
        Email=user.Email,
        Headquarter=user.Headquarter,
        Permissions=user.Permissions,
        HashedPassword=get_password_hash(generate_password())
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


# Endpoint para actualizar un usuario existente
@app.put("/users/{user_id}", response_model=UserModel)
def update_user(user_id: int, updated_user: UserModel, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.Id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    for key, value in updated_user.dict(exclude_unset=True).items():
        setattr(db_user, key, value)
    db.commit()
    db.refresh(db_user)
    return db_user


# Endpoint para eliminar un usuario
@app.delete("/users/{user_id}", response_model=UserModel)
def delete_user(user_id: int, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.Id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    db.delete(db_user)
    db.commit()
    return db_user


# Endpoint para obtener todas las unidades
@app.get("/units/", response_model=List[UnitModel])
def get_units(db: Session = Depends(get_db)):
    return db.query(Unit).all()


# Endpoint para buscar unidades
@app.get("/units/search/", response_model=List[UnitModel])
def search_units(driver: Optional[str] = None, db: Session = Depends(get_db)):
    return db.query(Unit).filter(Unit.Driver.contains(driver)).all() if driver else db.query(Unit).all()


# Endpoint para crear una nueva unidad
@app.post("/units/", response_model=UnitModel)
def create_unit(unit: UnitModel, db: Session = Depends(get_db)):
    db_unit = Unit(Driver=unit.Driver)
    db.add(db_unit)
    db.commit()
    db.refresh(db_unit)
    return db_unit


# Endpoint para actualizar una unidad existente
@app.put("/units/{unit_id}", response_model=UnitModel)
def update_unit(unit_id: int, updated_unit: UnitModel, db: Session = Depends(get_db)):
    db_unit = db.query(Unit).filter(Unit.Id == unit_id).first()
    if not db_unit:
        raise HTTPException(status_code=404, detail="Unidad no encontrada")
    for key, value in updated_unit.dict(exclude_unset=True).items():
        setattr(db_unit, key, value)
    db.commit()
    db.refresh(db_unit)
    return db_unit


# Endpoint para eliminar una unidad
@app.delete("/units/{unit_id}", response_model=UnitModel)
def delete_unit(unit_id: int, db: Session = Depends(get_db)):
    db_unit = db.query(Unit).filter(Unit.Id == unit_id).first()
    if not db_unit:
        raise HTTPException(status_code=404, detail="Unidad no encontrada")
    db.delete(db_unit)
    db.commit()
    return db_unit


# Endpoint para obtener todas las cámaras
@app.get("/cameras/", response_model=List[CameraModel])
def get_cameras(db: Session = Depends(get_db)):
    return db.query(Camera).all()


# Endpoint para crear una nueva cámara
@app.post("/cameras/", response_model=CameraModel)
def create_camera(camera: CameraModel, db: Session = Depends(get_db)):
    db_camera = Camera(
        Name=camera.Name,
        Location=camera.Location,
        UnitId=camera.UnitId
    )
    db.add(db_camera)
    db.commit()
    db.refresh(db_camera)
    return db_camera


# Endpoint para actualizar una cámara existente
@app.put("/cameras/{camera_id}", response_model=CameraModel)
def update_camera(camera_id: int, updated_camera: CameraModel, db: Session = Depends(get_db)):
    db_camera = db.query(Camera).filter(Camera.Id == camera_id).first()
    if not db_camera:
        raise HTTPException(status_code=404, detail="Cámara no encontrada")
    for key, value in updated_camera.dict(exclude_unset=True).items():
        setattr(db_camera, key, value)
    db.commit()
    db.refresh(db_camera)
    return db_camera


# Endpoint para eliminar una cámara
@app.delete("/cameras/{camera_id}", response_model=CameraModel)
def delete_camera(camera_id: int, db: Session = Depends(get_db)):
    db_camera = db.query(Camera).filter(Camera.Id == camera_id).first()
    if not db_camera:
        raise HTTPException(status_code=404, detail="Cámara no encontrada")
    db.delete(db_camera)
    db.commit()
    return db_camera


# Endpoint para buscar reportes por incidente
@app.get("/reports/search/incident", response_model=List[ReportModel])
def search_reports_incident(incident: Optional[str] = None, db: Session = Depends(get_db)):
    return db.query(Report).filter(Report.Incident.contains(incident)).all() if incident else db.query(Report).all()


# Endpoint para buscar reportes
@app.get("/reports/search/", response_model=List[ReportModel])
def search_reports(incident: Optional[str] = None, address: Optional[str] = None, date_time: Optional[datetime] = None,
                   db: Session = Depends(get_db)):
    query = db.query(Report)
    if incident:
        query = query.filter(Report.Incident.contains(incident))
    if address:
        query = query.filter(Report.Address.contains(address))
    if date_time:
        query = query.filter(Report.DateTime == date_time)
    return query.all()


# Endpoint para crear un nuevo reporte
@app.post("/reports/", response_model=ReportModel)
def create_report(report: ReportModel, db: Session = Depends(get_db)):
    db_report = Report(
        DateTime=report.DateTime,
        Address=report.Address,
        Incident=report.Incident,
        TrackingLink=report.TrackingLink,
        Image=report.Image
    )
    db.add(db_report)
    db.commit()
    db.refresh(db_report)
    return db_report


# Endpoint para actualizar un reporte existente
@app.put("/reports/{report_id}", response_model=ReportModel)
def update_report(report_id: int, updated_report: ReportModel, db: Session = Depends(get_db)):
    db_report = db.query(Report).filter(Report.Id == report_id).first()
    if not db_report:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")
    for key, value in updated_report.dict(exclude_unset=True).items():
        setattr(db_report, key, value)
    db.commit()
    db.refresh(db_report)
    return db_report


# Endpoint para eliminar un reporte
@app.delete("/reports/{report_id}", response_model=ReportModel)
def delete_report(report_id: int, db: Session = Depends(get_db)):
    db_report = db.query(Report).filter(Report.Id == report_id).first()
    if not db_report:
        raise HTTPException(status_code=404, detail="Reporte no encontrado")
    db.delete(db_report)
    db.commit()
    return db_report
