from fastapi import FastAPI
from interface.api import app as fastapi_app
from infrastructure.database import engine
from domain.models import Base
from dotenv import load_dotenv
from fastapi.middleware.cors import CORSMiddleware

# Cargar las variables de entorno del archivo .env
load_dotenv()

# Crear las tablas en la base de datos
Base.metadata.create_all(bind=engine)

# Crear la instancia de FastAPI
app = FastAPI()

# Configura CORS
origins = [
    "http://localhost",
    "https://zuri-alarm.vercel.app/",
]

methods = ["GET", "POST", "PUT", "DELETE"]

headers = ["Content-Type", "Authorization"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=methods,
    allow_headers=headers,
)

# Incluir la aplicación FastAPI configurada en la capa de interfaz (Ejemplo de link: http://localhost:8000/api)
app.mount("/api", fastapi_app)

#if __name__ == "__main__":
#    import uvicorn
#    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
