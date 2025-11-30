from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from LSD import model
from LSD.database import engine, Base
from LSD.routers import sqli, user, history, chatbot

app = FastAPI()
model.Base.metadata.create_all(bind=engine)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve frontend files
try:
    app.mount("/frontend", StaticFiles(directory="frontend"), name="frontend")
except:
    pass

@app.get("/health")
async def health_check():
    return {"status": "ok"}

app.include_router(user.router)
app.include_router(sqli.router)
app.include_router(chatbot.router)
app.include_router(history.router)