from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from recommender import analyze_password


app = FastAPI(
    title="Secure Password Recommendation API",
    description="ML-powered password strength and security recommendation system.",
    version="1.0.0"
)


# Allow your frontend to communicate with this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class PasswordRequest(BaseModel):
    password: str


@app.get("/")
def home():
    return {
        "status": "online",
        "service": "Password Recommendation System",
        "message": "ML engine is ready."
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.post("/analyze-password")
def analyze(request: PasswordRequest):

    password = request.password

    if not password:
        raise HTTPException(
            status_code=400,
            detail="Password cannot be empty."
        )

    if len(password) > 256:
        raise HTTPException(
            status_code=400,
            detail="Password is too long."
        )

    try:
        result = analyze_password(password)
        return result

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error)
        )