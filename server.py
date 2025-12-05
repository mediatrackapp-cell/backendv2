# server.py
import os
import secrets
import logging
import threading
from pathlib import Path
from datetime import datetime, timezone, timedelta
from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
import jwt
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
from typing import List, Optional
import uuid

# ========== ENVIRONMENT ==========
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

MONGO_URL = os.environ.get("MONGO_URL")
DB_NAME = os.environ.get("DB_NAME", "media_tracker")
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_urlsafe(32))
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", 60 * 24 * 7))

EMAIL_HOST = os.environ.get("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.environ.get("EMAIL_PORT", 587))
EMAIL_USERNAME = os.environ.get("EMAIL_USERNAME")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:3000")

# ========== DATABASE ==========
if not MONGO_URL:
    raise RuntimeError("MONGO_URL not set in environment")
client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]

# ========== SECURITY ==========
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()
ALGORITHM = "HS256"

# ========== APP SETUP ==========
app = FastAPI()
api_router = APIRouter(prefix="/api")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*",
        "https://frontendv2-x6m0.onrender.com",
        "http://localhost:3000",
        "https://backendv2-t8my.onrender.com"  # add this
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ========== MODELS ==========
class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    name: str
    hashed_password: str
    is_verified: bool = False
    verification_token: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserSignup(BaseModel):
    email: EmailStr
    password: str
    name: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    is_verified: bool

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class MediaItem(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    title: str
    type: str
    status: str = "plan"
    current: int = 0
    total: int = 0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class MediaItemCreate(BaseModel):
    title: str
    type: str
    status: str = "plan"
    current: int = 0
    total: int = 0

class MediaItemUpdate(BaseModel):
    title: Optional[str] = None
    type: Optional[str] = None
    status: Optional[str] = None
    current: Optional[int] = None
    total: Optional[int] = None

# ========== HELPERS ==========
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": int(expire.timestamp())})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> User:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token payload")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_doc = await db.users.find_one({"id": user_id}, {"_id": 0})
    if not user_doc:
        raise HTTPException(status_code=401, detail="User not found")
    if isinstance(user_doc.get("created_at"), str):
        user_doc["created_at"] = datetime.fromisoformat(user_doc["created_at"])
    return User(**user_doc)

def send_verification_email(email: str, token: str, name: str):
    if not EMAIL_USERNAME or not EMAIL_PASSWORD:
        logger.warning("Email credentials not configured; skipping email send")
        return

    try:
        verification_link = f"{FRONTEND_URL}?verify={token}"

        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Verify Your Email - Media Tracker"
        msg["From"] = EMAIL_USERNAME
        msg["To"] = email

        html = f"""
        <html>
          <body>
            <h2>Welcome {name}!</h2>
            <p>Click below to verify your email:</p>
            <a href="{verification_link}">Verify Email</a>
          </body>
        </html>
        """

        msg.attach(MIMEText(html, "html"))

        # ✔ Correct Gmail mode
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
            server.sendmail(EMAIL_USERNAME, email, msg.as_string())

        logger.info(f"Verification email sent to {email}")

    except Exception as e:
        logger.error(f"Email send failed: {e}")

        
def send_verification_email_async(email, token, name):
    threading.Thread(target=send_verification_email, args=(email, token, name)).start()



# ========== AUTH ROUTES ==========
@api_router.post("/auth/signup")
async def signup(user_data: UserSignup):
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    verification_token = secrets.token_urlsafe(32)
    user = User(
        email=user_data.email,
        name=user_data.name,
        hashed_password=hash_password(user_data.password),
        verification_token=verification_token,
        is_verified=False
    )

    user_dict = user.model_dump()
    user_dict["created_at"] = user_dict["created_at"].isoformat()
    await db.users.insert_one(user_dict)

    send_verification_email_async(user.email, verification_token, user.name)

    return {"message": "Registration successful. Check your email!", "email": user.email}

@api_router.get("/auth/verify-email")
async def verify_email(token: str):
    user_doc = await db.users.find_one({"verification_token": token})
    if not user_doc:
        raise HTTPException(status_code=400, detail="Invalid or expired token")
    await db.users.update_one(
        {"verification_token": token},
        {"$set": {"is_verified": True, "verification_token": None}}
    )
    return {"message": "Email verified successfully!"}

@api_router.post("/auth/login", response_model=Token)
async def login(user_data: UserLogin):
    user_doc = await db.users.find_one({"email": user_data.email}, {"_id": 0})
    if not user_doc:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if isinstance(user_doc.get("created_at"), str):
        user_doc["created_at"] = datetime.fromisoformat(user_doc["created_at"])
    user = User(**user_doc)

    if not verify_password(user_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Verify your email first")

    access_token = create_access_token({"sub": user.id, "email": user.email})
    user_response = UserResponse(id=user.id, email=user.email, name=user.name, is_verified=user.is_verified)
    return Token(access_token=access_token, user=user_response)

@api_router.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return UserResponse(id=current_user.id, email=current_user.email, name=current_user.name, is_verified=current_user.is_verified)

# ========== MEDIA ROUTES ==========
@api_router.post("/media", response_model=MediaItem)
async def create_media(media_data: MediaItemCreate, current_user: User = Depends(get_current_user)):
    media = MediaItem(user_id=current_user.id, **media_data.model_dump())
    media_dict = media.model_dump()
    media_dict["created_at"] = media_dict["created_at"].isoformat()
    media_dict["updated_at"] = media_dict["updated_at"].isoformat()
    await db.media.insert_one(media_dict)
    return media

@api_router.get("/media", response_model=List[MediaItem])
async def get_media(current_user: User = Depends(get_current_user)):
    items = await db.media.find({"user_id": current_user.id}, {"_id": 0}).to_list(1000)
    for item in items:
        if isinstance(item.get("created_at"), str):
            item["created_at"] = datetime.fromisoformat(item["created_at"])
        if isinstance(item.get("updated_at"), str):
            item["updated_at"] = datetime.fromisoformat(item["updated_at"])
    return items

@api_router.put("/media/{media_id}", response_model=MediaItem)
async def update_media(media_id: str, media_data: MediaItemUpdate, current_user: User = Depends(get_current_user)):
    media_doc = await db.media.find_one({"id": media_id, "user_id": current_user.id}, {"_id": 0})
    if not media_doc:
        raise HTTPException(status_code=404, detail="Media not found")

    update_data = media_data.model_dump(exclude_unset=True)
    update_data["updated_at"] = datetime.now(timezone.utc).isoformat()
    await db.media.update_one({"id": media_id, "user_id": current_user.id}, {"$set": update_data})

    updated_media = await db.media.find_one({"id": media_id}, {"_id": 0})
    updated_media["created_at"] = datetime.fromisoformat(updated_media["created_at"])
    updated_media["updated_at"] = datetime.fromisoformat(updated_media["updated_at"])
    return MediaItem(**updated_media)

@api_router.delete("/media/{media_id}")
async def delete_media(media_id: str, current_user: User = Depends(get_current_user)):
    result = await db.media.delete_one({"id": media_id, "user_id": current_user.id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Media not found")
    return {"message": "Media deleted successfully"}

# ========== BASIC ROUTE ==========
@api_router.get("/")
async def root():
    return {"message": "Media Tracker API running"}

# Include router
app.include_router(api_router)

# Shutdown
@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()


#
@app.get("/debug/env")
async def debug_env():
    return {
        "mongo": bool(os.getenv("MONGO_URL")),
        "db_name": os.getenv("DB_NAME"),
        "email_user": os.getenv("EMAIL_USERNAME"),
        "email_password": "SET" if os.getenv("EMAIL_PASSWORD") else "MISSING",
        "frontend": os.getenv("FRONTEND_URL"),
        "secret_key": "SET" if os.getenv("SECRET_KEY") else "MISSING"
    }

@api_router.post("/auth/resend-verification")
async def resend_verification(email: dict):
    user_email = email.get("email")
    if not user_email:
        raise HTTPException(status_code=400, detail="Email is required")

    # Find user
    user_doc = await db.users.find_one({"email": user_email})
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found")

    # Check if already verified
    if user_doc.get("is_verified"):
        return {"message": "Email is already verified"}

    # Generate new token
    new_token = secrets.token_urlsafe(32)

    # Update database
    await db.users.update_one(
        {"email": user_email},
        {"$set": {"verification_token": new_token}}
    )

    # Send email
    send_verification_email(user_email, new_token, user_doc.get("name", ""))

    return {"message": "Verification email resent successfully"}



app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # allow all origins for testing
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)













