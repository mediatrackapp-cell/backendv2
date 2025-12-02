# server.py
from fastapi import FastAPI, APIRouter, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import jwt  # PyJWT
from passlib.context import CryptContext
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

# MongoDB connection
mongo_url = os.environ.get("MONGO_URL")
if not mongo_url:
    raise RuntimeError("MONGO_URL not set in environment")
db_name = os.environ.get("DB_NAME", "media_tracker")
client = AsyncIOMotorClient(mongo_url)
db = client[db_name]

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()
SECRET_KEY = os.environ.get("SECRET_KEY", secrets.token_urlsafe(32))
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", 60 * 24 * 7))  # default 7 days

# Email configuration
EMAIL_HOST = os.environ.get("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.environ.get("EMAIL_PORT", 587))
EMAIL_USERNAME = os.environ.get("EMAIL_USERNAME")
EMAIL_PASSWORD = os.environ.get("EMAIL_PASSWORD")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "http://localhost:3000")

# Create the main app
app = FastAPI()
api_router = APIRouter(prefix="/api")

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
    type: str  # manga, manhwa, manhua, anime
    status: str = "plan"  # plan, reading, completed, on-hold, dropped
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

# ========== HELPER FUNCTIONS ==========

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    # PyJWT expects a JSON-serializable exp (timestamp). Use int timestamp.
    to_encode.update({"exp": int(expire.timestamp())})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> User:
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user_doc = await db.users.find_one({"id": user_id}, {"_id": 0})
    if user_doc is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    # Ensure created_at is a datetime object (Motor stores whatever you inserted)
    if isinstance(user_doc.get("created_at"), str):
        try:
            user_doc["created_at"] = datetime.fromisoformat(user_doc["created_at"])
        except Exception:
            user_doc["created_at"] = datetime.now(timezone.utc)

    return User(**user_doc)

def send_verification_email(email: str, token: str, name: str):
    # This function raises HTTPException on failure so route can handle it if desired.
    if not EMAIL_USERNAME or not EMAIL_PASSWORD:
        logging.warning("EMAIL_USERNAME or EMAIL_PASSWORD not configured; skipping email send")
        return

    try:
        verification_link = f"{FRONTEND_URL}?verify={token}"

        msg = MIMEMultipart("alternative")
        msg["Subject"] = "Verify Your Email - Media Tracker"
        msg["From"] = EMAIL_USERNAME
        msg["To"] = email

        html = f"""
        <html>
          <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
              <h2 style="color: #26c6da;">Welcome to Media Tracker, {name}!</h2>
              <p>Thank you for signing up. Please verify your email address to complete your registration.</p>
              <div style="margin: 30px 0;">
                <a href="{verification_link}" 
                   style="background: linear-gradient(135deg, #26c6da 0%, #00acc1 100%);
                          color: white;
                          padding: 12px 30px;
                          text-decoration: none;
                          border-radius: 8px;
                          display: inline-block;
                          font-weight: bold;">
                  Verify Email
                </a>
              </div>
              <p style="color: #666; font-size: 14px;">
                Or copy and paste this link into your browser:<br>
                <a href="{verification_link}" style="color: #26c6da;">{verification_link}</a>
              </p>
              <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
              <p style="color: #999; font-size: 12px;">
                If you didn't create an account, you can safely ignore this email.
              </p>
            </div>
          </body>
        </html>
        """

        part = MIMEText(html, "html")
        msg.attach(part)

        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
            server.send_message(msg)

        logging.info(f"Verification email sent to {email}")
    except Exception as e:
        logging.error(f"Failed to send email: {str(e)}")
        # don't raise here — let signup succeed even if email fails,
        # but log the error. If you want to fail signup on email error, re-raise.
        # raise HTTPException(status_code=500, detail="Failed to send verification email")

# ========== AUTH ROUTES ==========

@api_router.post("/auth/signup")
async def signup(user_data: UserSignup):
    # Check if user already exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Create verification token
    verification_token = secrets.token_urlsafe(32)

    # Create user
    user = User(
        email=user_data.email,
        name=user_data.name,
        hashed_password=hash_password(user_data.password),
        verification_token=verification_token,
        is_verified=False
    )

    # Save to database
    user_dict = user.model_dump()
    # store ISO strings for datetimes so DB contains JSON-serializable values
    user_dict["created_at"] = user_dict["created_at"].isoformat()
    await db.users.insert_one(user_dict)

    # Try to send verification email (non-blocking)
    try:
        send_verification_email(user_data.email, verification_token, user_data.name)
    except Exception:
        logging.exception("Email sending failed; registration still created")

    return {
        "message": "Registration successful! Please check your email to verify your account.",
        "email": user_data.email
    }

@api_router.get("/auth/verify-email")
async def verify_email(token: str):
    user_doc = await db.users.find_one({"verification_token": token})
    if not user_doc:
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")

    # Update user as verified
    await db.users.update_one(
        {"verification_token": token},
        {"$set": {"is_verified": True, "verification_token": None}}
    )

    return {"message": "Email verified successfully! You can now log in."}

@api_router.post("/auth/login", response_model=Token)
async def login(user_data: UserLogin):
    # Find user
    user_doc = await db.users.find_one({"email": user_data.email}, {"_id": 0})
    if not user_doc:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # Normalize created_at to datetime for Pydantic model
    if isinstance(user_doc.get("created_at"), str):
        try:
            user_doc["created_at"] = datetime.fromisoformat(user_doc["created_at"])
        except Exception:
            user_doc["created_at"] = datetime.now(timezone.utc)

    user = User(**user_doc)

    # Verify password
    if not verify_password(user_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # Check if verified
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Please verify your email before logging in")

    # Create access token (include 'sub' for user id)
    access_token = create_access_token(data={"sub": user.id, "email": user.email})

    user_response = UserResponse(
        id=user.id,
        email=user.email,
        name=user.name,
        is_verified=user.is_verified
    )

    return Token(access_token=access_token, user=user_response)

@api_router.get("/auth/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        name=current_user.name,
        is_verified=current_user.is_verified
    )

# ========== MEDIA ROUTES ==========

@api_router.post("/media", response_model=MediaItem)
async def create_media(media_data: MediaItemCreate, current_user: User = Depends(get_current_user)):
    media = MediaItem(
        user_id=current_user.id,
        title=media_data.title,
        type=media_data.type,
        status=media_data.status,
        current=media_data.current,
        total=media_data.total
    )

    media_dict = media.model_dump()
    media_dict["created_at"] = media_dict["created_at"].isoformat()
    media_dict["updated_at"] = media_dict["updated_at"].isoformat()

    await db.media.insert_one(media_dict)
    return media

@api_router.get("/media", response_model=List[MediaItem])
async def get_media(current_user: User = Depends(get_current_user)):
    media_items = await db.media.find({"user_id": current_user.id}, {"_id": 0}).to_list(1000)

    # Convert ISO strings back to datetime
    for item in media_items:
        if isinstance(item.get("created_at"), str):
            item["created_at"] = datetime.fromisoformat(item["created_at"])
        if isinstance(item.get("updated_at"), str):
            item["updated_at"] = datetime.fromisoformat(item["updated_at"])

    return media_items

@api_router.put("/media/{media_id}", response_model=MediaItem)
async def update_media(
    media_id: str,
    media_data: MediaItemUpdate,
    current_user: User = Depends(get_current_user)
):
    # Find media item
    media_doc = await db.media.find_one({"id": media_id, "user_id": current_user.id}, {"_id": 0})
    if not media_doc:
        raise HTTPException(status_code=404, detail="Media item not found")

    # Update fields
    update_data = media_data.model_dump(exclude_unset=True)
    update_data["updated_at"] = datetime.now(timezone.utc).isoformat()

    await db.media.update_one(
        {"id": media_id, "user_id": current_user.id},
        {"$set": update_data}
    )

    # Get updated media
    updated_media = await db.media.find_one({"id": media_id}, {"_id": 0})

    # Convert ISO strings back
    if isinstance(updated_media.get("created_at"), str):
        updated_media["created_at"] = datetime.fromisoformat(updated_media["created_at"])
    if isinstance(updated_media.get("updated_at"), str):
        updated_media["updated_at"] = datetime.fromisoformat(updated_media["updated_at"])

    return MediaItem(**updated_media)

@api_router.delete("/media/{media_id}")
async def delete_media(media_id: str, current_user: User = Depends(get_current_user)):
    result = await db.media.delete_one({"id": media_id, "user_id": current_user.id})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Media item not found")
    return {"message": "Media item deleted successfully"}

# ========== BASIC ROUTES ==========

@api_router.get("/")
async def root():
    return {"message": "Media Tracker API", "status": "running"}

# Include router
app.include_router(api_router)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
