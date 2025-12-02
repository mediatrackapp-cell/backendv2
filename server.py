from fastapi import FastAPI, APIRouter, HTTPException
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
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets


ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# Create the main app without a prefix
app = FastAPI()

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")


# Define Models
class UserRegistration(BaseModel):
    model_config = ConfigDict(extra="ignore")
    
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    client_name: str
    email: EmailStr
    verification_token: str = Field(default_factory=lambda: secrets.token_urlsafe(32))
    is_verified: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    verified_at: Optional[datetime] = None

class RegistrationCreate(BaseModel):
    client_name: str
    email: EmailStr

class VerificationRequest(BaseModel):
    token: str

# Email sending function
async def send_verification_email(email: str, name: str, token: str):
    """Send verification email using Gmail SMTP"""
    try:
        gmail_user = os.environ.get('GMAIL_USER')
        gmail_password = os.environ.get('GMAIL_APP_PASSWORD')
        
        if not gmail_user or not gmail_password:
            logging.error("Gmail credentials not configured")
            return False
        
        # Get frontend URL from environment
        frontend_url = os.environ.get('FRONTEND_URL', 'http://localhost:3000')
        verification_link = f"{frontend_url}/verify?token={token}"
        
        # Create message
        message = MIMEMultipart("alternative")
        message["Subject"] = "Verify Your Email - Registration Confirmation"
        message["From"] = gmail_user
        message["To"] = email
        
        # Email body
        html = f"""
        <html>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                <div style="max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                    <h2 style="color: #4F46E5;">Welcome, {name}!</h2>
                    <p>Thank you for registering. Please verify your email address to complete your registration.</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="{verification_link}" 
                           style="background-color: #4F46E5; color: white; padding: 12px 30px; 
                                  text-decoration: none; border-radius: 5px; display: inline-block;">
                            Verify Email
                        </a>
                    </div>
                    <p style="color: #666; font-size: 14px;">
                        Or copy and paste this link into your browser:<br>
                        <a href="{verification_link}">{verification_link}</a>
                    </p>
                    <p style="color: #999; font-size: 12px; margin-top: 30px;">
                        If you didn't register for this account, please ignore this email.
                    </p>
                </div>
            </body>
        </html>
        """
        
        part = MIMEText(html, "html")
        message.attach(part)
        
        # Send email
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(gmail_user, gmail_password)
            server.send_message(message)
        
        logging.info(f"Verification email sent to {email}")
        return True
        
    except Exception as e:
        logging.error(f"Failed to send email: {str(e)}")
        return False

# Add your routes to the router instead of directly to app
@api_router.get("/")
async def root():
    return {"message": "Registration API with Email Verification"}

@api_router.post("/register")
async def register_user(input: RegistrationCreate):
    """Register a new user and send verification email"""
    try:
        # Check if email already exists
        existing_user = await db.users.find_one({"email": input.email}, {"_id": 0})
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        # Create user object
        user = UserRegistration(**input.model_dump())
        
        # Convert to dict and serialize datetime
        doc = user.model_dump()
        doc['created_at'] = doc['created_at'].isoformat()
        
        # Save to database
        await db.users.insert_one(doc)
        
        # Send verification email
        email_sent = await send_verification_email(
            user.email, 
            user.client_name, 
            user.verification_token
        )
        
        if not email_sent:
            logging.warning(f"User registered but email not sent: {user.email}")
        
        return {
            "message": "Registration successful! Please check your email to verify your account.",
            "email": user.email,
            "id": user.id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Registration error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")

@api_router.get("/verify")
async def verify_email(token: str):
    """Verify user email with token"""
    try:
        # Find user by token
        user = await db.users.find_one({"verification_token": token}, {"_id": 0})
        
        if not user:
            raise HTTPException(status_code=404, detail="Invalid verification token")
        
        if user.get('is_verified'):
            return {"message": "Email already verified", "verified": True}
        
        # Update user as verified
        await db.users.update_one(
            {"verification_token": token},
            {
                "$set": {
                    "is_verified": True,
                    "verified_at": datetime.now(timezone.utc).isoformat()
                }
            }
        )
        
        return {
            "message": "Email verified successfully!",
            "verified": True,
            "client_name": user['client_name']
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Verification error: {str(e)}")
        raise HTTPException(status_code=500, detail="Verification failed")

@api_router.get("/users")
async def get_users():
    """Get all registered users"""
    users = await db.users.find({}, {"_id": 0, "verification_token": 0}).to_list(1000)
    
    # Convert ISO string timestamps back to datetime objects
    for user in users:
        if isinstance(user.get('created_at'), str):
            user['created_at'] = datetime.fromisoformat(user['created_at'])
        if user.get('verified_at') and isinstance(user['verified_at'], str):
            user['verified_at'] = datetime.fromisoformat(user['verified_at'])
    
    return users

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()