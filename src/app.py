"""
High School Management System API

A comprehensive FastAPI application with user authentication that allows students 
to view and sign up for extracurricular activities at Mergington High School.
"""

from datetime import timedelta
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import os
from pathlib import Path
from typing import List, Optional

from models import User, UserCreate, LoginRequest, Token, UserRole, ActivitySignup
from database import db
from auth import (
    verify_token, 
    create_access_token, 
    ACCESS_TOKEN_EXPIRE_MINUTES,
    verify_password
)

app = FastAPI(
    title="Mergington High School API",
    description="API for viewing and signing up for extracurricular activities with user authentication"
)

# Security scheme
security = HTTPBearer()

# Mount the static files directory
current_dir = Path(__file__).parent
app.mount("/static", StaticFiles(directory=os.path.join(Path(__file__).parent,
          "static")), name="static")

# In-memory activity database (converted to use user emails from authenticated users)
activities = {
    "Chess Club": {
        "description": "Learn strategies and compete in chess tournaments",
        "schedule": "Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 12,
        "participants": []
    },
    "Programming Class": {
        "description": "Learn programming fundamentals and build software projects",
        "schedule": "Tuesdays and Thursdays, 3:30 PM - 4:30 PM",
        "max_participants": 20,
        "participants": []
    },
    "Gym Class": {
        "description": "Physical education and sports activities",
        "schedule": "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM",
        "max_participants": 30,
        "participants": []
    },
    "Soccer Team": {
        "description": "Join the school soccer team and compete in matches",
        "schedule": "Tuesdays and Thursdays, 4:00 PM - 5:30 PM",
        "max_participants": 22,
        "participants": []
    },
    "Basketball Team": {
        "description": "Practice and play basketball with the school team",
        "schedule": "Wednesdays and Fridays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": []
    },
    "Art Club": {
        "description": "Explore your creativity through painting and drawing",
        "schedule": "Thursdays, 3:30 PM - 5:00 PM",
        "max_participants": 15,
        "participants": []
    },
    "Drama Club": {
        "description": "Act, direct, and produce plays and performances",
        "schedule": "Mondays and Wednesdays, 4:00 PM - 5:30 PM",
        "max_participants": 20,
        "participants": []
    },
    "Math Club": {
        "description": "Solve challenging problems and participate in math competitions",
        "schedule": "Tuesdays, 3:30 PM - 4:30 PM",
        "max_participants": 10,
        "participants": []
    },
    "Debate Team": {
        "description": "Develop public speaking and argumentation skills",
        "schedule": "Fridays, 4:00 PM - 5:30 PM",
        "max_participants": 12,
        "participants": []
    }
}


# Dependency to get current user from JWT token
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> User:
    """Get current authenticated user from JWT token"""
    token = credentials.credentials
    token_data = verify_token(token)
    
    user = db.get_user_by_username(token_data.username)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return User(
        id=user.id,
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        role=user.role,
        is_active=user.is_active
    )


# Optional authentication dependency (allows unauthenticated access)
async def get_current_user_optional(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Optional[User]:
    """Get current user if authenticated, None otherwise"""
    if not credentials:
        return None
    
    try:
        return await get_current_user(credentials)
    except HTTPException:
        return None


# Permission checking functions
def require_role(allowed_roles: List[UserRole]):
    """Dependency factory to require specific roles"""
    async def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        return current_user
    return role_checker


# Admin or Club Admin permissions
require_admin_permissions = require_role([UserRole.FEDERATION_ADMIN, UserRole.CLUB_ADMIN])
# Federation Admin only
require_federation_admin = require_role([UserRole.FEDERATION_ADMIN])


# Routes

@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


# Authentication endpoints
@app.post("/auth/register", response_model=User)
def register_user(user_data: UserCreate):
    """Register a new user"""
    try:
        db_user = db.create_user(user_data)
        return User(
            id=db_user.id,
            email=db_user.email,
            username=db_user.username,
            full_name=db_user.full_name,
            role=db_user.role,
            is_active=db_user.is_active
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/auth/login", response_model=Token)
def login(login_data: LoginRequest):
    """Authenticate user and return access token"""
    user = db.authenticate_user(login_data.username, login_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/auth/me", response_model=User)
def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information"""
    return current_user


# Activity endpoints
@app.get("/activities")
def get_activities(current_user: Optional[User] = Depends(get_current_user_optional)):
    """Get all activities (public endpoint, but shows different info based on auth)"""
    if current_user and current_user.role in [UserRole.CLUB_ADMIN, UserRole.FEDERATION_ADMIN]:
        # Admins see full participant details
        return activities
    else:
        # Students and unauthenticated users see limited info
        limited_activities = {}
        for name, details in activities.items():
            limited_activities[name] = {
                "description": details["description"],
                "schedule": details["schedule"],
                "max_participants": details["max_participants"],
                "participants": len(details["participants"]),  # Only count, not emails
                "spots_available": details["max_participants"] - len(details["participants"])
            }
        return limited_activities


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(
    activity_name: str, 
    current_user: User = Depends(get_current_user)
):
    """Sign up the current user for an activity (students only)"""
    # Only students can sign up for activities
    if current_user.role != UserRole.STUDENT:
        raise HTTPException(
            status_code=403, 
            detail="Only students can sign up for activities"
        )
    
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Check if activity is full
    if len(activity["participants"]) >= activity["max_participants"]:
        raise HTTPException(
            status_code=400,
            detail="Activity is full"
        )

    # Validate student is not already signed up
    if current_user.email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="You are already signed up for this activity"
        )

    # Add student
    activity["participants"].append(current_user.email)
    return {"message": f"Successfully signed up for {activity_name}"}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(
    activity_name: str,
    email: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """Unregister from an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Determine which email to unregister
    target_email = email
    
    if current_user.role == UserRole.STUDENT:
        # Students can only unregister themselves
        target_email = current_user.email
    elif current_user.role in [UserRole.CLUB_ADMIN, UserRole.FEDERATION_ADMIN]:
        # Admins can unregister others, but need email parameter
        if not email:
            raise HTTPException(
                status_code=400,
                detail="Email parameter required for admin operations"
            )
        target_email = email
    else:
        raise HTTPException(
            status_code=403,
            detail="Insufficient permissions"
        )

    # Validate student is signed up
    if target_email not in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is not signed up for this activity"
        )

    # Remove student
    activity["participants"].remove(target_email)
    return {"message": f"Successfully unregistered {target_email} from {activity_name}"}


@app.post("/activities/{activity_name}/register-student")
def admin_register_student(
    activity_name: str,
    signup_data: ActivitySignup,
    current_user: User = Depends(require_admin_permissions)
):
    """Admin endpoint to register a student for an activity"""
    # Validate activity exists
    if activity_name not in activities:
        raise HTTPException(status_code=404, detail="Activity not found")

    # Get the specific activity
    activity = activities[activity_name]

    # Check if activity is full
    if len(activity["participants"]) >= activity["max_participants"]:
        raise HTTPException(
            status_code=400,
            detail="Activity is full"
        )

    # Validate student is not already signed up
    if signup_data.user_email in activity["participants"]:
        raise HTTPException(
            status_code=400,
            detail="Student is already signed up for this activity"
        )

    # Add student
    activity["participants"].append(signup_data.user_email)
    return {"message": f"Successfully registered {signup_data.user_email} for {activity_name}"}


# User management endpoints (Federation Admin only)
@app.get("/users", response_model=List[User])
def list_users(current_user: User = Depends(require_federation_admin)):
    """List all users (Federation Admin only)"""
    users = []
    for user in db.users.values():
        users.append(User(
            id=user.id,
            email=user.email,
            username=user.username,
            full_name=user.full_name,
            role=user.role,
            is_active=user.is_active
        ))
    return users
