"""
Database models for the High School Management System
"""
from typing import Optional, List
from pydantic import BaseModel, EmailStr
from enum import Enum


class UserRole(str, Enum):
    STUDENT = "student"
    CLUB_ADMIN = "club_admin"
    FEDERATION_ADMIN = "federation_admin"


class UserBase(BaseModel):
    email: EmailStr
    username: str
    full_name: str
    role: UserRole = UserRole.STUDENT
    is_active: bool = True


class UserCreate(UserBase):
    password: str


class UserUpdate(BaseModel):
    username: Optional[str] = None
    full_name: Optional[str] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None


class User(UserBase):
    id: str
    
    class Config:
        from_attributes = True


class UserInDB(User):
    hashed_password: str


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class LoginRequest(BaseModel):
    username: str
    password: str


class ActivitySignup(BaseModel):
    activity_name: str
    user_email: str