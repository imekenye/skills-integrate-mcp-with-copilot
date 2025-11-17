"""
In-memory database simulation for users and activities
TODO: Replace with actual database in production
"""
from typing import Dict, Optional
from models import UserInDB, UserRole, User, UserCreate
from auth import get_password_hash
import uuid


class Database:
    def __init__(self):
        # In-memory user storage
        self.users: Dict[str, UserInDB] = {}
        self.users_by_username: Dict[str, str] = {}  # username -> user_id mapping
        self.users_by_email: Dict[str, str] = {}     # email -> user_id mapping
        
        # Initialize with some default users
        self._create_default_users()
    
    def _create_default_users(self):
        """Create default users for testing"""
        # Federation Admin
        admin_user = UserCreate(
            email="admin@mergington.edu",
            username="admin",
            full_name="System Administrator",
            password="admin123",
            role=UserRole.FEDERATION_ADMIN
        )
        self.create_user(admin_user)
        
        # Club Admin (Teacher)
        teacher_user = UserCreate(
            email="teacher@mergington.edu",
            username="teacher",
            full_name="Ms. Johnson",
            password="teacher123",
            role=UserRole.CLUB_ADMIN
        )
        self.create_user(teacher_user)
        
        # Student
        student_user = UserCreate(
            email="student@mergington.edu",
            username="student",
            full_name="John Doe",
            password="student123",
            role=UserRole.STUDENT
        )
        self.create_user(student_user)
    
    def create_user(self, user_data: UserCreate) -> UserInDB:
        """Create a new user"""
        # Check if username or email already exists
        if user_data.username in self.users_by_username:
            raise ValueError("Username already exists")
        if user_data.email in self.users_by_email:
            raise ValueError("Email already exists")
        
        # Create user
        user_id = str(uuid.uuid4())
        hashed_password = get_password_hash(user_data.password)
        
        db_user = UserInDB(
            id=user_id,
            email=user_data.email,
            username=user_data.username,
            full_name=user_data.full_name,
            role=user_data.role,
            is_active=True,
            hashed_password=hashed_password
        )
        
        # Store user
        self.users[user_id] = db_user
        self.users_by_username[user_data.username] = user_id
        self.users_by_email[user_data.email] = user_id
        
        return db_user
    
    def get_user_by_username(self, username: str) -> Optional[UserInDB]:
        """Get user by username"""
        user_id = self.users_by_username.get(username)
        if user_id:
            return self.users.get(user_id)
        return None
    
    def get_user_by_email(self, email: str) -> Optional[UserInDB]:
        """Get user by email"""
        user_id = self.users_by_email.get(email)
        if user_id:
            return self.users.get(user_id)
        return None
    
    def get_user_by_id(self, user_id: str) -> Optional[UserInDB]:
        """Get user by ID"""
        return self.users.get(user_id)
    
    def authenticate_user(self, username: str, password: str) -> Optional[UserInDB]:
        """Authenticate user with username and password"""
        from auth import verify_password
        
        user = self.get_user_by_username(username)
        if not user:
            return None
        if not verify_password(password, user.hashed_password):
            return None
        if not user.is_active:
            return None
        return user


# Global database instance
db = Database()