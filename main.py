
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.openapi.utils import get_openapi
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator
from typing import Optional, List
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from uuid import uuid4

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

users_db = {}
events_db = {}
changelogs_db = {}

SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class UserCreate(BaseModel):
    username: str
    password: str
    role: str

class Token(BaseModel):
    access_token: str
    token_type: str

class EventCreate(BaseModel):
    title: str
    description: str
    location: str
    start_time: datetime
    end_time: datetime

    @validator('start_time', 'end_time', pre=True)
    def parse_datetime(cls, value):
        if isinstance(value, str) and value.endswith('Z'):
            return value[:-1]
        return value

class EventUpdate(BaseModel):
    title: Optional[str]
    description: Optional[str]
    location: Optional[str]
    start_time: Optional[datetime]
    end_time: Optional[datetime]

class Event(EventCreate):
    id: str
    owner: str

class Changelog(BaseModel):
    id: str
    event_id: str
    changed_by: str
    timestamp: datetime
    field_changed: str
    old_value: str
    new_value: str

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None or username not in users_db:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
        return users_db[username]
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

@app.post("/register", status_code=201)
def register(new_user: UserCreate):
    if new_user.username in users_db:
        raise HTTPException(status_code=400, detail="Username already exists")
    users_db[new_user.username] = {
        "username": new_user.username,
        "hashed_password": get_password_hash(new_user.password),
        "role": new_user.role
    }
    return {"msg": "User registered successfully"}

@app.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": form_data.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/events/", response_model=Event)
def create_event(new_event: EventCreate, current_user: dict = Depends(get_current_user)):
    if current_user["role"] not in ["admin", "editor"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not authorized to create events")
    event_id = str(uuid4())
    event_obj = new_event.dict()
    event_obj.update({"id": event_id, "owner": current_user["username"]})
    events_db[event_id] = event_obj
    return event_obj

from fastapi import Path

@app.get("/events/", response_model=List[Event])
def list_events():
    return list(events_db.values())

@app.put("/events/{event_id}", response_model=Event)
def update_event(
    event_id: str = Path(..., description="The ID of the event to update"),
    updates: EventUpdate = Depends(),
    current_user: dict = Depends(get_current_user)
):
    event = events_db.get(event_id)
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")

    if current_user["role"] not in ["admin", "editor"]:
        raise HTTPException(status_code=403, detail="Not authorized to update events")

    updated_fields = updates.dict(exclude_unset=True)
    for field, value in updated_fields.items():
        # Save changelog for each changed field
        changelogs_db.setdefault(event_id, []).append({
            "id": str(uuid4()),
            "event_id": event_id,
            "changed_by": current_user["username"],
            "timestamp": datetime.utcnow(),
            "field_changed": field,
            "old_value": str(event.get(field)),
            "new_value": str(value)
        })
        event[field] = value

    return event

@app.get("/events/{event_id}/changelog", response_model=List[Changelog])
def get_changelog(event_id: str, current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admin can view changelog")
    return changelogs_db.get(event_id, [])


# Other routes omitted for brevity ...

@app.get("/")
def read_root():
    return {"message": "Welcome to the Collaborative Event Management API. Visit /docs to explore."}

def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title="Collaborative Event Management System",
        version="1.0.0",
        description="API for managing events collaboratively with JWT auth",
        routes=app.routes,
    )

    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }

    for path in openapi_schema["paths"].values():
        for method in path.values():
            method.setdefault("security", []).append({"BearerAuth": []})

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi
