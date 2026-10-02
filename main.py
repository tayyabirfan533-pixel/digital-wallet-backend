import os
import json
import hashlib
from datetime import datetime, timedelta, timezone

import redis
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import (
    create_engine, Column, Integer, String, Float, DateTime,
    ForeignKey, Text, select
)
from sqlalchemy.orm import declarative_base, sessionmaker, Session

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./wallet.db")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
SECRET_KEY = os.getenv("SECRET_KEY", "wallet-secret-2026")
ALGORITHM = "HS256"

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2 = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

try:
    rdb = redis.from_url(REDIS_URL, decode_responses=True)
    rdb.ping()
    REDIS_OK = True
except Exception:
    rdb = None
    REDIS_OK = False

app = FastAPI(title="Digital Wallet & Transaction Management API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    email = Column(String(150), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="user")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Wallet(Base):
    __tablename__ = "wallets"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    balance = Column(Float, default=0.0)


class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    receiver_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    amount = Column(Float, nullable=False)
    status = Column(String(30), default="Completed")
    idempotency_key = Column(String(255), unique=True, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    message = Column(Text, nullable=False)
    is_read = Column(Integer, default=0)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


Base.metadata.create_all(bind=engine)


class Register(BaseModel):
    name: str
    email: str
    password: str


class Login(BaseModel):
    email: str
    password: str


class Deposit(BaseModel):
    amount: float


class Transfer(BaseModel):
    receiver_id: int
    amount: float
    idempotency_key: str


class ConnectionManager:
    def __init__(self):
        self.connections = {}

    async def connect(self, user_id, websocket):
        await websocket.accept()
        self.connections.setdefault(user_id, []).append(websocket)

    def disconnect(self, user_id, websocket):
        if user_id in self.connections and websocket in self.connections[user_id]:
            self.connections[user_id].remove(websocket)

    async def send(self, user_id, data):
        for ws in self.connections.get(user_id, []):
            try:
                await ws.send_json(data)
            except Exception:
                pass


manager = ConnectionManager()


def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def create_token(user_id):
    payload = {
        "sub": str(user_id),
        "exp": datetime.now(timezone.utc) + timedelta(days=1),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def current_user(token: str = Depends(oauth2), session: Session = Depends(db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload["sub"])
    except (JWTError, ValueError, KeyError):
        raise HTTPException(status_code=401, detail="Invalid token")

    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user


def notify(session, user_id, message):
    n = Notification(user_id=user_id, message=message)
    session.add(n)


@app.get("/")
def root():
    return {
        "message": "Digital Wallet API is running",
        "docs": "/docs",
        "redis": REDIS_OK,
    }


@app.get("/health")
def health():
    return {"status": "healthy", "redis": REDIS_OK}


@app.post("/api/auth/register")
def register(data: Register, session: Session = Depends(db)):
    email = data.email.lower().strip()

    if session.scalar(select(User).where(User.email == email)):
        raise HTTPException(400, "Email already registered")

    user = User(
        name=data.name,
        email=email,
        password_hash=pwd.hash(data.password),
    )
    session.add(user)
    session.flush()

    session.add(Wallet(user_id=user.id, balance=0))
    session.commit()

    return {
        "message": "User registered successfully",
        "user_id": user.id,
    }


@app.post("/api/auth/login")
def login(data: Login, session: Session = Depends(db)):
    user = session.scalar(
        select(User).where(User.email == data.email.lower().strip())
    )

    if not user or not pwd.verify(data.password, user.password_hash):
        raise HTTPException(401, "Invalid email or password")

    return {
        "access_token": create_token(user.id),
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "name": user.name,
            "email": user.email,
            "role": user.role,
        },
    }


@app.get("/api/me")
def me(user: User = Depends(current_user), session: Session = Depends(db)):
    wallet = session.scalar(select(Wallet).where(Wallet.user_id == user.id))

    return {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "role": user.role,
        "balance": wallet.balance if wallet else 0,
    }


@app.post("/api/wallet/deposit")
def deposit(
    data: Deposit,
    user: User = Depends(current_user),
    session: Session = Depends(db),
):
    if data.amount <= 0:
        raise HTTPException(400, "Amount must be greater than zero")

    wallet = session.scalar(
        select(Wallet)
        .where(Wallet.user_id == user.id)
        .with_for_update()
    )

    wallet.balance += data.amount

    transaction = Transaction(
        receiver_id=user.id,
        amount=data.amount,
        status="Completed",
    )
    session.add(transaction)
    notify(session, user.id, f"Deposit of {data.amount} completed")
    session.commit()

    return {
        "message": "Deposit successful",
        "balance": wallet.balance,
        "transaction_id": transaction.id,
    }


@app.post("/api/transfers")
async def transfer(
    data: Transfer,
    user: User = Depends(current_user),
    session: Session = Depends(db),
):
    if data.amount <= 0:
        raise HTTPException(400, "Amount must be greater than zero")

    if data.receiver_id == user.id:
        raise HTTPException(400, "Cannot transfer to yourself")

    # Redis idempotency check
    if REDIS_OK:
        redis_key = f"idempotency:{user.id}:{data.idempotency_key}"
        if rdb.get(redis_key):
            raise HTTPException(409, "Duplicate transfer request")

        rdb.setex(redis_key, 86400, "processing")

    existing = session.scalar(
        select(Transaction).where(
            Transaction.idempotency_key == data.idempotency_key
        )
    )

    if existing:
        raise HTTPException(409, "Duplicate transfer request")

    sender_wallet = session.scalar(
        select(Wallet)
        .where(Wallet.user_id == user.id)
        .with_for_update()
    )

    receiver_wallet = session.scalar(
        select(Wallet)
        .where(Wallet.user_id == data.receiver_id)
        .with_for_update()
    )

    if not receiver_wallet:
        if REDIS_OK:
            rdb.delete(redis_key)
        raise HTTPException(404, "Receiver not found")

    if sender_wallet.balance < data.amount:
        if REDIS_OK:
            rdb.delete(redis_key)
        raise HTTPException(400, "Insufficient balance")

    sender_wallet.balance -= data.amount
    receiver_wallet.balance += data.amount

    transaction = Transaction(
        sender_id=user.id,
        receiver_id=data.receiver_id,
        amount=data.amount,
        status="Completed",
        idempotency_key=data.idempotency_key,
    )

    session.add(transaction)

    notify(
        session,
        user.id,
        f"Transfer of {data.amount} completed",
    )
    notify(
        session,
        data.receiver_id,
        f"You received {data.amount}",
    )

    session.commit()

    if REDIS_OK:
        rdb.setex(redis_key, 86400, str(transaction.id))

    await manager.send(
        user.id,
        {
            "type": "wallet_update",
            "message": "Transfer completed",
            "balance": sender_wallet.balance,
        },
    )

    await manager.send(
        data.receiver_id,
        {
            "type": "wallet_update",
            "message": "Money received",
            "balance": receiver_wallet.balance,
        },
    )

    return {
        "message": "Transfer completed",
        "transaction_id": transaction.id,
        "status": transaction.status,
        "balance": sender_wallet.balance,
    }


@app.get("/api/transactions")
def transactions(
    page: int = 1,
    limit: int = 10,
    status: str | None = None,
    user: User = Depends(current_user),
    session: Session = Depends(db),
):
    page = max(page, 1)
    limit = min(max(limit, 1), 100)

    query = select(Transaction).where(
        (Transaction.sender_id == user.id)
        | (Transaction.receiver_id == user.id)
    )

    if status:
        query = query.where(Transaction.status == status)

    query = query.order_by(Transaction.id.desc())
    rows = session.scalars(query.offset((page - 1) * limit).limit(limit)).all()

    return {
        "page": page,
        "limit": limit,
        "transactions": [
            {
                "id": t.id,
                "sender_id": t.sender_id,
                "receiver_id": t.receiver_id,
                "amount": t.amount,
                "status": t.status,
                "created_at": t.created_at,
            }
            for t in rows
        ],
    }


@app.get("/api/notifications")
def notifications(
    user: User = Depends(current_user),
    session: Session = Depends(db),
):
    rows = session.scalars(
        select(Notification)
        .where(Notification.user_id == user.id)
        .order_by(Notification.id.desc())
    ).all()

    return [
        {
            "id": n.id,
            "message": n.message,
            "is_read": n.is_read,
            "created_at": n.created_at,
        }
        for n in rows
    ]


@app.get("/api/admin/analytics")
def admin_analytics(
    user: User = Depends(current_user),
    session: Session = Depends(db),
):
    if user.role != "admin":
        raise HTTPException(403, "Admin access required")

    users = session.query(User).count()
    wallet_balance = sum(
        w.balance for w in session.query(Wallet).all()
    )
    transaction_count = session.query(Transaction).count()
    completed = session.query(Transaction).filter(
        Transaction.status == "Completed"
    ).count()

    return {
        "total_users": users,
        "total_wallet_balance": wallet_balance,
        "total_transactions": transaction_count,
        "completed_transactions": completed,
    }


@app.websocket("/ws/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: int):
    await manager.connect(user_id, websocket)

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(user_id, websocket)