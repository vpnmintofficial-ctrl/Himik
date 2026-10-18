import os
import asyncio
import sqlite3
import hashlib
import hmac
import time
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

from aiogram import Bot, Dispatcher, F
from aiogram.types import Message
from aiogram.filters import CommandStart

load_dotenv()

BOT_TOKEN = os.getenv("BOT_TOKEN")
ADMIN_TG_ID = int(os.getenv("ADMIN_TG_ID", "8667961334"))
DB_PATH = os.getenv("DB_PATH", "/tmp/doxtox.db")

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher()


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            tg_id INTEGER UNIQUE NOT NULL,
            city TEXT DEFAULT '',
            bio TEXT DEFAULT '',
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_username TEXT NOT NULL,
            to_username TEXT NOT NULL,
            text TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            delivered_tg INTEGER DEFAULT 0
        );
        """)


@dp.message(CommandStart())
async def start_cmd(message: Message):
    await message.answer(
        f"Привет, {message.from_user.first_name}!\n\n"
        f"Твой Telegram ID: {message.from_user.id}\n\n"
        f"Используй его для регистрации на dox•Tox.\n"
        f"Пароль придумай сам (8+ символов)."
    )


@dp.message(F.text)
async def relay_incoming(message: Message):
    text = message.text or ""
    if text.startswith("/send "):
        parts = text[6:].split(" ", 1)
        if len(parts) < 2:
            return await message.answer("Формат: /send username текст")
        to_user, msg_text = parts
        with db() as conn:
            sender = conn.execute(
                "SELECT username FROM users WHERE tg_id = ?", (message.from_user.id,)
            ).fetchone()
            if not sender:
                return await message.answer("Сначала зарегистрируйся на сайте.")
            recipient = conn.execute(
                "SELECT tg_id FROM users WHERE username = ?", (to_user,)
            ).fetchone()
            if not recipient:
                return await message.answer("Пользователь не найден.")
            conn.execute(
                "INSERT INTO messages (from_username, to_username, text, created_at, delivered_tg) "
                "VALUES (?, ?, ?, ?, 1)",
                (sender["username"], to_user, msg_text, int(datetime.now().timestamp())),
            )
            try:
                await bot.send_message(recipient["tg_id"], f"💬 @{sender['username']}: {msg_text}")
            except Exception:
                pass
            await message.answer("✅ Отправлено")


async def run_bot():
    await dp.start_polling(bot)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    task = asyncio.create_task(run_bot())
    yield
    task.cancel()
    await bot.session.close()


app = FastAPI(lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ================= МОДЕЛИ ДАННЫХ =================

class RegisterIn(BaseModel):
    username: str
    password: str
    tg_id: int
    city: str = ""


class LoginIn(BaseModel):
    username: str
    password: str


class SendIn(BaseModel):
    from_username: str
    to_username: str
    text: str


class TelegramAuthIn(BaseModel):
    id: int
    first_name: str = ""
    last_name: str = ""
    username: str = ""
    photo_url: str = ""
    auth_date: int
    hash: str


# ================= ЭНДПОИНТЫ =================

@app.get("/")
async def root():
    return {"status": "dox•Tox работает"}


@app.post("/register")
async def register(data: RegisterIn):
    username = data.username.strip()
    if len(username) < 2:
        raise HTTPException(400, "Имя минимум 2 символа")
    if len(data.password) < 8:
        raise HTTPException(400, "Пароль минимум 8 символов")
    with db() as conn:
        if conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
            raise HTTPException(409, "Имя занято")
        if conn.execute("SELECT 1 FROM users WHERE tg_id = ?", (data.tg_id,)).fetchone():
            raise HTTPException(409, "Этот TG ID уже зарегистрирован")
        conn.execute(
            "INSERT INTO users (username, password, tg_id, city, created_at) VALUES (?, ?, ?, ?, ?)",
            (username, data.password, data.tg_id, data.city, int(datetime.now().timestamp())),
        )
    return {"ok": True, "username": username}


@app.post("/login")
async def login(data: LoginIn):
    with db() as conn:
        user = conn.execute(
            "SELECT username, tg_id, city, bio FROM users WHERE username = ? AND password = ?",
            (data.username.strip(), data.password),
        ).fetchone()
    if not user:
        raise HTTPException(401, "Неверное имя или пароль")
    return dict(user)


# --- ВХОД ЧЕРЕЗ TELEGRAM ---

@app.post("/auth/telegram")
async def auth_telegram(data: TelegramAuthIn):
    # 1. Извлекаем данные и убираем хэш
    user_dict = data.model_dump()
    check_hash = user_dict.pop("hash")
    
    # 2. Формируем строку для проверки (сортируем ключи, исключаем пустые)
    data_check_string = "\n".join(
        f"{k}={v}" for k, v in sorted(user_dict.items()) if v is not None and v != ""
    )
    
    # 3. Вычисляем секретный ключ и хэш по алгоритму Telegram
    secret_key = hashlib.sha256(BOT_TOKEN.encode()).digest()
    calculated_hash = hmac.new(secret_key, data_check_string.encode(), hashlib.sha256).hexdigest()

    # 4. Сверяем
    if calculated_hash != check_hash:
        raise HTTPException(401, "Неверная подпись Telegram")

    # 5. Проверяем время (не старше 24 часов)
    if time.time() - data.auth_date > 86400:
        raise HTTPException(401, "Данные устарели")

    # 6. Проверяем/создаем пользователя в БД
    with db() as conn:
        user = conn.execute(
            "SELECT username, tg_id, city, bio FROM users WHERE tg_id = ?", 
            (data.id,)
        ).fetchone()
        
        if not user:
            # Если пользователя нет — регистрируем автоматически
            uname = data.username or f"user_{data.id}"
            
            # Проверка на занятость ника
            if conn.execute("SELECT 1 FROM users WHERE username = ?", (uname,)).fetchone():
                uname = f"{uname}_{data.id}"
                
            conn.execute(
                "INSERT INTO users (username, password, tg_id, city, created_at) VALUES (?, ?, ?, ?, ?)",
                (uname, "telegram_auth", data.id, "", int(datetime.now().timestamp()))
            )
            user = conn.execute(
                "SELECT username, tg_id, city, bio FROM users WHERE tg_id = ?", 
                (data.id,)
            ).fetchone()

    return {"ok": True, "user": dict(user)}


# --- ОСТАЛЬНЫЕ ЭНДПОИНТЫ ---

@app.post("/send")
async def send_message(data: SendIn):
    with db() as conn:
        if not conn.execute("SELECT 1 FROM users WHERE username = ?", (data.from_username,)).fetchone():
            raise HTTPException(404, "Отправитель не найден")
        recipient = conn.execute(
            "SELECT tg_id FROM users WHERE username = ?", (data.to_username,)
        ).fetchone()
        if not recipient:
            raise HTTPException(404, "Получатель не найден")
        cur = conn.execute(
            "INSERT INTO messages (from_username, to_username, text, created_at) VALUES (?, ?, ?, ?)",
            (data.from_username, data.to_username, data.text, int(datetime.now().timestamp())),
        )
        msg_id = cur.lastrowid
    try:
        await bot.send_message(recipient["tg_id"], f"💬 @{data.from_username}: {data.text}")
        with db() as conn:
            conn.execute("UPDATE messages SET delivered_tg = 1 WHERE id = ?", (msg_id,))
    except Exception:
        pass
    return {"ok": True, "id": msg_id}


@app.get("/messages")
async def get_messages(user: str, with_user: str):
    with db() as conn:
        rows = conn.execute(
            """SELECT id, from_username, to_username, text, created_at FROM messages
               WHERE (from_username = ? AND to_username = ?)
                  OR (from_username = ? AND to_username = ?)
               ORDER BY created_at ASC""",
            (user, with_user, with_user, user),
        ).fetchall()
    return [dict(r) for r in rows]


@app.get("/users")
async def list_users():
    with db() as conn:
        rows = conn.execute(
            "SELECT username, city, bio, created_at FROM users ORDER BY created_at DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def check_admin(x_admin_id):
    if not x_admin_id or int(x_admin_id) != ADMIN_TG_ID:
        raise HTTPException(403, "Доступ только для админа")


@app.get("/admin/users")
async def admin_users(x_admin_id: str = Header(None)):
    check_admin(x_admin_id)
    with db() as conn:
        rows = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    return [dict(r) for r in rows]


@app.delete("/admin/users/{username}")
async def admin_delete_user(username: str, x_admin_id: str = Header(None)):
    check_admin(x_admin_id)
    with db() as conn:
        conn.execute("DELETE FROM users WHERE username = ?", (username,))
    return {"ok": True}


@app.get("/admin/messages")
async def admin_messages(x_admin_id: str = Header(None)):
    check_admin(x_admin_id)
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM messages ORDER BY created_at DESC LIMIT 500"
        ).fetchall()
    return [dict(r) for r in rows]
