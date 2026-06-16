from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import sqlite3
import json
import bcrypt
import uuid
from datetime import datetime
from typing import Dict, Set
import asyncio
import os

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============ БАЗА ДАННЫХ ============
class Database:
    def __init__(self):
        self.conn = sqlite3.connect('messenger.db', check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.create_tables()
    
    def create_tables(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                login TEXT UNIQUE NOT NULL,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                avatar TEXT DEFAULT 'default.png',
                description TEXT DEFAULT '',
                registered_at TEXT DEFAULT CURRENT_TIMESTAMP,
                last_seen TEXT DEFAULT CURRENT_TIMESTAMP,
                is_online INTEGER DEFAULT 0
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_user_id INTEGER,
                to_user_id INTEGER,
                text TEXT,
                file_path TEXT DEFAULT NULL,
                file_type TEXT DEFAULT NULL,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'sending',
                is_read INTEGER DEFAULT 0,
                FOREIGN KEY (from_user_id) REFERENCES users(id),
                FOREIGN KEY (to_user_id) REFERENCES users(id)
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS chats (
                user_id INTEGER,
                contact_id INTEGER,
                pinned INTEGER DEFAULT 0,
                last_message_time TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (contact_id) REFERENCES users(id),
                PRIMARY KEY (user_id, contact_id)
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        self.conn.commit()
    
    # ===== АВТОРИЗАЦИЯ =====
    def register_user(self, login, username, password):
        try:
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            self.cursor.execute('''
                INSERT INTO users (login, username, password)
                VALUES (?, ?, ?)
            ''', (login, username, hashed.decode()))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def login_user(self, login, password):
        self.cursor.execute('SELECT id, login, username, password FROM users WHERE login = ?', (login,))
        user = self.cursor.fetchone()
        if user and bcrypt.checkpw(password.encode(), user[3].encode()):
            token = str(uuid.uuid4())
            self.cursor.execute('INSERT INTO sessions (token, user_id) VALUES (?, ?)', (token, user[0]))
            self.conn.commit()
            return token, user[0], user[2]
        return None
    
    def logout_user(self, token):
        self.cursor.execute('DELETE FROM sessions WHERE token = ?', (token,))
        self.conn.commit()
        return True
    
    def get_user_by_token(self, token):
        self.cursor.execute('SELECT user_id FROM sessions WHERE token = ?', (token,))
        result = self.cursor.fetchone()
        if result:
            return self.get_user_by_id(result[0])
        return None
    
    def get_user_by_id(self, user_id):
        self.cursor.execute('SELECT id, username, login, avatar, description, registered_at, is_online, last_seen FROM users WHERE id = ?', (user_id,))
        return self.cursor.fetchone()
    
    def get_user_by_login(self, login):
        self.cursor.execute('SELECT id, username, avatar, description, registered_at, is_online FROM users WHERE login = ?', (login,))
        return self.cursor.fetchone()
    
    def get_user_by_username(self, username):
        self.cursor.execute('SELECT id, username, login, avatar, description, registered_at, is_online, last_seen FROM users WHERE username = ?', (username,))
        return self.cursor.fetchone()
    
    # ===== ПОИСК =====
    def search_users(self, username_query, exclude_id):
        self.cursor.execute('''
            SELECT id, username, avatar, is_online, last_seen 
            FROM users 
            WHERE username LIKE ? AND id != ?
            LIMIT 3
        ''', (f'%{username_query}%', exclude_id))
        return self.cursor.fetchall()
    
    # ===== ПРОФИЛЬ =====
    def update_username(self, user_id, new_username):
        try:
            self.cursor.execute('UPDATE users SET username = ? WHERE id = ?', (new_username, user_id))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def update_password(self, user_id, new_password):
        hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
        self.cursor.execute('UPDATE users SET password = ? WHERE id = ?', (hashed.decode(), user_id))
        self.conn.commit()
        return True
    
    def update_avatar(self, user_id, avatar_path):
        self.cursor.execute('UPDATE users SET avatar = ? WHERE id = ?', (avatar_path, user_id))
        self.conn.commit()
        return True
    
    def update_description(self, user_id, description):
        self.cursor.execute('UPDATE users SET description = ? WHERE id = ?', (description, user_id))
        self.conn.commit()
        return True
    
    def delete_account(self, user_id):
        self.cursor.execute('DELETE FROM messages WHERE from_user_id = ? OR to_user_id = ?', (user_id, user_id))
        self.cursor.execute('DELETE FROM chats WHERE user_id = ? OR contact_id = ?', (user_id, user_id))
        self.cursor.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))
        self.cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        self.conn.commit()
        return True
    
    def update_last_seen(self, user_id):
        self.cursor.execute('UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?', (user_id,))
        self.conn.commit()
    
    def set_online(self, user_id, status):
        self.cursor.execute('UPDATE users SET is_online = ? WHERE id = ?', (status, user_id))
        self.conn.commit()
    
    # ===== СООБЩЕНИЯ =====
    def save_message(self, from_user_id, to_user_id, text, file_path=None, file_type=None):
        self.cursor.execute('''
            INSERT INTO messages (from_user_id, to_user_id, text, file_path, file_type)
            VALUES (?, ?, ?, ?, ?)
        ''', (from_user_id, to_user_id, text, file_path, file_type))
        self.conn.commit()
        message_id = self.cursor.lastrowid
        
        self.cursor.execute('''
            INSERT OR REPLACE INTO chats (user_id, contact_id, last_message_time)
            VALUES (?, ?, CURRENT_TIMESTAMP)
        ''', (from_user_id, to_user_id))
        self.cursor.execute('''
            INSERT OR REPLACE INTO chats (user_id, contact_id, last_message_time)
            VALUES (?, ?, CURRENT_TIMESTAMP)
        ''', (to_user_id, from_user_id))
        self.conn.commit()
        
        return self.get_message_by_id(message_id)
    
    def get_message_by_id(self, message_id):
        self.cursor.execute('''
            SELECT id, from_user_id, to_user_id, text, file_path, file_type, 
                   timestamp, status, is_read 
            FROM messages WHERE id = ?
        ''', (message_id,))
        return self.cursor.fetchone()
    
    def get_chat_messages(self, user_id, contact_id, limit=50):
        self.cursor.execute('''
            SELECT id, from_user_id, to_user_id, text, file_path, file_type, 
                   timestamp, status, is_read 
            FROM messages 
            WHERE (from_user_id = ? AND to_user_id = ?) 
               OR (from_user_id = ? AND to_user_id = ?)
            ORDER BY timestamp DESC LIMIT ?
        ''', (user_id, contact_id, contact_id, user_id, limit))
        return self.cursor.fetchall()
    
    def get_user_chats(self, user_id):
        self.cursor.execute('''
            SELECT c.contact_id, u.username, u.avatar, u.is_online, u.last_seen,
                   c.pinned, c.last_message_time,
                   (SELECT text FROM messages 
                    WHERE (from_user_id = ? AND to_user_id = c.contact_id) 
                       OR (from_user_id = c.contact_id AND to_user_id = ?)
                    ORDER BY timestamp DESC LIMIT 1) as last_message
            FROM chats c
            JOIN users u ON c.contact_id = u.id
            WHERE c.user_id = ?
            ORDER BY c.pinned DESC, c.last_message_time DESC
        ''', (user_id, user_id, user_id))
        return self.cursor.fetchall()
    
    def mark_message_as_read(self, message_id):
        self.cursor.execute('UPDATE messages SET is_read = 1, status = "read" WHERE id = ?', (message_id,))
        self.conn.commit()
    
    def mark_all_as_read(self, user_id, contact_id):
        self.cursor.execute('''
            UPDATE messages 
            SET is_read = 1, status = 'read' 
            WHERE from_user_id = ? AND to_user_id = ? AND is_read = 0
        ''', (contact_id, user_id))
        self.conn.commit()
    
    def update_message_status(self, message_id, status):
        self.cursor.execute('UPDATE messages SET status = ? WHERE id = ?', (status, message_id))
        self.conn.commit()
    
    # ===== ЧАТЫ =====
    def pin_chat(self, user_id, contact_id):
        self.cursor.execute('''
            UPDATE chats SET pinned = 1 
            WHERE user_id = ? AND contact_id = ?
        ''', (user_id, contact_id))
        self.conn.commit()
    
    def unpin_chat(self, user_id, contact_id):
        self.cursor.execute('''
            UPDATE chats SET pinned = 0 
            WHERE user_id = ? AND contact_id = ?
        ''', (user_id, contact_id))
        self.conn.commit()
    
    def delete_chat(self, user_id, contact_id):
        self.cursor.execute('''
            DELETE FROM messages 
            WHERE (from_user_id = ? AND to_user_id = ?) 
               OR (from_user_id = ? AND to_user_id = ?)
        ''', (user_id, contact_id, contact_id, user_id))
        self.cursor.execute('''
            DELETE FROM chats 
            WHERE (user_id = ? AND contact_id = ?) 
               OR (user_id = ? AND contact_id = ?)
        ''', (user_id, contact_id, contact_id, user_id))
        self.conn.commit()
        return True
    
    def delete_all_chats(self, user_id):
        self.cursor.execute('''
            DELETE FROM messages 
            WHERE from_user_id = ? OR to_user_id = ?
        ''', (user_id, user_id))
        self.cursor.execute('''
            DELETE FROM chats 
            WHERE user_id = ? OR contact_id = ?
        ''', (user_id, user_id))
        self.conn.commit()
        return True

# ============ ВЕБ-СОКЕТЫ ============
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[int, WebSocket] = {}
        self.db = Database()
    
    async def connect(self, websocket: WebSocket, user_id: int):
        await websocket.accept()
        self.active_connections[user_id] = websocket
        self.db.set_online(user_id, 1)
        await self.broadcast_status(user_id, True)
    
    def disconnect(self, user_id: int):
        if user_id in self.active_connections:
            del self.active_connections[user_id]
        self.db.set_online(user_id, 0)
        self.db.update_last_seen(user_id)
    
    async def send_personal(self, message: dict, user_id: int):
        if user_id in self.active_connections:
            await self.active_connections[user_id].send_text(json.dumps(message))
    
    async def broadcast_status(self, user_id: int, is_online: bool):
        status_message = {
            'type': 'status',
            'user_id': user_id,
            'is_online': is_online,
            'last_seen': datetime.now().isoformat()
        }
        for connection in self.active_connections.values():
            await connection.send_text(json.dumps(status_message))

manager = ConnectionManager()

# ============ API ЭНДПОЙНТЫ ============

@app.post("/register")
async def register(login: str, username: str, password: str):
    if len(password) < 8:
        raise HTTPException(status_code=400, detail="Пароль должен быть минимум 8 символов")
    
    db = Database()
    success = db.register_user(login, username, password)
    if not success:
        raise HTTPException(status_code=400, detail="Логин или юзернейм уже заняты")
    return {"success": True}

@app.post("/login")
async def login(login: str, password: str):
    db = Database()
    result = db.login_user(login, password)
    if not result:
        raise HTTPException(status_code=401, detail="Неверный логин или пароль")
    token, user_id, username = result
    return {"token": token, "user_id": user_id, "username": username}

@app.post("/logout")
async def logout(token: str):
    db = Database()
    db.logout_user(token)
    return {"success": True}

@app.get("/check_session")
async def check_session(token: str):
    db = Database()
    user = db.get_user_by_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Сессия недействительна")
    return {
        "user_id": user[0],
        "username": user[1],
        "login": user[2],
        "avatar": user[3],
        "description": user[4]
    }

@app.get("/profile/{user_id}")
async def get_profile(user_id: int):
    db = Database()
    user = db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    return {
        "id": user[0],
        "username": user[1],
        "login": user[2],
        "avatar": user[3],
        "description": user[4],
        "registered_at": user[5],
        "is_online": user[6],
        "last_seen": user[7]
    }

@app.get("/search/{query}")
async def search_users(query: str, user_id: int):
    db = Database()
    users = db.search_users(query, user_id)
    return [
        {
            "id": u[0],
            "username": u[1],
            "avatar": u[2],
            "is_online": u[3],
            "last_seen": u[4]
        }
        for u in users
    ]

@app.put("/update_username")
async def update_username(user_id: int, new_username: str):
    db = Database()
    success = db.update_username(user_id, new_username)
    if not success:
        raise HTTPException(status_code=400, detail="Юзернейм уже занят")
    return {"success": True}

@app.put("/update_password")
async def update_password(user_id: int, old_password: str, new_password: str):
    if len(new_password) < 8:
        raise HTTPException(status_code=400, detail="Пароль должен быть минимум 8 символов")
    
    db = Database()
    user = db.get_user_by_id(user_id)
    db.cursor.execute('SELECT password FROM users WHERE id = ?', (user_id,))
    current_hash = db.cursor.fetchone()[0]
    if not bcrypt.checkpw(old_password.encode(), current_hash.encode()):
        raise HTTPException(status_code=401, detail="Неверный старый пароль")
    
    db.update_password(user_id, new_password)
    return {"success": True}

@app.put("/update_description")
async def update_description(user_id: int, description: str):
    db = Database()
    db.update_description(user_id, description)
    return {"success": True}

@app.delete("/delete_account/{user_id}")
async def delete_account(user_id: int):
    db = Database()
    db.delete_account(user_id)
    return {"success": True}

@app.get("/chats/{user_id}")
async def get_chats(user_id: int):
    db = Database()
    chats = db.get_user_chats(user_id)
    return [
        {
            "contact_id": c[0],
            "username": c[1],
            "avatar": c[2],
            "is_online": c[3],
            "last_seen": c[4],
            "pinned": c[5],
            "last_message_time": c[6],
            "last_message": c[7] if c[7] else ""
        }
        for c in chats
    ]

@app.get("/messages/{user_id}/{contact_id}")
async def get_messages(user_id: int, contact_id: int, limit: int = 50):
    db = Database()
    db.mark_all_as_read(user_id, contact_id)
    messages = db.get_chat_messages(user_id, contact_id, limit)
    return [
        {
            "id": m[0],
            "from_user_id": m[1],
            "to_user_id": m[2],
            "text": m[3] if m[3] else "",
            "file_path": m[4],
            "file_type": m[5],
            "timestamp": m[6],
            "status": m[7],
            "is_read": m[8]
        }
        for m in messages
    ]

@app.put("/pin_chat")
async def pin_chat(user_id: int, contact_id: int):
    db = Database()
    db.pin_chat(user_id, contact_id)
    return {"success": True}

@app.put("/unpin_chat")
async def unpin_chat(user_id: int, contact_id: int):
    db = Database()
    db.unpin_chat(user_id, contact_id)
    return {"success": True}

@app.delete("/delete_chat")
async def delete_chat(user_id: int, contact_id: int):
    db = Database()
    db.delete_chat(user_id, contact_id)
    return {"success": True}

@app.delete("/delete_all_chats/{user_id}")
async def delete_all_chats(user_id: int):
    db = Database()
    db.delete_all_chats(user_id)
    return {"success": True}

# ============ ВЕБ-СОКЕТ ЭНДПОЙНТ ============
@app.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    db = Database()
    user = db.get_user_by_token(token)
    
    if not user:
        await websocket.close(code=4001)
        return
    
    user_id = user[0]
    await manager.connect(websocket, user_id)
    
    try:
        while True:
            data = await websocket.receive_text()
            message_data = json.loads(data)
            
            if message_data['type'] == 'message':
                to_user_id = message_data['to_user_id']
                text = message_data.get('text', '')
                
                db = Database()
                message = db.save_message(user_id, to_user_id, text)
                
                msg_data = {
                    'type': 'message',
                    'id': message[0],
                    'from_user_id': user_id,
                    'to_user_id': to_user_id,
                    'text': message[3] if message[3] else "",
                    'file_path': message[4],
                    'file_type': message[5],
                    'timestamp': message[6],
                    'status': 'sent',
                    'is_read': 0
                }
                await manager.send_personal(msg_data, user_id)
                await manager.send_personal(msg_data, to_user_id)
                db.update_message_status(message[0], 'sent')
                
            elif message_data['type'] == 'read':
                message_id = message_data['message_id']
                db = Database()
                db.mark_message_as_read(message_id)
                message = db.get_message_by_id(message_id)
                if message:
                    read_data = {
                        'type': 'read',
                        'message_id': message_id,
                        'from_user_id': message[1]
                    }
                    await manager.send_personal(read_data, message[1])
                    
    except WebSocketDisconnect:
        manager.disconnect(user_id)
        await manager.broadcast_status(user_id, False)

# ============ HEALTH CHECK ============
@app.get("/")
async def root():
    return {"status": "ok", "message": "ArtMessage server is running"}

# ============ ЗАПУСК ============
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port)
