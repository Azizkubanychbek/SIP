const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const cors = require('cors');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'messenger-secret-key';

app.use(cors());
app.use(express.json());
app.use(express.static('public'));

// База данных
const db = new sqlite3.Database('messenger.db');

// Создаем таблицы
db.serialize(() => {
    // Пользователи
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Сообщения
    db.run(`CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER NOT NULL,
        receiver_id INTEGER NOT NULL,
        content TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (sender_id) REFERENCES users (id),
        FOREIGN KEY (receiver_id) REFERENCES users (id)
    )`);

    // Создаем тестовых пользователей
    db.get("SELECT COUNT(*) as count FROM users", (err, row) => {
        if (row.count === 0) {
            const hashedPassword = bcrypt.hashSync('123456', 10);
            db.run("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", 
                ['alice', 'alice@test.com', hashedPassword]);
            db.run("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", 
                ['bob', 'bob@test.com', hashedPassword]);
            console.log('✅ Тестовые пользователи: alice/123456, bob/123456');
        }
    });
});

// Проверка токена
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'Токен не предоставлен' });
    }
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Недействительный токен' });
        }
        req.user = user;
        next();
    });
}

// Маршруты
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/chat', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'chat.html'));
});

// Регистрация
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Все поля обязательны' });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        
        db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', 
            [username, email, hashedPassword], function(err) {
            if (err) {
                if (err.message.includes('UNIQUE constraint failed')) {
                    return res.status(400).json({ error: 'Пользователь уже существует' });
                }
                return res.status(500).json({ error: 'Ошибка сервера' });
            }
            
            const token = jwt.sign({ id: this.lastID, username, email }, JWT_SECRET);
            res.json({ token, user: { id: this.lastID, username, email } });
        });
    } catch (error) {
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// Вход
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Имя пользователя и пароль обязательны' });
    }
    
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }
        
        if (!user) {
            return res.status(401).json({ error: 'Неверные учетные данные' });
        }
        
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Неверные учетные данные' });
        }
        
        const token = jwt.sign({ id: user.id, username: user.username, email: user.email }, JWT_SECRET);
        res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
    });
});

// Получение информации о пользователе
app.get('/api/me', authenticateToken, (req, res) => {
    res.json(req.user);
});

// Получение списка пользователей
app.get('/api/users', authenticateToken, (req, res) => {
    db.all('SELECT id, username, email FROM users WHERE id != ?', [req.user.id], (err, users) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }
        res.json(users);
    });
});

// Получение сообщений
app.get('/api/messages/:userId', authenticateToken, (req, res) => {
    const { userId } = req.params;
    const currentUserId = req.user.id;
    
    db.all(`
        SELECT m.*, u.username as sender_name 
        FROM messages m 
        JOIN users u ON m.sender_id = u.id 
        WHERE (m.sender_id = ? AND m.receiver_id = ?) 
           OR (m.sender_id = ? AND m.receiver_id = ?)
        ORDER BY m.created_at ASC
    `, [currentUserId, userId, userId, currentUserId], (err, messages) => {
        if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }
        res.json(messages);
    });
});

// Отправка сообщения
app.post('/api/messages', authenticateToken, (req, res) => {
    const { receiverId, content } = req.body;
    const senderId = req.user.id;
    
    if (!receiverId || !content) {
        return res.status(400).json({ error: 'Получатель и содержание обязательны' });
    }
    
    db.run('INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)', 
        [senderId, receiverId, content], function(err) {
        if (err) {
            return res.status(500).json({ error: 'Ошибка сервера' });
        }
        
        // Получаем информацию о сообщении
        db.get(`
            SELECT m.*, u.username as sender_name 
            FROM messages m 
            JOIN users u ON m.sender_id = u.id 
            WHERE m.id = ?
        `, [this.lastID], (err, message) => {
            if (err) {
                return res.status(500).json({ error: 'Ошибка сервера' });
            }
            res.json(message);
        });
    });
});

// Socket.IO обработка
const connectedUsers = new Map();

io.on('connection', (socket) => {
    console.log('🔌 Пользователь подключился:', socket.id);
    
    // Присоединение пользователя
    socket.on('join', (userId) => {
        connectedUsers.set(userId, socket.id);
        socket.userId = userId;
        console.log(`👤 Пользователь ${userId} присоединился`);
        
        // Уведомляем всех о новом пользователе
        io.emit('user_joined', { userId });
    });
    
    // Отправка сообщения
    socket.on('send_message', (data) => {
        const { receiverId, content } = data;
        const senderId = socket.userId;
        
        // Сохраняем в базу
        db.run('INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)', 
            [senderId, receiverId, content], function(err) {
            if (err) {
                console.error('Ошибка сохранения сообщения:', err);
                return;
            }
            
            // Отправляем получателю
            const receiverSocketId = connectedUsers.get(receiverId);
            if (receiverSocketId) {
                io.to(receiverSocketId).emit('new_message', {
                    id: this.lastID,
                    senderId,
                    content,
                    createdAt: new Date().toISOString()
                });
            }
        });
    });
    
    // Инициация звонка
    socket.on('call_user', (data) => {
        const { targetUserId, callType } = data;
        const callerId = socket.userId;
        const callId = 'call-' + Date.now();
        
        console.log(`📞 Звонок от ${callerId} к ${targetUserId} (${callType})`);
        
        // Отправляем уведомление получателю
        const targetSocketId = connectedUsers.get(targetUserId);
        if (targetSocketId) {
            io.to(targetSocketId).emit('incoming_call', {
                callId,
                callerId,
                callType
            });
        }
    });
    
    // Ответ на звонок
    socket.on('answer_call', (data) => {
        const { callId, answer } = data;
        console.log(`📞 Ответ на звонок ${callId}: ${answer}`);
        
        // Уведомляем инициатора
        io.emit('call_answered', { callId, answer });
    });
    
    // WebRTC сигналы
    socket.on('webrtc_signal', (data) => {
        const { targetUserId, signal, type } = data;
        const targetSocketId = connectedUsers.get(targetUserId);
        
        if (targetSocketId) {
            io.to(targetSocketId).emit('webrtc_signal', {
                fromUserId: socket.userId,
                signal,
                type
            });
        }
    });
    
    // Завершение звонка
    socket.on('end_call', (data) => {
        const { callId } = data;
        console.log(`📞 Завершение звонка ${callId}`);
        
        // Уведомляем всех
        io.emit('call_ended', { callId });
    });
    
    // Отключение пользователя
    socket.on('disconnect', () => {
        if (socket.userId) {
            connectedUsers.delete(socket.userId);
            console.log(`👤 Пользователь ${socket.userId} отключился`);
            io.emit('user_left', { userId: socket.userId });
        }
    });
});

server.listen(PORT, () => {
    console.log(`🚀 Мессенджер запущен на порту ${PORT}`);
    console.log(`📱 Откройте: http://localhost:${PORT}`);
    if (process.env.NODE_ENV !== 'production') {
        console.log(`📱 Для доступа с телефона используйте IP вашего компьютера`);
    }
}); 