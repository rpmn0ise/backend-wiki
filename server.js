const express = require("express");
const { MongoClient, ObjectId } = require("mongodb");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const cors = require("cors");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 10000;

// ===================================
// MONGODB CONNECTION
// ===================================

const client = new MongoClient(process.env.MONGODB_URI);
let db;

async function connectDB() {
    try {
        await client.connect();
        db = client.db("sgpi_wiki");
        console.log("✅ MongoDB Atlas connecté avec succès");
        
        const collections = await db.listCollections().toArray();
        const collectionNames = collections.map(c => c.name);
        
        if (!collectionNames.includes("users")) {
            await db.createCollection("users");
            console.log("📁 Collection 'users' créée");
        }
        
        if (!collectionNames.includes("sessions")) {
            await db.createCollection("sessions");
            console.log("📁 Collection 'sessions' créée");
        }
        
        if (!collectionNames.includes("registration_keys")) {
            await db.createCollection("registration_keys");
            console.log("📁 Collection 'registration_keys' créée");
        }
        
        await db.collection("users").createIndex({ username: 1 }, { unique: true });
        await db.collection("sessions").createIndex({ token: 1 }, { unique: true });
        await db.collection("sessions").createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
        await db.collection("registration_keys").createIndex({ key: 1 }, { unique: true });
        
        console.log("✅ Index MongoDB créés");
        
    } catch (err) {
        console.error("❌ Erreur de connexion à MongoDB:", err);
        console.error("Vérifiez votre MONGODB_URI dans le fichier .env");
        process.exit(1);
    }
}

connectDB();

process.on('SIGINT', async () => {
    await client.close();
    console.log("MongoDB déconnecté");
    process.exit(0);
});

// ===================================
// MIDDLEWARE
// ===================================

app.use(cors({
    origin: [
        "https://rpmn0ise.neocities.org",
        "http://localhost:8080",
        "http://127.0.0.1:8080"
    ],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Admin-Key']
}));

app.use(express.json());

app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
    next();
});

// ===================================
// HELPER FUNCTIONS
// ===================================

function generateSessionToken() {
    return crypto.randomBytes(32).toString('hex');
}

function generateRegistrationKey() {
    return 'SGPI-' + crypto.randomBytes(4).toString('hex');
}

async function hashPassword(password) {
    const saltRounds = 10;
    return await bcrypt.hash(password, saltRounds);
}

async function verifyPassword(password, hash) {
    return await bcrypt.compare(password, hash);
}

async function verifySession(token) {
    if (!token) return null;
    
    try {
        const session = await db.collection("sessions").findOne({
            token: token,
            expiresAt: { $gt: new Date() }
        });
        
        if (!session) return null;
        
        const user = await db.collection("users").findOne({
            _id: session.userId,
            isActive: true
        });
        
        if (!user) return null;
        
        return { 
            ...session, 
            username: user.username,
            userId: user._id
        };
    } catch (err) {
        console.error('Erreur vérification session:', err);
        return null;
    }
}

async function requireAuth(req, res, next) {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
        return res.status(401).json({ error: "Token manquant" });
    }
    
    const session = await verifySession(token);
    
    if (!session) {
        return res.status(401).json({ error: "Session invalide ou expirée" });
    }
    
    req.user = {
        id: session.userId,
        username: session.username
    };
    
    next();
}

function requireAdmin(req, res, next) {
    const adminKey = req.headers['x-admin-key'] || req.query.admin_key;
    
    if (!adminKey || adminKey !== process.env.ADMIN_KEY) {
        return res.status(403).json({ error: "Accès refusé - Clé admin invalide" });
    }
    
    next();
}

// ===================================
// AUTH ENDPOINTS - INSCRIPTION
// ===================================

app.post("/api/auth/register", async (req, res) => {
    const { registrationKey, username, password, passwordConfirm } = req.body;
    
    if (!registrationKey || !username || !password || !passwordConfirm) {
        return res.status(400).json({ 
            error: "Tous les champs sont requis"
        });
    }
    
    if (password !== passwordConfirm) {
        return res.status(400).json({ error: "Les mots de passe ne correspondent pas" });
    }
    
    if (username.length < 3 || username.length > 50) {
        return res.status(400).json({ error: "Le pseudo doit contenir entre 3 et 50 caractères" });
    }
    
    if (password.length < 8) {
        return res.status(400).json({ error: "Le mot de passe doit contenir au moins 8 caractères" });
    }
    
    if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
        return res.status(400).json({ 
            error: "Le pseudo ne peut contenir que des lettres, chiffres, tirets (-) et underscores (_)" 
        });
    }
    
    try {
        const key = await db.collection("registration_keys").findOne({ 
            key: registrationKey 
        });
        
        if (!key) {
            return res.status(404).json({ 
                error: "Clé d'inscription invalide"
            });
        }
        
        if (key.used) {
            return res.status(403).json({ 
                error: "Cette clé a déjà été utilisée"
            });
        }
        
        if (new Date(key.expiresAt) < new Date()) {
            return res.status(403).json({ 
                error: "Cette clé a expiré"
            });
        }
        
        const existingUser = await db.collection("users").findOne({ 
            username: username 
        });
        
        if (existingUser) {
            return res.status(409).json({ 
                error: "Ce pseudo est déjà pris"
            });
        }
        
        const passwordHash = await hashPassword(password);
        
        const newUser = {
            username: username,
            passwordHash: passwordHash,
            registrationKey: registrationKey,
            createdAt: new Date(),
            lastLogin: null,
            isActive: true
        };
        
        const result = await db.collection("users").insertOne(newUser);
        
        await db.collection("registration_keys").updateOne(
            { key: registrationKey },
            { 
                $set: { 
                    used: true, 
                    usedBy: result.insertedId,
                    usedAt: new Date()
                }
            }
        );
        
        console.log(`✅ Nouveau compte créé : ${username} (ID: ${result.insertedId})`);
        
        res.json({
            success: true,
            message: "Compte créé avec succès ! Vous pouvez maintenant vous connecter.",
            user: {
                id: result.insertedId,
                username: username,
                createdAt: newUser.createdAt
            }
        });
        
    } catch (err) {
        console.error('❌ Erreur inscription:', err);
        
        if (err.code === 11000) {
            return res.status(409).json({ 
                error: "Ce pseudo est déjà pris" 
            });
        }
        
        res.status(500).json({ 
            error: "Erreur serveur lors de l'inscription"
        });
    }
});

// ===================================
// AUTH ENDPOINTS - CONNEXION
// ===================================

app.post("/api/auth/login", async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ 
            error: "Pseudo et mot de passe requis" 
        });
    }
    
    try {
        const user = await db.collection("users").findOne({ 
            username: username 
        });
        
        if (!user) {
            return res.status(401).json({ 
                error: "Pseudo ou mot de passe incorrect" 
            });
        }
        
        if (!user.isActive) {
            return res.status(403).json({ 
                error: "Votre compte a été désactivé. Contactez un administrateur." 
            });
        }
        
        const passwordValid = await verifyPassword(password, user.passwordHash);
        
        if (!passwordValid) {
            return res.status(401).json({ 
                error: "Pseudo ou mot de passe incorrect" 
            });
        }
        
        const token = generateSessionToken();
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 30);
        
        await db.collection("sessions").insertOne({
            userId: user._id,
            token: token,
            createdAt: new Date(),
            expiresAt: expiresAt
        });
        
        await db.collection("users").updateOne(
            { _id: user._id },
            { $set: { lastLogin: new Date() } }
        );
        
        console.log(`✅ Connexion réussie : ${username}`);
        
        res.json({
            success: true,
            message: "Connexion réussie",
            token: token,
            expiresAt: expiresAt.toISOString(),
            user: {
                id: user._id,
                username: user.username
            }
        });
        
    } catch (err) {
        console.error('❌ Erreur connexion:', err);
        res.status(500).json({ 
            error: "Erreur serveur lors de la connexion" 
        });
    }
});

// ===================================
// AUTH ENDPOINTS - VÉRIFICATION SESSION
// ===================================

app.get("/api/auth/verify", async (req, res) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
        return res.status(401).json({ 
            valid: false,
            error: "Token manquant" 
        });
    }
    
    const session = await verifySession(token);
    
    if (!session) {
        return res.status(401).json({ 
            valid: false,
            error: "Session invalide ou expirée" 
        });
    }
    
    res.json({
        valid: true,
        user: {
            id: session.userId,
            username: session.username
        },
        expiresAt: session.expiresAt
    });
});

// ===================================
// AUTH ENDPOINTS - DÉCONNEXION
// ===================================

app.post("/api/auth/logout", async (req, res) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
        return res.status(400).json({ error: "Token manquant" });
    }
    
    try {
        const result = await db.collection("sessions").deleteOne({ token: token });
        
        if (result.deletedCount === 0) {
            return res.status(404).json({ error: "Session non trouvée" });
        }
        
        console.log(`✅ Déconnexion : token ${token.substring(0, 8)}...`);
        
        res.json({ 
            success: true, 
            message: "Déconnexion réussie" 
        });
        
    } catch (err) {
        console.error('❌ Erreur déconnexion:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// ===================================
// AUTH ENDPOINTS - CHANGER MOT DE PASSE
// ===================================

app.post("/api/auth/change-password", requireAuth, async (req, res) => {
    const { currentPassword, newPassword, newPasswordConfirm } = req.body;
    
    if (!currentPassword || !newPassword || !newPasswordConfirm) {
        return res.status(400).json({ error: "Tous les champs sont requis" });
    }
    
    if (newPassword !== newPasswordConfirm) {
        return res.status(400).json({ error: "Les nouveaux mots de passe ne correspondent pas" });
    }
    
    if (newPassword.length < 8) {
        return res.status(400).json({ 
            error: "Le nouveau mot de passe doit contenir au moins 8 caractères" 
        });
    }
    
    if (newPassword === currentPassword) {
        return res.status(400).json({ 
            error: "Le nouveau mot de passe doit être différent de l'ancien" 
        });
    }
    
    try {
        const user = await db.collection("users").findOne({ 
            _id: req.user.id 
        });
        
        if (!user) {
            return res.status(404).json({ error: "Utilisateur introuvable" });
        }
        
        const passwordValid = await verifyPassword(currentPassword, user.passwordHash);
        
        if (!passwordValid) {
            return res.status(401).json({ 
                error: "Mot de passe actuel incorrect" 
            });
        }
        
        const newPasswordHash = await hashPassword(newPassword);
        
        await db.collection("users").updateOne(
            { _id: user._id },
            { $set: { passwordHash: newPasswordHash } }
        );
        
        console.log(`✅ Mot de passe changé : ${user.username}`);
        
        res.json({ 
            success: true, 
            message: "Mot de passe modifié avec succès" 
        });
        
    } catch (err) {
        console.error('❌ Erreur changement mot de passe:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// ===================================
// AUTH ENDPOINTS - INFOS COMPTE
// ===================================

app.get("/api/auth/account", requireAuth, async (req, res) => {
    try {
        const user = await db.collection("users").findOne(
            { _id: req.user.id },
            { projection: { passwordHash: 0 } }
        );
        
        if (!user) {
            return res.status(404).json({ error: "Utilisateur introuvable" });
        }
        
        const activeSessions = await db.collection("sessions").countDocuments({
            userId: user._id,
            expiresAt: { $gt: new Date() }
        });
        
        res.json({
            success: true,
            user: {
                id: user._id,
                username: user.username,
                createdAt: user.createdAt,
                lastLogin: user.lastLogin,
                isActive: user.isActive,
                activeSessions: activeSessions
            }
        });
        
    } catch (err) {
        console.error('❌ Erreur infos compte:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// ===================================
// ADMIN ENDPOINTS - GÉNÉRER CLÉ
// ===================================

app.post("/api/admin/generate-key", requireAdmin, async (req, res) => {
    const { generatedBy, expiresInHours } = req.body;
    
    try {
        const key = generateRegistrationKey();
        const expiresAt = new Date();
        const hours = expiresInHours || 24;
        expiresAt.setHours(expiresAt.getHours() + hours);
        
        await db.collection("registration_keys").insertOne({
            key: key,
            generatedBy: generatedBy || 'admin',
            generatedAt: new Date(),
            used: false,
            usedBy: null,
            usedAt: null,
            expiresAt: expiresAt
        });
        
        console.log(`✅ Nouvelle clé générée : ${key} (expire dans ${hours}h)`);
        
        res.json({
            success: true,
            key: key,
            generatedAt: new Date().toISOString(),
            expiresAt: expiresAt.toISOString(),
            expiresIn: `${hours} heures`
        });
        
    } catch (err) {
        console.error('❌ Erreur génération clé:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// ===================================
// ADMIN ENDPOINTS - LISTE UTILISATEURS
// ===================================

app.get("/api/admin/users", requireAdmin, async (req, res) => {
    try {
        const users = await db.collection("users")
            .find({})
            .project({ passwordHash: 0 })
            .sort({ createdAt: -1 })
            .toArray();
        
        for (let user of users) {
            const activeSessions = await db.collection("sessions").countDocuments({
                userId: user._id,
                expiresAt: { $gt: new Date() }
            });
            user.activeSessions = activeSessions;
        }
        
        res.json({
            success: true,
            users: users,
            total: users.length,
            active: users.filter(u => u.isActive).length,
            inactive: users.filter(u => !u.isActive).length
        });
        
    } catch (err) {
        console.error('❌ Erreur liste utilisateurs:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// ===================================
// ADMIN ENDPOINTS - LISTE CLÉS
// ===================================

app.get("/api/admin/keys", requireAdmin, async (req, res) => {
    const { showExpired } = req.query;
    
    try {
        let query = {};
        
        if (showExpired !== 'true') {
            query.expiresAt = { $gt: new Date() };
        }
        
        const keys = await db.collection("registration_keys")
            .find(query)
            .sort({ generatedAt: -1 })
            .limit(100)
            .toArray();
        
        for (let key of keys) {
            if (key.usedBy) {
                const user = await db.collection("users").findOne(
                    { _id: key.usedBy },
                    { projection: { username: 1 } }
                );
                key.usedByUsername = user ? user.username : 'Utilisateur supprimé';
            }
            
            const now = new Date();
            if (key.used) {
                key.status = 'used';
            } else if (new Date(key.expiresAt) < now) {
                key.status = 'expired';
            } else {
                key.status = 'available';
            }
        }
        
        res.json({
            success: true,
            keys: keys,
            total: keys.length,
            available: keys.filter(k => k.status === 'available').length,
            used: keys.filter(k => k.status === 'used').length,
            expired: keys.filter(k => k.status === 'expired').length
        });
        
    } catch (err) {
        console.error('❌ Erreur liste clés:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// ===================================
// ADMIN ENDPOINTS - RÉVOQUER COMPTE
// ===================================

app.delete("/api/admin/revoke/:userId", requireAdmin, async (req, res) => {
    const { userId } = req.params;
    
    try {
        const result = await db.collection("users").findOneAndUpdate(
            { _id: new ObjectId(userId) },
            { $set: { isActive: false } },
            { returnDocument: 'after' }
        );
        
        if (!result) {
            return res.status(404).json({ error: "Utilisateur introuvable" });
        }
        
        await db.collection("sessions").deleteMany({ 
            userId: new ObjectId(userId) 
        });
        
        console.log(`❌ Compte révoqué : ${result.username}`);
        
        res.json({
            success: true,
            message: `Compte ${result.username} révoqué avec succès`
        });
        
    } catch (err) {
        console.error('❌ Erreur révocation:', err);
        
        if (err.message.includes('Argument passed in must be a string')) {
            return res.status(400).json({ error: "ID utilisateur invalide" });
        }
        
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// ===================================
// ADMIN ENDPOINTS - RÉACTIVER COMPTE
// ===================================

app.post("/api/admin/reactivate/:userId", requireAdmin, async (req, res) => {
    const { userId } = req.params;
    
    try {
        const result = await db.collection("users").findOneAndUpdate(
            { _id: new ObjectId(userId) },
            { $set: { isActive: true } },
            { returnDocument: 'after' }
        );
        
        if (!result) {
            return res.status(404).json({ error: "Utilisateur introuvable" });
        }
        
        console.log(`✅ Compte réactivé : ${result.username}`);
        
        res.json({
            success: true,
            message: `Compte ${result.username} réactivé avec succès`
        });
        
    } catch (err) {
        console.error('❌ Erreur réactivation:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// ===================================
// ADMIN ENDPOINTS - STATS
// ===================================

app.get("/api/admin/stats", requireAdmin, async (req, res) => {
    try {
        const totalUsers = await db.collection("users").countDocuments();
        const activeUsers = await db.collection("users").countDocuments({ isActive: true });
        const totalSessions = await db.collection("sessions").countDocuments({ 
            expiresAt: { $gt: new Date() } 
        });
        const totalKeys = await db.collection("registration_keys").countDocuments();
        const availableKeys = await db.collection("registration_keys").countDocuments({
            used: false,
            expiresAt: { $gt: new Date() }
        });
        const usedKeys = await db.collection("registration_keys").countDocuments({ used: true });
        
        const recentUsers = await db.collection("users")
            .find({})
            .project({ username: 1, createdAt: 1 })
            .sort({ createdAt: -1 })
            .limit(5)
            .toArray();
        
        res.json({
            success: true,
            stats: {
                users: {
                    total: totalUsers,
                    active: activeUsers,
                    inactive: totalUsers - activeUsers
                },
                sessions: {
                    active: totalSessions
                },
                keys: {
                    total: totalKeys,
                    available: availableKeys,
                    used: usedKeys,
                    expired: totalKeys - availableKeys - usedKeys
                }
            },
            recentUsers: recentUsers
        });
        
    } catch (err) {
        console.error('❌ Erreur stats:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// ===================================
// ADMIN ENDPOINTS - DASHBOARD HTML
// ===================================

app.get("/api/admin/dashboard", requireAdmin, (req, res) => {
    const adminKey = req.query.admin_key;
    
    res.send(`
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Dashboard - Wiki SGPI</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Courier New', monospace; padding: 20px; background: #0a0a0a; color: #ffa500; line-height: 1.6; }
        h1 { margin-bottom: 30px; border-bottom: 2px solid #ffa500; padding-bottom: 10px; }
        .card { background: #1a1a1a; border: 2px solid #ffa500; padding: 20px; margin: 15px 0; border-radius: 8px; }
        .card h2 { margin-bottom: 15px; color: #ffa500; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-card { background: #2a2a2a; padding: 15px; border-radius: 5px; text-align: center; }
        .stat-number { font-size: 2rem; color: #00ff00; font-weight: bold; }
        .stat-label { color: #888; font-size: 0.9rem; }
        button { background: #ffa500; color: #000; border: none; padding: 10px 20px; cursor: pointer; margin: 5px; font-family: 'Courier New', monospace; border-radius: 5px; font-weight: bold; }
        button:hover { background: #ff8800; }
        button:disabled { background: #555; cursor: not-allowed; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { border: 1px solid #ffa500; padding: 10px; text-align: left; }
        th { background: #2a2a2a; font-weight: bold; }
        tr:hover { background: #2a2a2a; }
        .status-active { color: #00ff00; }
        .status-inactive { color: #ff0000; }
        .status-available { color: #00ff00; }
        .status-used { color: #888; }
        .status-expired { color: #ff0000; }
        code { background: #2a2a2a; padding: 2px 6px; border-radius: 3px; font-family: 'Courier New', monospace; }
        .copy-btn { padding: 5px 10px; font-size: 0.8rem; }
        .new-key-display { background: #2a2a2a; padding: 15px; border-radius: 5px; margin-top: 15px; display: none; }
        .new-key-display.show { display: block; }
        .key-highlight { font-size: 1.5rem; color: #00ff00; font-weight: bold; word-break: break-all; }
    </style>
</head>
<body>
    <h1>👑 SGPI Wiki - Dashboard Admin</h1>
    
    <div class="card">
        <h2>📊 Statistiques</h2>
        <div id="stats-loading">Chargement...</div>
        <div id="stats-content" style="display: none;">
            <div class="stats-grid">
                <div class="stat-card"><div class="stat-number" id="stat-users-total">0</div><div class="stat-label">Utilisateurs</div></div>
                <div class="stat-card"><div class="stat-number" id="stat-users-active">0</div><div class="stat-label">Actifs</div></div>
                <div class="stat-card"><div class="stat-number" id="stat-sessions">0</div><div class="stat-label">Sessions actives</div></div>
                <div class="stat-card"><div class="stat-number" id="stat-keys-available">0</div><div class="stat-label">Clés disponibles</div></div>
            </div>
        </div>
    </div>
    
    <div class="card">
        <h2>🔑 Générer une clé d'inscription</h2>
        <button onclick="generateKey()">Générer nouvelle clé (24h)</button>
        <div id="new-key" class="new-key-display"></div>
    </div>
    
    <div class="card">
        <h2>👥 Utilisateurs</h2>
        <button onclick="loadUsers()">🔄 Rafraîchir</button>
        <div id="users-list">Chargement...</div>
    </div>
    
    <div class="card">
        <h2>🎟️ Clés d'inscription</h2>
        <button onclick="loadKeys(false)">Actives uniquement</button>
        <button onclick="loadKeys(true)">Toutes les clés</button>
        <div id="keys-list">Chargement...</div>
    </div>
    
    <script>
        const ADMIN_KEY = '${adminKey}';
        const API_URL = window.location.origin;
        
        async function loadStats() {
            try {
                const res = await fetch(\`\${API_URL}/api/admin/stats?admin_key=\${ADMIN_KEY}\`);
                const data = await res.json();
                document.getElementById('stat-users-total').textContent = data.stats.users.total;
                document.getElementById('stat-users-active').textContent = data.stats.users.active;
                document.getElementById('stat-sessions').textContent = data.stats.sessions.active;
                document.getElementById('stat-keys-available').textContent = data.stats.keys.available;
                document.getElementById('stats-loading').style.display = 'none';
                document.getElementById('stats-content').style.display = 'block';
            } catch (err) { console.error('Erreur stats:', err); }
        }
        
        async function generateKey() {
            try {
                const res = await fetch(\`\${API_URL}/api/admin/generate-key\`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'x-admin-key': ADMIN_KEY },
                    body: JSON.stringify({ generatedBy: 'dashboard' })
                });
                const data = await res.json();
                const keyDiv = document.getElementById('new-key');
                keyDiv.className = 'new-key-display show';
                keyDiv.innerHTML = \`<div><strong style="color: #00ff00;">✅ Clé générée !</strong><br><br><div class="key-highlight">\${data.key}</div><br><button class="copy-btn" onclick="copyToClipboard('\${data.key}')">📋 Copier</button><br><br><small style="color: #888;">Expire : \${new Date(data.expiresAt).toLocaleString('fr-FR')}<br>Valide : \${data.expiresIn}</small></div>\`;
                loadStats(); loadKeys(false);
            } catch (err) { alert('Erreur : ' + err.message); }
        }
        
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => alert('✅ Clé copiée !'));
        }
        
        async function loadUsers() {
            try {
                const res = await fetch(\`\${API_URL}/api/admin/users?admin_key=\${ADMIN_KEY}\`);
                const data = await res.json();
                let html = '<table><thead><tr><th>Pseudo</th><th>Créé le</th><th>Dernière connexion</th><th>Sessions</th><th>Statut</th><th>Actions</th></tr></thead><tbody>';
                data.users.forEach(u => {
                    const createdDate = new Date(u.createdAt).toLocaleDateString('fr-FR');
                    const lastLogin = u.lastLogin ? new Date(u.lastLogin).toLocaleDateString('fr-FR') : 'Jamais';
                    const statusClass = u.isActive ? 'status-active' : 'status-inactive';
                    const statusText = u.isActive ? '✅ Actif' : '❌ Inactif';
                    html += \`<tr><td><strong>\${u.username}</strong></td><td>\${createdDate}</td><td>\${lastLogin}</td><td>\${u.activeSessions || 0}</td><td class="\${statusClass}">\${statusText}</td><td>\${u.isActive ? \`<button onclick="revokeUser('\${u._id}', '\${u.username}')">Révoquer</button>\` : \`<button onclick="reactivateUser('\${u._id}', '\${u.username}')">Réactiver</button>\`}</td></tr>\`;
                });
                html += \`</tbody></table><p style="margin-top: 10px; color: #888;">Total: \${data.total} (\${data.active} actifs, \${data.inactive} inactifs)</p>\`;
                document.getElementById('users-list').innerHTML = html;
            } catch (err) { document.getElementById('users-list').innerHTML = '<p style="color: #ff0000;">Erreur</p>'; }
        }
        
        async function loadKeys(showExpired) {
            try {
                const res = await fetch(\`\${API_URL}/api/admin/keys?admin_key=\${ADMIN_KEY}&showExpired=\${showExpired}\`);
                const data = await res.json();
                let html = '<table><thead><tr><th>Clé</th><th>Généré le</th><th>Expire le</th><th>Statut</th><th>Utilisée par</th></tr></thead><tbody>';
                data.keys.forEach(k => {
                    const generatedDate = new Date(k.generatedAt).toLocaleString('fr-FR');
                    const expiresDate = new Date(k.expiresAt).toLocaleString('fr-FR');
                    let statusClass = '', statusText = '';
                    if (k.status === 'available') { statusClass = 'status-available'; statusText = '✅ Disponible'; }
                    else if (k.status === 'used') { statusClass = 'status-used'; statusText = '✓ Utilisée'; }
                    else { statusClass = 'status-expired'; statusText = '❌ Expirée'; }
                    html += \`<tr><td><code>\${k.key}</code></td><td>\${generatedDate}</td><td>\${expiresDate}</td><td class="\${statusClass}">\${statusText}</td><td>\${k.usedByUsername || '-'}</td></tr>\`;
                });
                html += \`</tbody></table><p style="margin-top: 10px; color: #888;">\${data.available} disponibles • \${data.used} utilisées • \${data.expired} expirées</p>\`;
                document.getElementById('keys-list').innerHTML = html;
            } catch (err) { document.getElementById('keys-list').innerHTML = '<p style="color: #ff0000;">Erreur</p>'; }
        }
        
        async function revokeUser(userId, username) {
            if (!confirm(\`Révoquer "\${username}" ?\\n\\nSupprimera toutes ses sessions.\`)) return;
            try {
                const res = await fetch(\`\${API_URL}/api/admin/revoke/\${userId}\`, { method: 'DELETE', headers: { 'x-admin-key': ADMIN_KEY } });
                const data = await res.json();
                alert(data.message || 'Révoqué');
                loadUsers(); loadStats();
            } catch (err) { alert('Erreur: ' + err.message); }
        }
        
        async function reactivateUser(userId, username) {
            if (!confirm(\`Réactiver "\${username}" ?\`)) return;
            try {
                const res = await fetch(\`\${API_URL}/api/admin/reactivate/\${userId}\`, { method: 'POST', headers: { 'x-admin-key': ADMIN_KEY } });
                const data = await res.json();
                alert(data.message || 'Réactivé');
                loadUsers(); loadStats();
            } catch (err) { alert('Erreur: ' + err.message); }
        }
        
        loadStats(); loadUsers(); loadKeys(false);
        setInterval(() => { loadStats(); }, 30000);
    </script>
</body>
</html>
    `);
});

// ===================================
// HEALTH CHECK & 404
// ===================================

app.get("/health", (req, res) => {
    res.json({ 
        status: "ok",
        timestamp: new Date().toISOString(),
        mongodb: db ? "connected" : "disconnected"
    });
});

app.use((req, res) => {
    res.status(404).json({ 
        error: "Endpoint introuvable",
        path: req.path 
    });
});

// ===================================
// START SERVER
// ===================================

app.listen(PORT, () => {
    console.log(`✅ Serveur démarré sur le port ${PORT}`);
    console.log(`📍 Dashboard admin: http://localhost:${PORT}/api/admin/dashboard?admin_key=${process.env.ADMIN_KEY}`);
});
