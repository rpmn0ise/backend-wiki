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
        
        // Créer les collections si elles n'existent pas
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
        
        // Créer les index pour performance et contraintes
        await db.collection("users").createIndex({ username: 1 }, { unique: true });
        await db.collection("sessions").createIndex({ token: 1 }, { unique: true });
        await db.collection("sessions").createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
        await db.collection("registration_keys").createIndex({ key: 1 }, { unique: true });
        
// Créer les nouvelles collections pour le panel admin
        if (!collectionNames.includes("categories")) {
            await db.createCollection("categories");
            console.log("📁 Collection 'categories' créée");
        }
        
        if (!collectionNames.includes("links")) {
            await db.createCollection("links");
            console.log("📁 Collection 'links' créée");
        }
        
        if (!collectionNames.includes("admin_logs")) {
            await db.createCollection("admin_logs");
            console.log("📁 Collection 'admin_logs' créée");
        }
        
        if (!collectionNames.includes("forums")) {
            await db.createCollection("forums");
            console.log("📁 Collection 'forums' créée");
        }
        
        if (!collectionNames.includes("forum_posts")) {
            await db.createCollection("forum_posts");
            console.log("📁 Collection 'forum_posts' créée");
        }
        
        // Index pour les nouvelles collections
        await db.collection("categories").createIndex({ order: 1 });
        await db.collection("links").createIndex({ categoryId: 1, sectionId: 1, order: 1 });
        await db.collection("admin_logs").createIndex({ timestamp: -1 });
        await db.collection("forum_posts").createIndex({ forumId: 1, createdAt: -1 });


        console.log("✅ Index MongoDB créés");
        
    } catch (err) {
        console.error("❌ Erreur de connexion à MongoDB:", err);
        console.error("Vérifiez votre MONGODB_URI dans le fichier .env");
        process.exit(1);
    }
}

// Connexion à la base de données au démarrage
connectDB();

// Fermer proprement la connexion MongoDB lors de l'arrêt
process.on('SIGINT', async () => {
    await client.close();
    console.log("MongoDB déconnecté");
    process.exit(0);
});

// ===================================
// MIDDLEWARE
// ===================================

// ===================================
// CORS CONFIGURATION CORRIGÉE
// ===================================

const allowedOrigins = [
    'https://rpmn0ise.neocities.org',
    'https://sgpi-wiki-frontend.onrender.com',
    'http://localhost:3000',
    'http://localhost:5500',
    'http://127.0.0.1:5500'
];

// 1. Configuration CORS avec le package (gère automatiquement les OPTIONS)
app.use(cors({
    origin: function (origin, callback) {
        // Autoriser requêtes sans origin (Postman, server-to-server)
        if (!origin) return callback(null, true);
        
        // Autoriser sous-domaines Neocities
        if (origin.endsWith('.neocities.org')) {
            return callback(null, true);
        }
        
        // Vérifier liste autorisée
        if (allowedOrigins.includes(origin)) {
            return callback(null, true);
        }
        
        // Permissif pour dev (mettre false en prod si tu veux bloquer)
        return callback(null, true);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Admin-Key'],
    optionsSuccessStatus: 204
}));

// 2. Parser JSON APRÈS CORS
app.use(express.json());

// 3. Headers CORS additionnels (pas de return ici !)
app.use((req, res, next) => {
    const origin = req.headers.origin;
    
    if (origin) {
        if (allowedOrigins.includes(origin) || origin.endsWith('.neocities.org')) {
            res.header('Access-Control-Allow-Origin', origin);
            res.header('Access-Control-Allow-Credentials', 'true');
        }
    }
    
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Admin-Key');
    
    // ⚠️ PAS DE return res.sendStatus() ICI !
    next(); // ← Toujours appeler next()
});

// 4. Logging
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - Origin: ${req.headers.origin || 'none'}`);
    next();
});

// ===================================
// HELPER FUNCTIONS
// ===================================

// Générer un token de session aléatoire
function generateSessionToken() {
    return crypto.randomBytes(32).toString('hex');
}

// Générer une clé d'inscription format SGPI-xxxxxxxx
function generateRegistrationKey() {
    return 'SGPI-' + crypto.randomBytes(4).toString('hex');
}

// Hasher un mot de passe avec bcrypt
async function hashPassword(password) {
    const saltRounds = 10;
    return await bcrypt.hash(password, saltRounds);
}

// Vérifier un mot de passe
async function verifyPassword(password, hash) {
    return await bcrypt.compare(password, hash);
}

// Vérifier si une session est valide
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

// Middleware pour vérifier l'authentification
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

// Middleware pour vérifier les droits admin
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
    
    // ===== VALIDATIONS =====
    
    if (!registrationKey || !username || !password || !passwordConfirm) {
        return res.status(400).json({ 
            error: "Tous les champs sont requis",
            details: {
                registrationKey: !registrationKey,
                username: !username,
                password: !password,
                passwordConfirm: !passwordConfirm
            }
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
        // ===== VÉRIFIER LA CLÉ D'INSCRIPTION =====
        
        const key = await db.collection("registration_keys").findOne({ 
            key: registrationKey 
        });
        
        if (!key) {
            return res.status(404).json({ 
                error: "Clé d'inscription invalide",
                hint: "Vérifiez que vous avez copié la clé correctement"
            });
        }
        
        if (key.used) {
            return res.status(403).json({ 
                error: "Cette clé a déjà été utilisée",
                usedAt: key.usedAt
            });
        }
        
        if (new Date(key.expiresAt) < new Date()) {
            return res.status(403).json({ 
                error: "Cette clé a expiré",
                expiresAt: key.expiresAt
            });
        }
        
        // ===== VÉRIFIER SI LE PSEUDO EST DISPONIBLE =====
        
        const existingUser = await db.collection("users").findOne({ 
            username: username 
        });
        
        if (existingUser) {
            return res.status(409).json({ 
                error: "Ce pseudo est déjà pris",
                suggestion: `Essayez ${username}${Math.floor(Math.random() * 100)}`
            });
        }
        
        // ===== CRÉER L'UTILISATEUR =====
        
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
        
        // ===== MARQUER LA CLÉ COMME UTILISÉE =====
        
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
            error: "Erreur serveur lors de l'inscription",
            details: process.env.NODE_ENV === 'development' ? err.message : undefined
        });
    }
});

// ===================================
// AUTH ENDPOINTS - CONNEXION
// ===================================

app.post("/api/auth/login", async (req, res) => {
    const { username, password } = req.body;
    
    // ===== VALIDATIONS =====
    
    if (!username || !password) {
        return res.status(400).json({ 
            error: "Pseudo et mot de passe requis" 
        });
    }
    
    try {
        // ===== TROUVER L'UTILISATEUR =====
        
        const user = await db.collection("users").findOne({ 
            username: username 
        });
        
        if (!user) {
            return res.status(401).json({ 
                error: "Pseudo ou mot de passe incorrect" 
            });
        }
        
        // ===== VÉRIFIER SI LE COMPTE EST ACTIF =====
        
        if (!user.isActive) {
            return res.status(403).json({ 
                error: "Votre compte a été désactivé. Contactez un administrateur." 
            });
        }
        
        // ===== VÉRIFIER LE MOT DE PASSE =====
        
        const passwordValid = await verifyPassword(password, user.passwordHash);
        
        if (!passwordValid) {
            return res.status(401).json({ 
                error: "Pseudo ou mot de passe incorrect" 
            });
        }
        
        // ===== CRÉER UNE SESSION (30 JOURS) =====
        
        const token = generateSessionToken();
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + 30);
        
        await db.collection("sessions").insertOne({
            userId: user._id,
            token: token,
            createdAt: new Date(),
            expiresAt: expiresAt
        });
        
        // ===== METTRE À JOUR LAST_LOGIN =====
        
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
    
    // ===== VALIDATIONS =====
    
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
        // ===== RÉCUPÉRER L'UTILISATEUR =====
        
        const user = await db.collection("users").findOne({ 
            _id: req.user.id 
        });
        
        if (!user) {
            return res.status(404).json({ error: "Utilisateur introuvable" });
        }
        
        // ===== VÉRIFIER L'ANCIEN MOT DE PASSE =====
        
        const passwordValid = await verifyPassword(currentPassword, user.passwordHash);
        
        if (!passwordValid) {
            return res.status(401).json({ 
                error: "Mot de passe actuel incorrect" 
            });
        }
        
        // ===== HASHER ET METTRE À JOUR =====
        
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
        
        // Compter les sessions actives
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
        const hours = expiresInHours || 24; // 24h par défaut
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
            .project({ passwordHash: 0 }) // Ne pas exposer les hash
            .sort({ createdAt: -1 })
            .toArray();
        
        // Ajouter le nombre de sessions actives pour chaque user
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
        
        // Par défaut, ne montrer que les clés non expirées
        if (showExpired !== 'true') {
            query.expiresAt = { $gt: new Date() };
        }
        
        const keys = await db.collection("registration_keys")
            .find(query)
            .sort({ generatedAt: -1 })
            .limit(100)
            .toArray();
        
        // Ajouter les usernames pour les clés utilisées
        for (let key of keys) {
            if (key.usedBy) {
                const user = await db.collection("users").findOne(
                    { _id: key.usedBy },
                    { projection: { username: 1 } }
                );
                key.usedByUsername = user ? user.username : 'Utilisateur supprimé';
            }
            
            // Ajouter le statut
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
        
        // Supprimer toutes les sessions actives
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
        
        // Derniers utilisateurs inscrits (5)
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
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body { 
            font-family: 'Courier New', monospace; 
            padding: 20px; 
            background: #0a0a0a; 
            color: #ffa500; 
            line-height: 1.6;
        }
        
        h1 {
            margin-bottom: 30px;
            border-bottom: 2px solid #ffa500;
            padding-bottom: 10px;
        }
        
        .card {
            background: #1a1a1a;
            border: 2px solid #ffa500;
            padding: 20px;
            margin: 15px 0;
            border-radius: 8px;
        }
        
        .card h2 {
            margin-bottom: 15px;
            color: #ffa500;
        }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        
        .stat-card {
            background: #2a2a2a;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
        }
        
        .stat-number {
            font-size: 2rem;
            color: #00ff00;
            font-weight: bold;
        }
        
        .stat-label {
            color: #888;
            font-size: 0.9rem;
        }
        
        button {
            background: #ffa500;
            color: #000;
            border: none;
            padding: 10px 20px;
            cursor: pointer;
            margin: 5px;
            font-family: 'Courier New', monospace;
            border-radius: 5px;
            font-weight: bold;
        }
        
        button:hover {
            background: #ff8800;
        }
        
        button:disabled {
            background: #555;
            cursor: not-allowed;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        
        th, td {
            border: 1px solid #ffa500;
            padding: 10px;
            text-align: left;
        }
        
        th {
            background: #2a2a2a;
            font-weight: bold;
        }
        
        tr:hover {
            background: #2a2a2a;
        }
        
        .status-active { color: #00ff00; }
        .status-inactive { color: #ff0000; }
        .status-available { color: #00ff00; }
        .status-used { color: #888; }
        .status-expired { color: #ff0000; }
        
        code {
            background: #2a2a2a;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        
        .copy-btn {
            padding: 5px 10px;
            font-size: 0.8rem;
        }
        
        #loading {
            text-align: center;
            padding: 20px;
            color: #888;
        }
        
        .new-key-display {
            background: #2a2a2a;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
            display: none;
        }
        
        .new-key-display.show {
            display: block;
        }
        
        .key-highlight {
            font-size: 1.5rem;
            color: #00ff00;
            font-weight: bold;
            word-break: break-all;
        }
    </style>
</head>
<body>
    <h1>👑 SGPI Wiki - Dashboard Admin</h1>
    
    <div class="card">
        <h2>📊 Statistiques</h2>
        <div id="stats-loading">Chargement...</div>
        <div id="stats-content" style="display: none;">
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number" id="stat-users-total">0</div>
                    <div class="stat-label">Utilisateurs</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" id="stat-users-active">0</div>
                    <div class="stat-label">Actifs</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" id="stat-sessions">0</div>
                    <div class="stat-label">Sessions actives</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number" id="stat-keys-available">0</div>
                    <div class="stat-label">Clés disponibles</div>
                </div>
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
        
        // Charger les stats
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
            } catch (err) {
                console.error('Erreur stats:', err);
            }
        }
        
        // Générer une clé
        async function generateKey() {
            try {
                const res = await fetch(\`\${API_URL}/api/admin/generate-key\`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'x-admin-key': ADMIN_KEY
                    },
                    body: JSON.stringify({ generatedBy: 'dashboard' })
                });
                
                const data = await res.json();
                
                const keyDiv = document.getElementById('new-key');
                keyDiv.className = 'new-key-display show';
                keyDiv.innerHTML = \`
                    <div>
                        <strong style="color: #00ff00;">✅ Clé générée avec succès !</strong><br><br>
                        <div class="key-highlight">\${data.key}</div><br>
                        <button class="copy-btn" onclick="copyToClipboard('\${data.key}')">📋 Copier la clé</button><br><br>
                        <small style="color: #888;">
                            Expire le : \${new Date(data.expiresAt).toLocaleString('fr-FR')}<br>
                            Valide pendant : \${data.expiresIn}
                        </small>
                    </div>
                \`;
                
                loadStats();
                loadKeys(false);
                
            } catch (err) {
                alert('Erreur génération clé: ' + err.message);
            }
        }
        
        // Copier dans le presse-papier
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(() => {
                alert('✅ Clé copiée dans le presse-papier !');
            });
        }
        
        // Charger les utilisateurs
        async function loadUsers() {
            try {
                const res = await fetch(\`\${API_URL}/api/admin/users?admin_key=\${ADMIN_KEY}\`);
                const data = await res.json();
                
                let html = \`
                    <table>
                        <thead>
                            <tr>
                                <th>Pseudo</th>
                                <th>Créé le</th>
                                <th>Dernière connexion</th>
                                <th>Sessions</th>
                                <th>Statut</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                \`;
                
                data.users.forEach(u => {
                    const createdDate = new Date(u.createdAt).toLocaleDateString('fr-FR');
                    const lastLogin = u.lastLogin ? new Date(u.lastLogin).toLocaleDateString('fr-FR') : 'Jamais';
                    const statusClass = u.isActive ? 'status-active' : 'status-inactive';
                    const statusText = u.isActive ? '✅ Actif' : '❌ Inactif';
                    
                    html += \`
                        <tr>
                            <td><strong>\${u.username}</strong></td>
                            <td>\${createdDate}</td>
                            <td>\${lastLogin}</td>
                            <td>\${u.activeSessions || 0}</td>
                            <td class="\${statusClass}">\${statusText}</td>
                            <td>
                                \${u.isActive ? 
                                    \`<button onclick="revokeUser('\${u._id}', '\${u.username}')">Révoquer</button>\` : 
                                    \`<button onclick="reactivateUser('\${u._id}', '\${u.username}')">Réactiver</button>\`
                                }
                            </td>
                        </tr>
                    \`;
                });
                
                html += \`
                        </tbody>
                    </table>
                    <p style="margin-top: 10px; color: #888;">
                        Total: \${data.total} utilisateurs (\${data.active} actifs, \${data.inactive} inactifs)
                    </p>
                \`;
                
                document.getElementById('users-list').innerHTML = html;
                
            } catch (err) {
                document.getElementById('users-list').innerHTML = '<p style="color: #ff0000;">Erreur de chargement</p>';
            }
        }
        
        // Charger les clés
        async function loadKeys(showExpired) {
            try {
                const url = \`\${API_URL}/api/admin/keys?admin_key=\${ADMIN_KEY}&showExpired=\${showExpired}\`;
                const res = await fetch(url);
                const data = await res.json();
                
                let html = \`
                    <table>
                        <thead>
                            <tr>
                                <th>Clé</th>
                                <th>Généré le</th>
                                <th>Expire le</th>
                                <th>Statut</th>
                                <th>Utilisée par</th>
                            </tr>
                        </thead>
                        <tbody>
                \`;
                
                data.keys.forEach(k => {
                    const generatedDate = new Date(k.generatedAt).toLocaleString('fr-FR');
                    const expiresDate = new Date(k.expiresAt).toLocaleString('fr-FR');
                    
                    let statusClass = '';
                    let statusText = '';
                    
                    if (k.status === 'available') {
                        statusClass = 'status-available';
                        statusText = '✅ Disponible';
                    } else if (k.status === 'used') {
                        statusClass = 'status-used';
                        statusText = '✓ Utilisée';
                    } else {
                        statusClass = 'status-expired';
                        statusText = '❌ Expirée';
                    }
                    
                    html += \`
                        <tr>
                            <td><code>\${k.key}</code></td>
                            <td>\${generatedDate}</td>
                            <td>\${expiresDate}</td>
                            <td class="\${statusClass}">\${statusText}</td>
                            <td>\${k.usedByUsername || '-'}</td>
                        </tr>
                    \`;
                });
                
                html += \`
                        </tbody>
                    </table>
                    <p style="margin-top: 10px; color: #888;">
                        \${data.available} disponibles • \${data.used} utilisées • \${data.expired} expirées
                    </p>
                \`;
                
                document.getElementById('keys-list').innerHTML = html;
                
            } catch (err) {
                document.getElementById('keys-list').innerHTML = '<p style="color: #ff0000;">Erreur de chargement</p>';
            }
        }
        
        // Révoquer un utilisateur
        async function revokeUser(userId, username) {
            if (!confirm(\`Révoquer le compte de "\${username}" ?\\n\\nCette action supprimera toutes ses sessions actives.\`)) {
                return;
            }
            
            try {
                const res = await fetch(\`\${API_URL}/api/admin/revoke/\${userId}\`, {
                    method: 'DELETE',
                    headers: { 'x-admin-key': ADMIN_KEY }
                });
                
                const data = await res.json();
                alert(data.message || 'Compte révoqué');
                loadUsers();
                loadStats();
                
            } catch (err) {
                alert('Erreur: ' + err.message);
            }
        }
        
        // Réactiver un utilisateur
        async function reactivateUser(userId, username) {
            if (!confirm(\`Réactiver le compte de "\${username}" ?\`)) {
                return;
            }
            
            try {
                const res = await fetch(\`\${API_URL}/api/admin/reactivate/\${userId}\`, {
                    method: 'POST',
                    headers: { 'x-admin-key': ADMIN_KEY }
                });
                
                const data = await res.json();
                alert(data.message || 'Compte réactivé');
                loadUsers();
                loadStats();
                
            } catch (err) {
                alert('Erreur: ' + err.message);
            }
        }
        
        // Chargement initial
        loadStats();
        loadUsers();
        loadKeys(false);
        
        // Auto-refresh toutes les 30 secondes
        setInterval(() => {
            loadStats();
        }, 30000);
    </script>
</body>
</html>
    `);
});


// ===================================
// PUBLIC ENDPOINTS - CATÉGORIES (sans authentification)
// ===================================

// Lister toutes les catégories (PUBLIC - pas besoin d'admin key)
app.get("/api/categories", async (req, res) => {
    try {
        const categories = await db.collection("categories")
            .find({})
            .sort({ order: 1 })
            .toArray();
        
        // Ajouter le nombre de sous-catégories, sous-sous-catégories et liens
        for (let cat of categories) {
            const linksCount = await db.collection("links").countDocuments({ 
                categoryId: cat._id.toString() 
            });
            cat.linksCount = linksCount;
            
            // Support structure 3 niveaux
            const subCategories = cat.subCategories || cat.sections || [];
            cat.sectionsCount = subCategories.length; // Rétrocompatibilité
            cat.subCategoriesCount = subCategories.length;
            
            // Compter les sous-sous-catégories
            let subSubCount = 0;
            subCategories.forEach(subCat => {
                const subSubCategories = subCat.subSubCategories || [];
                subSubCount += subSubCategories.length;
            });
            cat.subSubCategoriesCount = subSubCount;
        }
        
        res.json({ success: true, categories });
    } catch (err) {
        console.error('❌ Erreur liste catégories:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// Récupérer une catégorie avec ses sections et liens (PUBLIC)
app.get("/api/categories/:slug", async (req, res) => {
    const { slug } = req.params;
    
    try {
        const category = await db.collection("categories").findOne({ slug: slug });
        
        if (!category) {
            return res.status(404).json({ error: "Catégorie introuvable" });
        }
        
        // Récupérer tous les liens de cette catégorie
        const links = await db.collection("links")
            .find({ categoryId: category._id.toString() })
            .sort({ order: 1 })
            .toArray();
        
        // Support nouvelle structure 3 niveaux (subCategories avec subSubCategories)
        const subCategories = category.subCategories || category.sections || [];
        
        for (let subCat of subCategories) {
            const subSubCategories = subCat.subSubCategories || [];
            
            if (subSubCategories.length > 0) {
                // Structure 3 niveaux : liens attachés aux sous-sous-catégories
                for (let subSubCat of subSubCategories) {
                    subSubCat.links = links.filter(l => 
                        l.subCategoryId === subCat.id && 
                        l.subSubCategoryId === subSubCat.id
                    );
                }
                subCat.subSubCategories = subSubCategories;
            } else {
                // Ancienne structure : liens directs dans la sous-catégorie
                subCat.links = links.filter(l => l.sectionId === subCat.id);
            }
        }
        
        res.json({ 
            success: true, 
            category: {
                ...category,
                sections: subCategories, // Rétrocompatibilité
                subCategories: subCategories // Nouvelle structure
            }
        });
    } catch (err) {
        console.error('❌ Erreur récupération catégorie:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// Export catégorie en Markdown
app.get("/api/export/category/:slug", async (req, res) => {
    const { slug } = req.params;
    
    try {
        const category = await db.collection("categories").findOne({ slug: slug });
        
        if (!category) {
            return res.status(404).json({ error: "Catégorie introuvable" });
        }
        
        // Récupérer tous les liens
        const links = await db.collection("links")
            .find({ categoryId: category._id.toString() })
            .sort({ order: 1 })
            .toArray();
        
        // Générer le markdown
        let markdown = `# ${category.emoji} ${category.name}\n\n`;
        
        const subCategories = category.subCategories || category.sections || [];
        
        for (const subCat of subCategories) {
            markdown += `## ${subCat.name}\n\n`;
            
            const subSubCategories = subCat.subSubCategories || [];
            
            if (subSubCategories.length > 0) {
                // Structure 3 niveaux
                for (const subSubCat of subSubCategories) {
                    markdown += `### ${subSubCat.name}\n\n`;
                    
                    const subSubLinks = links.filter(l => 
                        l.subCategoryId === subCat.id && 
                        l.subSubCategoryId === subSubCat.id
                    );
                    
                    if (subSubLinks.length > 0) {
                        subSubLinks.forEach(link => {
                            markdown += `- [${link.name}](${link.url})`;
                            if (link.badge) markdown += ` ${link.badge}`;
                            if (link.description) markdown += ` - ${link.description}`;
                            markdown += `\n`;
                        });
                        markdown += `\n`;
                    }
                }
            } else {
                // Ancienne structure
                const subCatLinks = links.filter(l => l.sectionId === subCat.id);
                
                if (subCatLinks.length > 0) {
                    subCatLinks.forEach(link => {
                        markdown += `- [${link.name}](${link.url})`;
                        if (link.badge) markdown += ` ${link.badge}`;
                        if (link.description) markdown += ` - ${link.description}`;
                        markdown += `\n`;
                    });
                    markdown += `\n`;
                }
            }
        }
        
        // Envoyer le fichier
        res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
        res.setHeader('Content-Disposition', `attachment; filename="${slug}.md"`);
        res.send(markdown);
        
    } catch (err) {
        console.error('❌ Erreur export:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// ===================================
// PANEL ADMIN - CATÉGORIES
// ===================================

// Lister toutes les catégories
app.get("/api/admin/categories", requireAdmin, async (req, res) => {
    try {
        const categories = await db.collection("categories")
            .find({})
            .sort({ order: 1 })
            .toArray();
        
        // Ajouter le nombre de sections/sous-catégories et liens pour chaque catégorie
        for (let cat of categories) {
            const linksCount = await db.collection("links").countDocuments({ 
                categoryId: cat._id.toString() 
            });
            cat.linksCount = linksCount;
            
            // Compatibilité : sections OU subCategories
            const subCats = cat.subCategories || cat.sections || [];
            cat.sectionsCount = subCats.length;
            cat.subCategoriesCount = subCats.length;
            
            // Compter les sous-sous-catégories
            let subSubCount = 0;
            for (let subCat of subCats) {
                if (subCat.subSubCategories) {
                    subSubCount += subCat.subSubCategories.length;
                }
            }
            cat.subSubCategoriesCount = subSubCount;
        }
        
        res.json({ success: true, categories });
    } catch (err) {
        console.error('❌ Erreur liste catégories:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// Créer une catégorie
app.post("/api/admin/categories", requireAdmin, async (req, res) => {
    const { name, emoji, slug, subCategories, order } = req.body;
    
    if (!name || !emoji || !slug) {
        return res.status(400).json({ error: "Nom, emoji et slug requis" });
    }
    
    try {
        // Trouver l'ordre max actuel si pas fourni
        let finalOrder = order;
        if (finalOrder === undefined || finalOrder === null) {
            const maxCategory = await db.collection("categories")
                .find({})
                .sort({ order: -1 })
                .limit(1)
                .toArray();
            
            finalOrder = maxCategory.length > 0 ? maxCategory[0].order + 1 : 0;
        }
        
        const newCategory = {
            name: name,
            emoji: emoji,
            slug: slug,
            order: finalOrder,
            sections: [], // Rétrocompatibilité
            subCategories: subCategories || [], // Nouvelle structure 3 niveaux
            createdAt: new Date()
        };
        
        const result = await db.collection("categories").insertOne(newCategory);
        
        // Log
        await db.collection("admin_logs").insertOne({
            action: "create_category",
            target: name,
            targetId: result.insertedId.toString(),
            timestamp: new Date()
        });
        
        console.log(`✅ Catégorie créée : ${name}`);
        res.json({ success: true, category: { ...newCategory, _id: result.insertedId } });
    } catch (err) {
        console.error('❌ Erreur création catégorie:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// Modifier une catégorie
app.put("/api/admin/categories/:id", requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { name, emoji, slug } = req.body;
    
    try {
        const result = await db.collection("categories").findOneAndUpdate(
            { _id: new ObjectId(id) },
            { $set: { name, emoji, slug } },
            { returnDocument: 'after' }
        );
        
        if (!result) {
            return res.status(404).json({ error: "Catégorie introuvable" });
        }
        
        await db.collection("admin_logs").insertOne({
            action: "update_category",
            target: name,
            targetId: id,
            timestamp: new Date()
        });
        
        console.log(`✅ Catégorie modifiée : ${name}`);
        res.json({ success: true, category: result });
    } catch (err) {
        console.error('❌ Erreur modification catégorie:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// Supprimer une catégorie
app.delete("/api/admin/categories/:id", requireAdmin, async (req, res) => {
    const { id } = req.params;
    
    try {
        const category = await db.collection("categories").findOne({ _id: new ObjectId(id) });
        
        if (!category) {
            return res.status(404).json({ error: "Catégorie introuvable" });
        }
        
        // Supprimer tous les liens de cette catégorie
        await db.collection("links").deleteMany({ categoryId: id });
        
        // Supprimer la catégorie
        await db.collection("categories").deleteOne({ _id: new ObjectId(id) });
        
        await db.collection("admin_logs").insertOne({
            action: "delete_category",
            target: category.name,
            targetId: id,
            timestamp: new Date()
        });
        
        console.log(`❌ Catégorie supprimée : ${category.name}`);
        res.json({ success: true, message: "Catégorie supprimée" });
    } catch (err) {
        console.error('❌ Erreur suppression catégorie:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// Réorganiser les catégories
app.post("/api/admin/categories/reorder", requireAdmin, async (req, res) => {
    const { categoryIds } = req.body;
    
    if (!Array.isArray(categoryIds)) {
        return res.status(400).json({ error: "categoryIds doit être un tableau" });
    }
    
    try {
        for (let i = 0; i < categoryIds.length; i++) {
            await db.collection("categories").updateOne(
                { _id: new ObjectId(categoryIds[i]) },
                { $set: { order: i } }
            );
        }
        
        await db.collection("admin_logs").insertOne({
            action: "reorder_categories",
            target: "categories",
            timestamp: new Date()
        });
        
        console.log(`✅ Catégories réorganisées`);
        res.json({ success: true, message: "Catégories réorganisées" });
    } catch (err) {
        console.error('❌ Erreur réorganisation:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// ===================================
// PANEL ADMIN - SECTIONS
// ===================================

// Ajouter une section à une catégorie
app.post("/api/admin/categories/:id/sections", requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { name } = req.body;
    
    if (!name) {
        return res.status(400).json({ error: "Nom de section requis" });
    }
    
    try {
        const category = await db.collection("categories").findOne({ _id: new ObjectId(id) });
        
        if (!category) {
            return res.status(404).json({ error: "Catégorie introuvable" });
        }
        
        const sections = category.sections || [];
        const newSection = {
            id: crypto.randomBytes(8).toString('hex'),
            name: name,
            order: sections.length
        };
        
        sections.push(newSection);
        
        await db.collection("categories").updateOne(
            { _id: new ObjectId(id) },
            { $set: { sections: sections } }
        );
        
        await db.collection("admin_logs").insertOne({
            action: "create_section",
            target: name,
            categoryId: id,
            timestamp: new Date()
        });
        
        console.log(`✅ Section créée : ${name} dans ${category.name}`);
        res.json({ success: true, section: newSection });
    } catch (err) {
        console.error('❌ Erreur création section:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// Modifier une section
app.put("/api/admin/categories/:catId/sections/:sectionId", requireAdmin, async (req, res) => {
    const { catId, sectionId } = req.params;
    const { name } = req.body;
    
    try {
        const category = await db.collection("categories").findOne({ _id: new ObjectId(catId) });
        
        if (!category) {
            return res.status(404).json({ error: "Catégorie introuvable" });
        }
        
        const sections = category.sections || [];
        const sectionIndex = sections.findIndex(s => s.id === sectionId);
        
        if (sectionIndex === -1) {
            return res.status(404).json({ error: "Section introuvable" });
        }
        
        sections[sectionIndex].name = name;
        
        await db.collection("categories").updateOne(
            { _id: new ObjectId(catId) },
            { $set: { sections: sections } }
        );
        
        await db.collection("admin_logs").insertOne({
            action: "update_section",
            target: name,
            categoryId: catId,
            timestamp: new Date()
        });
        
        console.log(`✅ Section modifiée : ${name}`);
        res.json({ success: true, section: sections[sectionIndex] });
    } catch (err) {
        console.error('❌ Erreur modification section:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// Supprimer une section
app.delete("/api/admin/categories/:catId/sections/:sectionId", requireAdmin, async (req, res) => {
    const { catId, sectionId } = req.params;
    
    try {
        const category = await db.collection("categories").findOne({ _id: new ObjectId(catId) });
        
        if (!category) {
            return res.status(404).json({ error: "Catégorie introuvable" });
        }
        
        const sections = category.sections || [];
        const updatedSections = sections.filter(s => s.id !== sectionId);
        
        // Supprimer tous les liens de cette section
        await db.collection("links").deleteMany({ 
            categoryId: catId,
            sectionId: sectionId
        });
        
        await db.collection("categories").updateOne(
            { _id: new ObjectId(catId) },
            { $set: { sections: updatedSections } }
        );
        
        await db.collection("admin_logs").insertOne({
            action: "delete_section",
            categoryId: catId,
            sectionId: sectionId,
            timestamp: new Date()
        });
        
        console.log(`❌ Section supprimée`);
        res.json({ success: true, message: "Section supprimée" });
    } catch (err) {
        console.error('❌ Erreur suppression section:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// Réorganiser les sections
app.post("/api/admin/categories/:catId/sections/reorder", requireAdmin, async (req, res) => {
    const { catId } = req.params;
    const { sectionIds } = req.body;
    
    if (!Array.isArray(sectionIds)) {
        return res.status(400).json({ error: "sectionIds doit être un tableau" });
    }
    
    try {
        const category = await db.collection("categories").findOne({ _id: new ObjectId(catId) });
        
        if (!category) {
            return res.status(404).json({ error: "Catégorie introuvable" });
        }
        
        const sections = category.sections || [];
        
        // Réorganiser les sections selon le nouvel ordre
        const reorderedSections = sectionIds.map((id, index) => {
            const section = sections.find(s => s.id === id);
            if (section) {
                section.order = index;
                return section;
            }
        }).filter(Boolean);
        
        await db.collection("categories").updateOne(
            { _id: new ObjectId(catId) },
            { $set: { sections: reorderedSections } }
        );
        
        await db.collection("admin_logs").insertOne({
            action: "reorder_sections",
            categoryId: catId,
            timestamp: new Date()
        });
        
        console.log(`✅ Sections réorganisées`);
        res.json({ success: true, message: "Sections réorganisées" });
    } catch (err) {
        console.error('❌ Erreur réorganisation sections:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// ===================================
// PANEL ADMIN - LIENS
// ===================================

// Lister les liens d'une catégorie/section
app.get("/api/admin/links", requireAdmin, async (req, res) => {
    const { categoryId, sectionId } = req.query;
    
    try {
        let query = {};
        if (categoryId) query.categoryId = categoryId;
        if (sectionId) query.sectionId = sectionId;
        
        const links = await db.collection("links")
            .find(query)
            .sort({ order: 1 })
            .toArray();
        
        res.json({ success: true, links });
    } catch (err) {
        console.error('❌ Erreur liste liens:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// Créer un lien
app.post("/api/admin/links", requireAdmin, async (req, res) => {
    const { categoryId, sectionId, name, url, description, badge } = req.body;
    
    if (!categoryId || !sectionId || !name || !url) {
        return res.status(400).json({ error: "Catégorie, section, nom et URL requis" });
    }
    
    try {
        // Trouver l'ordre max actuel dans cette section
        const maxLink = await db.collection("links")
            .find({ categoryId, sectionId })
            .sort({ order: -1 })
            .limit(1)
            .toArray();
        
        const newOrder = maxLink.length > 0 ? maxLink[0].order + 1 : 0;
        
        const newLink = {
            categoryId,
            sectionId,
            name,
            url,
            description: description || "",
            badge: badge || "",
            order: newOrder,
            createdAt: new Date()
        };
        
        const result = await db.collection("links").insertOne(newLink);
        
        await db.collection("admin_logs").insertOne({
            action: "create_link",
            target: name,
            targetId: result.insertedId.toString(),
            timestamp: new Date()
        });
        
        console.log(`✅ Lien créé : ${name}`);
        res.json({ success: true, link: { ...newLink, _id: result.insertedId } });
    } catch (err) {
        console.error('❌ Erreur création lien:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// Modifier un lien
app.put("/api/admin/links/:id", requireAdmin, async (req, res) => {
    const { id } = req.params;
    const { name, url, description, badge } = req.body;
    
    try {
        const result = await db.collection("links").findOneAndUpdate(
            { _id: new ObjectId(id) },
            { $set: { name, url, description, badge } },
            { returnDocument: 'after' }
        );
        
        if (!result) {
            return res.status(404).json({ error: "Lien introuvable" });
        }
        
        await db.collection("admin_logs").insertOne({
            action: "update_link",
            target: name,
            targetId: id,
            timestamp: new Date()
        });
        
        console.log(`✅ Lien modifié : ${name}`);
        res.json({ success: true, link: result });
    } catch (err) {
        console.error('❌ Erreur modification lien:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// Supprimer un lien
app.delete("/api/admin/links/:id", requireAdmin, async (req, res) => {
    const { id } = req.params;
    
    try {
        const link = await db.collection("links").findOne({ _id: new ObjectId(id) });
        
        if (!link) {
            return res.status(404).json({ error: "Lien introuvable" });
        }
        
        await db.collection("links").deleteOne({ _id: new ObjectId(id) });
        
        await db.collection("admin_logs").insertOne({
            action: "delete_link",
            target: link.name,
            targetId: id,
            timestamp: new Date()
        });
        
        console.log(`❌ Lien supprimé : ${link.name}`);
        res.json({ success: true, message: "Lien supprimé" });
    } catch (err) {
        console.error('❌ Erreur suppression lien:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// Réorganiser les liens
app.post("/api/admin/links/reorder", requireAdmin, async (req, res) => {
    const { linkIds } = req.body;
    
    if (!Array.isArray(linkIds)) {
        return res.status(400).json({ error: "linkIds doit être un tableau" });
    }
    
    try {
        for (let i = 0; i < linkIds.length; i++) {
            await db.collection("links").updateOne(
                { _id: new ObjectId(linkIds[i]) },
                { $set: { order: i } }
            );
        }
        
        await db.collection("admin_logs").insertOne({
            action: "reorder_links",
            target: "links",
            timestamp: new Date()
        });
        
        console.log(`✅ Liens réorganisés`);
        res.json({ success: true, message: "Liens réorganisés" });
    } catch (err) {
        console.error('❌ Erreur réorganisation liens:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// ===================================
// PANEL ADMIN - LOGS
// ===================================

// Récupérer les logs
app.get("/api/admin/logs", requireAdmin, async (req, res) => {
    const { limit = 50 } = req.query;
    
    try {
        const logs = await db.collection("admin_logs")
            .find({})
            .sort({ timestamp: -1 })
            .limit(parseInt(limit))
            .toArray();
        
        res.json({ success: true, logs });
    } catch (err) {
        console.error('❌ Erreur récupération logs:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// ===================================
// HEALTH CHECK
// ===================================

app.get("/health", (req, res) => {
    res.json({ 
        status: "ok",
        timestamp: new Date().toISOString(),
        mongodb: db ? "connected" : "disconnected"
    });
});


// ===================================
// SYSTÈME DE COMPTES ADMIN (routes temporaires)
// ===================================

app.post("/api/admin-auth/login", async (req, res) => {
    const { username, password } = req.body;
    
    // Temporaire : accepter si password = adminsgpi
    if (password === 'adminsgpi') {
        const fakeToken = crypto.randomBytes(32).toString('hex');
        
        res.json({
            success: true,
            token: fakeToken,
            admin: {
                id: 'temp-admin-id',
                username: username,
                email: 'admin@sgpi.local',
                role: 'super_admin',
                permissions: {
                    manageCategories: true,
                    manageLinks: true,
                    manageUsers: true,
                    manageAdmins: true,
                    viewLogs: true,
                    exportData: true
                }
            }
        });
    } else {
        res.status(401).json({ error: "Identifiants incorrects" });
    }
});

app.get("/api/admin-auth/verify", async (req, res) => {
    const token = req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
        return res.status(401).json({ error: "Token manquant" });
    }
    
    // Temporaire : accepter n'importe quel token
    res.json({
        valid: true,
        admin: {
            id: 'temp-admin-id',
            username: 'admin',
            email: 'admin@sgpi.local',
            role: 'super_admin',
            permissions: {
                manageCategories: true,
                manageLinks: true,
                manageUsers: true,
                manageAdmins: true,
                viewLogs: true,
                exportData: true
            }
        }
    });
});

// Route batch-delete pour suppression en masse des liens
app.post("/api/admin/links/batch-delete", requireAdmin, async (req, res) => {
    const { categoryId, subCategoryId, subSubCategoryId } = req.body;
    
    try {
        const filter = { categoryId };
        if (subCategoryId) filter.subCategoryId = subCategoryId;
        if (subSubCategoryId) filter.subSubCategoryId = subSubCategoryId;
        
        const result = await db.collection("links").deleteMany(filter);
        
        console.log(`✅ ${result.deletedCount} liens supprimés`);
        
        res.json({ 
            success: true, 
            deletedCount: result.deletedCount 
        });
    } catch (err) {
        console.error('❌ Erreur batch-delete:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

app.get("/api/admin-auth/list", async (req, res) => {
    // Temporaire : retourner une liste vide
    res.json({
        success: true,
        admins: []
    });
});

console.log("✅ Routes Panel Admin Unifié chargées");



// ===================================
// ROUTES ADDITIONNELLES PANEL ADMIN UNIFIÉ
// À ajouter dans server.js AVANT app.listen() (ligne 1981)
// ===================================

// ===================================
// QUICK-ADD (Ajout rapide de liens)
// ===================================

app.post("/api/admin/quick-add", requireAdmin, async (req, res) => {
    const { categoryId, subCategoryId, subSubCategoryId, links } = req.body;

    // Validation - subSubCategoryId est maintenant OPTIONNEL
    if (
        !categoryId
        || !subCategoryId
        || !Array.isArray(links)
        || links.length === 0
    ) {
        return res.status(400).json({ error: "Données invalides ou incomplètes" });
    }

    try {
        // Construire le filtre pour trouver l'ordre max
        const filter = {
            categoryId,
            subCategoryId
        };
        
        // Ajouter subSubCategoryId au filtre seulement s'il existe
        if (subSubCategoryId) {
            filter.subSubCategoryId = subSubCategoryId;
        }
        
        // Trouver l'ordre max actuel
        const maxLink = await db.collection("links")
            .find(filter)
            .sort({ order: -1 })
            .limit(1)
            .toArray();

        let currentOrder = maxLink.length > 0 ? maxLink[0].order + 1 : 0;

        // Construire les documents à insérer
        const linksToInsert = links.map(link => {
            const linkDoc = {
                categoryId,
                subCategoryId,          // Niveau 2 (toujours présent)
                name: link.name,
                url: link.url,
                description: link.description || "",
                badge: link.badge || "",
                order: currentOrder++,
                createdAt: new Date()
            };
            
            // Ajouter subSubCategoryId seulement s'il existe (liens spécifiques)
            if (subSubCategoryId) {
                linkDoc.subSubCategoryId = subSubCategoryId;
                linkDoc.sectionId = subSubCategoryId; // Rétrocompatibilité
            } else {
                // Liens généraux dans la sous-catégorie
                linkDoc.sectionId = subCategoryId; // Rétrocompatibilité
            }
            
            return linkDoc;
        });

        // Insertion
        await db.collection("links").insertMany(linksToInsert);

        // Log Admin
        await db.collection("admin_logs").insertOne({
            action: "quick_add",
            target: `${links.length} liens`,
            targetId: categoryId,
            timestamp: new Date()
        });

        const level = subSubCategoryId ? "sous-sous-catégorie" : "sous-catégorie";
        console.log(`✅ ${links.length} liens ajoutés dans ${level}`);

        res.json({
            success: true,
            message: `${links.length} lien${links.length > 1 ? "s" : ""} ajouté${links.length > 1 ? "s" : ""} ${subSubCategoryId ? 'dans la sous-sous-catégorie' : 'dans la sous-catégorie'}`
        });

    } catch (err) {
        console.error("❌ Erreur quick-add 3 niveaux:", err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// ===================================
// STATISTIQUES DASHBOARD
// ===================================

app.get("/api/admin/stats/dashboard", async (req, res) => {
    // Vérifier la clé admin (temporaire)
    const adminKey = req.headers['x-admin-key'] || req.query.admin_key;
    
    if (adminKey !== process.env.ADMIN_KEY) {
        return res.status(403).json({ error: "Accès refusé" });
    }
    
    try {
        const stats = {
            categories: await db.collection("categories").countDocuments(),
            subCategories: 0,
            subSubCategories: 0,
            links: await db.collection("links").countDocuments(),
            users: await db.collection("users").countDocuments()
        };
        
        // Compter les sous-catégories et sous-sous-catégories
        const categories = await db.collection("categories").find({}).toArray();
        
        categories.forEach(cat => {
            const subCats = cat.subCategories || cat.sections || [];
            stats.subCategories += subCats.length;
            
            subCats.forEach(subCat => {
                const subSubCats = subCat.subSubCategories || [];
                stats.subSubCategories += subSubCats.length;
            });
        });
        
        // Activité récente
        const recentActivity = await db.collection("admin_logs")
            .find({})
            .sort({ timestamp: -1 })
            .limit(10)
            .toArray();
        
        // Top catégories
        const allCategories = await db.collection("categories")
            .find({})
            .sort({ order: 1 })
            .toArray();
        
        for (let cat of allCategories) {
            cat.linksCount = await db.collection("links").countDocuments({ 
                categoryId: cat._id.toString() 
            });
            
            const subCats = cat.subCategories || cat.sections || [];
            cat.subCategoriesCount = subCats.length;
            
            let subSubCount = 0;
            subCats.forEach(subCat => {
                subSubCount += (subCat.subSubCategories || []).length;
            });
            cat.subSubCategoriesCount = subSubCount;
        }
        
        const topCategories = allCategories
            .sort((a, b) => b.linksCount - a.linksCount)
            .slice(0, 5);
        
        res.json({
            success: true,
            stats,
            recentActivity,
            topCategories
        });
        
    } catch (err) {
        console.error('❌ Erreur stats:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// ===================================
// RECHERCHE GLOBALE
// ===================================

app.get("/api/admin/search", async (req, res) => {
    // Vérifier la clé admin (temporaire)
    const adminKey = req.headers['x-admin-key'] || req.query.admin_key;
    
    if (adminKey !== process.env.ADMIN_KEY) {
        return res.status(403).json({ error: "Accès refusé" });
    }
    
    const { q } = req.query;
    
    if (!q || q.length < 2) {
        return res.json({
            success: true,
            results: { categories: [], sections: [], links: [] }
        });
    }
    
    try {
        const searchRegex = new RegExp(q, 'i');
        
        // Rechercher dans les catégories
        const categories = await db.collection("categories")
            .find({ $or: [
                { name: searchRegex },
                { slug: searchRegex }
            ]})
            .limit(10)
            .toArray();
        
        for (let cat of categories) {
            cat.linksCount = await db.collection("links").countDocuments({ 
                categoryId: cat._id.toString() 
            });
            cat.sectionsCount = cat.sections?.length || 0;
        }
        
        // Rechercher dans les liens
        const links = await db.collection("links")
            .find({ $or: [
                { name: searchRegex },
                { url: searchRegex },
                { description: searchRegex }
            ]})
            .limit(20)
            .toArray();
        
        res.json({
            success: true,
            results: {
                categories,
                sections: [],
                links
            }
        });
        
    } catch (err) {
        console.error('❌ Erreur recherche:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// ===================================
// VALIDATION DES LIENS
// ===================================

app.post("/api/admin/validate-links", async (req, res) => {
    // Vérifier la clé admin (temporaire)
    const adminKey = req.headers['x-admin-key'] || req.query.admin_key;
    
    if (adminKey !== process.env.ADMIN_KEY) {
        return res.status(403).json({ error: "Accès refusé" });
    }
    
    try {
        const links = await db.collection("links").find({}).toArray();
        const results = [];
        
        // Limiter à 100 liens pour éviter timeout
        const linksToCheck = links.slice(0, 100);
        
        for (const link of linksToCheck) {
            // Validation basique (sans fetch pour éviter problèmes de dépendances)
            try {
                // Vérifier que l'URL est valide
                new URL(link.url);
                
                results.push({
                    id: link._id,
                    name: link.name,
                    url: link.url,
                    status: 'ok',
                    message: 'URL valide'
                });
            } catch (err) {
                results.push({
                    id: link._id,
                    name: link.name,
                    url: link.url,
                    status: 'error',
                    error: 'URL invalide'
                });
            }
        }
        
        res.json({
            success: true,
            results,
            totalChecked: results.length,
            totalLinks: links.length,
            message: 'Validation basique effectuée (vérification HTTP désactivée)'
        });
        
    } catch (err) {
        console.error('❌ Erreur validation:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});

// ===================================
// EXPORT COMPLET
// ===================================

app.get("/api/admin/export/full", async (req, res) => {
    // Vérifier la clé admin (temporaire)
    const adminKey = req.headers['x-admin-key'] || req.query.admin_key;
    
    if (adminKey !== process.env.ADMIN_KEY) {
        return res.status(403).json({ error: "Accès refusé" });
    }
    
    try {
        const categories = await db.collection("categories").find({}).toArray();
        const links = await db.collection("links").find({}).toArray();
        const users = await db.collection("users").countDocuments();
        
        const backup = {
            exportDate: new Date().toISOString(),
            version: "2.0",
            stats: {
                totalCategories: categories.length,
                totalLinks: links.length,
                totalUsers: users
            },
            categories,
            links
        };
        
        res.json({
            success: true,
            backup
        });
        
    } catch (err) {
        console.error('❌ Erreur export:', err);
        res.status(500).json({ error: "Erreur serveur" });
    }
});



// ===================================
// FIN DES ROUTES ADDITIONNELLES
// Placer AVANT app.listen()
// ===================================

// ===================================
// 404 HANDLER
// ===================================

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
