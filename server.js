const express = require('express');
const fetch = require('node-fetch');
const axios = require('axios');
const cors = require('cors');
const session = require('express-session');
const { google } = require('googleapis');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// ==========================================
//  IN-MEMORY STORES (swap to Redis/DB later)
// ==========================================

const tokensDB = new Map();
const whatsappDB = new Map();
const lastMessageCheck = new Map();

// Periodically clean up old message check entries (every hour)
setInterval(() => {
    const oneWeekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
    for (const [userId, msgs] of lastMessageCheck.entries()) {
        for (const [msgId, ts] of Object.entries(msgs)) {
            if (ts < oneWeekAgo) delete msgs[msgId];
        }
        if (Object.keys(msgs).length === 0) lastMessageCheck.delete(userId);
    }
}, 60 * 60 * 1000);

// ==========================================
//  HELPER FUNCTIONS
// ==========================================

function logError(context, error) {
    console.error(`[${context}] Error:`, {
        message: error.message,
        stack: error.stack,
        timestamp: new Date().toISOString()
    });
}

function generateCsrfToken() {
    return crypto.randomBytes(32).toString('hex');
}

function validateCsrfToken(req) {
    const tokenFromHeader = req.headers['x-csrf-token'];
    const tokenFromSession = req.session.csrfToken;
    if (!tokenFromHeader || !tokenFromSession) return false;
    // Constant-time comparison to prevent timing attacks
    try {
        return crypto.timingSafeEqual(
            Buffer.from(tokenFromHeader, 'hex'),
            Buffer.from(tokenFromSession, 'hex')
        );
    } catch {
        return false;
    }
}

// ==========================================
//  SECURITY MIDDLEWARE
// ==========================================

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            scriptSrc: ["'self'", "https://cdnjs.cloudflare.com", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:", "https://seraphielspark.github.io"],
            connectSrc: ["'self'", "https://kingoftech.app.n8n.cloud", "https://flowon.onrender.com"],
            frameSrc: ["'none'"],
            objectSrc: ["'none'"]
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// ==========================================
//  CORS
// ==========================================

const ALLOWED_ORIGINS = [
    'https://seraphielspark.github.io',
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'http://localhost:5500',
    'http://127.0.0.1:5500'
];

app.use(cors({
    origin: (origin, callback) => {
        if (!origin) return callback(null, true); // allow no-origin (mobile apps, curl, etc.)
        if (ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
        console.warn('[CORS] Blocked origin:', origin);
        callback(null, false);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'X-CSRF-Token'],
    exposedHeaders: ['Set-Cookie'],
    optionsSuccessStatus: 200
}));

// ==========================================
//  BODY PARSERS
// ==========================================

app.use(cookieParser(process.env.COOKIE_SECRET || 'cookie-secret-CHANGE-THIS-IN-PRODUCTION'));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ==========================================
//  SESSION
// ==========================================

app.use(session({
    name: 'fluxon.sid',
    secret: process.env.SESSION_SECRET || 'super-secret-key-CHANGE-THIS-IN-PRODUCTION',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: IS_PRODUCTION,
        sameSite: IS_PRODUCTION ? 'none' : 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000,
        path: '/'
    },
    rolling: true
}));

// ==========================================
//  RATE LIMITERS
// ==========================================

const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: { error: 'Too many login attempts, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false
});

app.use('/api/', globalLimiter);

// ==========================================
//  AUTHENTICATION MIDDLEWARE
// ==========================================

const authenticate = (req, res, next) => {
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    next();
};

// Custom CSRF middleware — validates token for all state-changing methods
// Applied selectively (not on login/create-session which bootstrap the token)
const csrfProtect = (req, res, next) => {
    const safeMethods = ['GET', 'HEAD', 'OPTIONS'];
    if (safeMethods.includes(req.method)) return next();
    if (!validateCsrfToken(req)) {
        return res.status(403).json({ error: 'Invalid or missing CSRF token' });
    }
    next();
};

// Helper: set CSRF cookie readable by JS (httpOnly: false intentional for XSRF pattern)
function setCsrfCookie(res, token) {
    res.cookie('XSRF-TOKEN', token, {
        httpOnly: false,
        secure: IS_PRODUCTION,
        sameSite: IS_PRODUCTION ? 'none' : 'lax',
        maxAge: 24 * 60 * 60 * 1000,
        path: '/'
    });
}

// ==========================================
//  TOKEN HELPERS
// ==========================================

async function saveTokensToDB({ userId, access_token, refresh_token, expires_at }) {
    if (!userId) return;
    tokensDB.set(userId, {
        access_token,
        refresh_token,
        expires_at,
        updated_at: Date.now()
    });
    console.log(`[Tokens] Cached for user: ${userId}`);
}

async function getTokensFromDB(userId) {
    if (!userId) return null;

    if (tokensDB.has(userId)) {
        return tokensDB.get(userId);
    }

    // Fallback to cloud storage
    console.log(`[Tokens] Cache miss for ${userId}, fetching from cloud...`);
    try {
        const response = await fetch(
            `https://kingoftech.app.n8n.cloud/webhook/get-user-tokens?userId=${encodeURIComponent(userId)}`,
            { timeout: 8000 }
        );

        if (!response.ok) {
            console.warn(`[Tokens] n8n returned ${response.status} for user ${userId}`);
            return null;
        }

        const data = await response.json();

        if (data && data.access_token) {
            const tokens = {
                access_token: data.access_token,
                refresh_token: data.refresh_token,
                expires_at: data.expires_at || (Date.now() + 3500 * 1000),
                updated_at: Date.now()
            };
            tokensDB.set(userId, tokens);
            console.log(`[Tokens] Restored from cloud for user: ${userId}`);
            return tokens;
        }

        return null;
    } catch (error) {
        logError('getTokensFromDB', error);
        return null;
    }
}

// Build and return a refreshed OAuth2 client, persisting new tokens if refreshed
async function getOAuth2Client(userId) {
    const userTokens = await getTokensFromDB(userId);
    if (!userTokens || !userTokens.access_token) return null;

    const oauth2Client = new google.auth.OAuth2(
        process.env.GOOGLE_CLIENT_ID,
        process.env.GOOGLE_CLIENT_SECRET,
        'https://flowon.onrender.com/api/google/oauth/callback'
    );

    oauth2Client.setCredentials({
        access_token: userTokens.access_token,
        refresh_token: userTokens.refresh_token,
        expiry_date: userTokens.expires_at
    });

    // Auto-save refreshed tokens
    oauth2Client.on('tokens', async (tokens) => {
        console.log(`[OAuth] Tokens refreshed for user ${userId}`);
        const updated = tokensDB.get(userId) || {};
        await saveTokensToDB({
            userId,
            access_token: tokens.access_token || updated.access_token,
            refresh_token: tokens.refresh_token || updated.refresh_token,
            expires_at: tokens.expiry_date || updated.expires_at
        });

        // Persist refreshed tokens to n8n cloud
        try {
            await axios.post('https://kingoftech.app.n8n.cloud/webhook/link', {
                userId,
                google_access_token: tokens.access_token || updated.access_token,
                google_refresh_token: tokens.refresh_token || updated.refresh_token,
                token_expiry: tokens.expiry_date || updated.expires_at,
                timestamp: new Date().toISOString()
            });
        } catch (err) {
            console.warn('[OAuth] Failed to persist refreshed tokens to n8n:', err.message);
        }
    });

    return oauth2Client;
}

// ==========================================
//  WHATSAPP HELPERS
// ==========================================

async function saveWhatsAppNumber(userId, phoneNumber) {
    if (!userId) return null;

    const data = {
        phoneNumber,
        registeredAt: new Date().toISOString(),
        verified: true
    };
    whatsappDB.set(userId, data);
    console.log(`[WhatsApp] Number saved for user: ${userId}`);

    try {
        await axios.post('https://kingoftech.app.n8n.cloud/webhook/whatsapp-register', {
            userId,
            phoneNumber,
            timestamp: new Date().toISOString()
        }, { headers: { 'Content-Type': 'application/json' } });
    } catch (error) {
        logError('saveWhatsAppNumber:n8n', error);
        // Non-fatal — local record already saved
    }

    return data;
}

function getWhatsAppNumber(userId) {
    if (!userId) return null;
    return whatsappDB.get(userId) || null;
}

async function sendWhatsAppNotification(userId, { from, subject, snippet, messageId }) {
    if (!userId) return false;

    try {
        const whatsapp = getWhatsAppNumber(userId);
        if (!whatsapp) {
            console.log(`[WhatsApp] No number registered for user ${userId}`);
            return false;
        }

        const message = `📧 *New Message Received*\n\n*From:* ${from}\n*Subject:* ${subject}\n\n*Preview:* ${snippet || 'No preview available'}\n\nCheck your inbox for more details.`;

        const response = await fetch('https://kingoftech.app.n8n.cloud/webhook/receive', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                to: whatsapp.phoneNumber,
                message,
                from,
                subject,
                userId,
                messageId,
                type: 'new_email_notification',
                timestamp: new Date().toISOString()
            })
        });

        if (!response.ok) throw new Error(`n8n returned ${response.status}`);

        console.log(`[WhatsApp] Notification sent to user ${userId} for message ${messageId}`);
        return true;
    } catch (error) {
        logError('sendWhatsAppNotification', error);
        return false;
    }
}

// ==========================================
//  GOOGLE OAuth HELPER — validate state nonce
// ==========================================

// Store OAuth state nonces: state => { userId, createdAt }
const oauthStateStore = new Map();

function createOAuthState(userId) {
    const state = crypto.randomBytes(24).toString('hex');
    oauthStateStore.set(state, { userId, createdAt: Date.now() });
    // Clean up after 10 minutes
    setTimeout(() => oauthStateStore.delete(state), 10 * 60 * 1000);
    return state;
}

function consumeOAuthState(state) {
    const entry = oauthStateStore.get(state);
    if (!entry) return null;
    if (Date.now() - entry.createdAt > 10 * 60 * 1000) {
        oauthStateStore.delete(state);
        return null;
    }
    oauthStateStore.delete(state);
    return entry.userId;
}

// ==========================================
//  HEALTH CHECK (no auth/rate-limit needed)
// ==========================================

app.get('/get', (req, res) => {
    res.json({
        status: 'online',
        timestamp: new Date().toISOString(),
        version: '3.0.0'
    });
});

// ==========================================
//  AUTH ROUTES (no CSRF required — bootstrapping)
// ==========================================

// Login
app.post('/api/login', authLimiter, async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }

        const response = await fetch('https://kingoftech.app.n8n.cloud/webhook/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });

        const data = await response.json();
        console.log('[Login] n8n response status:', response.status);

        if (!response.ok || !data.userid) {
            return res.status(401).json({ error: data.message || 'Invalid email or password' });
        }

        // Regenerate session to prevent session fixation attacks
        req.session.regenerate((err) => {
            if (err) {
                logError('Session regenerate', err);
                return res.status(500).json({ error: 'Session creation failed' });
            }

            const csrfToken = generateCsrfToken();
            req.session.userId = data.userid;
            req.session.userEmail = email;
            req.session.loginTime = Date.now();
            req.session.csrfToken = csrfToken;

            req.session.save((saveErr) => {
                if (saveErr) {
                    logError('Session save', saveErr);
                    return res.status(500).json({ error: 'Session save failed' });
                }

                setCsrfCookie(res, csrfToken);

                console.log(`[Login] ✓ Session created for user: ${data.userid}`);
                res.json({
                    success: true,
                    message: 'Login successful',
                    userid: data.userid,
                    userId: data.userid,
                    email
                });
            });
        });

    } catch (error) {
        logError('Login', error);
        res.status(500).json({ error: 'Server error occurred' });
    }
});

// Logout
app.post('/api/logout', authenticate, csrfProtect, (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            logError('Logout', err);
            return res.status(500).json({ error: 'Logout failed' });
        }
        res.clearCookie('fluxon.sid');
        res.clearCookie('XSRF-TOKEN');
        res.json({ success: true });
    });
});

// Session status check
app.get('/api/session', (req, res) => {
    if (req.session && req.session.userId) {
        res.json({
            authenticated: true,
            userId: req.session.userId,
            userEmail: req.session.userEmail
        });
    } else {
        res.json({ authenticated: false });
    }
});

// CSRF token — for SPAs that need to fetch it after page load
app.get('/api/csrf-token', authenticate, (req, res) => {
    // Ensure CSRF token exists
    if (!req.session.csrfToken) {
        req.session.csrfToken = generateCsrfToken();
        req.session.save(() => {}); // non-blocking save
    }
    setCsrfCookie(res, req.session.csrfToken);
    res.json({ csrfToken: req.session.csrfToken });
});

// Create session (used when OAuth flow or external auth sets userId)
app.post('/api/create-session', async (req, res) => {
    try {
        const { userId, email } = req.body;

        if (!userId) {
            return res.status(400).json({ error: 'User ID required' });
        }

        req.session.regenerate((err) => {
            if (err) {
                logError('Session regenerate', err);
                return res.status(500).json({ error: 'Session creation failed' });
            }

            const csrfToken = generateCsrfToken();
            req.session.userId = userId;
            req.session.userEmail = email || '';
            req.session.loginTime = Date.now();
            req.session.csrfToken = csrfToken;

            req.session.save((saveErr) => {
                if (saveErr) {
                    logError('Session save', saveErr);
                    return res.status(500).json({ error: 'Session save failed' });
                }

                setCsrfCookie(res, csrfToken);
                console.log(`[Session] ✓ Session created for user: ${userId}`);

                res.json({
                    success: true,
                    userId,
                    sessionId: req.sessionID
                });
            });
        });

    } catch (error) {
        logError('Create session', error);
        res.status(500).json({ error: 'Server error occurred' });
    }
});

// ==========================================
//  GOOGLE OAUTH
// ==========================================

// Step 1: Redirect user to Google — requires session (user must be logged in)
app.get('/api/google/connect', authenticate, (req, res) => {
    const userId = req.session.userId;
    const state = createOAuthState(userId); // secure nonce bound to userId

    const scope = encodeURIComponent(
        'openid email profile ' +
        'https://www.googleapis.com/auth/gmail.send ' +
        'https://www.googleapis.com/auth/gmail.readonly ' +
        'https://www.googleapis.com/auth/gmail.modify'
    );

    const redirectUri = encodeURIComponent('https://flowon.onrender.com/api/google/oauth/callback');
    const authUrl = `https://accounts.google.com/o/oauth2/v2/auth` +
        `?client_id=${process.env.GOOGLE_CLIENT_ID}` +
        `&redirect_uri=${redirectUri}` +
        `&response_type=code` +
        `&scope=${scope}` +
        `&access_type=offline` +
        `&prompt=consent` +
        `&state=${state}`;

    res.redirect(authUrl);
});

// Step 2: OAuth callback — validates state nonce
app.get('/api/google/oauth/callback', async (req, res) => {
    const { code, state, error } = req.query;

    if (error) {
        console.warn('[OAuth] Google returned error:', error);
        return res.redirect('https://seraphielspark.github.io/flowon/flow.html?status=error&reason=' + encodeURIComponent(error));
    }

    if (!code) return res.status(400).send('No authorization code provided');
    if (!state) return res.status(400).send('Missing state parameter');

    // Validate and consume the state nonce
    const userId = consumeOAuthState(state);
    if (!userId) {
        console.warn('[OAuth] Invalid or expired state nonce');
        return res.status(400).send('Invalid or expired OAuth state. Please try connecting again.');
    }

    try {
        const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', null, {
            params: {
                code,
                client_id: process.env.GOOGLE_CLIENT_ID,
                client_secret: process.env.GOOGLE_CLIENT_SECRET,
                redirect_uri: 'https://flowon.onrender.com/api/google/oauth/callback',
                grant_type: 'authorization_code'
            }
        });

        const { access_token, refresh_token, expires_in } = tokenResponse.data;
        const expires_at = Date.now() + expires_in * 1000;

        await saveTokensToDB({ userId, access_token, refresh_token, expires_at });

        // Send tokens to n8n for persistence (non-fatal if it fails)
        try {
            await axios.post('https://kingoftech.app.n8n.cloud/webhook/link', {
                userId,
                google_access_token: access_token,
                google_refresh_token: refresh_token || 'ALREADY_AUTHORIZED',
                token_expiry: expires_at,
                timestamp: new Date().toISOString()
            });
            console.log(`[OAuth] Tokens sent to n8n for user: ${userId}`);
        } catch (n8nError) {
            console.warn('[OAuth] Failed to persist tokens to n8n:', n8nError.message);
        }

        res.redirect('https://seraphielspark.github.io/flowon/flow.html?status=connected');

    } catch (err) {
        logError('OAuth callback', err);
        res.redirect('https://seraphielspark.github.io/flowon/flow.html?status=error&reason=token_exchange_failed');
    }
});

// Google connection status
app.get('/api/google/status', authenticate, async (req, res) => {
    const userId = req.session.userId;
    const tokens = await getTokensFromDB(userId);
    res.json({
        connected: !!(tokens && tokens.access_token),
        userId,
        hasTokens: !!tokens
    });
});

// ==========================================
//  READ-ONLY ROUTES (GET — no CSRF needed)
// ==========================================

// Get user data
app.get('/api/userdata/:flowid', authenticate, async (req, res) => {
    const { flowid } = req.params;

    if (req.session.userId !== flowid) {
        return res.status(403).json({ error: 'Access denied' });
    }

    try {
        const response = await fetch(
            `https://kingoftech.app.n8n.cloud/webhook/e6bf03cc-c9e6-4727-91c5-375b420ac2ce/${flowid}/`
        );

        if (!response.ok) {
            return res.status(response.status).json({ error: 'Failed to fetch user data' });
        }

        const data = await response.json();

        const whatsapp = getWhatsAppNumber(flowid);
        data.whatsapp_connected = !!whatsapp;
        data.whatsapp_number = whatsapp ? whatsapp.phoneNumber : null;

        res.json(data);
    } catch (err) {
        logError('User data fetch', err);
        res.status(500).json({ error: 'Failed to fetch data from n8n' });
    }
});

// WhatsApp status
app.get('/api/whatsapp/status', authenticate, (req, res) => {
    try {
        const userId = req.session.userId;
        const whatsapp = getWhatsAppNumber(userId);

        if (whatsapp) {
            res.json({
                connected: true,
                phoneNumber: whatsapp.phoneNumber,
                registeredAt: whatsapp.registeredAt
            });
        } else {
            res.json({ connected: false });
        }
    } catch (error) {
        logError('WhatsApp status', error);
        res.status(500).json({ error: 'Failed to get WhatsApp status' });
    }
});

// Inbox messages
app.get('/api/inbox', authenticate, async (req, res) => {
    try {
        const userId = req.session.userId;

        const oauth2Client = await getOAuth2Client(userId);
        if (!oauth2Client) {
            return res.status(401).json({ error: 'Gmail not connected. Please connect your Google account.' });
        }

        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

        const listResponse = await gmail.users.messages.list({
            userId: 'me',
            maxResults: 20,
            q: 'in:inbox'
        });

        const messages = listResponse.data.messages || [];
        if (messages.length === 0) return res.json([]);

        const inboxMessages = await Promise.all(
            messages.map(async (msg) => {
                try {
                    const message = await gmail.users.messages.get({
                        userId: 'me',
                        id: msg.id,
                        format: 'full'
                    });

                    const headers = message.data.payload.headers;
                    const getHeader = (name) => headers.find(h => h.name === name)?.value || '';

                    const from = getHeader('From');
                    const subject = getHeader('Subject') || '(No Subject)';
                    const date = getHeader('Date') || new Date().toISOString();
                    const isRead = !message.data.labelIds?.includes('UNREAD');

                    let fromName = from;
                    let fromEmail = from;
                    const emailMatch = from.match(/<(.+?)>/);
                    if (emailMatch) {
                        fromEmail = emailMatch[1];
                        fromName = from.replace(`<${fromEmail}>`, '').trim().replace(/^"|"$/g, '') || fromEmail.split('@')[0];
                    }

                    let bodyText = '';
                    let bodyHtml = '';

                    const extractBody = (parts) => {
                        for (const part of parts || []) {
                            if (part.mimeType === 'text/plain' && part.body?.data && !bodyText) {
                                bodyText = Buffer.from(part.body.data, 'base64').toString('utf-8');
                            }
                            if (part.mimeType === 'text/html' && part.body?.data && !bodyHtml) {
                                bodyHtml = Buffer.from(part.body.data, 'base64').toString('utf-8');
                            }
                            if (part.parts) extractBody(part.parts); // nested multipart
                        }
                    };

                    if (message.data.payload.parts) {
                        extractBody(message.data.payload.parts);
                    } else if (message.data.payload.body?.data) {
                        const raw = Buffer.from(message.data.payload.body.data, 'base64').toString('utf-8');
                        if (message.data.payload.mimeType === 'text/html') {
                            bodyHtml = raw;
                        } else {
                            bodyText = raw;
                        }
                    }

                    return {
                        id: msg.id,
                        threadId: message.data.threadId,
                        from_name: fromName,
                        from_email: fromEmail,
                        subject: subject.substring(0, 200),
                        date,
                        body_text: bodyText.substring(0, 10000),
                        body_html: bodyHtml,
                        read: isRead,
                        snippet: message.data.snippet || '',
                        labelIds: message.data.labelIds || []
                    };
                } catch (msgError) {
                    console.error(`[Inbox] Error fetching message ${msg.id}:`, msgError.message);
                    return null;
                }
            })
        );

        const validMessages = inboxMessages
            .filter(Boolean)
            .sort((a, b) => new Date(b.date) - new Date(a.date));

        // WhatsApp notifications for new unread messages
        const whatsapp = getWhatsAppNumber(userId);
        if (whatsapp) {
            const unreadMessages = validMessages.filter(m => !m.read);
            if (!lastMessageCheck.has(userId)) lastMessageCheck.set(userId, {});
            const userChecked = lastMessageCheck.get(userId);

            for (const msg of unreadMessages) {
                if (!userChecked[msg.id]) {
                    userChecked[msg.id] = Date.now();
                    // Fire and forget — don't block the response
                    sendWhatsAppNotification(userId, {
                        from: msg.from_name || msg.from_email,
                        subject: msg.subject,
                        snippet: msg.snippet,
                        messageId: msg.id
                    }).catch(err => logError('WhatsApp notify in inbox', err));
                }
            }
        }

        res.json(validMessages);

    } catch (error) {
        logError('Inbox fetch', error);
        if (error.code === 401 || error.status === 401) {
            return res.status(401).json({ error: 'Gmail authentication failed. Please reconnect your Google account.' });
        }
        res.status(500).json({ error: 'Failed to fetch inbox messages' });
    }
});

// Unread count
app.get('/api/inbox/unread/count', authenticate, async (req, res) => {
    try {
        const userId = req.session.userId;

        const oauth2Client = await getOAuth2Client(userId);
        if (!oauth2Client) return res.json({ count: 0 });

        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

        const response = await gmail.users.messages.list({
            userId: 'me',
            q: 'in:inbox is:unread',
            maxResults: 500
        });

        res.json({ count: response.data.messages?.length || 0 });
    } catch (error) {
        logError('Unread count', error);
        res.json({ count: 0 });
    }
});

// Token debug info
app.get('/api/debug/tokens/:userId', authenticate, async (req, res) => {
    const { userId } = req.params;

    if (req.session.userId !== userId) {
        return res.status(403).json({ error: 'Access denied' });
    }

    const tokens = await getTokensFromDB(userId);
    if (tokens) {
        res.json({
            exists: true,
            hasAccessToken: !!tokens.access_token,
            hasRefreshToken: !!tokens.refresh_token,
            expires_at: tokens.expires_at,
            expired: Date.now() > tokens.expires_at,
            userId
        });
    } else {
        res.json({ exists: false, userId });
    }
});

// ==========================================
//  STATE-CHANGING ROUTES (POST/PUT/DELETE — CSRF required)
// ==========================================

// Update customers
app.post('/api/updatecustomers', authenticate, csrfProtect, async (req, res) => {
    const { customers, templates } = req.body;
    const userId = req.session.userId;

    try {
        const response = await fetch('https://kingoftech.app.n8n.cloud/webhook/updatecustomers', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                userid: userId,
                customers: JSON.stringify(customers),
                templates: JSON.stringify(templates)
            })
        });
        const data = await response.json();
        res.json({ success: true, message: 'Data updated successfully', data });
    } catch (err) {
        logError('Update customers', err);
        res.status(500).json({ error: 'Failed to update customers' });
    }
});

// Create table
app.post('/api/createtable', authenticate, csrfProtect, async (req, res) => {
    const { name } = req.body;
    const userId = req.session.userId;

    if (!name || typeof name !== 'string' || name.trim().length === 0) {
        return res.status(400).json({ error: 'Table name is required' });
    }

    try {
        const response = await fetch('https://kingoftech.app.n8n.cloud/webhook/createtable', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ userid: userId, name: name.trim() })
        });
        const data = await response.json();
        res.json(data);
    } catch (err) {
        logError('Create table', err);
        res.status(500).json({ error: 'Failed to create table' });
    }
});

// Update templates
app.post('/api/updatetemplates', authenticate, csrfProtect, async (req, res) => {
    const { templates } = req.body;
    const userId = req.session.userId;

    try {
        const response = await fetch('https://kingoftech.app.n8n.cloud/webhook/updatetemplates', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ userid: userId, templates })
        });

        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            const data = await response.json();
            res.json(data);
        } else {
            res.json({ success: true, message: 'Templates updated' });
        }
    } catch (err) {
        logError('Update templates', err);
        res.status(500).json({ error: 'Failed to update templates' });
    }
});

// Send automated messages (email campaign)
app.post('/api/send-automated-messages', authenticate, csrfProtect, async (req, res) => {
    try {
        const userId = req.session.userId;
        const campaignData = req.body;

        const userTokens = await getTokensFromDB(userId);
        if (!userTokens || !userTokens.access_token) {
            return res.status(400).json({ error: 'Gmail not connected. Please connect your Google account.' });
        }

        if (!Array.isArray(campaignData.recipients) || campaignData.recipients.length === 0) {
            return res.status(400).json({ error: 'At least one recipient is required' });
        }

        const payload = {
            recipients: campaignData.recipients,
            body: campaignData.body || '',
            fromName: campaignData.fromName || '',
            fromEmail: campaignData.fromEmail || '',
            subject: campaignData.subject || '',
            access_token: userTokens.access_token,
            refresh_token: userTokens.refresh_token,
            userId
        };

        console.log(`[Campaign] Sending for user ${userId} to ${payload.recipients.length} recipients`);

        const response = await fetch('https://kingoftech.app.n8n.cloud/webhook/send-automated-messages', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            const errorText = await response.text();
            console.error(`[Campaign] n8n returned ${response.status}:`, errorText);
            return res.status(response.status).json({ error: 'Campaign dispatch failed' });
        }

        const contentType = response.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
            const data = await response.json();
            res.json(data);
        } else {
            const text = await response.text();
            res.json({ success: true, message: 'Messages queued successfully', response: text });
        }

    } catch (err) {
        logError('Send messages', err);
        res.status(500).json({ error: 'Failed to send messages: ' + err.message });
    }
});

// Receive email webhook (no auth — called by external service)
app.post('/api/receive-email', (req, res) => {
    const emailData = req.body;
    console.log('[Webhook] Email received:', emailData);
    res.status(200).json({ success: true });
});

// Register WhatsApp number
app.post('/api/whatsapp/register', authenticate, csrfProtect, async (req, res) => {
    try {
        const userId = req.session.userId;
        const { phoneNumber } = req.body;

        if (!phoneNumber) {
            return res.status(400).json({ error: 'Phone number is required' });
        }

        const phoneRegex = /^\+?[1-9]\d{1,14}$/;
        if (!phoneRegex.test(phoneNumber.replace(/\s/g, ''))) {
            return res.status(400).json({ error: 'Invalid phone number format. Use international format e.g. +1234567890' });
        }

        await saveWhatsAppNumber(userId, phoneNumber.replace(/\s/g, ''));
        res.json({ success: true, message: 'WhatsApp number registered', phoneNumber });

    } catch (error) {
        logError('WhatsApp register', error);
        res.status(500).json({ error: 'Failed to register WhatsApp number' });
    }
});

// Manually trigger WhatsApp notification
app.post('/api/whatsapp/notify', authenticate, csrfProtect, async (req, res) => {
    try {
        const userId = req.session.userId;
        const { message, from, subject } = req.body;

        const whatsapp = getWhatsAppNumber(userId);
        if (!whatsapp) {
            return res.status(400).json({ error: 'No WhatsApp number registered for this user' });
        }

        const response = await fetch('https://kingoftech.app.n8n.cloud/webhook/receive', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                to: whatsapp.phoneNumber,
                message,
                from,
                subject,
                userId,
                timestamp: new Date().toISOString()
            })
        });

        if (!response.ok) throw new Error(`n8n returned ${response.status}`);

        res.json({ success: true, message: 'Notification sent' });

    } catch (error) {
        logError('WhatsApp notify', error);
        res.status(500).json({ error: 'Failed to send WhatsApp notification' });
    }
});

// Trigger WhatsApp notification for a specific message
app.post('/api/whatsapp/notify-new-message', authenticate, csrfProtect, async (req, res) => {
    try {
        const userId = req.session.userId;
        const { messageId, from, subject, snippet } = req.body;

        const result = await sendWhatsAppNotification(userId, { from, subject, snippet, messageId });

        if (result) {
            res.json({ success: true, message: 'WhatsApp notification sent' });
        } else {
            res.json({ skipped: true, reason: 'No WhatsApp number registered or send failed' });
        }

    } catch (error) {
        logError('WhatsApp new message notify', error);
        res.status(500).json({ error: 'Failed to send WhatsApp notification' });
    }
});

// Mark message as read
app.post('/api/inbox/read/:messageId', authenticate, csrfProtect, async (req, res) => {
    try {
        const { messageId } = req.params;
        const userId = req.session.userId;

        const oauth2Client = await getOAuth2Client(userId);
        if (!oauth2Client) {
            return res.status(401).json({ error: 'Gmail not connected' });
        }

        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

        await gmail.users.messages.modify({
            userId: 'me',
            id: messageId,
            requestBody: { removeLabelIds: ['UNREAD'] }
        });

        res.json({ success: true });
    } catch (error) {
        logError('Mark as read', error);
        res.status(500).json({ error: 'Failed to mark message as read' });
    }
});

// Delete message (move to trash)
app.delete('/api/inbox/:messageId', authenticate, csrfProtect, async (req, res) => {
    try {
        const { messageId } = req.params;
        const userId = req.session.userId;

        const oauth2Client = await getOAuth2Client(userId);
        if (!oauth2Client) {
            return res.status(401).json({ error: 'Gmail not connected' });
        }

        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

        await gmail.users.messages.trash({
            userId: 'me',
            id: messageId
        });

        res.json({ success: true });
    } catch (error) {
        logError('Delete message', error);
        res.status(500).json({ error: 'Failed to delete message' });
    }
});

// Clear message notification history (debug)
app.post('/api/debug/clear-message-history', authenticate, csrfProtect, (req, res) => {
    const userId = req.session.userId;

    if (lastMessageCheck.has(userId)) {
        lastMessageCheck.delete(userId);
        res.json({ success: true, message: `Message history cleared for user ${userId}` });
    } else {
        res.json({ success: false, message: `No history found for user ${userId}` });
    }
});

// ==========================================
//  GLOBAL ERROR HANDLER
// ==========================================

app.use((err, req, res, next) => {
    logError('Unhandled', err);
    res.status(500).json({ error: 'An unexpected error occurred' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

// ==========================================
//  START SERVER
// ==========================================

app.listen(PORT, () => {
    console.log(`✓ Server running on port ${PORT}`);
    console.log(`✓ Environment: ${IS_PRODUCTION ? 'production' : 'development'}`);
    console.log(`✓ CORS origins: ${ALLOWED_ORIGINS.join(', ')}`);
});
