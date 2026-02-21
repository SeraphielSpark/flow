const express = require('express');
const fetch = require('node-fetch');
const axios = require('axios');
const cors = require('cors');
const session = require('express-session');
const { google } = require('googleapis');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const csrf = require('csurf');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// ==========================================
//  SECURITY MIDDLEWARE
// ==========================================

// Helmet for security headers
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

// Cookie parser
app.use(cookieParser(process.env.COOKIE_SECRET || 'cookie-secret-change-this'));

// CORS with credentials support
const corsOptions = {
    origin: function (origin, callback) {
        const allowedOrigins = [
            'https://seraphielspark.github.io',
            'http://localhost:3000',
            'http://127.0.0.1:3000'
        ];
        if (!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// Body parsers with size limits
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// ==========================================
//  SESSION CONFIGURATION - FIXED
// ==========================================

// Memory store for sessions (use Redis in production)
const sessionStore = new session.MemoryStore();

// Session setup (HTTP-only cookies) - IMPROVED CONFIGURATION
app.use(session({
    name: 'fluxon.sid',
    secret: process.env.SESSION_SECRET || 'super-secret-key-change-this',
    store: sessionStore,
    resave: true, // Changed to true to ensure session is saved
    saveUninitialized: true, // Changed to true to create session even if not modified
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        path: '/'
    },
    rolling: true // Refresh session with each request
}));

// Debug middleware to log session creation
app.use((req, res, next) => {
    console.log('Session ID:', req.sessionID);
    console.log('Session user:', req.session.userId);
    next();
});

// CSRF protection (exclude certain paths)
const csrfProtection = csrf({
    cookie: {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/'
    }
});

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        return req.path === '/get';
    }
});

// Apply rate limiting to all API routes
app.use('/api/', limiter);

// ==========================================
//  AUTHENTICATION MIDDLEWARE
// ==========================================

// Authentication middleware
const authenticate = (req, res, next) => {
    console.log('Authenticate check - Session userId:', req.session.userId);
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    next();
};

// Optional authentication
const optionalAuth = (req, res, next) => {
    next();
};

// ==========================================
//  HELPER FUNCTIONS
// ==========================================

let tokensDB = {};
let whatsappDB = {};
let lastMessageCheck = {};

// Rate limiting for token operations
const tokenRateLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    keyGenerator: (req) => req.session.userId || req.ip
});

async function saveTokensToDB({ userId, access_token, refresh_token, expires_at }) {
    if (!userId) return;
    tokensDB[userId] = { 
        access_token, 
        refresh_token, 
        expires_at,
        updated_at: Date.now()
    };
    console.log(`Tokens cached in memory for User: ${userId}`);
}

async function getTokensFromDB(userId) {
    if (!userId) return null;
    
    if (tokensDB[userId]) {
        return tokensDB[userId];
    }

    console.log(`Cache miss for ${userId}. Fetching tokens from n8n/Airtable...`);
    try {
        const response = await fetch(`https://kingoftech.app.n8n.cloud/webhook/get-user-tokens?userId=${encodeURIComponent(userId)}`);
        
        if (!response.ok) {
            console.error(`n8n returned ${response.status} for token fetch`);
            return null;
        }
        
        const data = await response.json();
        
        if (data && data.access_token) {
            tokensDB[userId] = {
                access_token: data.access_token,
                refresh_token: data.refresh_token,
                expires_at: data.expires_at || (Date.now() + 3500 * 1000),
                updated_at: Date.now()
            };
            console.log(`Tokens restored from cloud for User: ${userId}`);
            return tokensDB[userId];
        }
        
        return null;
    } catch (error) {
        console.error("Error fetching tokens from n8n:", error.message);
        return null;
    }
}

// WhatsApp number management
async function saveWhatsAppNumber(userId, phoneNumber) {
    if (!userId) return null;
    
    whatsappDB[userId] = {
        phoneNumber,
        registeredAt: new Date().toISOString(),
        verified: true
    };
    console.log(`WhatsApp number saved for User: ${userId}`);
    
    try {
        await axios.post('https://kingoftech.app.n8n.cloud/webhook/whatsapp-register', {
            userId: userId,
            phoneNumber: phoneNumber,
            timestamp: new Date().toISOString()
        }, {
            headers: { 'Content-Type': 'application/json' }
        });
        console.log(`WhatsApp registration sent to n8n for User: ${userId}`);
    } catch (error) {
        console.error("Failed to send WhatsApp registration to n8n:", error.message);
    }
    
    return whatsappDB[userId];
}

async function getWhatsAppNumber(userId) {
    if (!userId) return null;
    return whatsappDB[userId];
}

// ==========================================
//  WHATSAPP NOTIFICATION HELPER
// ==========================================

async function sendWhatsAppNotification(userId, messageDetails) {
    if (!userId) return false;
    
    try {
        const whatsapp = await getWhatsAppNumber(userId);
        
        if (!whatsapp) {
            console.log(`No WhatsApp registered for user ${userId}, skipping notification`);
            return false;
        }

        const { from, subject, snippet, messageId } = messageDetails;
        
        const whatsappMessage = `📧 *New Message Received*\n\n*From:* ${from}\n*Subject:* ${subject}\n\n*Preview:* ${snippet || 'No preview available'}\n\nCheck your inbox for more details.`;
        
        const payload = {
            to: whatsapp.phoneNumber,
            message: whatsappMessage,
            from: from,
            subject: subject,
            userId: userId,
            messageId: messageId,
            type: 'new_email_notification',
            timestamp: new Date().toISOString()
        };
        
        const response = await fetch(`https://kingoftech.app.n8n.cloud/webhook/receive`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        if (!response.ok) {
            throw new Error(`n8n returned ${response.status}`);
        }
        
        console.log(`WhatsApp notification sent to user ${userId} for message ${messageId}`);
        return true;
        
    } catch (error) {
        console.error('WhatsApp notification error:', error);
        return false;
    }
}

// ==========================================
//  LOGIN/LOGOUT ENDPOINTS
// ==========================================

// Login endpoint
app.post('/api/login', limiter, async (req, res) => {
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
        
        if (!response.ok) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const data = await response.json();
        
        if (!data.userId) {
            return res.status(401).json({ error: 'Authentication failed' });
        }
        
        // Set session
        req.session.userId = data.userId;
        req.session.userEmail = email;
        req.session.loginTime = Date.now();
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');
        
        // Save session explicitly
        req.session.save((err) => {
            if (err) {
                console.error('Session save error:', err);
                return res.status(500).json({ error: 'Failed to save session' });
            }
            
            console.log('Session saved for user:', data.userId);
            console.log('Session ID:', req.sessionID);
            
            // Set CSRF cookie
            res.cookie('XSRF-TOKEN', req.session.csrfToken, {
                httpOnly: false,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'lax',
                maxAge: 24 * 60 * 60 * 1000
            });
            
            res.json({ 
                success: true, 
                userId: data.userId,
                email: email
            });
        });
        
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Logout endpoint
app.post('/api/logout', authenticate, (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Logout failed' });
        }
        
        res.clearCookie('fluxon.sid');
        res.clearCookie('XSRF-TOKEN');
        res.json({ success: true });
    });
});

// Session check endpoint - IMPROVED LOGGING
app.get('/api/session', (req, res) => {
    console.log('Session check - Session ID:', req.sessionID);
    console.log('Session check - UserId:', req.session.userId);
    
    if (req.session.userId) {
        res.json({
            authenticated: true,
            userId: req.session.userId,
            userEmail: req.session.userEmail,
            sessionId: req.sessionID
        });
    } else {
        res.json({ authenticated: false });
    }
});

// CSRF token endpoint
app.get('/api/csrf-token', authenticate, (req, res) => {
    if (!req.session.csrfToken) {
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');
        res.cookie('XSRF-TOKEN', req.session.csrfToken, {
            httpOnly: false,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            maxAge: 24 * 60 * 60 * 1000
        });
    }
    
    res.json({ csrfToken: req.session.csrfToken });
});

// ==========================================
//  CREATE SESSION ENDPOINT - FIXED
// ==========================================

app.post('/api/create-session', async (req, res) => {
  try {
    const { userId, email } = req.body;
    
    if (!userId) {
      return res.status(400).json({ error: 'User ID required' });
    }
    
    console.log('Creating session for user:', userId);
    
    // Regenerate session to ensure clean state
    req.session.regenerate((err) => {
        if (err) {
            console.error('Session regeneration error:', err);
            return res.status(500).json({ error: 'Failed to create session' });
        }
        
        // Set session data
        req.session.userId = userId;
        req.session.userEmail = email || 'user@example.com';
        req.session.loginTime = Date.now();
        req.session.csrfToken = crypto.randomBytes(32).toString('hex');
        
        // Save session
        req.session.save((saveErr) => {
            if (saveErr) {
                console.error('Session save error:', saveErr);
                return res.status(500).json({ error: 'Failed to save session' });
            }
            
            console.log('Session created successfully for user:', userId);
            console.log('Session ID:', req.sessionID);
            
            // Set CSRF cookie
            res.cookie('XSRF-TOKEN', req.session.csrfToken, {
                httpOnly: false,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'lax',
                maxAge: 24 * 60 * 60 * 1000
            });
            
            res.json({ success: true, userId });
        });
    });
    
  } catch (error) {
    console.error('Session creation error:', error);
    res.status(500).json({ error: 'Failed to create session' });
  }
});

// ==========================================
//  CSRF EXEMPTED ROUTES
// ==========================================

// --- 1. Proxy GET User Data ---
app.get('/api/userdata/:flowid', authenticate, async (req, res) => {
    const { flowid } = req.params;
    
    if (req.session.userId !== flowid) {
        return res.status(403).json({ error: 'Access denied' });
    }
    
    try {
        const response = await fetch(`https://kingoftech.app.n8n.cloud/webhook/e6bf03cc-c9e6-4727-91c5-375b420ac2ce/${flowid}/`);
        const data = await response.json();
        
        const whatsapp = await getWhatsAppNumber(flowid);
        if (whatsapp) {
            data.whatsapp_connected = true;
            data.whatsapp_number = whatsapp.phoneNumber;
        } else {
            data.whatsapp_connected = false;
        }
        
        res.json(data);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to fetch data from n8n' });
    }
});

// --- 6. Simple GET endpoint ---
app.get('/get', (req, res) => {
    res.json({ 
        status: 'online',
        timestamp: new Date().toISOString(),
        version: '2.0.0-secure'
    });
});

// --- 9. Get WhatsApp status ---
app.get('/api/whatsapp/status', authenticate, async (req, res) => {
    try {
        const userId = req.session.userId;
        const whatsapp = await getWhatsAppNumber(userId);
        
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
        console.error('WhatsApp status error:', error);
        res.status(500).json({ error: 'Failed to get WhatsApp status' });
    }
});

// --- 14. Get all inbox messages ---
app.get('/api/inbox', authenticate, async (req, res) => {
    try {
        const userId = req.session.userId;
        
        const userTokens = await getTokensFromDB(userId);
        if (!userTokens || !userTokens.access_token) {
            return res.status(401).json({ error: 'Gmail not connected' });
        }

        const oauth2Client = new google.auth.OAuth2(
            process.env.GOOGLE_CLIENT_ID,
            process.env.GOOGLE_CLIENT_SECRET,
            'https://flowon.onrender.com/api/google/oauth/callback'
        );

        oauth2Client.setCredentials({
            access_token: userTokens.access_token,
            refresh_token: userTokens.refresh_token
        });

        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

        const response = await gmail.users.messages.list({
            userId: 'me',
            maxResults: 20,
            q: 'in:inbox'
        });

        const messages = response.data.messages || [];
        
        if (messages.length === 0) {
            return res.json([]);
        }
        
        const inboxMessages = await Promise.all(
            messages.map(async (msg) => {
                try {
                    const message = await gmail.users.messages.get({
                        userId: 'me',
                        id: msg.id,
                        format: 'full'
                    });

                    const headers = message.data.payload.headers;
                    const from = headers.find(h => h.name === 'From')?.value || 'Unknown';
                    const subject = headers.find(h => h.name === 'Subject')?.value || '(No Subject)';
                    const date = headers.find(h => h.name === 'Date')?.value || new Date().toISOString();
                    const isRead = !message.data.labelIds?.includes('UNREAD');
                    
                    let fromName = from;
                    let fromEmail = from;
                    const emailMatch = from.match(/<(.+?)>/);
                    if (emailMatch) {
                        fromEmail = emailMatch[1];
                        fromName = from.replace(`<${fromEmail}>`, '').trim() || fromEmail.split('@')[0];
                    }

                    let bodyText = '';
                    let bodyHtml = '';
                    
                    if (message.data.payload.parts) {
                        const textPart = message.data.payload.parts.find(part => part.mimeType === 'text/plain');
                        const htmlPart = message.data.payload.parts.find(part => part.mimeType === 'text/html');
                        
                        if (textPart?.body?.data) {
                            bodyText = Buffer.from(textPart.body.data, 'base64').toString('utf-8');
                        }
                        if (htmlPart?.body?.data) {
                            bodyHtml = Buffer.from(htmlPart.body.data, 'base64').toString('utf-8');
                        }
                    } else if (message.data.payload.body?.data) {
                        if (message.data.payload.mimeType === 'text/html') {
                            bodyHtml = Buffer.from(message.data.payload.body.data, 'base64').toString('utf-8');
                        } else {
                            bodyText = Buffer.from(message.data.payload.body.data, 'base64').toString('utf-8');
                        }
                    }

                    return {
                        id: msg.id,
                        threadId: message.data.threadId,
                        from_name: fromName,
                        from_email: fromEmail,
                        subject: subject.substring(0, 200),
                        date: date,
                        body_text: bodyText.substring(0, 10000),
                        body_html: bodyHtml,
                        read: isRead,
                        snippet: message.data.snippet || '',
                        labelIds: message.data.labelIds || []
                    };
                } catch (msgError) {
                    console.error(`Error fetching message ${msg.id}:`, msgError);
                    return null;
                }
            })
        );

        const validMessages = inboxMessages.filter(msg => msg !== null);
        validMessages.sort((a, b) => new Date(b.date) - new Date(a.date));

        const whatsapp = await getWhatsAppNumber(userId);
        if (whatsapp) {
            const unreadMessages = validMessages.filter(msg => !msg.read);
            
            if (unreadMessages.length > 0) {
                console.log(`Found ${unreadMessages.length} unread messages for user ${userId}`);
                
                if (!lastMessageCheck[userId]) {
                    lastMessageCheck[userId] = {};
                }
                
                for (const msg of unreadMessages) {
                    if (!lastMessageCheck[userId][msg.id]) {
                        console.log(`New message detected for user ${userId}: ${msg.id}`);
                        
                        await sendWhatsAppNotification(userId, {
                            from: msg.from_name || msg.from_email,
                            subject: msg.subject,
                            snippet: msg.snippet,
                            messageId: msg.id
                        });
                        
                        lastMessageCheck[userId][msg.id] = Date.now();
                    }
                }
            }
        }

        res.json(validMessages);

    } catch (error) {
        console.error('Error fetching inbox:', error);
        
        if (error.code === 401) {
            return res.status(401).json({ error: 'Gmail authentication failed. Please reconnect.' });
        }
        
        res.status(500).json({ error: 'Failed to fetch inbox messages' });
    }
});

// --- 17. Get unread count ---
app.get('/api/inbox/unread/count', authenticate, async (req, res) => {
    try {
        const userId = req.session.userId;

        const userTokens = await getTokensFromDB(userId);
        if (!userTokens || !userTokens.access_token) {
            return res.json({ count: 0 });
        }

        const oauth2Client = new google.auth.OAuth2(
            process.env.GOOGLE_CLIENT_ID,
            process.env.GOOGLE_CLIENT_SECRET
        );

        oauth2Client.setCredentials({
            access_token: userTokens.access_token,
            refresh_token: userTokens.refresh_token
        });

        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

        const response = await gmail.users.messages.list({
            userId: 'me',
            q: 'in:inbox is:unread',
            maxResults: 500
        });

        res.json({ count: response.data.messages?.length || 0 });
    } catch (error) {
        console.error('Error fetching unread count:', error);
        res.json({ count: 0 });
    }
});

// --- 18. Debug token status ---
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
            user_id: userId
        });
    } else {
        res.json({ 
            exists: false, 
            user_id: userId
        });
    }
});

// --- 19. Google connection status ---
app.get('/api/google/status', authenticate, async (req, res) => {
    const userId = req.session.userId;
    const tokens = await getTokensFromDB(userId);
    const connected = !!(tokens && tokens.access_token);
    
    res.json({ 
        connected,
        userId,
        hasTokens: !!tokens
    });
});

// ==========================================
//  CSRF PROTECTED ROUTES
// ==========================================
app.use('/api/', csrfProtection);

// --- 2. Proxy POST Update Customers ---
app.post('/api/updatecustomers', authenticate, async (req, res) => {
    const { customers, templates } = req.body;
    const userId = req.session.userId;
    
    try {
        const response = await fetch(`https://kingoftech.app.n8n.cloud/webhook/updatecustomers`, {
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
        console.error('Update Customers Error:', err);
        res.status(500).json({ error: 'Failed to update customers' });
    }
});

// --- 3. Proxy POST Create Table ---
app.post('/api/createtable', authenticate, async (req, res) => {
    const { name } = req.body;
    const userId = req.session.userId;
    
    try {
        const response = await fetch(`https://kingoftech.app.n8n.cloud/webhook/createtable`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ userid: userId, name })
        });
        const data = await response.json();
        res.json(data);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to create table' });
    }
});

// --- 4. Proxy POST Update Templates ---
app.post('/api/updatetemplates', authenticate, async (req, res) => {
    const { templates } = req.body;
    const userId = req.session.userId;
    
    try {
        const response = await fetch(`https://kingoftech.app.n8n.cloud/webhook/updatetemplates`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ userid: userId, templates })
        });
        
        const contentType = response.headers.get("content-type");
        if (contentType && contentType.indexOf("application/json") !== -1) {
            const data = await response.json();
            res.json(data);
        } else {
            res.json({ success: true, message: 'Templates sent to webhook' });
        }
    } catch (err) {
        console.error('Update Templates Error:', err);
        res.status(500).json({ error: 'Failed to update templates' });
    }
});

// --- 5. Proxy POST Send Automated Messages ---
app.post('/api/send-automated-messages', authenticate, async (req, res) => {
    try {
        const userId = req.session.userId;
        const campaignData = req.body;

        const userTokens = await getTokensFromDB(userId);
        
        if (!userTokens) {
            return res.status(400).json({ error: 'User Gmail not connected or tokens expired. Please reconnect.' });
        }

        const payload = {
            recipients: campaignData.recipients || [],
            body: campaignData.body || '',
            fromName: campaignData.fromName || '',
            fromEmail: campaignData.fromEmail || '',
            subject: campaignData.subject || '',
            access_token: userTokens.access_token,
            refresh_token: userTokens.refresh_token,
            userId: userId
        };

        console.log(`Sending campaign for User ${userId} to ${payload.recipients.length} recipients`);

        const response = await fetch(`https://kingoftech.app.n8n.cloud/webhook/send-automated-messages`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });

        if (!response.ok) {
            const errorText = await response.text();
            console.error(`n8n returned ${response.status}:`, errorText);
            return res.status(response.status).json({ error: 'n8n webhook failed' });
        }

        const contentType = response.headers.get("content-type");
        if (contentType && contentType.indexOf("application/json") !== -1) {
            const data = await response.json();
            res.json(data);
        } else {
            const text = await response.text();
            res.json({ success: true, message: 'Messages queued successfully', response: text });
        }

    } catch (err) {
        console.error('Send Messages Error:', err);
        res.status(500).json({ error: 'Failed to send messages: ' + err.message });
    }
});

// --- 7. Receive email webhook ---
app.post('/api/receive-email', (req, res) => {
    const emailData = req.body;
    console.log('Email received webhook:', emailData);
    res.status(200).send({ success: true });
});

// --- 8. Register WhatsApp number ---
app.post('/api/whatsapp/register', authenticate, async (req, res) => {
    try {
        const userId = req.session.userId;
        const { phoneNumber } = req.body;
        
        if (!phoneNumber) {
            return res.status(400).json({ error: 'Missing phoneNumber' });
        }
        
        const phoneRegex = /^\+?[1-9]\d{1,14}$/;
        if (!phoneRegex.test(phoneNumber.replace(/\s/g, ''))) {
            return res.status(400).json({ error: 'Invalid phone number format. Use international format (e.g., +1234567890)' });
        }
        
        await saveWhatsAppNumber(userId, phoneNumber);
        
        res.json({ 
            success: true, 
            message: 'WhatsApp number registered successfully',
            phoneNumber: phoneNumber
        });
        
    } catch (error) {
        console.error('WhatsApp registration error:', error);
        res.status(500).json({ error: 'Failed to register WhatsApp number' });
    }
});

// --- 10. Webhook to receive WhatsApp messages ---
app.post('/api/whatsapp/notify', authenticate, async (req, res) => {
    try {
        const userId = req.session.userId;
        const { message, from, subject } = req.body;
        
        const whatsapp = await getWhatsAppNumber(userId);
        
        if (!whatsapp) {
            return res.status(400).json({ error: 'User has no WhatsApp number registered' });
        }
        
        const payload = {
            to: whatsapp.phoneNumber,
            message: message,
            from: from,
            subject: subject,
            userId: userId,
            timestamp: new Date().toISOString()
        };
        
        const response = await fetch(`https://kingoftech.app.n8n.cloud/webhook/receive`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        
        if (!response.ok) {
            throw new Error(`n8n returned ${response.status}`);
        }
        
        res.json({ success: true, message: 'Notification sent to WhatsApp' });
        
    } catch (error) {
        console.error('WhatsApp notification error:', error);
        res.status(500).json({ error: 'Failed to send WhatsApp notification' });
    }
});

// --- 11. Trigger WhatsApp notification for new inbox message ---
app.post('/api/whatsapp/notify-new-message', authenticate, async (req, res) => {
    try {
        const userId = req.session.userId;
        const { messageId, from, subject, snippet } = req.body;
        
        const result = await sendWhatsAppNotification(userId, {
            from,
            subject,
            snippet,
            messageId
        });
        
        if (result) {
            res.json({ success: true, message: 'WhatsApp notification sent' });
        } else {
            res.json({ skipped: true, reason: 'No WhatsApp number registered or send failed' });
        }
        
    } catch (error) {
        console.error('WhatsApp notification error:', error);
        res.status(500).json({ error: 'Failed to send WhatsApp notification' });
    }
});

// --- 12. Google OAuth Connect ---
app.get('/api/google/connect', authenticate, (req, res) => {
    const userId = req.session.userId;

    const redirectUri = 'https://flowon.onrender.com/api/google/oauth/callback';
    const clientId = process.env.GOOGLE_CLIENT_ID;
    
    const scope = encodeURIComponent('openid email profile https://www.googleapis.com/auth/gmail.send https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.modify');

    const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${clientId}&redirect_uri=${redirectUri}&response_type=code&scope=${scope}&access_type=offline&prompt=consent&state=${userId}`;
    
    res.redirect(authUrl);
});

// --- 13. Google OAuth Callback ---
app.get('/api/google/oauth/callback', async (req, res) => {
    const code = req.query.code;
    const userId = req.query.state; 

    if (!code) return res.status(400).send("No code provided");
    if (!userId) return res.status(400).send("No userId returned in state parameter");

    try {
        const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', null, {
            params: {
                code: code,
                client_id: process.env.GOOGLE_CLIENT_ID,
                client_secret: process.env.GOOGLE_CLIENT_SECRET,
                redirect_uri: 'https://flowon.onrender.com/api/google/oauth/callback',
                grant_type: 'authorization_code'
            }
        });

        const { access_token, refresh_token, expires_in } = tokenResponse.data;
        
        await saveTokensToDB({
            userId,
            access_token,
            refresh_token,
            expires_at: Date.now() + expires_in * 1000
        });

        try {
            console.log(`Sending credentials to n8n for User: ${userId}`);
            await axios.post('https://kingoftech.app.n8n.cloud/webhook/link', {
                userId: userId, 
                google_access_token: access_token,
                google_refresh_token: refresh_token || "ALREADY_AUTHORIZED", 
                token_expiry: Date.now() + expires_in * 1000,
                timestamp: new Date().toISOString()
            });
        } catch (n8nError) {
            console.error("Failed to send keys to n8n:", n8nError.message);
        }

        res.redirect('https://seraphielspark.github.io/flowon/flow.html?status=connected');

    } catch (err) {
        console.error("OAuth token exchange error:", err.response?.data || err.message);
        res.status(500).send("Failed to connect Gmail");
    }
});

// --- 15. Mark message as read ---
app.post('/api/inbox/read/:messageId', authenticate, async (req, res) => {
    try {
        const { messageId } = req.params;
        const userId = req.session.userId;

        const userTokens = await getTokensFromDB(userId);
        if (!userTokens || !userTokens.access_token) {
            return res.status(401).json({ error: 'Gmail not connected' });
        }

        const oauth2Client = new google.auth.OAuth2(
            process.env.GOOGLE_CLIENT_ID,
            process.env.GOOGLE_CLIENT_SECRET
        );

        oauth2Client.setCredentials({
            access_token: userTokens.access_token,
            refresh_token: userTokens.refresh_token
        });

        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

        await gmail.users.messages.modify({
            userId: 'me',
            id: messageId,
            requestBody: {
                removeLabelIds: ['UNREAD']
            }
        });

        res.json({ success: true });
    } catch (error) {
        console.error('Error marking message as read:', error);
        res.status(500).json({ error: 'Failed to mark message as read' });
    }
});

// --- 16. Delete message ---
app.delete('/api/inbox/:messageId', authenticate, async (req, res) => {
    try {
        const { messageId } = req.params;
        const userId = req.session.userId;

        const userTokens = await getTokensFromDB(userId);
        if (!userTokens || !userTokens.access_token) {
            return res.status(401).json({ error: 'Gmail not connected' });
        }

        const oauth2Client = new google.auth.OAuth2(
            process.env.GOOGLE_CLIENT_ID,
            process.env.GOOGLE_CLIENT_SECRET
        );

        oauth2Client.setCredentials({
            access_token: userTokens.access_token,
            refresh_token: userTokens.refresh_token
        });

        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

        await gmail.users.messages.trash({
            userId: 'me',
            id: messageId
        });

        res.json({ success: true });
    } catch (error) {
        console.error('Error deleting message:', error);
        res.status(500).json({ error: 'Failed to delete message' });
    }
});

// --- 20. Debug endpoint to clear message check history ---
app.post('/api/debug/clear-message-history', authenticate, (req, res) => {
    const userId = req.session.userId;
    
    if (lastMessageCheck[userId]) {
        delete lastMessageCheck[userId];
        res.json({ success: true, message: `Message history cleared for user ${userId}` });
    } else {
        res.json({ success: false, message: `No history found for user ${userId}` });
    }
});

// --- Start Server ---
app.listen(PORT, () => {
    console.log(`Secure server running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});
