const express = require('express');
const fetch = require('node-fetch'); // Ensure you are using node-fetch v2 for CommonJS
const axios = require('axios');
const cors = require('cors');
const session = require('express-session');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// --- CORS setup ---
const corsOptions = {
  origin: '*', // Allow all origins (Replace with your specific domain in production for security)
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// --- Body parsers ---
app.use(express.json({ limit: '50mb' })); // Increased limit for large customer lists
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// --- Session setup ---
app.use(session({
  secret: process.env.SESSION_SECRET || 'super-secret-key-change-this',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));

// ==========================================
//  HELPER FUNCTIONS (Token Management)
// ==========================================

// In-Memory Cache (Fast access, wipes on restart)
let tokensDB = {}; 

/**
 * Save tokens to local memory.
 * Note: Persistence to Airtable happens via the n8n webhook call in the OAuth callback.
 */
async function saveTokensToDB({ userId, access_token, refresh_token, expires_at }) {
  tokensDB[userId] = { access_token, refresh_token, expires_at };
  console.log(`Tokens cached in memory for User: ${userId}`);
}

/**
 * Retrieve tokens.
 * 1. Checks local memory first (Fast).
 * 2. If missing (e.g., after server restart), fetches from n8n/Airtable.
 */
async function getTokensFromDB(userId) {
  // 1. Try Memory
  if (tokensDB[userId]) {
    return tokensDB[userId];
  }

  // 2. Try Fetching from Cloud (n8n -> Airtable)
  console.log(`Cache miss for ${userId}. Fetching tokens from n8n/Airtable...`);
  try {
    // YOU MUST CREATE THIS WEBHOOK IN n8n:
    // Method: GET
    // Path: /webhook/get-user-tokens
    // Parameter: ?userId=...
    // Response: JSON { "access_token": "...", "refresh_token": "...", "expires_at": ... }
    const response = await fetch(`https://kingoftech.app.n8n.cloud/webhook/get-user-tokens?userId=${encodeURIComponent(userId)}`);
    
    if (!response.ok) {
        console.error(`n8n returned ${response.status} for token fetch`);
        return null;
    }
    
    const data = await response.json();
    
    // Validate response
    if (data && data.access_token) {
        // Save to memory so we don't have to fetch next time
        tokensDB[userId] = {
            access_token: data.access_token,
            refresh_token: data.refresh_token,
            expires_at: data.expires_at || (Date.now() + 3500 * 1000)
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

// ==========================================
//  AUTHENTICATION ENDPOINTS (SIGNUP & LOGIN)
// ==========================================

/**
 * Signup Endpoint - Proxy to n8n webhook
 * Matches your n8n workflow structure exactly
 */
app.post('/webhook/signup', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Validate required fields
    if (!username || !email || !password) {
      return res.status(400).json({ 
        message: 'Username, email, and password are required' 
      });
    }

    console.log(`Signup attempt for: ${email}`);

    // Forward to n8n webhook
    const response = await fetch('https://kingoftech.app.n8n.cloud/webhook/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        username, 
        email, 
        password 
      })
    });

    const data = await response.json();
    
    // Return the response from n8n which includes userid
    res.status(response.status).json(data);
    
  } catch (err) {
    console.error('Signup Error:', err.message);
    res.status(500).json({ 
      message: 'Signup failed. Please try again.' 
    });
  }
});

/**
 * Login Endpoint - Proxy to n8n webhook
 * Matches your n8n workflow structure exactly
 */
app.post('/webhook/login', async (req, res) => {
  try {
    const { userid } = req.body;
    
    // Validate required field
    if (!userid) {
      return res.status(400).json({ 
        message: 'User ID is required' 
      });
    }

    console.log(`Login attempt for User ID: ${userid}`);

    // Forward to n8n webhook
    const response = await fetch('https://kingoftech.app.n8n.cloud/webhook/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userid })
    });

    const data = await response.json();
    
    // Return the response from n8n
    res.status(response.status).json(data);
    
  } catch (err) {
    console.error('Login Error:', err.message);
    res.status(500).json({ 
      message: 'Login failed. Please check your User ID.' 
    });
  }
});

/**
 * Get User Data by User ID
 * This matches your existing /api/userdata/:flowid endpoint but adds better error handling
 */
app.get('/api/userdata/:flowid', async (req, res) => {
  const { flowid } = req.params;
  try {
    const response = await fetch(`https://kingoftech.app.n8n.cloud/webhook/e6bf03cc-c9e6-4727-91c5-375b420ac2ce/${flowid}/`);
    
    if (!response.ok) {
      return res.status(response.status).json({ 
        error: 'User not found or data unavailable' 
      });
    }
    
    const data = await response.json();
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch data from n8n' });
  }
});

// ==========================================
//  EXISTING API ENDPOINTS (PRESERVED EXACTLY)
// ==========================================

// --- 2. Proxy POST Update Customers ---
app.post('/api/updatecustomers', async (req, res) => {
  const { userId, customers, templates } = req.body;
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

// --- 3. Proxy POST Create Table (Legacy) ---
app.post('/api/createtable', async (req, res) => {
  const { userid, name } = req.body;
  try {
    const response = await fetch(`https://kingoftech.app.n8n.cloud/webhook/createtable`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userid, name })
    });
    const data = await response.json();
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to create table' });
  }
});

// --- 4. Proxy POST Update Templates ---
app.post('/api/updatetemplates', async (req, res) => {
  const { userid, templates } = req.body;
  try {
    const response = await fetch(`https://kingoftech.app.n8n.cloud/webhook/updatetemplates`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userid, templates })
    });
    
    // Handle responses that might not be JSON
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
app.post('/api/send-automated-messages', async (req, res) => {
  try {
    const { userId, ...campaignData } = req.body;

    if (!userId) {
        return res.status(400).json({ error: 'Missing userId in request' });
    }

    // 1. Retrieve Gmail access_token (Memory or Cloud)
    const userTokens = await getTokensFromDB(userId);
    
    if (!userTokens) {
        console.warn(`Attempt to send email failed: No tokens found for user ${userId}`);
        return res.status(400).json({ error: 'User Gmail not connected or tokens expired. Please reconnect.' });
    }

    // 2. Construct the Payload for n8n
    const payload = {
      userId: userId,
      ...campaignData,
      access_token: userTokens.access_token,
      refresh_token: userTokens.refresh_token // Optional: Send refresh token if n8n handles rotation
    };

    console.log(`Sending campaign for User ${userId} to n8n...`);

    // 3. Send to n8n
    const response = await fetch(`https://kingoftech.app.n8n.cloud/webhook/send-automated-messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const contentType = response.headers.get("content-type");
    if (contentType && contentType.indexOf("application/json") !== -1) {
        const data = await response.json();
        res.json(data);
    } else {
        res.json({ success: true, message: 'Messages queued successfully' });
    }

  } catch (err) {
    console.error('Send Messages Error:', err);
    res.status(500).json({ error: 'Failed to send messages' });
  }
});

// --- 6. Simple GET endpoint (Health Check) ---
app.get('/get', (req, res) => {
  res.json('Backend is Online');
});

// --- 7. Receive email (Webhook Endpoint) ---
app.post('/api/receive-email', (req, res) => {
  const emailData = req.body;
  console.log('Email received webhook:', emailData);
  res.status(200).send({ success: true });
});

// --- 8. Inbox Proxy (Fetch messages) ---
// Note: You might need to implement this endpoint if your frontend calls /api/inbox
app.get('/api/inbox', async (req, res) => {
    // Mock response or proxy to n8n if implemented
    // For now returning empty array or you can wire it to n8n
    res.json([]); 
});

// ==========================================
//  GOOGLE OAUTH FLOW
// ==========================================

// --- 9. Google OAuth Connect (Start) ---
app.get('/api/google/connect', (req, res) => {
  const userId = req.query.userId; 
  if (!userId) {
    return res.status(400).send("Missing userId. Cannot link account.");
  }

  const redirectUri = 'https://flowon.onrender.com/api/google/oauth/callback';
  const clientId = process.env.GOOGLE_CLIENT_ID;
  
  // Scopes: OpenID, Email, Profile, Send Gmail, Read Gmail
  const scope = encodeURIComponent('openid email profile https://www.googleapis.com/auth/gmail.send https://www.googleapis.com/auth/gmail.readonly');

  // Pass userId in state so we know who is connecting
  const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${clientId}&redirect_uri=${redirectUri}&response_type=code&scope=${scope}&access_type=offline&prompt=consent&state=${userId}`;
  
  res.redirect(authUrl);
});

// --- 10. Google OAuth Callback (Finish) ---
app.get('/api/google/oauth/callback', async (req, res) => {
  const code = req.query.code;
  const userId = req.query.state; 

  if (!code) return res.status(400).send("No code provided");
  if (!userId) return res.status(400).send("No userId returned in state parameter");

  try {
    // 1. Exchange Code for Tokens
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
    
    // 2. Save to Local DB (Cache)
    await saveTokensToDB({
      userId,
      access_token,
      refresh_token,
      expires_at: Date.now() + expires_in * 1000
    });

    // 3. Send credentials to n8n (Persist to Airtable)
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
        // We continue anyway because we have them in memory for now
    }

    // 4. Redirect back to Frontend
    res.redirect('https://seraphielspark.github.io/flowon/flow.html?status=connected');

  } catch (err) {
    console.error("OAuth token exchange error:", err.response?.data || err.message);
    res.status(500).send("Failed to connect Gmail");
  }
});

// --- Start Server ---
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
