const express = require('express');
const fetch = require('node-fetch');
const axios = require('axios');
const cors = require('cors');
const session = require('express-session');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// --- CORS setup ---
const corsOptions = {
  origin: '*', // replace '*' with your frontend domain in production
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// --- Body parsers ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// --- Session setup ---
app.use(session({
  secret: process.env.SESSION_SECRET || 'super-secret',
  resave: false,
  saveUninitialized: true
}));

// --- Helper functions (InMemory DB) ---
// Note: In production, use a real database (MongoDB, PostgreSQL) to persist tokens across restarts.
const tokensDB = {}; 

async function saveTokensToDB({ userId, access_token, refresh_token, expires_at }) {
  tokensDB[userId] = { access_token, refresh_token, expires_at };
}

async function getTokensFromDB(userId) {
  return tokensDB[userId];
}

// --- 1. Proxy GET User Data ---
app.get('/api/userdata/:flowid', async (req, res) => {
  const { flowid } = req.params;
  try {
    const response = await fetch(`https://kingoftech.app.n8n.cloud/webhook/e6bf03cc-c9e6-4727-91c5-375b420ac2ce/${flowid}/`);
    const data = await response.json();
    res.json(data);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to fetch data from n8n' });
  }
});

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

// --- 3. Proxy POST Create Table ---
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

// --- 5. Proxy POST Send Automated Messages (UPDATED) ---
app.post('/api/send-automated-messages', async (req, res) => {
  try {
    // 1. Destructure userId and gather the rest of the body as 'campaignData'
    // This supports the flat structure sent by your frontend ({ userId, recipients, subject... })
    const { userId, ...campaignData } = req.body;

    if (!userId) {
        return res.status(400).json({ error: 'Missing userId in request' });
    }

    // 2. Retrieve Gmail access_token from Local DB
    const userTokens = await getTokensFromDB(userId);
    
    if (!userTokens) {
        // If no token in local DB, we can't authenticate the request to Google
        return res.status(400).json({ error: 'User Gmail not connected' });
    }

    // 3. Construct the Payload for n8n
    // Explicitly including userId and access_token
    const payload = {
      userId: userId,                 // <--- Explicitly added
      ...campaignData,                // Spreads: recipients, subject, body, campaignName, etc.
      access_token: userTokens.access_token 
    };

    console.log(`Sending campaign for User ${userId} to n8n...`);

    // 4. Send to n8n
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

// --- 6. Simple GET endpoint ---
app.get('/get', (req, res) => {
  res.json('Welcome To HTTP REQUEST CLASS');
});

// --- 7. Receive email (example) ---
app.post('/api/receive-email', (req, res) => {
  const emailData = req.body;
  console.log('Email received:', emailData);
  res.status(200).send({ success: true });
});

// --- 8. Google OAuth connect ---
app.get('/api/google/connect', (req, res) => {
  const userId = req.query.userId; 

  if (!userId) {
    return res.status(400).send("Missing userId. Cannot link account.");
  }

  const redirectUri = 'https://flowon.onrender.com/api/google/oauth/callback';
  const clientId = process.env.GOOGLE_CLIENT_ID;
  
  const scope = encodeURIComponent('openid email profile https://www.googleapis.com/auth/gmail.send https://www.googleapis.com/auth/gmail.readonly');

  // Pass userId in state
  const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${clientId}&redirect_uri=${redirectUri}&response_type=code&scope=${scope}&access_type=offline&prompt=consent&state=${userId}`;

  res.redirect(authUrl);
});

// --- 9. Google OAuth callback ---
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
    
    // Save to Local DB
    await saveTokensToDB({
      userId,
      access_token,
      refresh_token,
      expires_at: Date.now() + expires_in * 1000
    });

    // Send credentials to n8n
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

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
