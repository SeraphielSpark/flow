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
  origin: '*', // replace '*' with frontend domain in production
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

// --- Helper functions (replace with real DB logic) ---
const tokensDB = {}; // demo in-memory storage

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
    const { userId, emailData } = req.body;

    // Retrieve Gmail access_token from DB
    const userTokens = await getTokensFromDB(userId);
    if (!userTokens) return res.status(400).json({ error: 'User Gmail not connected' });

    // Include token in payload to n8n
    const payload = {
      ...emailData,
      access_token: userTokens.access_token
    };

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
        res.json({ success: true, message: 'Messages queued' });
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
// --- 8. Google OAuth connect (UPDATED) ---
app.get('/api/google/connect', (req, res) => {
  // 1. Get userId from the frontend request query
  const userId = req.query.userId; 

  if (!userId) {
    return res.status(400).send("Missing userId. Cannot link account.");
  }

  const redirectUri = 'https://flowon.onrender.com/api/google/oauth/callback';
  const clientId = process.env.GOOGLE_CLIENT_ID;
  
  // Scopes: Gmail send, read, and basic profile
  const scope = encodeURIComponent('openid email profile https://www.googleapis.com/auth/gmail.send https://www.googleapis.com/auth/gmail.readonly');

  // 2. Pass userId into the 'state' parameter. 
  // Google returns this value unchanged in the callback.
  const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${clientId}&redirect_uri=${redirectUri}&response_type=code&scope=${scope}&access_type=offline&prompt=consent&state=${userId}`;

  res.redirect(authUrl);
});

// --- 9. Google OAuth callback (UPDATED) ---
app.get('/api/google/oauth/callback', async (req, res) => {
  const code = req.query.code;
  // 1. Retrieve the userId from the 'state' query param returned by Google
  const userId = req.query.state; 

  if (!code) return res.status(400).send("No code provided");
  if (!userId) return res.status(400).send("No userId returned in state parameter");

  try {
    // 2. Exchange code for tokens from Google
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
    
    // 3. Save to Local DB (Optional cache)
    await saveTokensToDB({
      userId,
      access_token,
      refresh_token,
      expires_at: Date.now() + expires_in * 1000
    });

    // 4. CRITICAL: Send Keys AND userId to n8n Webhook
    try {
        console.log(`Sending credentials to n8n for User: ${userId}`);

        await axios.post('https://kingoftech.app.n8n.cloud/webhook/link', {
            // STRICTLY sending the userId we recovered
            userId: userId, 
            google_access_token: access_token,
            // Refresh token is only returned on the first consent. 
            // If undefined, the user has already authorized the app previously.
            google_refresh_token: refresh_token || "ALREADY_AUTHORIZED", 
            token_expiry: Date.now() + expires_in * 1000,
            timestamp: new Date().toISOString()
        });
        
        console.log("Keys successfully sent to n8n");
    } catch (n8nError) {
        console.error("Failed to send keys to n8n:", n8nError.message);
    }

    // 5. Redirect back to Frontend
    res.redirect('https://seraphielspark.github.io/flowon/flow.html?status=connected');

  } catch (err) {
    console.error("OAuth token exchange error:", err.response?.data || err.message);
    res.status(500).send("Failed to connect Gmail");
  }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));


