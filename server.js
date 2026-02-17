const express = require('express');
const fetch = require('node-fetch');
const axios = require('axios');
const cors = require('cors');
const session = require('express-session');
const { google } = require('googleapis');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// --- CORS setup ---
const corsOptions = {
  origin: '*',
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

// --- Body parsers ---
app.use(express.json({ limit: '50mb' }));
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

let tokensDB = {};

async function saveTokensToDB({ userId, access_token, refresh_token, expires_at }) {
  tokensDB[userId] = { access_token, refresh_token, expires_at };
  console.log(`Tokens cached in memory for User: ${userId}`);
}

async function getTokensFromDB(userId) {
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
//  API ENDPOINTS
// ==========================================

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

// --- 5. Proxy POST Send Automated Messages (FIXED to match n8n) ---
app.post('/api/send-automated-messages', async (req, res) => {
  try {
    const { userId, ...campaignData } = req.body;

    if (!userId) {
        return res.status(400).json({ error: 'Missing userId in request' });
    }

    const userTokens = await getTokensFromDB(userId);
    
    if (!userTokens) {
        console.warn(`Attempt to send email failed: No tokens found for user ${userId}`);
        return res.status(400).json({ error: 'User Gmail not connected or tokens expired. Please reconnect.' });
    }

    // IMPORTANT: Wrap everything in "body" object to match n8n function expectations
    const payload = {
      body: {
        recipients: campaignData.recipients || [],
        body: campaignData.body || '',
        fromName: campaignData.fromName || '',
        fromEmail: campaignData.fromEmail || '',
        subject: campaignData.subject || ''
      },
      access_token: userTokens.access_token,
      refresh_token: userTokens.refresh_token,
      userId: userId  // Send userId at top level as well
    };

    console.log(`Sending campaign for User ${userId} to ${payload.body.recipients.length} recipients`);

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

// --- 6. Simple GET endpoint ---
app.get('/get', (req, res) => {
  res.json('Backend is Online');
});

// --- 7. Receive email webhook ---
app.post('/api/receive-email', (req, res) => {
  const emailData = req.body;
  console.log('Email received webhook:', emailData);
  res.status(200).send({ success: true });
});

// ==========================================
//  GOOGLE OAUTH FLOW
// ==========================================

// --- 8. Google OAuth Connect ---
app.get('/api/google/connect', (req, res) => {
  const userId = req.query.userId; 
  if (!userId) {
    return res.status(400).send("Missing userId. Cannot link account.");
  }

  const redirectUri = 'https://flowon.onrender.com/api/google/oauth/callback';
  const clientId = process.env.GOOGLE_CLIENT_ID;
  
  const scope = encodeURIComponent('openid email profile https://www.googleapis.com/auth/gmail.send https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.modify');

  const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${clientId}&redirect_uri=${redirectUri}&response_type=code&scope=${scope}&access_type=offline&prompt=consent&state=${userId}`;
  
  res.redirect(authUrl);
});

// --- 9. Google OAuth Callback ---
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

// ==========================================
//  INBOX ENDPOINTS (FULL IMPLEMENTATION)
// ==========================================

// --- 10. Get all inbox messages ---
app.get('/api/inbox', async (req, res) => {
  try {
    const userId = req.query.userId;
    
    if (!userId) {
      return res.status(400).json({ error: 'Missing userId parameter' });
    }
    
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
            read: !message.data.labelIds?.includes('UNREAD'),
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

    res.json(validMessages);

  } catch (error) {
    console.error('Error fetching inbox:', error);
    
    if (error.code === 401) {
      return res.status(401).json({ error: 'Gmail authentication failed. Please reconnect.' });
    }
    
    res.status(500).json({ error: 'Failed to fetch inbox messages' });
  }
});

// --- 11. Mark message as read ---
app.post('/api/inbox/read/:messageId', async (req, res) => {
  try {
    const { messageId } = req.params;
    const userId = req.query.userId;
    
    if (!userId) {
      return res.status(400).json({ error: 'Missing userId' });
    }

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

// --- 12. Delete message ---
app.delete('/api/inbox/:messageId', async (req, res) => {
  try {
    const { messageId } = req.params;
    const userId = req.query.userId;
    
    if (!userId) {
      return res.status(400).json({ error: 'Missing userId' });
    }

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

// --- 13. Get unread count ---
app.get('/api/inbox/unread/count', async (req, res) => {
  try {
    const userId = req.query.userId;
    
    if (!userId) {
      return res.json({ count: 0 });
    }

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

// ==========================================
//  DEBUG & STATUS ENDPOINTS
// ==========================================

// --- 14. Debug token status ---
app.get('/api/debug/tokens/:userId', async (req, res) => {
  const { userId } = req.params;
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

// --- 15. Google connection status ---
app.get('/api/google/status', async (req, res) => {
  const userId = req.query.userId;
  
  if (!userId) {
    return res.status(400).json({ 
      connected: false, 
      error: 'No userId provided' 
    });
  }
  
  const tokens = await getTokensFromDB(userId);
  const connected = !!(tokens && tokens.access_token);
  
  res.json({ 
    connected,
    userId,
    hasTokens: !!tokens
  });
});

// --- Start Server ---
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
