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

// --- 8. Google OAuth connect (UPDATED with userId) ---
app.get('/api/google/connect', (req, res) => {
  const redirectUri = 'https://flowon.onrender.com/api/google/oauth/callback';
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const userId = req.query.userId; // Get userId from query param
  const scope = encodeURIComponent('openid email profile https://www.googleapis.com/auth/gmail.send https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/gmail.modify');

  // Include userId in the state parameter to pass through OAuth flow
  const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${clientId}&redirect_uri=${redirectUri}&response_type=code&scope=${scope}&access_type=offline&prompt=consent&state=${encodeURIComponent(userId || '')}`;

  res.redirect(authUrl);
});

// --- 9. Google OAuth callback (UPDATED with userId handling) ---
app.get('/api/google/oauth/callback', async (req, res) => {
  const code = req.query.code;
  const state = req.query.state; // This contains the userId we passed
  
  if (!code) return res.status(400).send("No code provided");

  try {
    // 1. Exchange code for tokens from Google
    const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', {
      code: code,
      client_id: process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      redirect_uri: 'https://flowon.onrender.com/api/google/oauth/callback',
      grant_type: 'authorization_code'
    });

    const { access_token, refresh_token, expires_in } = tokenResponse.data;

    // 2. Get userId from state parameter (passed from frontend)
    const userId = state || req.session.userId || 'demo-user';
    
    // 3. Save to Local DB
    await saveTokensToDB({
      userId,
      access_token,
      refresh_token,
      expires_at: Date.now() + expires_in * 1000
    });

    // 4. Send Keys to n8n Webhook (optional)
    try {
        await axios.post('https://kingoftech.app.n8n.cloud/webhook/link', {
            userId: userId,
            google_access_token: access_token,
            google_refresh_token: refresh_token,
            token_expiry: Date.now() + expires_in * 1000
        });
        console.log("Keys successfully sent to n8n");
    } catch (n8nError) {
        console.error("Failed to send keys to n8n:", n8nError.message);
    }

    // 5. Redirect back to Frontend with userId in URL to maintain session
    res.redirect(`https://seraphielspark.github.io/flow/index.html?status=connected&userId=${encodeURIComponent(userId)}`);

  } catch (err) {
    console.error("OAuth token exchange error:", err.response?.data || err.message);
    res.status(500).send("Failed to connect Gmail");
  }
});

// --- 10. NEW: Fetch Inbox using stored Google tokens ---
app.get('/api/inbox', async (req, res) => {
  try {
    // Get userId from query param
    const userId = req.query.userId || req.session.userId || 'demo-user';
    
    // Retrieve user's Google tokens from DB
    const userTokens = await getTokensFromDB(userId);
    if (!userTokens || !userTokens.access_token) {
      return res.status(401).json({ error: 'Gmail not connected' });
    }

    // Create OAuth2 client with stored tokens
    const oauth2Client = new google.auth.OAuth2(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET,
      'https://flowon.onrender.com/api/google/oauth/callback'
    );

    oauth2Client.setCredentials({
      access_token: userTokens.access_token,
      refresh_token: userTokens.refresh_token
    });

    // Create Gmail API client
    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

    // Fetch latest 20 messages from inbox
    const response = await gmail.users.messages.list({
      userId: 'me',
      maxResults: 20,
      q: 'in:inbox' // Only get inbox messages
    });

    const messages = response.data.messages || [];
    
    // Fetch full message details for each message
    const inboxMessages = await Promise.all(
      messages.map(async (msg) => {
        const message = await gmail.users.messages.get({
          userId: 'me',
          id: msg.id,
          format: 'full'
        });

        // Extract headers
        const headers = message.data.payload.headers;
        const from = headers.find(h => h.name === 'From')?.value || 'Unknown';
        const subject = headers.find(h => h.name === 'Subject')?.value || '(No Subject)';
        const date = headers.find(h => h.name === 'Date')?.value || new Date().toISOString();
        
        // Parse from field to extract name and email
        let fromName = from;
        let fromEmail = from;
        const emailMatch = from.match(/<(.+?)>/);
        if (emailMatch) {
          fromEmail = emailMatch[1];
          fromName = from.replace(`<${fromEmail}>`, '').trim() || fromEmail.split('@')[0];
        }

        // Extract body
        let bodyText = '';
        let bodyHtml = '';
        
        if (message.data.payload.parts) {
          // Multipart message
          const textPart = message.data.payload.parts.find(part => part.mimeType === 'text/plain');
          const htmlPart = message.data.payload.parts.find(part => part.mimeType === 'text/html');
          
          if (textPart?.body?.data) {
            bodyText = Buffer.from(textPart.body.data, 'base64').toString('utf-8');
          }
          if (htmlPart?.body?.data) {
            bodyHtml = Buffer.from(htmlPart.body.data, 'base64').toString('utf-8');
          }
        } else if (message.data.payload.body?.data) {
          // Single part message
          if (message.data.payload.mimeType === 'text/html') {
            bodyHtml = Buffer.from(message.data.payload.body.data, 'base64').toString('utf-8');
          } else {
            bodyText = Buffer.from(message.data.payload.body.data, 'base64').toString('utf-8');
          }
        }

        return {
          id: msg.id,
          from_name: fromName,
          from_email: fromEmail,
          subject: subject,
          date: date,
          body_text: bodyText.substring(0, 5000), // Limit size
          body_html: bodyHtml,
          read: !message.data.labelIds?.includes('UNREAD'),
          snippet: message.data.snippet
        };
      })
    );

    // Sort by date (newest first)
    inboxMessages.sort((a, b) => new Date(b.date) - new Date(a.date));

    res.json(inboxMessages);
  } catch (error) {
    console.error('Error fetching inbox:', error);
    res.status(500).json({ error: 'Failed to fetch inbox messages' });
  }
});

// --- 11. NEW: Mark message as read ---
app.post('/api/inbox/read/:messageId', async (req, res) => {
  try {
    const { messageId } = req.params;
    const userId = req.query.userId || req.session.userId || 'demo-user';
    
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

    // Remove UNREAD label
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

// --- 12. NEW: Delete message (move to trash) ---
app.delete('/api/inbox/:messageId', async (req, res) => {
  try {
    const { messageId } = req.params;
    const userId = req.query.userId || req.session.userId || 'demo-user';
    
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

    // Move to trash (instead of permanent delete)
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

// --- 13. NEW: Get unread count ---
app.get('/api/inbox/unread/count', async (req, res) => {
  try {
    const userId = req.query.userId || req.session.userId || 'demo-user';
    
    const userTokens = await getTokensFromDB(userId);
    if (!userTokens || !userTokens.access_token) {
      return res.json({ count: 0 }); // Return 0 if not connected
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

// --- 14. NEW: Get single message by ID ---
app.get('/api/inbox/message/:messageId', async (req, res) => {
  try {
    const { messageId } = req.params;
    const userId = req.query.userId || req.session.userId || 'demo-user';
    
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

    const message = await gmail.users.messages.get({
      userId: 'me',
      id: messageId,
      format: 'full'
    });

    // Extract headers
    const headers = message.data.payload.headers;
    const from = headers.find(h => h.name === 'From')?.value || 'Unknown';
    const subject = headers.find(h => h.name === 'Subject')?.value || '(No Subject)';
    const date = headers.find(h => h.name === 'Date')?.value || new Date().toISOString();
    
    // Parse from field
    let fromName = from;
    let fromEmail = from;
    const emailMatch = from.match(/<(.+?)>/);
    if (emailMatch) {
      fromEmail = emailMatch[1];
      fromName = from.replace(`<${fromEmail}>`, '').trim() || fromEmail.split('@')[0];
    }

    // Extract body
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

    res.json({
      id: messageId,
      from_name: fromName,
      from_email: fromEmail,
      subject: subject,
      date: date,
      body_text: bodyText,
      body_html: bodyHtml,
      read: !message.data.labelIds?.includes('UNREAD'),
      snippet: message.data.snippet
    });

  } catch (error) {
    console.error('Error fetching message:', error);
    res.status(500).json({ error: 'Failed to fetch message' });
  }
});

// --- 15. NEW: Archive message (remove from inbox) ---
app.post('/api/inbox/archive/:messageId', async (req, res) => {
  try {
    const { messageId } = req.params;
    const userId = req.query.userId || req.session.userId || 'demo-user';
    
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

    // Remove INBOX label (archives the message)
    await gmail.users.messages.modify({
      userId: 'me',
      id: messageId,
      requestBody: {
        removeLabelIds: ['INBOX']
      }
    });

    res.json({ success: true });
  } catch (error) {
    console.error('Error archiving message:', error);
    res.status(500).json({ error: 'Failed to archive message' });
  }
});

// --- 16. NEW: Search inbox ---
app.get('/api/inbox/search', async (req, res) => {
  try {
    const { q } = req.query;
    const userId = req.query.userId || req.session.userId || 'demo-user';
    
    if (!q) {
      return res.status(400).json({ error: 'Search query required' });
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

    // Search messages
    const response = await gmail.users.messages.list({
      userId: 'me',
      q: q,
      maxResults: 50
    });

    const messages = response.data.messages || [];
    
    // Get full details for each message
    const searchResults = await Promise.all(
      messages.map(async (msg) => {
        const message = await gmail.users.messages.get({
          userId: 'me',
          id: msg.id,
          format: 'metadata',
          metadataHeaders: ['From', 'Subject', 'Date']
        });

        const headers = message.data.payload.headers;
        return {
          id: msg.id,
          from: headers.find(h => h.name === 'From')?.value || 'Unknown',
          subject: headers.find(h => h.name === 'Subject')?.value || '(No Subject)',
          date: headers.find(h => h.name === 'Date')?.value || new Date().toISOString(),
          snippet: message.data.snippet
        };
      })
    );

    res.json(searchResults);
  } catch (error) {
    console.error('Error searching inbox:', error);
    res.status(500).json({ error: 'Failed to search inbox' });
  }
});

// --- 17. NEW: Refresh token if expired ---
async function refreshAccessToken(userId) {
  const userTokens = await getTokensFromDB(userId);
  if (!userTokens || !userTokens.refresh_token) {
    return null;
  }

  // Check if token is expired (5 minutes buffer)
  if (userTokens.expires_at && userTokens.expires_at > Date.now() + 300000) {
    return userTokens.access_token; // Still valid
  }

  try {
    const oauth2Client = new google.auth.OAuth2(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET,
      'https://flowon.onrender.com/api/google/oauth/callback'
    );

    oauth2Client.setCredentials({
      refresh_token: userTokens.refresh_token
    });

    const { credentials } = await oauth2Client.refreshAccessToken();
    
    // Update stored tokens
    await saveTokensToDB({
      userId,
      access_token: credentials.access_token,
      refresh_token: userTokens.refresh_token, // Keep existing refresh token
      expires_at: Date.now() + credentials.expiry_date
    });

    return credentials.access_token;
  } catch (error) {
    console.error('Error refreshing token:', error);
    return null;
  }
}

// --- 18. NEW: Middleware to ensure valid token for protected routes ---
app.use('/api/gmail/*', async (req, res, next) => {
  const userId = req.query.userId || req.session.userId || 'demo-user';
  const newToken = await refreshAccessToken(userId);
  
  if (!newToken) {
    // Token refresh failed, but we'll let the actual endpoint handle it
    // This just ensures we have the latest token in the DB
  }
  next();
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
