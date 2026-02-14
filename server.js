const express = require('express');
const fetch = require('node-fetch');
const app = express();
const cors = require('cors');

const PORT = process.env.PORT || 3000;

// Correctly apply CORS options
const corsOptions = {
  origin: '*', // In production, replace '*' with your specific frontend domain
  optionsSuccessStatus: 200
};
app.use(cors(corsOptions));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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

// --- 2. Proxy POST Update Customers (Now includes templates) ---
app.post('/api/updatecustomers', async (req, res) => {
  // Destructure all possible fields sent by frontend
  const { userId, customers, templates } = req.body;
  
  try {
    const response = await fetch(`https://kingoftech.app.n8n.cloud/webhook/updatecustomers`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        userid: userId,
        customers: JSON.stringify(customers), // Send as JSON string if n8n expects it
        templates: JSON.stringify(templates)  // Pass templates along
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

// --- 4. Proxy POST Update Templates (New) ---
app.post('/api/updatetemplates', async (req, res) => {
  const { userid, templates } = req.body;
  try {
    const response = await fetch(`https://kingoftech.app.n8n.cloud/webhook/updatetemplates`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ userid, templates })
    });
    
    // Check if response is JSON, otherwise send status
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

// --- 5. Proxy POST Send Automated Messages (New) ---
app.post('/api/send-automated-messages', async (req, res) => {
  try {
    // Forward the entire body (campaign data) to n8n
    const response = await fetch(`https://kingoftech.app.n8n.cloud/webhook/send-automated-messages`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req.body)
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

app.get('/get', (req, res) => {
  res.json('Welcome To HTTP REQUEST CLASS');
});
app.post('/api/receive-email', (req, res) => {
  const emailData = req.body;
  console.log('Email received:', emailData);
  // Save to DB or display in real-time
  res.status(200).send({ success: true });
});


app.listen(PORT, () => console.log(`Server running on port ${PORT}`));