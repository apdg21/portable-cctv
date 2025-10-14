const express = require('express');
const cors = require('cors');
const { google } = require('googleapis');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Google Sheets setup
let auth;
try {
  // For Render Secret Files - it will be available at /etc/secrets/credentials.json
  const credentialsPath = process.env.NODE_ENV === 'production' 
    ? '/etc/secrets/credentials.json' 
    : 'credentials.json';

  auth = new google.auth.GoogleAuth({
    keyFile: credentialsPath,
    scopes: ['https://www.googleapis.com/auth/spreadsheets'],
  });
  
  console.log('Google Auth configured with:', credentialsPath);
} catch (error) {
  console.error('Error loading credentials:', error.message);
  console.log('Please make sure credentials.json exists at the specified path');
  process.exit(1);
}

const sheets = google.sheets({ version: 'v4', auth });
const SPREADSHEET_ID = process.env.SPREADSHEET_ID;
const JWT_SECRET = process.env.JWT_SECRET;

// Validate required environment variables
if (!SPREADSHEET_ID) {
  console.error('Missing SPREADSHEET_ID environment variable');
  process.exit(1);
}

if (!JWT_SECRET) {
  console.error('Missing JWT_SECRET environment variable');
  process.exit(1);
}

// Google Sheets helper functions
class GoogleSheetsDB {
  constructor(sheets, spreadsheetId) {
    this.sheets = sheets;
    this.spreadsheetId = spreadsheetId;
  }

  async appendRow(sheetName, row) {
    try {
      await this.sheets.spreadsheets.values.append({
        spreadsheetId: this.spreadsheetId,
        range: `${sheetName}!A:Z`,
        valueInputOption: 'RAW',
        resource: { values: [row] },
      });
      return true;
    } catch (error) {
      console.error('Error appending row:', error);
      throw error;
    }
  }

  async getRows(sheetName) {
    try {
      const response = await this.sheets.spreadsheets.values.get({
        spreadsheetId: this.spreadsheetId,
        range: `${sheetName}!A:Z`,
      });
      return response.data.values || [];
    } catch (error) {
      console.error('Error getting rows:', error);
      return [];
    }
  }

  async updateRow(sheetName, rowIndex, row) {
    try {
      await this.sheets.spreadsheets.values.update({
        spreadsheetId: this.spreadsheetId,
        range: `${sheetName}!A${rowIndex}:Z${rowIndex}`,
        valueInputOption: 'RAW',
        resource: { values: [row] },
      });
      return true;
    } catch (error) {
      console.error('Error updating row:', error);
      throw error;
    }
  }
}

const db = new GoogleSheetsDB(sheets, SPREADSHEET_ID);

// Initialize Google Sheets (run once)
app.post('/api/init', async (req, res) => {
  try {
    // Create sheets if they don't exist
    const sheetNames = ['users', 'cameras', 'events', 'snapshots'];
    
    for (const sheetName of sheetNames) {
      try {
        await sheets.spreadsheets.batchUpdate({
          spreadsheetId: SPREADSHEET_ID,
          resource: {
            requests: [{
              addSheet: {
                properties: {
                  title: sheetName
                }
              }
            }]
          }
        });

        // Add headers
        const headers = getHeadersForSheet(sheetName);
        await db.appendRow(sheetName, headers);
        console.log(`Created sheet: ${sheetName}`);
      } catch (error) {
        // Sheet might already exist
        console.log(`Sheet ${sheetName} might already exist`);
      }
    }

    res.json({ message: 'Database initialized successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

function getHeadersForSheet(sheetName) {
  const headers = {
    users: ['id', 'email', 'password', 'name', 'createdAt'],
    cameras: ['id', 'userId', 'name', 'location', 'streamId', 'quality', 'status', 'createdAt'],
    events: ['id', 'cameraId', 'type', 'description', 'timestamp'],
    snapshots: ['id', 'cameraId', 'imageUrl', 'timestamp', 'uploadedToCloud']
  };
  return headers[sheetName] || [];
}

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Auth Routes
app.post('/api/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    if (!email || !password || !name) {
      return res.status(400).json({ error: 'Email, password, and name are required' });
    }

    // Check if user exists
    const users = await db.getRows('users');
    const existingUser = users.find(row => row[1] === email);
    
    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create user
    const user = {
      id: Date.now().toString(),
      email,
      password: hashedPassword,
      name,
      createdAt: new Date().toISOString()
    };

    await db.appendRow('users', Object.values(user));

    // Generate token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      token,
      user: { id: user.id, email: user.email, name: user.name }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    const users = await db.getRows('users');
    const userRow = users.find(row => row[1] === email);
    
    if (!userRow) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const user = {
      id: userRow[0],
      email: userRow[1],
      password: userRow[2],
      name: userRow[3]
    };

    // Verify password
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Generate token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({
      success: true,
      token,
      user: { id: user.id, email: user.email, name: user.name }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Camera Routes
app.post('/api/cameras', authenticateToken, async (req, res) => {
  try {
    const { name, location, quality } = req.body;
    
    if (!name || !location) {
      return res.status(400).json({ error: 'Name and location are required' });
    }

    const camera = {
      id: Date.now().toString(),
      userId: req.user.userId,
      name,
      location,
      streamId: `CAM-${Date.now()}`,
      quality: quality || 'medium',
      status: 'offline',
      createdAt: new Date().toISOString()
    };

    await db.appendRow('cameras', Object.values(camera));

    res.json({ success: true, camera });
  } catch (error) {
    console.error('Create camera error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/cameras', authenticateToken, async (req, res) => {
  try {
    const cameras = await db.getRows('cameras');
    const userCameras = cameras
      .filter(row => row[1] === req.user.userId)
      .map(row => ({
        id: row[0],
        userId: row[1],
        name: row[2],
        location: row[3],
        streamId: row[4],
        quality: row[5],
        status: row[6],
        createdAt: row[7]
      }));

    res.json({ success: true, cameras: userCameras });
  } catch (error) {
    console.error('Get cameras error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Event Routes
app.post('/api/events', authenticateToken, async (req, res) => {
  try {
    const { cameraId, type, description } = req.body;
    
    if (!cameraId || !type) {
      return res.status(400).json({ error: 'Camera ID and event type are required' });
    }

    const event = {
      id: Date.now().toString(),
      cameraId,
      type,
      description: description || '',
      timestamp: new Date().toISOString()
    };

    await db.appendRow('events', Object.values(event));
    res.json({ success: true, event });
  } catch (error) {
    console.error('Create event error:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/events', authenticateToken, async (req, res) => {
  try {
    const events = await db.getRows('events');
    const userEvents = events.map(row => ({
      id: row[0],
      cameraId: row[1],
      type: row[2],
      description: row[3],
      timestamp: row[4]
    }));

    // Sort by timestamp descending (newest first)
    userEvents.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    res.json({ success: true, events: userEvents });
  } catch (error) {
    console.error('Get events error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'SecureCam API is running',
    timestamp: new Date().toISOString()
  });
});

// Serve frontend (if you're serving HTML from the same server)
app.get('/', (req, res) => {
  res.send(`
    <html>
      <head>
        <title>SecureCam API</title>
      </head>
      <body>
        <h1>SecureCam CCTV API</h1>
        <p>API is running successfully!</p>
        <p>Use the frontend app to interact with this API.</p>
      </body>
    </html>
  `);
});

// Start server
app.listen(PORT, () => {
  console.log(`SecureCam server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`Google Sheet ID: ${SPREADSHEET_ID}`);
});

module.exports = app;
