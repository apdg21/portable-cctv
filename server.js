const express = require('express');
const cors = require('cors');
const { google } = require('googleapis');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ===== 1. MIDDLEWARE =====
app.use(cors());
app.use(express.json());

// Debug middleware to see incoming requests
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

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
const JWT_SECRET = process.env.JWT_SECRET || 'fallback-secret-key-for-development';

// Validate required environment variables
if (!SPREADSHEET_ID) {
  console.error('Missing SPREADSHEET_ID environment variable');
  process.exit(1);
}

console.log('SecureCam fullstack server started successfully');
console.log('Spreadsheet ID:', SPREADSHEET_ID);
console.log('Environment:', process.env.NODE_ENV || 'development');

// Store active streams in memory
const activeStreams = new Map();

// WebRTC signaling - store offers/answers/candidates
const webrtcSessions = new Map();

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

// Helper function to find WebRTC session by stream ID
function findWebRTCSessionByStreamId(streamId) {
  for (const [sessionId, session] of webrtcSessions.entries()) {
    // Extract camera ID from stream ID format: stream-CAMERAID-timestamp
    const cameraIdFromStream = streamId.replace('stream-', '').split('-')[0];
    if (session.cameraId === cameraIdFromStream) {
      return { sessionId, session };
    }
  }
  return null;
}

// Helper function to find WebRTC session by camera ID
function findWebRTCSessionByCameraId(cameraId) {
  for (const [sessionId, session] of webrtcSessions.entries()) {
    if (session.cameraId === cameraId) {
      return { sessionId, session };
    }
  }
  return null;
}

function getHeadersForSheet(sheetName) {
  const headers = {
    users: ['id', 'email', 'password', 'name', 'createdAt'],
    cameras: ['id', 'userId', 'name', 'location', 'streamId', 'quality', 'status', 'createdAt'],
    events: ['id', 'cameraId', 'type', 'description', 'timestamp'],
    snapshots: ['id', 'cameraId', 'imageUrl', 'timestamp', 'uploadedToCloud']
  };
  return headers[sheetName] || [];
}

// ===== 2. API ROUTES =====

// ===== 2.1 HEALTH & TEST ROUTES =====
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'OK', 
    message: 'SecureCam Fullstack is running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    streamingEnabled: true,
    webrtcEnabled: true,
    activeSessions: webrtcSessions.size,
    activeStreams: activeStreams.size
  });
});

app.get('/api/test', (req, res) => {
  res.json({ 
    success: true, 
    message: 'API is working!',
    timestamp: new Date().toISOString()
  });
});

// ===== 2.2 INIT ROUTE =====
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

// ===== 2.3 AUTH ROUTES =====
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
    console.log('All users from sheet:', users); // Debug log
    
    const userRow = users.find(row => row[1] === email);
    
    if (!userRow) {
      console.log('User not found for email:', email);
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Debug: Log the user row structure
    console.log('Found user row:', userRow);

    const user = {
      id: userRow[0],
      email: userRow[1],
      password: userRow[2],
      name: userRow[3]
    };

    console.log('User object:', user); // Debug log

    // Verify password
    const isValid = await bcrypt.compare(password, user.password);
    console.log('Password validation result:', isValid); // Debug log
    
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

// ===== 2.4 CAMERA ROUTES =====
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
      .filter(row => row[1] === req.user.userId && row[6] !== 'deleted')
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

// Delete camera
app.post('/api/cameras/:id/delete', authenticateToken, async (req, res) => {
  try {
    const cameraId = req.params.id;
    
    // Get all cameras
    const cameras = await db.getRows('cameras');
    const cameraToDelete = cameras.find(row => row[0] === cameraId && row[1] === req.user.userId);
    
    if (!cameraToDelete) {
      return res.status(404).json({ error: 'Camera not found or not authorized' });
    }

    // Stop any active streams for this camera
    for (const [streamId, stream] of activeStreams.entries()) {
      if (stream.cameraId === cameraId) {
        activeStreams.delete(streamId);
      }
    }

    // Clean up WebRTC sessions
    for (const [sessionId, session] of webrtcSessions.entries()) {
      if (session.cameraId === cameraId) {
        webrtcSessions.delete(sessionId);
      }
    }

    // Mark as deleted by updating status
    const cameraIndex = cameras.findIndex(row => row[0] === cameraId && row[1] === req.user.userId);
    if (cameraIndex !== -1) {
      cameras[cameraIndex][6] = 'deleted'; // Update status column
      await db.updateRow('cameras', cameraIndex + 1, cameras[cameraIndex]);
    }

    // Log deletion event
    await db.appendRow('events', [
      Date.now().toString(),
      cameraId,
      'camera_deleted',
      `Camera "${cameraToDelete[2]}" was deleted`,
      new Date().toISOString()
    ]);

    console.log(`Camera marked as deleted: ${cameraId}`);
    
    res.json({ 
      success: true, 
      message: 'Camera deleted successfully'
    });
  } catch (error) {
    console.error('Error deleting camera:', error);
    res.status(500).json({ error: error.message });
  }
});

// ===== 2.5 STREAMING ROUTES =====
app.post('/api/streams/start', authenticateToken, async (req, res) => {
  try {
    const { cameraId, cameraName } = req.body;
    
    if (!cameraId) {
      return res.status(400).json({ error: 'Camera ID is required' });
    }

    const streamId = `stream-${cameraId}-${Date.now()}`;
    
    // Store stream info
    activeStreams.set(streamId, {
      cameraId,
      cameraName: cameraName || 'Camera Stream',
      owner: req.user.userId,
      startedAt: new Date().toISOString(),
      isActive: true,
      type: 'webrtc', // Changed from 'local' to 'webrtc'
      viewerCount: 0
    });

    // Log stream event
    await db.appendRow('events', [
      Date.now().toString(),
      cameraId,
      'stream_started',
      `WebRTC stream started: ${cameraName || 'Camera'}`,
      new Date().toISOString()
    ]);

    console.log(`Stream session created: ${streamId}`);
    
    res.json({ 
      success: true, 
      streamId,
      streamInfo: {
        id: streamId,
        cameraId,
        cameraName: cameraName || 'Camera Stream',
        startedAt: new Date().toISOString(),
        type: 'webrtc'
      },
      message: 'WebRTC stream session created! Camera is now streaming.'
    });
  } catch (error) {
    console.error('Error starting stream:', error);
    res.status(500).json({ error: 'Failed to start streaming session: ' + error.message });
  }
});

// Stop a stream
app.post('/api/streams/:id/stop', authenticateToken, async (req, res) => {
  try {
    const streamId = req.params.id;
    const stream = activeStreams.get(streamId);
    
    if (stream && stream.owner === req.user.userId) {
      // Also clean up WebRTC session if exists
      webrtcSessions.forEach((session, sessionId) => {
        if (session.cameraId === stream.cameraId) {
          webrtcSessions.delete(sessionId);
        }
      });

      // Log stream event
      await db.appendRow('events', [
        Date.now().toString(),
        stream.cameraId,
        'stream_stopped',
        `Stream stopped: ${stream.cameraName}`,
        new Date().toISOString()
      ]);

      activeStreams.delete(streamId);
      console.log(`Stream stopped: ${streamId}`);
      
      res.json({ success: true, message: 'Stream stopped successfully' });
    } else {
      res.status(404).json({ error: 'Stream not found or not authorized' });
    }
  } catch (error) {
    console.error('Error stopping stream:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get stream info
app.get('/api/streams/:id', authenticateToken, async (req, res) => {
  try {
    const streamId = req.params.id;
    const stream = activeStreams.get(streamId);
    
    if (stream && stream.isActive) {
      res.json({ 
        success: true, 
        streamInfo: stream
      });
    } else {
      res.status(404).json({ error: 'Stream not found or inactive' });
    }
  } catch (error) {
    console.error('Error getting stream:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get all active streams
app.get('/api/streams', authenticateToken, async (req, res) => {
  try {
    const streams = Array.from(activeStreams.entries())
      .filter(([id, stream]) => stream.isActive && stream.owner === req.user.userId)
      .map(([id, stream]) => ({
        id,
        cameraId: stream.cameraId,
        cameraName: stream.cameraName,
        owner: stream.owner,
        startedAt: stream.startedAt,
        isActive: stream.isActive,
        type: stream.type,
        viewerCount: stream.viewerCount || 0
      }));
    
    res.json({ success: true, streams });
  } catch (error) {
    console.error('Error getting streams:', error);
    res.status(500).json({ error: error.message });
  }
});

// ===== 2.6 WEBRTC ROUTES =====
// Create a WebRTC session - COMPATIBILITY ENDPOINT
app.post('/api/webrtc/create-session', authenticateToken, async (req, res) => {
  try {
    const { cameraId, cameraName } = req.body;
    
    if (!cameraId) {
      return res.status(400).json({ error: 'Camera ID is required' });
    }

    const sessionId = uuidv4();
    
    // Create WebRTC session with multi-viewer support
    webrtcSessions.set(sessionId, {
      cameraId,
      cameraName: cameraName || 'Camera Stream',
      owner: req.user.userId,
      createdAt: new Date().toISOString(),
      offer: null,
      answers: new Map(), // Store multiple answers for multiple viewers
      candidates: new Map(), // Store candidates per viewer
      viewers: new Map(), // Track active viewers with last activity
      isActive: true,
      lastActivity: Date.now()
    });

    // Store stream info
    activeStreams.set(sessionId, {
      cameraId,
      cameraName: cameraName || 'Camera Stream',
      owner: req.user.userId,
      startedAt: new Date().toISOString(),
      isActive: true,
      type: 'webrtc',
      viewerCount: 0
    });

    // Log stream event
    await db.appendRow('events', [
      Date.now().toString(),
      cameraId,
      'webrtc_session_created',
      `WebRTC session created: ${cameraName || 'Camera'}`,
      new Date().toISOString()
    ]);

    console.log(`WebRTC session created: ${sessionId} for camera: ${cameraId}`);
    
    res.json({ 
      success: true, 
      sessionId,
      message: 'WebRTC session created successfully'
    });
  } catch (error) {
    console.error('Error creating WebRTC session:', error);
    res.status(500).json({ error: 'Failed to create WebRTC session: ' + error.message });
  }
});

// Create a WebRTC session - NEW ENDPOINT
app.post('/api/webrtc/session', authenticateToken, async (req, res) => {
  try {
    const { cameraId, cameraName } = req.body;
    
    if (!cameraId) {
      return res.status(400).json({ error: 'Camera ID is required' });
    }

    const sessionId = uuidv4();
    
    // Create WebRTC session with multi-viewer support
    webrtcSessions.set(sessionId, {
      cameraId,
      cameraName: cameraName || 'Camera Stream',
      owner: req.user.userId,
      createdAt: new Date().toISOString(),
      offer: null,
      answers: new Map(), // Store multiple answers for multiple viewers
      candidates: new Map(), // Store candidates per viewer
      viewers: new Map(), // Track active viewers with last activity
      isActive: true,
      lastActivity: Date.now()
    });

    // Store stream info
    activeStreams.set(sessionId, {
      cameraId,
      cameraName: cameraName || 'Camera Stream',
      owner: req.user.userId,
      startedAt: new Date().toISOString(),
      isActive: true,
      type: 'webrtc',
      viewerCount: 0
    });

    // Log stream event
    await db.appendRow('events', [
      Date.now().toString(),
      cameraId,
      'webrtc_session_created',
      `WebRTC session created: ${cameraName || 'Camera'}`,
      new Date().toISOString()
    ]);

    console.log(`WebRTC session created: ${sessionId}`);
    
    res.json({ 
      success: true, 
      sessionId,
      message: 'WebRTC session created successfully'
    });
  } catch (error) {
    console.error('Error creating WebRTC session:', error);
    res.status(500).json({ error: 'Failed to create WebRTC session: ' + error.message });
  }
});

// Store WebRTC offer
app.post('/api/webrtc/session/:sessionId/offer', authenticateToken, async (req, res) => {
  try {
    const { sessionId } = req.params;
    const { offer } = req.body;
    
    const session = webrtcSessions.get(sessionId);
    if (!session) {
      return res.status(404).json({ error: 'WebRTC session not found' });
    }

    session.offer = offer;
    session.lastActivity = Date.now();
    
    console.log(`Offer stored for session: ${sessionId}`);
    res.json({ success: true });
  } catch (error) {
    console.error('Error storing offer:', error);
    res.status(500).json({ error: error.message });
  }
});

// Enhanced answer storage for multiple viewers WITH RECONNECTION FIX
app.post('/api/webrtc/session/:sessionId/answer', authenticateToken, async (req, res) => {
  try {
    const { sessionId } = req.params;
    const { answer } = req.body;
    const viewerId = req.user.userId;
    
    const session = webrtcSessions.get(sessionId);
    if (!session) {
      return res.status(404).json({ error: 'WebRTC session not found' });
    }

    // ✅ FIX #1: Reset viewer state if they reconnect
    if (session.answers.has(viewerId) || session.candidates.has(viewerId)) {
      console.log(`🔄 Viewer ${viewerId} reconnected — resetting previous WebRTC data`);
      session.answers.delete(viewerId);
      session.candidates.delete(viewerId);
    }

    // Store answer for this specific viewer
    session.answers.set(viewerId, answer);
    session.viewers.set(viewerId, Date.now()); // Track last activity
    session.lastActivity = Date.now();
    
    // Update viewer count in active streams
    const stream = activeStreams.get(sessionId);
    if (stream) {
      stream.viewerCount = session.viewers.size;
    }
    
    console.log(`✅ Answer stored for viewer ${viewerId} in session: ${sessionId}`);
    res.json({ success: true });
  } catch (error) {
    console.error('Error storing answer:', error);
    res.status(500).json({ error: error.message });
  }
});

// Enhanced candidate storage for multiple viewers WITH RECONNECTION FIX
app.post('/api/webrtc/session/:sessionId/candidate', authenticateToken, async (req, res) => {
  try {
    const { sessionId } = req.params;
    const { candidate } = req.body;
    const viewerId = req.user.userId;
    
    const session = webrtcSessions.get(sessionId);
    if (!session) {
      return res.status(404).json({ error: 'WebRTC session not found' });
    }

    // ✅ FIX #1: Reset viewer state if they reconnect (for candidates too)
    if (!session.answers.has(viewerId) && session.candidates.has(viewerId)) {
      console.log(`🔄 Viewer ${viewerId} reconnected without answer — clearing old candidates`);
      session.candidates.delete(viewerId);
    }

    // Initialize candidates array for this viewer if it doesn't exist
    if (!session.candidates.has(viewerId)) {
      session.candidates.set(viewerId, []);
    }
    
    session.candidates.get(viewerId).push(candidate);
    session.viewers.set(viewerId, Date.now()); // Update last activity
    session.lastActivity = Date.now();
    
    console.log(`✅ ICE candidate added for viewer ${viewerId} in session: ${sessionId}`);
    res.json({ success: true });
  } catch (error) {
    console.error('Error adding ICE candidate:', error);
    res.status(500).json({ error: error.message });
  }
});

// ✅ FIX #2: Cleanup endpoint for when viewer leaves
app.post('/api/webrtc/session/:sessionId/leave', authenticateToken, async (req, res) => {
  try {
    const { sessionId } = req.params;
    const viewerId = req.user.userId;
    
    const session = webrtcSessions.get(sessionId);
    if (session) {
      // Clean up all viewer data
      session.viewers.delete(viewerId);
      session.answers.delete(viewerId);
      session.candidates.delete(viewerId);
      
      // Update viewer count
      const stream = activeStreams.get(sessionId);
      if (stream) {
        stream.viewerCount = session.viewers.size;
      }
      
      console.log(`👋 Viewer ${viewerId} left session ${sessionId} - data cleaned up`);
    }
    
    res.json({ success: true, message: 'Viewer data cleaned up' });
  } catch (error) {
    console.error('Error cleaning up viewer data:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get ICE candidates for streamer
app.get('/api/webrtc/session/:sessionId/candidates', authenticateToken, async (req, res) => {
  try {
    const { sessionId } = req.params;
    
    const session = webrtcSessions.get(sessionId);
    if (!session) {
      return res.status(404).json({ error: 'WebRTC session not found' });
    }

    // Get all candidates from all viewers
    const allCandidates = [];
    for (const [viewerId, candidates] of session.candidates.entries()) {
      allCandidates.push(...candidates);
    }

    res.json({ 
      success: true, 
      candidates: allCandidates 
    });
  } catch (error) {
    console.error('Error getting candidates:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get answers for streamer
app.get('/api/webrtc/session/:sessionId/answers', authenticateToken, async (req, res) => {
  try {
    const { sessionId } = req.params;
    
    const session = webrtcSessions.get(sessionId);
    if (!session) {
      return res.status(404).json({ error: 'WebRTC session not found' });
    }

    // Get all answers from viewers
    const answers = Array.from(session.answers.values());

    res.json({ 
      success: true, 
      answers 
    });
  } catch (error) {
    console.error('Error getting answers:', error);
    res.status(500).json({ error: error.message });
  }
});

// Enhanced WebRTC session data with viewer tracking
app.get('/api/webrtc/session/:streamId', authenticateToken, async (req, res) => {
  try {
    const { streamId } = req.params;
    const viewerId = req.user.userId;
    
    let session = webrtcSessions.get(streamId);
    let sessionId = streamId;
    
    // If not found by direct ID, try to find by stream ID
    if (!session) {
      const found = findWebRTCSessionByStreamId(streamId);
      if (found) {
        session = found.session;
        sessionId = found.sessionId;
      }
    }
    
    // If still not found, try by camera ID
    if (!session) {
      const found = findWebRTCSessionByCameraId(streamId);
      if (found) {
        session = found.session;
        sessionId = found.sessionId;
      }
    }
    
    if (!session) {
      return res.status(404).json({ error: 'WebRTC session not found' });
    }

    // Update viewer activity
    session.viewers.set(viewerId, Date.now());
    session.lastActivity = Date.now();
    
    // Get viewer-specific data
    const viewerAnswer = session.answers.get(viewerId);
    const viewerCandidates = session.candidates.get(viewerId) || [];

    res.json({ 
      success: true, 
      session: {
        sessionId,
        cameraId: session.cameraId,
        cameraName: session.cameraName,
        offer: session.offer,
        answer: viewerAnswer,
        candidates: viewerCandidates,
        isActive: session.isActive,
        viewerCount: session.viewers.size
      }
    });
  } catch (error) {
    console.error('Error getting WebRTC session:', error);
    res.status(500).json({ error: error.message });
  }
});

// Enhanced polling with viewer tracking
app.get('/api/webrtc/session/:streamId/poll', authenticateToken, async (req, res) => {
  try {
    const { streamId } = req.params;
    const viewerId = req.user.userId;
    
    let session = webrtcSessions.get(streamId);
    let sessionId = streamId;
    
    // If not found by direct ID, try to find by stream ID
    if (!session) {
      const found = findWebRTCSessionByStreamId(streamId);
      if (found) {
        session = found.session;
        sessionId = found.sessionId;
      }
    }
    
    // If still not found, try by camera ID
    if (!session) {
      const found = findWebRTCSessionByCameraId(streamId);
      if (found) {
        session = found.session;
        sessionId = found.sessionId;
      }
    }
    
    if (!session) {
      return res.status(404).json({ error: 'WebRTC session not found' });
    }

    // Update viewer activity
    session.viewers.set(viewerId, Date.now());
    session.lastActivity = Date.now();

    // Check if viewer has already submitted an answer
    const hasViewerAnswer = session.answers.has(viewerId);
    const viewerCandidates = session.candidates.get(viewerId) || [];

    res.json({ 
      success: true, 
      hasOffer: !!session.offer,
      hasAnswer: hasViewerAnswer,
      candidates: viewerCandidates,
      isActive: session.isActive,
      viewerCount: session.viewers.size
    });
  } catch (error) {
    console.error('Error polling WebRTC session:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get session statistics
app.get('/api/webrtc/session/:streamId/stats', authenticateToken, async (req, res) => {
  try {
    const { streamId } = req.params;
    
    let session = webrtcSessions.get(streamId);
    let sessionId = streamId;
    
    // If not found by direct ID, try to find by stream ID
    if (!session) {
      const found = findWebRTCSessionByStreamId(streamId);
      if (found) {
        session = found.session;
        sessionId = found.sessionId;
      }
    }
    
    // If still not found, try by camera ID
    if (!session) {
      const found = findWebRTCSessionByCameraId(streamId);
      if (found) {
        session = found.session;
        sessionId = found.sessionId;
      }
    }
    
    if (!session) {
      return res.status(404).json({ error: 'WebRTC session not found' });
    }

    res.json({ 
      success: true, 
      stats: {
        sessionId,
        viewerCount: session.viewers.size,
        isActive: session.isActive,
        createdAt: session.createdAt,
        lastActivity: session.lastActivity,
        cameraName: session.cameraName
      }
    });
  } catch (error) {
    console.error('Error getting session stats:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get all active WebRTC sessions for user
app.get('/api/webrtc/sessions', authenticateToken, async (req, res) => {
  try {
    const userSessions = [];
    
    for (const [sessionId, session] of webrtcSessions.entries()) {
      if (session.owner === req.user.userId && session.isActive) {
        userSessions.push({
          sessionId,
          cameraId: session.cameraId,
          cameraName: session.cameraName,
          viewerCount: session.viewers.size,
          createdAt: session.createdAt
        });
      }
    }
    
    res.json({ success: true, sessions: userSessions });
  } catch (error) {
    console.error('Error getting user sessions:', error);
    res.status(500).json({ error: error.message });
  }
});

// ===== 2.7 EVENT ROUTES =====
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

// ===== 3. CLEANUP INTERVALS =====
// Enhanced cleanup: Remove inactive viewers AND sessions
setInterval(() => {
  const now = Date.now();
  const viewerInactiveTimeout = 30 * 1000; // 30 seconds for viewers
  const sessionInactiveTimeout = 5 * 60 * 1000; // 5 minutes for sessions
  
  for (const [sessionId, session] of webrtcSessions.entries()) {
    // Clean up inactive viewers within active sessions
    let removedViewers = 0;
    for (const [viewerId, lastActivity] of session.viewers.entries()) {
      if (now - lastActivity > viewerInactiveTimeout) {
        session.viewers.delete(viewerId);
        session.answers.delete(viewerId);
        session.candidates.delete(viewerId);
        removedViewers++;
      }
    }
    
    if (removedViewers > 0) {
      console.log(`🧹 Cleaned up ${removedViewers} inactive viewers from session: ${sessionId}`);
      
      // Update viewer count in active streams
      const stream = activeStreams.get(sessionId);
      if (stream) {
        stream.viewerCount = session.viewers.size;
      }
    }
    
    // Clean up entire session if inactive
    if (now - session.lastActivity > sessionInactiveTimeout) {
      console.log(`🧹 Cleaning up inactive WebRTC session: ${sessionId}`);
      webrtcSessions.delete(sessionId);
      
      // Also remove from active streams
      if (activeStreams.has(sessionId)) {
        activeStreams.delete(sessionId);
      }
    }
  }
}, 30000); // Run every 30 seconds

// ===== 4. STATIC FILES (MUST COME AFTER ALL API ROUTES) =====
app.use(express.static(__dirname));

// ===== 5. CATCH-ALL ROUTE (MUST BE VERY LAST) =====
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 SecureCam Fullstack running on port ${PORT}`);
  console.log(`📍 Frontend: http://localhost:${PORT}`);
  console.log(`🔗 Backend API: http://localhost:${PORT}/api`);
  console.log(`🌐 WebRTC signaling enabled with viewer reconnection fixes`);
  console.log(`📊 Active WebRTC Sessions: ${webrtcSessions.size}`);
  console.log(`📹 Active Streams: ${activeStreams.size}`);
});

module.exports = app;
