const express = require('express');
const cors = require('cors');
const { google } = require('googleapis');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Serve static files (frontend)
app.use(express.static(__dirname));

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

// ===== ENHANCED WEBRTC SIGNALING WITH VIEWER RECONNECTION FIXES =====

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

// ===== STREAMING ROUTES =====
// ... [KEEP ALL YOUR EXISTING STREAMING, CAMERA, AUTH ROUTES EXACTLY THE SAME] ...
// The rest of your routes remain unchanged - they're already correct

// Health check endpoint
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

// Serve frontend for all other routes
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
