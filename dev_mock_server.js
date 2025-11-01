const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const app = express();
const port = 5000;

// Create uploads directory
const uploadDir = path.join(__dirname, 'dev_uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const fileId = uuidv4();
    cb(null, `${fileId}_${file.originalname}`);
  }
});

const upload = multer({ storage });

// CORS middleware
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin) {
    res.header('Access-Control-Allow-Origin', origin);
    res.header('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS,PUT,PATCH');
    res.header('Access-Control-Allow-Headers', 'Content-Type,x-api-key,x-tenant-slug,Authorization');
    res.header('Access-Control-Allow-Credentials', 'true');
  }
  
  if (req.method === 'OPTIONS') {
    res.status(204).send();
    return;
  }
  
  next();
});

// Upload endpoint
app.post('/upload', upload.single('file'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ ok: false, error: 'no_file' });
    }

    const { family_slug = 'default', type = 'photo' } = req.body;
    const fileId = uuidv4();
    const filename = req.file.originalname;
    const fileSize = req.file.size;

    const responseData = {
      ok: true,
      id: fileId,
      key: `dev/${family_slug}/${fileId}/${filename}`,
      type: type,
      filename: filename,
      size: fileSize,
      publicUrl: `http://localhost:${port}/uploads/${req.file.filename}`,
      message: 'File uploaded to local development storage'
    };

    console.log(`✅ Mock upload successful: ${filename} (${fileSize} bytes)`);
    res.json(responseData);
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ ok: false, error: 'upload_failed' });
  }
});

// Serve uploaded files
app.get('/uploads/:filename', (req, res) => {
  const filepath = path.join(uploadDir, req.params.filename);
  if (fs.existsSync(filepath)) {
    res.sendFile(filepath);
  } else {
    res.status(404).send('File not found');
  }
});

// Health check
app.get(['/health', '/status'], (req, res) => {
  res.json({ status: 'ok', message: 'Development mock server' });
});

app.listen(port, () => {
  console.log('🚀 Starting development mock upload server...');
  console.log(`📁 Upload directory: ${uploadDir}`);
  console.log(`🌐 Server running on http://localhost:${port}`);
  console.log('📸 Ready to accept uploads!');
});

module.exports = app;