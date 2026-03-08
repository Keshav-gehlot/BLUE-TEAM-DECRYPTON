import express from 'express';
import cors from 'cors';
import fs from 'fs';
import path from 'path';
import multer from 'multer';
import crypto from 'crypto';
import { createServer as createViteServer } from 'vite';

const app = express();
const PORT = 3001;

app.use(cors());
app.use(express.json());

const EVIDENCE_DIR = path.join(process.cwd(), 'evidence_locker');
const LOGS_FILE = path.join(EVIDENCE_DIR, 'logs.json');

if (!fs.existsSync(EVIDENCE_DIR)) {
  fs.mkdirSync(EVIDENCE_DIR, { recursive: true });
}

if (!fs.existsSync(LOGS_FILE)) {
  fs.writeFileSync(LOGS_FILE, JSON.stringify([]));
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, EVIDENCE_DIR);
  },
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  }
});

const upload = multer({ storage });

app.post('/api/upload-evidence', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }
  res.json({ message: 'File uploaded successfully', filename: req.file.filename });
});

app.get('/api/evidence', (req, res) => {
  try {
    const files = fs.readdirSync(EVIDENCE_DIR);
    const fileDetails = files.map(filename => {
      const filePath = path.join(EVIDENCE_DIR, filename);
      const content = fs.readFileSync(filePath);
      const hash = crypto.createHash('sha256').update(content).digest('hex');
      return { 
        filename, 
        hash,
        isEncrypted: filename.endsWith('.txt')
      };
    });
    res.json(fileDetails);
  } catch (error) {
    res.status(500).json({ error: 'Failed to read evidence locker' });
  }
});

app.post('/api/restore/:filename', (req, res) => {
  try {
    const filename = req.params.filename;
    const filePath = path.join(EVIDENCE_DIR, filename);

    // Strict startsWith(EVIDENCE_DIR) security check
    if (!filePath.startsWith(EVIDENCE_DIR)) {
      return res.status(403).json({ error: 'Invalid file path' });
    }

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' });
    }

    const content = fs.readFileSync(filePath, 'utf-8');
    
    if (content.startsWith('ENC:')) {
      const base64String = content.substring(4);
      const binaryBuffer = Buffer.from(base64String, 'base64');
      
      const newFilename = filename.replace(/\.txt$/, '');
      const newFilePath = path.join(EVIDENCE_DIR, newFilename);
      
      fs.writeFileSync(newFilePath, binaryBuffer);
      fs.unlinkSync(filePath);
      
      res.json({ message: 'File restored successfully', filename: newFilename });
    } else {
      res.status(400).json({ error: 'File is not encrypted with expected signature' });
    }
  } catch (error) {
    console.error('Restore error:', error);
    res.status(500).json({ error: 'Failed to restore file' });
  }
});

app.get('/api/download/:filename', (req, res) => {
  try {
    const filename = req.params.filename;
    const filePath = path.join(EVIDENCE_DIR, filename);

    // Strict startsWith(EVIDENCE_DIR) security check
    if (!filePath.startsWith(EVIDENCE_DIR)) {
      return res.status(403).json({ error: 'Invalid file path' });
    }

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' });
    }

    res.download(filePath);
  } catch (error) {
    console.error('Download error:', error);
    res.status(500).json({ error: 'Failed to download file' });
  }
});

app.get('/api/analyze/:filename', (req, res) => {
  try {
    const filename = req.params.filename;
    const filePath = path.join(EVIDENCE_DIR, filename);

    if (!filePath.startsWith(EVIDENCE_DIR)) {
      return res.status(403).json({ error: 'Invalid file path' });
    }

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' });
    }

    const content = fs.readFileSync(filePath, 'utf-8');
    
    // Extract mock IoCs
    const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
    const ips = [...new Set(content.match(ipRegex) || [])];
    
    const domainRegex = /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/gi;
    const allDomains = [...new Set(content.match(domainRegex) || [])];
    const domains = allDomains.filter(d => !ips.includes(d));

    const threatKeywords = ['mimikatz', 'ransomware', 'payload', 'reverse_shell', 'encrypt', 'crypto', 'bitcoin', 'backdoor', 'c2', 'cobalt strike', 'metasploit'];
    const lowerContent = content.toLowerCase();
    const keywords = threatKeywords.filter(kw => lowerContent.includes(kw));

    // Compute Threat Score
    let score = (ips.length * 15) + (domains.length * 10) + (keywords.length * 20);
    score = Math.min(score, 100);

    let riskLevel = 'Low';
    if (score >= 70) riskLevel = 'Critical';
    else if (score >= 40) riskLevel = 'Medium';

    res.json({
      content,
      iocs: { ips, domains, keywords },
      score,
      riskLevel
    });
  } catch (error) {
    console.error('Analyze error:', error);
    res.status(500).json({ error: 'Failed to analyze file' });
  }
});

app.get('/api/logs', (req, res) => {
  try {
    if (!fs.existsSync(LOGS_FILE)) return res.json([]);
    res.json(JSON.parse(fs.readFileSync(LOGS_FILE, 'utf-8')));
  } catch (error) {
    res.status(500).json({ error: 'Failed to read logs' });
  }
});

app.post('/api/logs', (req, res) => {
  try {
    const newLog = req.body;
    let logs = [];
    if (fs.existsSync(LOGS_FILE)) {
      logs = JSON.parse(fs.readFileSync(LOGS_FILE, 'utf-8'));
    }
    // Keep last 100 logs
    if (logs.length > 100) logs.shift();
    logs.push(newLog);
    fs.writeFileSync(LOGS_FILE, JSON.stringify(logs, null, 2));
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to add log' });
  }
});

app.delete('/api/evidence/:filename', (req, res) => {
  try {
    const filename = req.params.filename;
    const filePath = path.join(EVIDENCE_DIR, filename);

    if (!filePath.startsWith(EVIDENCE_DIR)) {
      return res.status(403).json({ error: 'Invalid file path' });
    }

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found' });
    }

    fs.unlinkSync(filePath);
    res.json({ message: 'File deleted successfully' });
  } catch (error) {
    console.error('Delete error:', error);
    res.status(500).json({ error: 'Failed to delete file' });
  }
});

async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static('dist'));
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
