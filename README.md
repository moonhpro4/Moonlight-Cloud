# Moonlight Cloud 🌙☁

A self-hosted file storage and sharing service with Google OAuth.

## Features
- Upload files up to **100 GB**
- Live upload **progress bar** with speed
- **Private shareable links** — files aren't public
- **CLI download commands** for Windows, Mac, Linux
- **Google Sign-In** via GSI popup (no Supabase needed)
- Guest: **10 GB / 3 uploads** | Google account: **300 GB**

## Setup

### 1. Install dependencies
```bash
npm install
```

### 2. Configure environment
Edit `.env`:
```
GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-google-client-secret
BASE_URL=https://your-domain.com
PORT=3000
```

### 3. Run locally
```bash
npm start
```
Visit `http://localhost:3000`

## Deploying

This is a **Node.js Express** backend — it needs a server, NOT Cloudflare Pages (which is static only).

### ✅ Recommended hosts (free tier):
| Host | Notes |
|------|-------|
| **Railway** | `railway up` — easiest, free tier available |
| **Render** | Free tier, sleeps after inactivity |
| **Fly.io** | `fly launch` — fast, global |
| **VPS (DigitalOcean/Hetzner)** | Full control, use `pm2` |

### Railway deploy (easiest):
```bash
npm install -g railway
railway login
railway init
railway up
railway domain
```

### Important for production:
- Add a **persistent volume** for the `uploads/` folder (files reset on redeploy otherwise)
- Use a **database** (SQLite or PostgreSQL) instead of in-memory `files` object
- Set `BASE_URL` env var to your live domain

## File structure
```
moonlight-cloud/
├── server.js          # Express backend
├── .env               # Environment variables
├── uploads/           # Stored files (add to .gitignore!)
└── public/
    ├── index.html     # Upload interface
    └── download.html  # Download page
```

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/auth/google` | Verify Google token, get session |
| POST | `/api/auth/logout` | Sign out |
| GET | `/api/quota` | Get storage quota info |
| POST | `/api/upload` | Upload a file (multipart) |
| GET | `/api/file/:id` | Get file metadata |
| GET | `/api/my-files` | List your uploads |
| DELETE | `/api/file/:id` | Delete a file |
| GET | `/download/:id` | Download page (HTML) |
| GET | `/download/:id/raw` | Raw file download (for CLI) |
