# Hemolink — Production Setup

Blood donor connection platform. Production-hardened.

## Requirements

- Node.js 18+
- npm

## Quick Start

```bash
# 1. Install dependencies
npm install

# 2. Create your .env file
cp .env.example .env

# 3. Edit .env — set a real JWT_SECRET and your domain in ALLOWED_ORIGINS
#    Generate a secret:
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"

# 4. Start the server
npm start
```

Open http://localhost:3000

The SQLite database is created automatically at `./data/hemolink.db` on first run.

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `JWT_SECRET` | ✅ | Long random string (min 32 chars). Never commit this. |
| `PORT` | no | Default: 3000 |
| `NODE_ENV` | no | `production` or `development` |
| `DB_PATH` | no | SQLite file path. Default: `./data/hemolink.db` |
| `ALLOWED_ORIGINS` | no | Comma-separated CORS origins. Default: `http://localhost:3000` |
| `JWT_EXPIRES_IN` | no | Token expiry. Default: `7d` |
| `RATE_LIMIT_MAX` | no | Max requests per window. Default: `100` |
| `AUTH_RATE_LIMIT_MAX` | no | Max auth attempts per 15 min. Default: `10` |

## Deploying to Production

### Render / Railway / Fly.io
1. Push to GitHub
2. Connect repo in platform dashboard
3. Set all env vars in the platform's environment settings
4. Set `NODE_ENV=production` and `ALLOWED_ORIGINS=https://yourdomain.com`
5. Deploy

### Behind Nginx (VPS)
```nginx
server {
    listen 443 ssl;
    server_name yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Use PM2 to keep the process alive:
```bash
npm install -g pm2
pm2 start server.js --name hemolink
pm2 save
pm2 startup
```

## Security Notes

- **Never commit `.env`** — it's in `.gitignore`
- **Back up `data/hemolink.db`** regularly if self-hosting
- Password hashing uses bcrypt with cost factor 12
- All auth routes are rate-limited (10 attempts / 15 min)
- JWT tokens expire after 7 days by default
- Phone numbers are only visible to authenticated users
