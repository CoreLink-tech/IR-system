# Deployment

Step-by-step from a blank Linux server to a running Security API and dashboard.
Follow in order. Commands are copy-paste exact.

## 1. Packages

    sudo apt update
    sudo apt install -y git curl build-essential nginx certbot python3-certbot-nginx
    # Node 20
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt install -y nodejs
    # MariaDB or MySQL 8
    sudo apt install -y mariadb-server

## 2. Database

Create a dedicated user and database (least privilege: only `security_*` tables will be created):

    sudo mysql -e "CREATE DATABASE ir_security CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
    sudo mysql -e "CREATE USER 'ir_app'@'localhost' IDENTIFIED BY 'REPLACE_WITH_STRONG_PASSWORD';"
    sudo mysql -e "GRANT ALL ON ir_security.* TO 'ir_app'@'localhost'; FLUSH PRIVILEGES;"

## 3. Application user and code

    sudo useradd --system --home /opt/ir-system --shell /usr/sbin/nologin ir
    sudo mkdir -p /opt/ir-system
    sudo chown ir:ir /opt/ir-system
    # As a deploy user with sudo:
    sudo -u ir git clone https://github.com/CoreLink-tech/IR-system.git /opt/ir-system/src
    cd /opt/ir-system/src/backend
    sudo -u ir cp .env.example .env
    sudo -u ir npm run gen:secrets
    # Paste the printed values into .env, set DATABASE_URL, CORS_ORIGINS, TRUSTED_PROXIES,
    # REQUIRE_2FA=true (or leave default in production), and TOTP_ENCRYPTION_KEY.

## 4. Install, migrate, seed

    cd /opt/ir-system/src/backend
    sudo -u ir npm ci
    sudo -u ir npx prisma generate
    sudo -u ir npx prisma migrate deploy
    sudo -u ir npm run seed
    sudo -u ir npm run build

The first super admin must enrol for two-step verification at first sign-in when REQUIRE_2FA is on.

## 5. Process manager (systemd)

Example unit `/etc/systemd/system/ir-api.service`:

    [Unit]
    Description=Security API
    After=network.target mariadb.service

    [Service]
    Type=simple
    User=ir
    WorkingDirectory=/opt/ir-system/src/backend
    EnvironmentFile=/opt/ir-system/src/backend/.env
    ExecStart=/usr/bin/node dist/main.js
    Restart=on-failure
    RestartSec=5
    # Hardening
    NoNewPrivileges=true
    PrivateTmp=true

    [Install]
    WantedBy=multi-user.target

    sudo systemctl daemon-reload
    sudo systemctl enable --now ir-api

## 6. Dashboard

    cd /opt/ir-system/src/frontend
    sudo -u ir npm ci
    sudo -u ir npm run build
    # Serve dist/ with nginx (see frontend/deploy/nginx.conf.example and security-headers.conf).
    # Point the dashboard's config at the API origin and set CORS_ORIGINS on the API to the
    # dashboard's exact origin.

## 7. Reverse proxy and TLS

Terminate TLS at nginx. Set `TRUSTED_PROXIES` to the proxy address or `private`.
Enable HSTS and the dashboard CSP from `frontend/deploy/security-headers.conf`.

## 8. Schedules

    # Cleanup (nightly)
    15 3 * * *  ir  cd /opt/ir-system/src/backend && /usr/bin/node dist/retention/cleanup.js
    # Backup (see docs/DATABASE.md scripts/backup.sh)

## 9. First sign-in checklist

1. Open the dashboard origin over HTTPS.
2. Sign in with the seeded admin.
3. Enrol two-step verification (QR / setup key + recovery codes).
4. Change the bootstrap password.
5. Create an API key for the website and install the PHP library.
6. Confirm GET /api/v1/health and GET /api/v1/health/ready return ok/ready.
7. Send a test event and confirm it appears in the dashboard.

## Docker alternative

See `backend/Dockerfile` and `frontend/Dockerfile`. Pass secrets via environment or a secrets
manager; never bake them into the image. Compose file is left to the operator so database
credentials stay out of the repository.

## Not verified in the Stage 10 authoring environment

- Full walkthrough on a blank VM (this document is written from the codebase and prior drills).
- Docker build in CI (workflow runs tests; image build can be added as a required check).
EOF
echo DEPLOYMENT written
ls frontend/deploy/ 2>/dev/null | head
echo done
