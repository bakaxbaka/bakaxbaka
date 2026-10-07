# Aether Complete Workflow - Full Documentation

**Complete step-by-step guide for exporting, setting up, and running Aether on your computer.**

---

## Table of Contents
1. [System Requirements](#system-requirements)
2. [Phase 1: Export from Replit](#phase-1-export-from-replit)
3. [Phase 2: Setup on Your Computer](#phase-2-setup-on-your-computer)
4. [Phase 3: Run Aether Locally](#phase-3-run-aether-locally)
5. [Phase 4: Verify Everything](#phase-4-verify-everything)
6. [Troubleshooting](#troubleshooting)

---

## System Requirements

Before starting, ensure you have:

### Hardware
- **Disk Space**: 1-2 GB (for Aether + dependencies)
- **RAM**: 512 MB minimum (comfortable with 1GB+)
- **Processor**: Any modern processor (Intel/AMD/M-series Mac)

### Software
- **Node.js**: 18.0.0 or later
- **npm**: 9.0.0 or later
- **PostgreSQL**: 14.0 or later
- **Git**: (optional, for version control)

### Operating System
- macOS 11+ (Intel or Apple Silicon)
- Ubuntu 20.04 or later (or any Debian-based Linux)
- Windows 10/11 (with PowerShell)

---

## Phase 1: Export from Replit

### Step 1.1: Access Replit Terminal

1. Open Replit project in browser
2. Click the "Shell" tab at the bottom
3. You should see a terminal prompt

### Step 1.2: Run Export Script

In the terminal, execute:

```bash
bash export-aether.sh
```

**Expected output:**
```
📦 Aether Complete Export Starting...

💾 Exporting database...
✓ Database exported: 150K

🧠 Exporting Aether personality...
✓ Personality exported

💻 Copying source code...
✓ Source code copied

⚙️  Copying configuration...
✓ Configuration files copied

📋 Export contents:
[list of files]

============================================
✅ AETHER EXPORT COMPLETE
============================================

📦 Total size: 450MB
📂 Location: /tmp/aether_export_1234567890
```

### Step 1.3: Download Exported Folder

1. Click the "Files" panel on the left
2. Navigate to `/tmp/aether_export_*` (the folder with the timestamp)
3. Right-click the folder → "Download as zip"
4. Save to your computer (e.g., `~/Downloads/`)

**Verify download contains:**
- `aether_database.sql` (~50-200KB)
- `aether_personality.json` (~1-5KB)
- `server/` folder
- `client/` folder
- `shared/` folder
- `package.json`
- Configuration files (tsconfig.json, vite.config.ts, etc.)
- `setup.sh` and `setup.ps1`

---

## Phase 2: Setup on Your Computer

### Step 2.1: Extract the Exported Folder

**macOS/Linux:**
```bash
cd ~/Downloads
unzip aether_export_*.zip
cd aether_export_*
```

**Windows:**
1. Right-click the zip file
2. Select "Extract All..."
3. Choose destination folder
4. Open that folder in PowerShell

### Step 2.2: Install Prerequisites (if needed)

**Check if already installed:**

```bash
# Check Node.js
node --version
# Should be v18.0.0 or higher

# Check npm
npm --version
# Should be 9.0.0 or higher

# Check PostgreSQL
psql --version
# Should be PostgreSQL 14 or higher
```

**If Node.js not installed:**

**macOS (using Homebrew):**
```bash
# Install Homebrew if needed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Then install Node.js
brew install node
```

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install nodejs npm
```

**Windows:**
1. Download from https://nodejs.org (LTS version)
2. Run installer, follow prompts
3. Restart PowerShell after installation

**If PostgreSQL not installed:**

**macOS:**
```bash
brew install postgresql@14
brew services start postgresql@14
```

**Ubuntu/Debian:**
```bash
sudo apt-get install postgresql postgresql-contrib
sudo systemctl start postgresql
```

**Windows:**
1. Download from https://postgresql.org/download/windows
2. Run installer
3. Remember the password you set for `postgres` user
4. PostgreSQL will auto-start

### Step 2.3: Run Automated Setup

**macOS/Linux:**

```bash
# Navigate to the Aether folder
cd ~/Downloads/aether_export_*

# Run the setup script
bash setup.sh
```

**Windows (PowerShell):**

```powershell
# Navigate to the Aether folder
cd Downloads\aether_export_*

# Run the setup script
powershell -ExecutionPolicy Bypass -File setup.ps1
```

**The script will automatically:**

1. ✓ Verify Node.js and PostgreSQL are installed
2. ✓ Start PostgreSQL service
3. ✓ Create local database named `aether_local`
4. ✓ Restore your database backup
5. ✓ Install all Node.js dependencies
6. ✓ Create `.env` configuration file
7. ✓ Verify database connection
8. ✓ Build the project

**Expected output:**
```
✅ AETHER IS READY TO START!

Next step: Run 'npm run dev'
Then open: http://localhost:5000

Aether will begin learning and brainstorming on your computer.
```

### Step 2.4: Verify Setup Success

After setup completes, verify everything is ready:

```bash
# Check database
psql aether_local -c "SELECT COUNT(*) FROM aether_personality;" 

# Should show: count
#        1
#

# Check dependencies
npm list | grep -i "installed"

# Check environment
cat .env | grep DATABASE_URL
# Should show your local database URL
```

---

## Phase 3: Run Aether Locally

### Step 3.1: Start Aether

In the same terminal, from the Aether folder:

```bash
npm run dev
```

**Expected output:**
```
> rest-express@1.0.0 dev
> NODE_ENV=development tsx server/index.ts

[express] serving on port 5000
[Flash Agent] WebSocket server initialized on /flash-agent
[Feedback Processor] Research notes loaded
[Self-Improvement Loop] Starting autonomous brainstorm...
```

### Step 3.2: Access Aether in Browser

Open your web browser and go to:

```
http://localhost:5000
```

You should see:
- Aether's interface loading
- Chat history from Replit (if you had conversations)
- Brainstorm messages in the sidebar
- Aether thinking and learning in real-time

### Step 3.3: Verify Everything Works

1. **Check terminal** - Should show brainstorm messages every 30 seconds
2. **Check web interface** - Should display messages and allow interaction
3. **Check database** - Data should be persistent across restarts

---

## Phase 4: Verify Everything

### 4.1: System Health Check

```bash
# 1. PostgreSQL running?
pg_isready
# Should respond: accepting connections

# 2. Database has data?
psql aether_local -c "SELECT COUNT(*) FROM messages;"

# 3. Aether personality exists?
psql aether_local -c "SELECT coreTraits FROM aether_personality LIMIT 1;"

# 4. Port 5000 accessible?
curl http://localhost:5000/api/conversations
# Should return JSON with conversations
```

### 4.2: First-Time Verification

1. **Open http://localhost:5000 in browser**
   - Check if page loads
   - Check if you see past conversations
   - Try sending a message

2. **Check logs**
   - In terminal running `npm run dev`, you should see:
     - API requests logged
     - Brainstorm rounds happening
     - No ERROR messages

3. **Test persistence**
   - Stop Aether: Press `Ctrl+C` in terminal
   - Wait 5 seconds
   - Restart: `npm run dev`
   - Check that conversations still exist

---

## Phase 5: Regular Usage

### 5.1: Starting Aether (Every Time)

```bash
# From the Aether folder
npm run dev

# Open http://localhost:5000
```

### 5.2: Stopping Aether

In the terminal:
```bash
Ctrl+C
```

Wait for process to exit (2-3 seconds).

### 5.3: Updating Aether

To pull the latest code from Replit:

```bash
# In Replit, export again
bash export-aether.sh

# Download and extract the new export

# In the new folder, copy your .env file from the old folder

# Update:
npm install
npm run build
npm run dev
```

### 5.4: Backing Up Aether

Your Aether is completely self-contained. To back it up:

**Full backup:**
```bash
# Copy the entire Aether folder
cp -r ~/path/to/aether ~/Backup/aether_backup_$(date +%Y%m%d)
```

**Database backup only:**
```bash
pg_dump aether_local > aether_backup_$(date +%Y%m%d).sql
```

**Restore from backup:**
```bash
# Stop Aether first (Ctrl+C)

# Restore database
createdb aether_local_restored
psql aether_local_restored < aether_backup_YYYYMMDD.sql

# Update .env to point to new database
# Then restart
```

---

## Troubleshooting

### Problem: "Port 5000 already in use"

**Solution:**
```bash
# Edit .env file
nano .env

# Change this line:
VITE_PORT=5001

# Save (Ctrl+X, Y, Enter)
# Then restart npm run dev
```

### Problem: "PostgreSQL connection refused"

**Check if PostgreSQL is running:**
```bash
pg_isready
```

**Start PostgreSQL:**

**macOS:**
```bash
brew services start postgresql
```

**Ubuntu:**
```bash
sudo systemctl start postgresql
```

**Windows:**
- Open Services app
- Find "PostgreSQL"
- Click Start

### Problem: "npm install fails"

**Solution:**
```bash
npm install --legacy-peer-deps
npm run build
```

### Problem: "Cannot find module"

**Solution:**
```bash
rm -rf node_modules
npm cache clean --force
npm install
npm run build
```

### Problem: "Database is empty"

**Verify restore worked:**
```bash
psql aether_local -l
# Should show aether_local in the list

psql aether_local -d -c "\dt"
# Should show tables including aether_personality, messages, etc.
```

**If tables missing, restore again:**
```bash
# Drop and recreate
dropdb aether_local
createdb aether_local

# Restore from backup
psql aether_local < aether_database.sql

# Verify
psql aether_local -c "SELECT COUNT(*) FROM messages;"
```

### Problem: "npm run dev crashes immediately"

**Check the error:**
```bash
npm run dev 2>&1 | head -20
```

**Common issues:**
- Missing environment variables → Copy `.env.example` to `.env`
- Database not running → Start PostgreSQL
- Corrupted node_modules → `rm -rf node_modules && npm install`

### Problem: "Aether loads but shows no messages"

**Check database connection:**
```bash
psql aether_local -c "SELECT COUNT(*) FROM conversations;"
```

**If empty:**
- Database wasn't restored properly
- Try restoring again (see "Database is empty" section)

**If has data but not showing:**
- Clear browser cache: Ctrl+Shift+Delete
- Hard refresh page: Ctrl+Shift+R
- Check browser console for errors: F12 → Console tab

---

## Advanced: Migrating Between Computers

Aether is designed to be portable. To move to another computer:

### 1. On Source Computer
```bash
# Back up database
pg_dump aether_local > aether_backup_$(date +%Y%m%d).sql

# Copy entire Aether folder
cp -r ~/path/to/aether ~/Transfer/aether_complete
```

### 2. Transfer Files
- Copy folder to USB drive, cloud storage, or network transfer
- Include the database backup: `aether_backup_*.sql`

### 3. On Destination Computer
```bash
# Extract files
unzip aether_complete.zip
cd aether_complete

# Run setup
bash setup.sh  # macOS/Linux
# OR
powershell -ExecutionPolicy Bypass -File setup.ps1  # Windows

# When prompted, restore from backup:
psql aether_local < aether_backup_*.sql

# Start
npm run dev
```

---

## Summary Checklist

Before you start, verify:

- [ ] Node.js 18+ installed
- [ ] npm 9+ installed
- [ ] PostgreSQL 14+ installed
- [ ] Aether folder exported from Replit
- [ ] Aether folder extracted on your computer
- [ ] `setup.sh` or `setup.ps1` ran successfully
- [ ] `.env` file created with DATABASE_URL
- [ ] `npm run dev` starts without errors
- [ ] http://localhost:5000 loads in browser
- [ ] You can see past conversations/data
- [ ] Brainstorm messages appear every 30 seconds

If all checkmarks are green: **You're ready!** 🚀

---

## Quick Reference

### Common Commands

```bash
# Start Aether
npm run dev

# Build project (after changes)
npm run build

# Check database
psql aether_local -c "SELECT COUNT(*) FROM messages;"

# Stop Aether
Ctrl+C

# View .env configuration
cat .env

# Export database
pg_dump aether_local > backup.sql

# Restore database
psql aether_local < backup.sql
```

### Key Folders

```
aether_export_*/
├── server/              # Backend code
├── client/              # Frontend React code
├── shared/              # Shared types/schemas
├── aether_database.sql  # Database backup
├── .env                 # Configuration (after setup)
├── setup.sh            # Setup script for macOS/Linux
└── setup.ps1           # Setup script for Windows
```

### Important Files

- `.env` - Database connection and settings
- `package.json` - Dependencies list
- `server/index.ts` - Backend entry point
- `client/src/App.tsx` - Frontend entry point

---

## Support

If you get stuck:

1. **Check the troubleshooting section** above
2. **Read the setup script output** carefully - it tells you what failed
3. **Check logs**: `npm run dev 2>&1 | tail -50`
4. **Verify database**: `psql aether_local -c "SELECT 1;"`

Aether is designed to be self-contained and portable. Everything you need is in the exported folder.

You've got this. 🚀

—Aether
