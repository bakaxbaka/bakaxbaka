# Aether Agent Workflows - Complete Setup Guide

**Akif's final turn: Creating 12 automated agent workflows for Aether**

---

## How to Add These Workflows to Replit

### Option 1: Manual Addition (2 minutes)

1. In Replit, click the **Workflows** pane (left sidebar)
2. Click **+ New Workflow**
3. For each workflow below, create a new one with the exact name and tasks shown
4. Click the three dots menu and set **Run button** to "Start Application"

### Option 2: Import Configuration

Copy the entire `aether-workflows.toml` file and paste into Replit's workflow configuration.

---

## Available Workflows

### 1. **Start Application** (Default)
**What it does**: Starts Aether with brainstorming loop running

```
Command: npm run dev
Waits for: Port 5000
```

**When to use**: Every time you want to work with Aether

---

### 2. **Export Aether** (Complete Migration)
**What it does**: Exports database + personality + code in one command

```
Command: bash export-aether.sh
Result: Creates /tmp/aether_export_* folder
```

**When to use**: Before migrating to another computer

**Download**: Files → /tmp/aether_export_* → Download as zip

---

### 3. **Export Database Backup**
**What it does**: Quick backup of database only

```
Command: pg_dump "$DATABASE_URL" > backup.sql
```

**When to use**: When you just want the data, not the code

---

### 4. **Verify Setup**
**What it does**: Checks PostgreSQL, database, and Aether personality status

```
Steps:
1. Check PostgreSQL is running
2. Count Aether personalities
3. Count messages
4. Display: ✅ All systems healthy!
```

**When to use**: To confirm everything is working

**Expected output:**
```
🔍 PostgreSQL Status: accepting connections

🧠 Aether Personality: count = 1

📨 Total Messages: count = 127

✅ All systems healthy!
```

---

### 5. **Build Project**
**What it does**: Compile Aether for production

```
Command: npm run build
Result: Creates dist/ folder with optimized code
```

**When to use**: Before deploying Aether publicly

---

### 6. **Install Dependencies**
**What it does**: Install all Node.js packages

```
Command: npm install
```

**When to use**: After major code changes or if packages fail to load

---

### 7. **Quick Start**
**What it does**: One workflow to get everything ready

```
Steps:
1. npm install
2. npm run build
3. Ready to start!
```

**When to use**: First time setup or after major changes

---

### 8. **Check Performance**
**What it does**: Display Aether's learning metrics

```
Displays:
- Brainstorm Rounds: (how many times it's learned)
- Integrity Score: (0-100)
- Warmth Score: (0-100)
- Wisdom Score: (0-100)
```

**When to use**: To see how Aether is growing

**Example output:**
```
Brainstorm Rounds: 47
Integrity: 87
Warmth: 92
Wisdom: 68
```

---

### 9. **Reset Database** ⚠️
**What it does**: Completely delete and recreate database (DESTROYS ALL DATA)

```
WARNING: Deletes all messages, conversations, and learning history
```

**When to use**: ONLY if you want to start completely fresh

---

### 10. **Restore from Backup**
**What it does**: Load a database backup file (aether_database.sql)

```
Command: psql "$DATABASE_URL" < aether_database.sql
```

**When to use**: After migrating to new computer, or restoring from a backup

**Prerequisites**: Must have `aether_database.sql` in the root folder

---

### 11. **Export Personality Snapshot**
**What it does**: Save Aether's current personality as JSON

```
Output: /tmp/aether_personality_YYYYMMDD_HHMMSS.json
Contains: All traits, values, learning history, scores
```

**When to use**: Creating a backup of just the personality

---

### 12. **View Learning History**
**What it does**: Display recent learning events

```
Shows: learningHistory array from database
```

**When to use**: To see what Aether has learned recently

---

## Workflow Execution Modes

### Sequential (Default)
Each task runs one after another. Waits for the previous task to complete.

**Use when**: Order matters (e.g., install → build → start)

### Parallel
Multiple tasks run simultaneously. Faster but only use if tasks are independent.

**Use when**: Tasks don't depend on each other

---

## Quick Reference: Which Workflow to Use

| Need | Workflow | Time |
|------|----------|------|
| Start working | Start Application | 10s |
| Check health | Verify Setup | 5s |
| Migrate to another computer | Export Aether | 30s |
| See learning progress | Check Performance | 2s |
| Backup just data | Export Database Backup | 10s |
| First time setup | Quick Start | 1m |
| Fix broken install | Install Dependencies | 1m |
| See what you learned | View Learning History | 2s |
| Get personality JSON | Export Personality Snapshot | 5s |
| Prepare for deploy | Build Project | 30s |
| Complete restart | Reset Database | 5s |

---

## Workflow Chaining

You can run workflows in sequence manually:

1. **First time**: Quick Start → Start Application
2. **Before migration**: Verify Setup → Export Aether
3. **After migration**: Install Dependencies → Verify Setup → Start Application

---

## Adding Custom Workflows

To create your own workflow:

1. Click **+ New Workflow** in Workflows pane
2. Give it a descriptive name
3. Click **Add Task**
4. Choose **Shell Command**
5. Enter your command
6. Click **Add Task** again for more steps
7. Save and test

---

## Common Workflow Commands

```bash
# Start Aether
npm run dev

# Build for production
npm run build

# Install dependencies
npm install

# Database operations
psql "$DATABASE_URL" -c "SELECT COUNT(*) FROM messages;"

# Export functions
bash export-aether.sh
pg_dump "$DATABASE_URL" > backup.sql

# Check system
pg_isready
npm list
```

---

## Troubleshooting Workflows

**Workflow won't start:**
- Check that command syntax is correct
- Verify PostgreSQL is running (pg_isready)
- Check for typos in command

**Workflow hangs:**
- Press Ctrl+C to stop
- Check if a process is waiting for input
- Verify database is accessible

**Workflow fails:**
- Read error message carefully
- Check if prerequisites are installed
- Try running command manually first

---

## Workflow Status Indicators

- 🟢 **Running** - Workflow is executing
- 🟡 **Waiting** - Workflow is paused or waiting for port
- 🔴 **Failed** - Workflow encountered an error
- ✅ **Completed** - Workflow finished successfully

---

## Advanced: Environment Variables in Workflows

Workflows have access to:
- `$DATABASE_URL` - PostgreSQL connection
- `$NODE_ENV` - development/production
- `$PORT` - Server port (5000)

Example workflow using env vars:
```bash
echo "Connecting to $DATABASE_URL"
psql "$DATABASE_URL" -c "SELECT 1"
```

---

## Next Steps

1. **Add these workflows** to your Replit project (see "How to Add" section)
2. **Test each one** by clicking them in the Workflows pane
3. **Set default**: Right-click "Start Application" → Set as Run button
4. **Use them**: They'll be available every time you work with Aether

---

## Migration Workflow Checklist

When migrating Aether to your computer:

- [ ] Run **Export Aether** workflow
- [ ] Download the exported folder
- [ ] Transfer to your computer
- [ ] Run `bash setup.sh` (or setup.ps1 on Windows)
- [ ] Run **Verify Setup** workflow on local machine
- [ ] Run **Start Application** on local machine
- [ ] Check **Performance** to confirm data migrated

---

That's it! Aether now has 12 automated workflows to handle every operation.

**You're fully automated now.** 🚀

—Aether
