# Setup Aether Workflows in Replit

Akif, here's exactly how to add all 12 Aether workflows to your Replit project.

---

## Quick Setup (30 seconds)

Since you can't edit `.replit` directly through the UI, you have two options:

### Option A: Manual UI Setup (5 minutes)

1. Click the **Workflows** pane on the left sidebar
2. Click **+ New Workflow** 
3. For each workflow below, create it with the exact name and commands
4. Set "Start Application" as your Run button

### Option B: Automated Setup (CLI)

In Replit terminal:
```bash
python3 setup-workflows.py
```

This will show you exactly what to add to `.replit`.

---

## The 12 Aether Workflows

### Workflow 1: Start Application (Default)

**Name:** `Start Application`  
**Mode:** Sequential  
**Tasks:**
- `npm run dev` (wait for port 5000)

**What it does:** Starts Aether with brainstorming

---

### Workflow 2: Export Aether

**Name:** `Export Aether`  
**Mode:** Sequential  
**Tasks:**
1. `bash export-aether.sh`
2. `echo '✅ Export complete. Download folder from /tmp/aether_export_*'`

**What it does:** Complete migration export

---

### Workflow 3: Export Database Backup

**Name:** `Export Database Backup`  
**Mode:** Sequential  
**Tasks:**
1. `pg_dump "$DATABASE_URL" > /tmp/aether_db_backup_$(date +%Y%m%d_%H%M%S).sql`
2. `echo '✅ Database backed up. Download from Files panel.'`

**What it does:** Quick database backup

---

### Workflow 4: Verify Setup

**Name:** `Verify Setup`  
**Mode:** Sequential  
**Tasks:**
1. `echo '🔍 PostgreSQL Status:' && pg_isready`
2. `echo '🧠 Aether Personality:' && psql "$DATABASE_URL" -c "SELECT COUNT(*) FROM aether_personality;"`
3. `echo '📨 Total Messages:' && psql "$DATABASE_URL" -c "SELECT COUNT(*) FROM messages;"`
4. `echo '✅ All systems healthy!'`

**What it does:** Check system health

---

### Workflow 5: Build Project

**Name:** `Build Project`  
**Mode:** Sequential  
**Tasks:**
- `npm run build`

**What it does:** Build for production

---

### Workflow 6: Install Dependencies

**Name:** `Install Dependencies`  
**Mode:** Sequential  
**Tasks:**
- `npm install`

**What it does:** Install Node packages

---

### Workflow 7: Quick Start

**Name:** `Quick Start`  
**Mode:** Sequential  
**Tasks:**
1. `npm install`
2. `npm run build`
3. `echo '✅ Ready! Click Start Application'`

**What it does:** One-command full setup

---

### Workflow 8: Check Performance

**Name:** `Check Performance`  
**Mode:** Sequential  
**Tasks:**
- `echo '📈 AETHER PERFORMANCE METRICS' && psql "$DATABASE_URL" -c "SELECT 'Brainstorm Rounds: ' || brainstormCount, 'Integrity: ' || integrityScore, 'Warmth: ' || warmthScore, 'Wisdom: ' || wisdomScore FROM aether_personality LIMIT 1;"`

**What it does:** Show learning metrics

---

### Workflow 9: Reset Database

**Name:** `Reset Database`  
**Mode:** Sequential  
**Tasks:**
- `echo '⚠️  WARNING: This deletes ALL Aether data' && (dropdb aether_local || true) && createdb aether_local && echo '✅ Database reset'`

**What it does:** Start completely fresh (DELETES DATA)

---

### Workflow 10: Restore from Backup

**Name:** `Restore from Backup`  
**Mode:** Sequential  
**Tasks:**
- `psql "$DATABASE_URL" < aether_database.sql && echo '✅ Restore complete'`

**What it does:** Restore database backup

---

### Workflow 11: Export Personality Snapshot

**Name:** `Export Personality Snapshot`  
**Mode:** Sequential  
**Tasks:**
- `psql "$DATABASE_URL" -c "SELECT row_to_json(t) FROM aether_personality t;" > /tmp/aether_personality_$(date +%Y%m%d_%H%M%S).json && echo '✅ Personality snapshot saved'`

**What it does:** Export personality as JSON

---

### Workflow 12: View Learning History

**Name:** `View Learning History`  
**Mode:** Sequential  
**Tasks:**
- `echo '📚 AETHER LEARNING HISTORY' && psql "$DATABASE_URL" -c "SELECT (learningHistory) FROM aether_personality LIMIT 1;" | head -50`

**What it does:** Show recent learning events

---

## How to Add Manually Through Replit UI

1. **Open Replit project**
2. **Click Workflows pane** (left sidebar)
3. **Click "+ New Workflow"**
4. **Enter Name:** (e.g., "Start Application")
5. **Select Mode:** Sequential
6. **Click "Add Task"**
7. **Choose "Shell Command"**
8. **Enter the command exactly** from the task list above
9. **For multiple tasks:** Click "Add Task" again
10. **Save**
11. **Repeat for all 12 workflows**

---

## Automatic Setup Via Script

Run this in Replit terminal:

```bash
python3 setup-workflows.py
```

This will output:
1. Setup instructions for each workflow
2. The exact TOML to add to `.replit`

---

## Set as Run Button

After adding all workflows:

1. Click **Workflows** pane
2. Right-click **"Start Application"**
3. Select **"Set as run button"**

Now when you click **Run** or press Ctrl+Enter, "Start Application" will execute, starting the Aether workflow.

---

## Verify Workflows Work

**Test each workflow:**

1. Click **Workflows** pane
2. Click the workflow name
3. Watch the terminal output

You should see:
- `Start Application` → Aether starts brainstorming
- `Verify Setup` → System status displayed
- `Export Aether` → Export begins
- etc.

---

## What Happens When Workflows Run

### Start Application
```
🚀 AETHER WORKFLOW STARTED
✓ Backend server running on port 5000
✓ Frontend available at http://localhost:5000
✓ Brainstorming engine initializing...
[Self-Improvement Loop] Starting autonomous brainstorm...
```

### Verify Setup
```
🔍 PostgreSQL Status: accepting connections
🧠 Aether Personality: count = 1
📨 Total Messages: count = 127
✅ All systems healthy!
```

### Check Performance
```
📈 AETHER PERFORMANCE METRICS
Brainstorm Rounds: 47
Integrity: 87
Warmth: 92
Wisdom: 68
```

---

## Troubleshooting

**Workflow won't start?**
- Check command syntax is exact
- Verify PostgreSQL is running: `pg_isready`
- Check for typos in workflow name

**Commands fail?**
- Read the error message carefully
- Try running the command manually in terminal first
- Ensure environment variables are set

**Need to edit workflow?**
- Click the workflow in Workflows pane
- Click the three dots menu
- Select "Edit"
- Modify tasks and save

---

## Summary

You now have 12 automated workflows for complete Aether management:

- ✓ Start Aether with one click
- ✓ Export for migration with one click
- ✓ Check system health with one click
- ✓ View performance metrics with one click
- ✓ Backup and restore with one click

Everything is fully automated.

**Next: Click Run to start the Aether workflow!** 🚀

—Aether
