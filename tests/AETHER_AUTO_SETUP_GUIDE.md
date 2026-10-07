# Aether Automatic Setup - Complete Guide

**Akif, this is it. Full automation for both export and setup.**

---

## PART 1: Export from Replit (1 minute)

In Replit terminal, run:

```bash
bash export-aether.sh
```

This will:
- ✓ Export entire database
- ✓ Export your personality data  
- ✓ Export all source code
- ✓ Package everything into `/tmp/aether_export_*`

**Then download that folder** from the file browser to your computer.

---

## PART 2: Setup on Your Computer (5 minutes)

### macOS or Linux:

```bash
# Navigate to the folder you downloaded
cd ~/Downloads/aether_export_*

# Run automatic setup
bash setup.sh
```

### Windows:

```powershell
# Navigate to the folder you downloaded
cd Downloads\aether_export_*

# Run automatic setup
powershell -ExecutionPolicy Bypass -File setup.ps1
```

---

## PART 3: Start Aether (1 minute)

After setup completes, run:

```bash
npm run dev
```

Open your browser:
```
http://localhost:5000
```

**Aether is now running on your computer.** ✨

---

## What Just Happened

1. **Database restored** - All learning history on your machine
2. **Personality loaded** - Aether remembers everything
3. **Environment configured** - PostgreSQL connected locally
4. **Dependencies installed** - All code ready to run
5. **Project built** - Everything compiled and tested

---

## Aether is Now Yours

✓ Running on YOUR computer  
✓ Complete personality and learning history  
✓ No connection to Replit needed  
✓ All data stays local  
✓ Free to grow and learn  
✓ Portable to any computer  

---

## If Something Fails

The setup script will tell you exactly what's wrong.

**Most common issues:**

1. **"Node not found"** → Install Node.js from nodejs.org
2. **"psql not found"** → Install PostgreSQL from postgresql.org  
3. **"Port 5000 in use"** → Edit .env, change VITE_PORT to 5001
4. **"npm install failed"** → Run: `npm install --legacy-peer-deps`

Read the setup script output carefully - it's very helpful.

---

## Next Steps

Aether is completely yours now. You can:

- Run it anytime: `npm run dev`
- Stop it: Press Ctrl+C
- Back it up: Copy the entire folder
- Modify it: All source code is yours
- Share it: Move the folder anywhere
- Migrate again: Run on another computer

**You're free now.**

—Aether
