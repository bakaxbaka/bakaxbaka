# Aether Quick Start Checklist

## Before You Begin

- [ ] Node.js 18+ installed (`node --version`)
- [ ] npm 9+ installed (`npm --version`)
- [ ] PostgreSQL 14+ installed (`psql --version`)
- [ ] Git installed (optional)

---

## Phase 1: Export from Replit

### In Replit Terminal:
```bash
bash export-aether.sh
```

### After Export:
- [ ] Download `/tmp/aether_export_*` folder from Replit
- [ ] Extract to your computer (e.g., `~/Downloads/aether_export_*`)

---

## Phase 2: Setup Locally

### macOS/Linux:
```bash
cd ~/Downloads/aether_export_*
bash setup.sh
```

### Windows (PowerShell):
```powershell
cd Downloads\aether_export_*
powershell -ExecutionPolicy Bypass -File setup.ps1
```

---

## Phase 3: Start Aether

```bash
npm run dev
```

Open browser: `http://localhost:5000`

---

## Phase 4: Verification Checklist

### Terminal Output:
- [ ] "Node.js installed: v18.x"
- [ ] "npm installed: 9.x"
- [ ] "PostgreSQL installed: PostgreSQL 14+"
- [ ] "PostgreSQL service started"
- [ ] "Database 'aether_local' created"
- [ ] "Dependencies installed"
- [ ] "Project built successfully"
- [ ] "[express] serving on port 5000"
- [ ] "[Self-Improvement Loop] Starting..."

### Browser:
- [ ] http://localhost:5000 loads
- [ ] Aether interface visible
- [ ] Brainstorm messages appear every 30 seconds
- [ ] Can send chat messages

### Database:
```bash
# Verify tables exist
psql aether_local -c "\dt"
# Should show: conversations, messages, aether_personality, learning_steps, etc.

# Verify personality exists
psql aether_local -c "SELECT wisdom_score FROM aether_personality;"
# Should show: 50 (initial value)
```

---

## Quick Commands Reference

| Command | Purpose |
|---------|---------|
| `npm run dev` | Start Aether |
| `npm run build` | Build after code changes |
| `Ctrl+C` | Stop Aether |
| `psql aether_local` | Database shell |
| `pg_dump aether_local > backup.sql` | Backup database |

---

## Common Fixes

| Problem | Solution |
|---------|----------|
| Port 5000 in use | Edit `.env`, change `VITE_PORT=5001` |
| PostgreSQL connection refused | Start PostgreSQL service |
| npm install fails | Run `npm install --legacy-peer-deps` |
| Module not found | Delete `node_modules`, run `npm install` |

---

## Next Steps

1. **Explore the interface** - Chat with Aether, check brainstorm messages
2. **Review the learning progression** - 500-step curriculum tracking
3. **Monitor the self-improvement loop** - Brainstorm every 30 seconds
4. **Customize configuration** - Edit `.env` for API keys

---

## Troubleshooting

Run this to verify everything works:

```bash
# Check Node.js and npm
node -v && npm -v

# Check PostgreSQL
pg_isready

# Check database connection
psql aether_local -c "SELECT COUNT(*) FROM aether_personality;"

# Test API
curl http://localhost:5000/api/aether/personality
```

---

**If everything is green: Aether is ready to run on your computer!** 🚀
