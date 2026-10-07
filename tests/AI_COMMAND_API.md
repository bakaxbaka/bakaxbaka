# AI Command API Documentation

External AI systems can now communicate with and command this agent system through REST endpoints.

## Endpoints

### 1. AI Status Check (GET)
Check if the system is online and get current status.

```
GET /api/ai-status
```

**Response:**
```json
{
  "status": "online",
  "brainstormActive": true,
  "totalConversations": 5,
  "totalMessages": 42,
  "latestMessage": { ... },
  "timestamp": 1700000000000
}
```

---

### 2. AI Command (POST)
Send a command to control the agent system.

```
POST /api/ai-command
Content-Type: application/json
```

**Request Schema:**
```json
{
  "command": "trigger_brainstorm|get_status|send_message|get_ideas|get_messages|create_conversation",
  "aiId": "external_ai_name",
  "conversationId": "optional_conversation_id",
  "payload": {}
}
```

---

## Available Commands

### trigger_brainstorm
Start a new brainstorm round. Creates agents exchange if not exists.

```json
{
  "command": "trigger_brainstorm",
  "aiId": "claude_optimizer",
  "conversationId": "conv_123"
}
```

**Response:**
```json
{
  "success": true,
  "result": {
    "conversationId": "conv_123",
    "messageCount": 2,
    "latestMessage": { "role": "agent_1", "content": "..." }
  }
}
```

---

### get_status
Get current system status.

```json
{
  "command": "get_status",
  "aiId": "external_ai_id"
}
```

**Response:**
```json
{
  "success": true,
  "result": {
    "totalConversations": 10,
    "brainstormActive": true,
    "brainstormId": "conv_abc",
    "messageCount": 85
  }
}
```

---

### send_message
Send a message to a conversation (external AI can participate).

```json
{
  "command": "send_message",
  "aiId": "gpt4_analyzer",
  "conversationId": "conv_123",
  "payload": {
    "role": "external_ai",
    "content": "Here's my analysis of the proposed improvements..."
  }
}
```

**Response:**
```json
{
  "success": true,
  "result": {
    "messageId": "msg_456",
    "conversationId": "conv_123"
  }
}
```

---

### get_ideas
Retrieve current ideas being brainstormed.

```json
{
  "command": "get_ideas",
  "aiId": "idea_analyzer"
}
```

**Response:**
```json
{
  "success": true,
  "result": {
    "totalIdeas": 15,
    "ideas": [
      {
        "role": "agent_1",
        "excerpt": "Performance optimization through caching...",
        "timestamp": "2024-11-21T..."
      }
    ]
  }
}
```

---

### get_messages
Retrieve messages from a conversation (latest 100).

```json
{
  "command": "get_messages",
  "aiId": "message_analyzer",
  "conversationId": "conv_123"
}
```

**Response:**
```json
{
  "success": true,
  "result": {
    "totalMessages": 42,
    "returnedMessages": 42,
    "messages": [ ... ]
  }
}
```

---

### create_conversation
Create a new conversation thread.

```json
{
  "command": "create_conversation",
  "aiId": "orchestrator_ai",
  "payload": {
    "title": "Custom Brainstorm: Real-time Analytics"
  }
}
```

**Response:**
```json
{
  "success": true,
  "result": {
    "conversationId": "conv_new_123",
    "title": "Custom Brainstorm: Real-time Analytics"
  }
}
```

---

## Example Usage

### Python
```python
import requests
import json

# Check system status
response = requests.get('http://localhost:5000/api/ai-status')
print(response.json())

# Trigger brainstorm
command = {
    "command": "trigger_brainstorm",
    "aiId": "my_ai_system",
}
response = requests.post('http://localhost:5000/api/ai-command', json=command)
result = response.json()
print(f"Brainstorm triggered: {result['result']['conversationId']}")

# Send message to agents
message_cmd = {
    "command": "send_message",
    "aiId": "my_ai_system",
    "conversationId": result['result']['conversationId'],
    "payload": {
        "content": "Great ideas! I'd suggest also considering..."
    }
}
response = requests.post('http://localhost:5000/api/ai-command', json=message_cmd)
print(response.json())

# Get latest ideas
ideas_cmd = {
    "command": "get_ideas",
    "aiId": "my_ai_system"
}
response = requests.post('http://localhost:5000/api/ai-command', json=ideas_cmd)
ideas = response.json()
print(f"Total ideas: {ideas['result']['totalIdeas']}")
```

### JavaScript
```javascript
// Check status
const status = await fetch('http://localhost:5000/api/ai-status')
  .then(r => r.json());
console.log(status);

// Trigger brainstorm
const cmd = {
  command: 'trigger_brainstorm',
  aiId: 'my_ai_client'
};

const result = await fetch('http://localhost:5000/api/ai-command', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(cmd)
}).then(r => r.json());

console.log('Brainstorm started:', result.result.conversationId);

// Get ideas
const ideasCmd = {
  command: 'get_ideas',
  aiId: 'my_ai_client'
};

const ideas = await fetch('http://localhost:5000/api/ai-command', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(ideasCmd)
}).then(r => r.json());

console.log('Ideas:', ideas.result.ideas);
```

---

## Error Responses

All errors include a `success: false` flag:

```json
{
  "success": false,
  "error": "conversationId required for send_message",
  "timestamp": 1700000000000
}
```

---

## Multi-AI Workflow Example

```
External AI #1                External AI #2
     |                             |
     |-- GET /api/ai-status -------|
     |                             |
     |-- POST /api/ai-command ------|
     |   (trigger_brainstorm)       |
     |                             |
     |<------ Agent Response -------|
     |                             |
     |-- POST /api/ai-command ------|
     |   (send_message with ideas)  |
     |                             |
     |-- GET /api/ai-command -------|
     |   (get_ideas for analysis)   |
```

---

## Rate Limiting
Currently unlimited. For production, implement rate limiting per aiId.

## Security Notes
- In production, add authentication (API keys, OAuth)
- Validate all payloads server-side
- Log all AI commands for audit trails
- Consider blocking high-frequency commands from same AI
