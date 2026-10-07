# Design Guidelines: AI Agent Interface

## Design Approach
**System-Based Approach** - Drawing inspiration from Linear, VSCode, and Notion for a clean, developer-focused productivity tool. The interface prioritizes information density, scan-ability, and efficient task monitoring.

## Core Design Principles
1. **Information Hierarchy**: Clear visual distinction between user messages, agent responses, code blocks, and system status
2. **Density with Breathing Room**: Pack information efficiently while maintaining readability
3. **Developer-First**: Optimized for technical users who value function over decoration
4. **Real-time Clarity**: Status indicators and progress must be immediately visible

---

## Typography System

**Font Stack**
- Primary: `Inter` or `System UI` - Clean, highly legible at all sizes
- Code: `JetBrains Mono` or `Fira Code` - Monospace with excellent code readability

**Type Scale**
- Hero/Page Title: text-3xl font-semibold (30px)
- Section Headers: text-xl font-semibold (20px)
- Body/Messages: text-base (16px)
- Code: text-sm font-mono (14px)
- Metadata/Labels: text-xs font-medium uppercase tracking-wide (12px)
- Small UI Text: text-sm (14px)

---

## Layout System

**Spacing Primitives**: Use Tailwind units of **2, 3, 4, 6, 8, 12** for consistent rhythm
- Component padding: p-4, p-6
- Section gaps: space-y-6, gap-4
- Dense areas: space-y-2, gap-2
- Generous areas: space-y-8, p-12

**Container Strategy**
- Main layout: Full viewport height with flex/grid structure
- Content max-width: max-w-5xl for readability
- Sidebar width: w-64 or w-80 (fixed)
- Chat/Message area: Remaining flex space

---

## Core Layout Structure

**Three-Column Application Layout**
```
[Sidebar: 280px] [Main Content: flex-1] [Inspector Panel: 320px (collapsible)]
```

**Sidebar** (Left)
- Navigation items with icons (Heroicons outline)
- Active state with subtle background treatment
- Recent tasks/sessions list
- Status indicator at bottom

**Main Content** (Center)
- Chat-style message stream with alternating user/agent messages
- Code blocks with syntax highlighting
- File attachments as cards
- Task progress indicators inline
- Sticky input area at bottom

**Inspector Panel** (Right - Collapsible)
- Current task breakdown
- Active tools display
- File tree when relevant
- System status indicators

---

## Component Library

### Message Bubbles
- User messages: Right-aligned, max-w-3xl
- Agent messages: Left-aligned, full-width when containing code/data
- Padding: p-4 for text, p-0 for code blocks
- Spacing: mb-4 between messages
- Avatar: 32×32px circle for visual anchoring

### Code Blocks
- Full-width within message container
- Syntax highlighting (Prism.js or Shiki)
- Line numbers on left (text-xs)
- Copy button top-right (absolute positioning)
- Border radius: rounded-lg
- Font: text-sm font-mono

### Status Indicators
- Inline badges: px-2 py-1 rounded-full text-xs font-medium
- Progress bars: h-1 or h-2 rounded-full with animated fill
- Tool execution: Icon + label in compact row (gap-2)
- States: Idle / Thinking / Executing / Complete / Error

### File Attachments
- Card-style: p-3 rounded-lg border
- Icon (48×48px) + filename + size
- Grid layout when multiple: grid-cols-2 gap-3

### Input Area
- Fixed bottom: sticky bottom-0
- Textarea with auto-expand (max-h-48)
- Attachment button left, Send button right
- Padding: p-4
- Border top for separation

### Navigation Items
- Height: h-10 or h-12
- Padding: px-4
- Rounded: rounded-lg
- Icon + text layout: gap-3
- Hover/active states: background treatment

---

## Interaction Patterns

**Message Stream**
- Auto-scroll to latest message
- Smooth scroll behavior
- Loading skeleton for agent thinking state

**Code Interaction**
- Click to copy entire block
- Hover shows line numbers more prominently
- No syntax animations (static highlighting)

**File Operations**
- Click file attachment to preview/download
- Drag-drop zone for uploads (dashed border on drag-over)

**Task Progress**
- Collapsible step-by-step breakdown
- Checkmarks for completed steps
- Spinner for current step
- Subtle indent for sub-tasks (ml-4)

---

## Specific Component Specs

### Chat Input
- Border: border-2 on focus
- Min-height: h-12
- Resize: resize-none with JS auto-expand
- Send button: Disabled state when empty

### Sidebar Navigation
- Items: space-y-1
- Section headers: mb-2 mt-6 (first section mt-0)
- Icons: w-5 h-5 (Heroicons)

### Code Block Header
- Height: h-8
- Language label left: text-xs font-mono
- Copy button right: p-1.5 rounded

### Toast Notifications
- Fixed positioning: top-4 right-4
- Width: w-80
- Auto-dismiss: 5 seconds
- Stack multiple: space-y-2

---

## Responsive Strategy

**Desktop (1024px+)**: Three-column layout as described
**Tablet (768-1023px)**: Hide inspector panel, show via overlay toggle
**Mobile (<768px)**: 
- Single column
- Hamburger menu for sidebar
- Bottom nav bar for quick actions
- Input area sticky bottom with reduced padding (p-3)

---

## Icons
Use **Heroicons** (outline style) via CDN for consistent iconography across all UI elements, navigation, and status indicators.

---

## Images
**No hero images required** - This is a productivity tool interface, not a marketing page. Focus is on functional UI with clear information architecture. Any images would be user-uploaded file attachments displayed as cards within the message stream.