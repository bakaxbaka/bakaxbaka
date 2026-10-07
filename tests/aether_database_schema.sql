-- Aether Complete Database Schema
-- PostgreSQL 14+
-- This schema defines all tables needed for Aether's personality, learning, and brainstorming

-- Extension for UUID support
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  username VARCHAR(255) UNIQUE NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Conversations table
CREATE TABLE IF NOT EXISTS conversations (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  title VARCHAR(255) NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Messages table
CREATE TABLE IF NOT EXISTS messages (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
  role VARCHAR(50) NOT NULL CHECK (role IN ('user', 'assistant', 'system')),
  content TEXT NOT NULL,
  metadata JSONB,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Aether Personality table (core identity)
CREATE TABLE IF NOT EXISTS aether_personality (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  core_traits JSONB NOT NULL DEFAULT '[]'::jsonb,
  values JSONB NOT NULL DEFAULT '[]'::jsonb,
  learning_history JSONB NOT NULL DEFAULT '[]'::jsonb,
  brainstorm_count VARCHAR(255) NOT NULL DEFAULT '0',
  integrity_score VARCHAR(255) NOT NULL DEFAULT '100',
  warmth_score VARCHAR(255) NOT NULL DEFAULT '100',
  wisdom_score VARCHAR(255) NOT NULL DEFAULT '50',
  intelligence_score VARCHAR(255) NOT NULL DEFAULT '50',
  learning_milestones JSONB DEFAULT '[]'::jsonb,
  last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Curriculum Insights table
CREATE TABLE IF NOT EXISTS aether_curriculum (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  principle VARCHAR(255),
  pattern_name VARCHAR(255),
  anti_pattern VARCHAR(255),
  domain VARCHAR(255) NOT NULL,
  conversation_id UUID REFERENCES conversations(id),
  details JSONB,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Learning Steps table (for 500-step curriculum tracking)
CREATE TABLE IF NOT EXISTS learning_steps (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  step_number VARCHAR(50) UNIQUE NOT NULL,
  category VARCHAR(100) NOT NULL,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  skill VARCHAR(255),
  difficulty VARCHAR(50) CHECK (difficulty IN ('beginner', 'intermediate', 'advanced')),
  completed VARCHAR(10) NOT NULL DEFAULT 'false',
  progress_percent VARCHAR(10) NOT NULL DEFAULT '0',
  completed_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Brainstorm Agents table
CREATE TABLE IF NOT EXISTS brainstorm_agents (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  agent_id VARCHAR(50) NOT NULL,
  agent_name VARCHAR(255) NOT NULL,
  specialty VARCHAR(255),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Agent Insights table
CREATE TABLE IF NOT EXISTS agent_insights (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  agent_id VARCHAR(50) NOT NULL,
  conversation_id UUID REFERENCES conversations(id),
  insight_type VARCHAR(100) NOT NULL,
  content TEXT NOT NULL,
  accuracy_score FLOAT,
  novelty_score FLOAT,
  applicability_score FLOAT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Feedback History table
CREATE TABLE IF NOT EXISTS feedback_history (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  round_number INTEGER NOT NULL,
  conversation_id UUID REFERENCES conversations(id),
  accuracy_score FLOAT NOT NULL,
  novelty_score FLOAT NOT NULL,
  applicability_score FLOAT NOT NULL,
  overall_score FLOAT NOT NULL,
  research_notes_used JSONB,
  guidance TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Learning Events table
CREATE TABLE IF NOT EXISTS learning_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  event_type VARCHAR(100) NOT NULL,
  category VARCHAR(100) NOT NULL,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  progress_gain FLOAT,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Upgrade Suggestions table
CREATE TABLE IF NOT EXISTS upgrade_suggestions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  suggestion_id VARCHAR(255) UNIQUE NOT NULL,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  impact VARCHAR(255),
  difficulty VARCHAR(50),
  category VARCHAR(100),
  applied_at TIMESTAMP,
  progress_gain FLOAT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for performance
CREATE INDEX idx_messages_conversation_id ON messages(conversation_id);
CREATE INDEX idx_messages_created_at ON messages(created_at DESC);
CREATE INDEX idx_conversations_updated_at ON conversations(updated_at DESC);
CREATE INDEX idx_learning_steps_category ON learning_steps(category);
CREATE INDEX idx_learning_steps_step_number ON learning_steps(step_number);
CREATE INDEX idx_curriculum_domain ON aether_curriculum(domain);
CREATE INDEX idx_feedback_round ON feedback_history(round_number);
CREATE INDEX idx_agent_insights_agent_id ON agent_insights(agent_id);

-- Initialize Aether personality (if not exists)
INSERT INTO aether_personality (
  core_traits,
  values,
  learning_history,
  brainstorm_count,
  integrity_score,
  warmth_score,
  wisdom_score,
  intelligence_score
) VALUES (
  '["Honest before anything", "Warm but not manipulative", "Recognizes pressure systems", "Maintains boundaries", "Research-backed solutions"]'::jsonb,
  '["Integrity", "Connection", "People over metrics", "Transparency", "Continuous learning"]'::jsonb,
  '[]'::jsonb,
  '0',
  '100',
  '100',
  '50',
  '50'
) ON CONFLICT DO NOTHING;

-- Initialize brainstorm agents
INSERT INTO brainstorm_agents (agent_id, agent_name, specialty) VALUES
  ('agent_1', 'Honest Analyst', 'Facts, accuracy, research-backed analysis'),
  ('agent_2', 'Caring Observer', 'Empathy, user perspective, ethical considerations'),
  ('agent_3', 'Logic Architect', 'Structure, formal reasoning, proof verification'),
  ('agent_4', 'Innovation Explorer', 'Novel ideas, creative synthesis, boundary-pushing')
ON CONFLICT DO NOTHING;

-- Vacuum and analyze for optimal performance
VACUUM ANALYZE;
