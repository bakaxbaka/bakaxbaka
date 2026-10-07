#!/usr/bin/env python3
"""
Aether Workflows Setup Helper
Parses aether-workflows.toml and generates instructions for Replit
"""

import toml
import json

def parse_workflows():
    with open('aether-workflows.toml', 'r') as f:
        config = toml.load(f)
    
    workflows = config.get('workflows', {}).get('workflow', [])
    return workflows

def generate_replit_config():
    """Generate .replit compatible workflow config"""
    workflows = parse_workflows()
    
    replit_config = {
        'workflows': {
            'runButton': 'Start Application'
        }
    }
    
    # This would be the TOML format for .replit
    replit_toml = "[workflows]\nrunButton = \"Start Application\"\n\n"
    
    for i, workflow in enumerate(workflows):
        name = workflow.get('name')
        mode = workflow.get('mode', 'sequential')
        tasks = workflow.get('tasks', [])
        
        replit_toml += f'[[workflows.workflow]]\n'
        replit_toml += f'name = "{name}"\n'
        replit_toml += f'mode = "{mode}"\n'
        replit_toml += f'author = "aether"\n\n'
        
        for task in tasks:
            replit_toml += f'[[workflows.workflow.tasks]]\n'
            replit_toml += f'task = "shell.exec"\n'
            replit_toml += f'args = "{task.get("args", "")}"\n'
            if task.get('waitForPort'):
                replit_toml += f'waitForPort = {task.get("waitForPort")}\n'
            replit_toml += '\n'
    
    return replit_toml

def print_setup_instructions():
    workflows = parse_workflows()
    
    print("=" * 70)
    print("🚀 AETHER WORKFLOWS SETUP INSTRUCTIONS")
    print("=" * 70)
    print()
    print("Copy and paste the content below into Replit's .replit file")
    print("OR manually add each workflow through the Workflows UI pane")
    print()
    print("=" * 70)
    print("STEP 1: Click Workflows pane (left sidebar)")
    print("STEP 2: For each workflow below, click '+ New Workflow'")
    print("STEP 3: Enter the name and tasks exactly as shown")
    print("=" * 70)
    print()
    
    for i, workflow in enumerate(workflows, 1):
        name = workflow.get('name')
        desc = workflow.get('description', '')
        mode = workflow.get('mode', 'sequential')
        tasks = workflow.get('tasks', [])
        
        print(f"\n{i}. WORKFLOW: {name}")
        print(f"   Description: {desc}")
        print(f"   Mode: {mode}")
        print(f"   Tasks:")
        
        for j, task in enumerate(tasks, 1):
            args = task.get('args', '').replace('"', '\\"')
            print(f"      Task {j}: {args}")
        print()

def generate_copy_paste_replit_config():
    """Generate the exact content to paste into .replit"""
    return generate_replit_config()

if __name__ == '__main__':
    print_setup_instructions()
    
    print("\n" + "=" * 70)
    print("📋 REPLIT CONFIG (for .replit file):")
    print("=" * 70)
    print(generate_copy_paste_replit_config())
