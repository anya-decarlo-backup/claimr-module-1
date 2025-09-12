#!/usr/bin/env python3
"""
Add unique IDs to all rules in YAML files that don't have them.
"""

import os
import re
import hashlib
import yaml
from pathlib import Path
import sys

def generate_rule_id(rule_content, file_path, rule_index):
    """Generate a unique rule ID based on content and location"""
    # Create a unique string from file path, rule index, and key content
    unique_string = f"{file_path}:{rule_index}:{rule_content.get('type', '')}:{rule_content.get('service_ref', {})}"
    
    # Generate a hash
    hash_obj = hashlib.md5(unique_string.encode())
    return f"rule_{hash_obj.hexdigest()[:12]}"

def process_yaml_file(file_path):
    """Add IDs to rules in a YAML file"""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    try:
        rules = yaml.safe_load(content)
        if not isinstance(rules, list):
            return False
        
        modified = False
        for i, rule in enumerate(rules):
            if isinstance(rule, dict) and 'id' not in rule:
                rule['id'] = generate_rule_id(rule, str(file_path), i)
                modified = True
        
        if modified:
            # Write back to file
            with open(file_path, 'w', encoding='utf-8') as f:
                yaml.dump(rules, f, default_flow_style=False, sort_keys=False, indent=2)
            return True
            
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False
    
    return False

def main():
    if len(sys.argv) != 2:
        print("Usage: python add_rule_ids.py <directory>")
        sys.exit(1)
    
    rules_dir = Path(sys.argv[1])
    if not rules_dir.exists():
        print(f"Directory {rules_dir} does not exist")
        sys.exit(1)
    
    yaml_files = list(rules_dir.rglob("*.yaml"))
    processed = 0
    
    for yaml_file in yaml_files:
        if process_yaml_file(yaml_file):
            print(f"Added IDs to {yaml_file}")
            processed += 1
    
    print(f"Processed {processed} files out of {len(yaml_files)} YAML files")

if __name__ == "__main__":
    main()
