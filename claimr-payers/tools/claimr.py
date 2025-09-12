#!/usr/bin/env python3
"""
Claimr CLI - Rules validation and simulation engine

Commands:
  rules-smoke-check: Validate rules against services and valuesets
  simulate: Run rule evaluation against a patient scenario
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Set, Any, Optional
from datetime import datetime, date

def load_ndjson(path: Path) -> List[Dict]:
    """Load NDJSON file into list of objects"""
    items = []
    if not path.exists():
        return items
    
    with path.open('r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('{') and '"example"' in line:
                continue
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return items

def build_service_index(services: List[Dict]) -> Dict[str, Dict]:
    """Build index of service_id -> service object"""
    return {svc.get('id'): svc for svc in services if svc.get('id')}

def build_valueset_index(valuesets: List[Dict]) -> Dict[str, Dict]:
    """Build index of valueset_id -> valueset object"""
    return {vs.get('id'): vs for vs in valuesets if vs.get('id')}

class ScopeResolver:
    """Resolves rule scope matching and service code resolution"""
    
    def __init__(self, services: List[Dict]):
        self.service_index = build_service_index(services)
    
    def matches_scope(self, rule: Dict, carrier_id: str, lob: str, state: str, 
                     plan_type: str, market: Optional[str] = None, 
                     dos: Optional[str] = None) -> bool:
        """Check if rule scope matches the given parameters"""
        scope = rule.get('scope', {})
        
        # Check carrier_id
        rule_carrier = scope.get('carrier_id')
        if rule_carrier and rule_carrier != carrier_id:
            return False
        
        # Check lob
        rule_lob = scope.get('lob')
        if rule_lob and rule_lob != lob:
            return False
        
        # Check state
        rule_state = scope.get('state')
        if rule_state and rule_state != state:
            return False
        
        # Check plan_type
        rule_plan_type = scope.get('plan_type')
        if rule_plan_type and rule_plan_type != plan_type:
            return False
        
        # Check market (optional)
        rule_market = scope.get('market')
        if rule_market and market and rule_market != market:
            return False
        
        # Check effective dates
        if dos:
            dos_date = datetime.fromisoformat(dos).date()
            
            effective_start = rule.get('effective_start')
            if effective_start:
                start_date = datetime.fromisoformat(effective_start).date()
                if dos_date < start_date:
                    return False
            
            effective_end = rule.get('effective_end')
            if effective_end:
                end_date = datetime.fromisoformat(effective_end).date()
                if dos_date > end_date:
                    return False
        
        return True
    
    def resolve_service_codes(self, rule: Dict) -> Set[str]:
        """Resolve service_ref to union of service_id codes + direct codes"""
        codes = set()
        service_ref = rule.get('service_ref', {})
        
        # Get codes from service_id
        service_id = service_ref.get('service_id')
        if service_id and service_id in self.service_index:
            service = self.service_index[service_id]
            service_codes = service.get('codes', {})
            for code_type in ['cpt', 'hcpcs', 'drg', 'rev']:
                if code_type in service_codes:
                    codes.update(service_codes[code_type])
        
        # Add direct codes from rule
        for code_type in ['cpt', 'hcpcs', 'drg', 'rev']:
            direct_codes = service_ref.get(code_type, [])
            if direct_codes:
                codes.update(direct_codes)
        
        return codes
    
    def filter_rules(self, rules: List[Dict], carrier_id: str, lob: str, 
                    state: str, plan_type: str, market: Optional[str] = None,
                    dos: Optional[str] = None) -> List[Dict]:
        """Filter rules by scope and add resolved service codes"""
        matching_rules = []
        
        for rule in rules:
            if self.matches_scope(rule, carrier_id, lob, state, plan_type, market, dos):
                # Add resolved service codes to rule
                rule_copy = rule.copy()
                rule_copy['_resolved_codes'] = list(self.resolve_service_codes(rule))
                matching_rules.append(rule_copy)
        
        return matching_rules

def extract_rule_references(rule: Dict) -> tuple[Set[str], Set[str]]:
    """Extract service_ids and valueset_ids referenced by a rule"""
    service_ids = set()
    valueset_ids = set()
    
    # Service references
    service_ref = rule.get('service_ref', {})
    if service_ref.get('service_id'):
        service_ids.add(service_ref['service_id'])
    
    # Valueset references in conditions
    conditions = rule.get('conditions', {})
    for block_name in ['all_of', 'any_of', 'none_of']:
        block = conditions.get(block_name, [])
        for condition in block:
            if condition.get('dx_in_value_set'):
                valueset_ids.add(condition['dx_in_value_set'])
            if condition.get('dx_in_history_value_set'):
                valueset_ids.add(condition['dx_in_history_value_set'])
            if condition.get('excludes_value_set'):
                valueset_ids.add(condition['excludes_value_set'])
    
    return service_ids, valueset_ids

def rules_smoke_check(args):
    """Validate rules against services and valuesets"""
    rules = load_ndjson(Path(args.rules))
    services = load_ndjson(Path(args.services))
    valuesets = []
    
    # Load valuesets from multiple files if provided
    for vs_path in args.valuesets:
        valuesets.extend(load_ndjson(Path(vs_path)))
    
    service_index = build_service_index(services)
    valueset_index = build_valueset_index(valuesets)
    
    errors = []
    warnings = []
    
    for rule in rules:
        rule_id = rule.get('id', 'unknown')
        service_ids, valueset_ids = extract_rule_references(rule)
        
        # Check service references
        for service_id in service_ids:
            if service_id not in service_index:
                errors.append(f"Rule {rule_id}: Missing service '{service_id}'")
        
        # Check valueset references
        for valueset_id in valueset_ids:
            if valueset_id not in valueset_index:
                errors.append(f"Rule {rule_id}: Missing valueset '{valueset_id}'")
    
    # Report results
    print(f"Checked {len(rules)} rules against {len(services)} services and {len(valuesets)} valuesets")
    
    if warnings:
        print(f"\nWarnings ({len(warnings)}):")
        for warning in warnings:
            print(f"  ⚠️  {warning}")
    
    if errors:
        print(f"\nErrors ({len(errors)}):")
        for error in errors:
            print(f"  ❌ {error}")
        
        if args.fail_on_missing:
            sys.exit(1)
    else:
        print("✅ All references validated successfully")

class RuleEvaluator:
    """Enhanced rule evaluator with condition matching and precedence handling"""
    
    def __init__(self, services: List[Dict], valuesets: List[Dict]):
        self.service_index = build_service_index(services)
        self.valueset_index = build_valueset_index(valuesets)
        self.scope_resolver = ScopeResolver(services)
    
    def evaluate_condition(self, condition: Dict, patient: Dict, trace: List[str]) -> bool:
        """Evaluate a single condition against patient data"""
        
        # dx_in_value_set
        if 'dx_in_value_set' in condition:
            vs_id = condition['dx_in_value_set']
            if vs_id not in self.valueset_index:
                trace.append(f"Missing valueset: {vs_id}")
                return False
            
            valueset = self.valueset_index[vs_id]
            vs_codes = set(valueset.get('codes', []))
            patient_dx = set(patient.get('diagnoses', []) or patient.get('diagnosis_codes', []))
            
            has_match = bool(vs_codes & patient_dx)
            trace.append(f"dx_in_value_set({vs_id}): {has_match} (patient dx: {list(patient_dx)[:3]}...)")
            return has_match
        
        # dx_in_history_value_set
        if 'dx_in_history_value_set' in condition:
            vs_id = condition['dx_in_history_value_set']
            if vs_id not in self.valueset_index:
                trace.append(f"Missing valueset: {vs_id}")
                return False
            
            valueset = self.valueset_index[vs_id]
            vs_codes = set(valueset.get('codes', []))
            patient_history = set(patient.get('history_diagnosis_codes', []))
            
            has_match = bool(vs_codes & patient_history)
            trace.append(f"dx_in_history_value_set({vs_id}): {has_match}")
            return has_match
        
        # Age checks
        if 'min_age' in condition:
            patient_age = patient.get('age', 0)
            min_age = condition['min_age']
            meets_min = patient_age >= min_age
            trace.append(f"min_age({min_age}): {meets_min} (patient age: {patient_age})")
            if not meets_min:
                return False
        
        if 'max_age' in condition:
            patient_age = patient.get('age', 0)
            max_age = condition['max_age']
            meets_max = patient_age <= max_age
            trace.append(f"max_age({max_age}): {meets_max} (patient age: {patient_age})")
            if not meets_max:
                return False
        
        # Sex check
        if 'sex' in condition:
            required_sex = condition['sex']
            patient_sex = patient.get('sex', '')
            matches_sex = patient_sex == required_sex
            trace.append(f"sex({required_sex}): {matches_sex} (patient: {patient_sex})")
            if not matches_sex:
                return False
        
        # Place of service
        if 'pos_in' in condition:
            required_pos = set(condition['pos_in'])
            patient_pos = patient.get('place_of_service', '')
            matches_pos = patient_pos in required_pos
            trace.append(f"pos_in({list(required_pos)}): {matches_pos} (patient: {patient_pos})")
            if not matches_pos:
                return False
        
        return True
    
    def evaluate_conditions_block(self, block: List[Dict], patient: Dict, trace: List[str]) -> bool:
        """Evaluate a conditions block (all_of, any_of, none_of)"""
        results = []
        for condition in block:
            result = self.evaluate_condition(condition, patient, trace)
            results.append(result)
        return results
    
    def evaluate_rule(self, rule: Dict, patient: Dict) -> Dict[str, Any]:
        """Evaluate a single rule against patient data"""
        trace = []
        rule_id = rule.get('id', 'unknown')
        
        # Check effective dates
        dos = patient.get('date_of_service')
        if dos:
            dos_date = datetime.fromisoformat(dos).date()
            
            effective_start = rule.get('effective_start')
            if effective_start:
                start_date = datetime.fromisoformat(effective_start).date()
                if dos_date < start_date:
                    trace.append(f"Rule not effective yet: DOS {dos} < start {effective_start}")
                    return {'matched': False, 'trace': trace}
            
            effective_end = rule.get('effective_end')
            if effective_end:
                end_date = datetime.fromisoformat(effective_end).date()
                if dos_date > end_date:
                    trace.append(f"Rule expired: DOS {dos} > end {effective_end}")
                    return {'matched': False, 'trace': trace}
        
        # Evaluate conditions
        conditions = rule.get('conditions', {})
        
        # all_of: all conditions must be true
        if 'all_of' in conditions:
            all_results = self.evaluate_conditions_block(conditions['all_of'], patient, trace)
            if not all(all_results):
                trace.append(f"all_of failed: {all_results}")
                return {'matched': False, 'trace': trace}
        
        # any_of: at least one condition must be true
        if 'any_of' in conditions:
            any_results = self.evaluate_conditions_block(conditions['any_of'], patient, trace)
            if not any(any_results):
                trace.append(f"any_of failed: {any_results}")
                return {'matched': False, 'trace': trace}
        
        # none_of: no conditions can be true
        if 'none_of' in conditions:
            none_results = self.evaluate_conditions_block(conditions['none_of'], patient, trace)
            if any(none_results):
                trace.append(f"none_of failed: {none_results}")
                return {'matched': False, 'trace': trace}
        
        # Rule matched
        logic = rule.get('logic', {})
        outcome = logic.get('outcome', 'UNKNOWN')
        notes = logic.get('notes', '')
        precedence = rule.get('precedence', 50)
        
        trace.append(f"Rule matched: {outcome}")
        
        return {
            'matched': True,
            'rule_id': rule_id,
            'rule_type': rule.get('type'),
            'outcome': outcome,
            'notes': notes,
            'precedence': precedence,
            'trace': trace
        }
    
    def evaluate_rules(self, rules: List[Dict], patient: Dict, strategy: str = 'highest_precedence') -> Dict[str, Any]:
        """Evaluate all rules and apply strategy"""
        matches = []
        all_traces = []
        
        for rule in rules:
            result = self.evaluate_rule(rule, patient)
            all_traces.extend(result.get('trace', []))
            
            if result.get('matched'):
                matches.append(result)
        
        if not matches:
            return {
                'outcome': None,
                'matched_rule_id': None,
                'notes': 'No rules matched',
                'trace': all_traces
            }
        
        # Apply strategy
        if strategy == 'highest_precedence':
            # Sort by precedence (higher wins), then by rule_id for deterministic tiebreaking
            matches.sort(key=lambda x: (-x['precedence'], x['rule_id']))
            winner = matches[0]
        elif strategy == 'first_hit':
            # First matching rule wins
            winner = matches[0]
        else:
            # Default to highest precedence
            matches.sort(key=lambda x: (-x['precedence'], x['rule_id']))
            winner = matches[0]
        
        return {
            'outcome': winner['outcome'],
            'matched_rule_id': winner['rule_id'],
            'notes': winner['notes'],
            'trace': all_traces,
            'all_matches': len(matches),
            'strategy': strategy
        }

def simulate(args):
    """Run rule evaluation against a patient scenario"""
    rules = load_ndjson(Path(args.rules))
    services = load_ndjson(Path(args.services))
    valuesets = []
    
    # Load valuesets from multiple files if provided
    for vs_path in args.valuesets:
        valuesets.extend(load_ndjson(Path(vs_path)))
    
    # Load patient scenario
    with open(args.patient, 'r') as f:
        patient = json.load(f)
    
    evaluator = RuleEvaluator(services, valuesets)
    
    print(f"Evaluating {len(rules)} rules for patient scenario: {args.patient}")
    
    # Use scope resolver if patient has scope info
    if all(k in patient for k in ['carrier_id', 'lob', 'state', 'plan_type']):
        resolver = ScopeResolver(services)
        applicable_rules = resolver.filter_rules(
            rules, patient['carrier_id'], patient['lob'], patient['state'], 
            patient['plan_type'], patient.get('market'), patient.get('dos')
        )
        
        # Filter by service_id if specified
        if 'service_id' in patient:
            service_filtered_rules = []
            for rule in applicable_rules:
                service_ref = rule.get('service_ref', {})
                if service_ref.get('service_id') == patient['service_id']:
                    service_filtered_rules.append(rule)
            applicable_rules = service_filtered_rules
    else:
        applicable_rules = rules
    
    print(f"Scope-filtered to {len(applicable_rules)} applicable rules")
    
    # Evaluate rules
    result = evaluator.evaluate_rules(applicable_rules, patient)
    
    # Output structured result
    print(f"\n📋 Evaluation Result:")
    print(f"   Outcome: {result['outcome'] or 'PROCEED'}")
    print(f"   Matched Rule: {result['matched_rule_id'] or 'None'}")
    print(f"   Notes: {result['notes']}")
    print(f"   Total Matches: {result.get('all_matches', 0)}")
    print(f"   Strategy: {result.get('strategy', 'highest_precedence')}")
    
    if args.verbose:
        print(f"\n🔍 Trace:")
        for trace_line in result['trace']:
            print(f"   {trace_line}")
    
    # Return structured JSON for programmatic use
    return result

def scope_resolve(args):
    """Filter rules by scope parameters and show resolved service codes"""
    rules = load_ndjson(Path(args.rules))
    services = load_ndjson(Path(args.services))
    
    resolver = ScopeResolver(services)
    
    # Convert hyphenated args to underscored
    carrier_id = args.carrier_id
    lob = args.lob
    state = args.state
    plan_type = getattr(args, 'plan_type')
    market = args.market
    dos = args.dos
    
    matching_rules = resolver.filter_rules(
        rules, carrier_id, lob, state, plan_type, market, dos
    )
    
    print(f"Scope filter: carrier_id={carrier_id}, lob={lob}, state={state}, plan_type={plan_type}")
    if market:
        print(f"             market={market}")
    if dos:
        print(f"             dos={dos}")
    
    print(f"\nFiltered {len(rules)} rules → {len(matching_rules)} matching rules:")
    
    for rule in matching_rules:
        rule_id = rule.get('id', 'unknown')
        rule_type = rule.get('type')
        resolved_codes = rule.get('_resolved_codes', [])
        
        print(f"  🎯 {rule_id} ({rule_type})")
        if resolved_codes:
            print(f"     Codes: {', '.join(resolved_codes)}")
        
        # Show scope details
        scope = rule.get('scope', {})
        scope_details = []
        for key in ['carrier_id', 'lob', 'state', 'plan_type', 'market']:
            if scope.get(key):
                scope_details.append(f"{key}={scope[key]}")
        if scope_details:
            print(f"     Scope: {', '.join(scope_details)}")
        
        # Show effective dates
        start = rule.get('effective_start')
        end = rule.get('effective_end')
        if start or end:
            print(f"     Effective: {start or 'open'} to {end or 'open'}")
        
        print()

def main():
    parser = argparse.ArgumentParser(description='Claimr CLI - Rules validation and simulation')
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # rules-smoke-check command
    smoke_parser = subparsers.add_parser('rules-smoke-check', help='Validate rules against services and valuesets')
    smoke_parser.add_argument('--rules', required=True, help='Path to rules NDJSON file')
    smoke_parser.add_argument('--services', required=True, help='Path to services NDJSON file')
    smoke_parser.add_argument('--valuesets', required=True, nargs='+', help='Path(s) to valueset NDJSON files')
    smoke_parser.add_argument('--fail-on-missing', action='store_true', help='Exit with error if references are missing')
    
    # simulate command
    sim_parser = subparsers.add_parser('simulate', help='Run rule evaluation against a patient scenario')
    sim_parser.add_argument('--rules', required=True, help='Path to rules NDJSON file')
    sim_parser.add_argument('--services', required=True, help='Path to services NDJSON file')
    sim_parser.add_argument('--valuesets', required=True, nargs='+', help='Path(s) to valueset NDJSON files')
    sim_parser.add_argument('--patient', required=True, help='Path to patient scenario JSON file')
    sim_parser.add_argument('--verbose', action='store_true', help='Show detailed trace output')
    
    # scope-resolve command
    scope_parser = subparsers.add_parser('scope-resolve', help='Filter rules by scope parameters')
    scope_parser.add_argument('--rules', required=True, help='Path to rules NDJSON file')
    scope_parser.add_argument('--services', required=True, help='Path to services NDJSON file')
    scope_parser.add_argument('--carrier-id', required=True, help='Carrier ID')
    scope_parser.add_argument('--lob', required=True, help='Line of business')
    scope_parser.add_argument('--state', required=True, help='State code')
    scope_parser.add_argument('--plan-type', required=True, help='Plan type')
    scope_parser.add_argument('--market', help='Market segment')
    scope_parser.add_argument('--dos', help='Date of service (YYYY-MM-DD)')
    
    args = parser.parse_args()
    
    if args.command == 'rules-smoke-check':
        rules_smoke_check(args)
    elif args.command == 'simulate':
        simulate(args)
    elif args.command == 'scope-resolve':
        scope_resolve(args)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == '__main__':
    main()
