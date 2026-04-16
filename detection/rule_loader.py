"""
SENTINEL-X Rule Loader
Loads YAML detection rule files and parses them into DetectionRule dataclasses.
"""
import os
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger("sentinel.detection.loader")


@dataclass
class RuleMatch:
    """Match criteria for a detection rule."""
    event_type: str
    category: str
    outcome: Optional[str] = None


@dataclass
class RuleCondition:
    """Additional condition for a detection rule."""
    field: str
    operator: str     # eq, neq, in, gte, lte, is_internal, is_external, regex
    value: object = None
    values: list = field(default_factory=list)


@dataclass
class RuleAggregate:
    """Aggregation settings for a detection rule."""
    group_by: list[str] = field(default_factory=list)
    count_threshold: int = 1
    time_window_seconds: int = 60
    unique_field: Optional[str] = None
    unique_threshold: Optional[int] = None
    sum_field: Optional[str] = None
    sum_threshold: Optional[int] = None
    periodicity_check: bool = False
    interval_variance_percent: int = 10


@dataclass
class RuleResponseAction:
    """Response action template for a detection rule."""
    type: str               # block_ip, kill_process, restrict_user, etc.
    target_field: Optional[str] = None
    message: Optional[str] = None


@dataclass
class DetectionRule:
    """Complete detection rule definition."""
    id: str
    name: str
    description: str
    mitre_technique: str
    mitre_tactic: str
    severity: str               # low | medium | high | critical
    confidence_base: float      # 0-100

    match: RuleMatch
    aggregate: RuleAggregate
    conditions: list[RuleCondition] = field(default_factory=list)
    response_actions: list[RuleResponseAction] = field(default_factory=list)

    enabled: bool = True


def load_rule(rule_path: str) -> DetectionRule:
    """Load a single YAML rule file into a DetectionRule object."""
    with open(rule_path) as f:
        raw = yaml.safe_load(f)

    # Parse match criteria
    match_data = raw.get('match', {})
    match = RuleMatch(
        event_type=match_data.get('event_type', ''),
        category=match_data.get('category', ''),
        outcome=match_data.get('outcome'),
    )

    # Parse conditions
    conditions = []
    for cond_data in raw.get('conditions', []):
        conditions.append(RuleCondition(
            field=cond_data.get('field', ''),
            operator=cond_data.get('operator', 'eq'),
            value=cond_data.get('value'),
            values=cond_data.get('values', []),
        ))

    # Parse aggregate
    agg_data = raw.get('aggregate', {})
    aggregate = RuleAggregate(
        group_by=agg_data.get('group_by', []),
        count_threshold=agg_data.get('count_threshold', 1),
        time_window_seconds=agg_data.get('time_window_seconds', 60),
        unique_field=agg_data.get('unique_field'),
        unique_threshold=agg_data.get('unique_threshold'),
        sum_field=agg_data.get('sum_field'),
        sum_threshold=agg_data.get('sum_threshold'),
        periodicity_check=agg_data.get('periodicity_check', False),
        interval_variance_percent=agg_data.get('interval_variance_percent', 10),
    )

    # Parse response actions
    response_actions = []
    for action_data in raw.get('response_actions', []):
        response_actions.append(RuleResponseAction(
            type=action_data.get('type', ''),
            target_field=action_data.get('target_field'),
            message=action_data.get('message'),
        ))

    return DetectionRule(
        id=raw['id'],
        name=raw['name'],
        description=raw.get('description', ''),
        mitre_technique=raw.get('mitre_technique', ''),
        mitre_tactic=raw.get('mitre_tactic', ''),
        severity=raw.get('severity', 'medium'),
        confidence_base=raw.get('confidence_base', 50),
        match=match,
        aggregate=aggregate,
        conditions=conditions,
        response_actions=response_actions,
    )


def load_all_rules(rules_dir: str = 'detection/rules', enabled_rules: str = 'all') -> list[DetectionRule]:
    """
    Load all YAML rule files from the rules directory.

    Args:
        rules_dir: Path to the directory containing YAML rule files
        enabled_rules: 'all' or list of specific rule IDs to enable

    Returns:
        List of DetectionRule objects
    """
    rules = []
    rules_path = Path(rules_dir)

    if not rules_path.exists():
        logger.warning(f"Rules directory not found: {rules_dir}")
        return rules

    for yaml_file in sorted(rules_path.glob('*.yaml')):
        try:
            rule = load_rule(str(yaml_file))

            # Apply enabled filter
            if enabled_rules != 'all':
                if isinstance(enabled_rules, list) and rule.id not in enabled_rules:
                    rule.enabled = False

            rules.append(rule)
            logger.info(f"Loaded rule: {rule.id} — {rule.name} "
                       f"[{rule.severity}] (enabled={rule.enabled})")
        except Exception as e:
            logger.error(f"Failed to load rule {yaml_file}: {e}")

    logger.info(f"Loaded {len(rules)} detection rules from {rules_dir}")
    return rules
