"""
SENTINEL-X Linux Responder — Linux-specific mitigation actions.
Uses iptables, kill, chmod, usermod.
"""
import logging

logger = logging.getLogger("sentinel.response.linux")


class LinuxResponder:
    """Generate Linux-specific response commands."""

    def build_actions(self, alert) -> list[dict]:
        """Build response actions based on the alert's rule response_actions."""
        actions = []

        for rule_action in alert.get('response_actions', []):
            action_type = rule_action.get('type', '')
            target_value = self._resolve_target(alert, rule_action.get('target_field'))

            if action_type == 'block_ip' and target_value:
                actions.append({
                    'action_type': 'block_ip',
                    'command': f'iptables -I INPUT -s {target_value} -j DROP',
                    'command_parts': ['iptables', '-I', 'INPUT', '-s', target_value, '-j', 'DROP'],
                    'justification': f'Block all incoming traffic from attacking IP {target_value}. '
                                   f'This immediately stops the active attack.',
                    'target': target_value,
                    'reversible': True,
                    'undo_command': f'iptables -D INPUT -s {target_value} -j DROP',
                })

            elif action_type == 'kill_process' and target_value:
                actions.append({
                    'action_type': 'kill_process',
                    'command': f'kill -9 {target_value}',
                    'command_parts': ['kill', '-9', str(target_value)],
                    'justification': f'Forcefully terminate suspicious process (PID: {target_value}). '
                                   f'Stops active malicious activity.',
                    'target': target_value,
                    'reversible': False,
                })

            elif action_type == 'restrict_user' and target_value:
                actions.append({
                    'action_type': 'restrict_user',
                    'command': f'usermod -L {target_value}',
                    'command_parts': ['usermod', '-L', target_value],
                    'justification': f'Lock user account "{target_value}" to prevent further unauthorized access.',
                    'target': target_value,
                    'reversible': True,
                    'undo_command': f'usermod -U {target_value}',
                })

            elif action_type == 'isolate_network':
                actions.append({
                    'action_type': 'isolate_network',
                    'command': 'iptables -I INPUT -j DROP && iptables -I OUTPUT -j DROP',
                    'command_parts': ['bash', '-c', 'iptables -I INPUT -j DROP && iptables -I OUTPUT -j DROP'],
                    'justification': 'EMERGENCY: Isolate this host from the network entirely. '
                                   'Use only in critical situations (ransomware, active breach).',
                    'target': 'network',
                    'reversible': True,
                    'undo_command': 'iptables -D INPUT -j DROP && iptables -D OUTPUT -j DROP',
                })

            elif action_type == 'dump_process' and target_value:
                actions.append({
                    'action_type': 'dump_process',
                    'command': f'gcore {target_value} && strings core.{target_value} > /tmp/sentinel_dump_{target_value}.txt',
                    'command_parts': ['bash', '-c',
                                     f'gcore {target_value} && strings core.{target_value} > /tmp/sentinel_dump_{target_value}.txt'],
                    'justification': f'Capture process memory dump (PID: {target_value}) for forensic analysis.',
                    'target': target_value,
                    'reversible': False,
                })

            elif action_type == 'revoke_port' and target_value:
                actions.append({
                    'action_type': 'revoke_port',
                    'command': f'iptables -A INPUT -p tcp --dport {target_value} -j DROP',
                    'command_parts': ['iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', str(target_value), '-j', 'DROP'],
                    'justification': f'Block incoming connections on port {target_value}.',
                    'target': target_value,
                    'reversible': True,
                    'undo_command': f'iptables -D INPUT -p tcp --dport {target_value} -j DROP',
                })

            elif action_type == 'notify':
                actions.append({
                    'action_type': 'notify',
                    'command': 'echo "[ALERT] ' + rule_action.get('message', 'Security alert') + '"',
                    'command_parts': ['echo', f'[ALERT] {rule_action.get("message", "Security alert")}'],
                    'justification': 'Log notification for audit trail.',
                    'target': 'notification',
                    'reversible': False,
                })

        return actions

    def _resolve_target(self, alert: dict, target_field: str) -> str:
        """Resolve a target field value from the alert data."""
        if not target_field:
            return ''
        return str(alert.get(target_field, ''))
