"""
SENTINEL-X Windows Responder — Windows-specific mitigation actions.
Uses netsh, taskkill, icacls, net user.
"""
import logging

logger = logging.getLogger("sentinel.response.windows")


class WindowsResponder:
    """Generate Windows-specific response commands."""

    def build_actions(self, alert) -> list[dict]:
        actions = []

        for rule_action in alert.get('response_actions', []):
            action_type = rule_action.get('type', '')
            target_value = self._resolve_target(alert, rule_action.get('target_field'))

            if action_type == 'block_ip' and target_value:
                actions.append({
                    'action_type': 'block_ip',
                    'command': f"netsh advfirewall firewall add rule name='SENTINEL_BLOCK_{target_value}' "
                              f"dir=in action=block remoteip={target_value}",
                    'command_parts': ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                                     f'name=SENTINEL_BLOCK_{target_value}',
                                     'dir=in', 'action=block', f'remoteip={target_value}'],
                    'justification': f'Block all incoming traffic from {target_value} via Windows Firewall.',
                    'target': target_value,
                    'reversible': True,
                    'undo_command': f"netsh advfirewall firewall delete rule name='SENTINEL_BLOCK_{target_value}'",
                })

            elif action_type == 'kill_process' and target_value:
                actions.append({
                    'action_type': 'kill_process',
                    'command': f'taskkill /F /PID {target_value}',
                    'command_parts': ['taskkill', '/F', '/PID', str(target_value)],
                    'justification': f'Forcefully terminate process PID {target_value}.',
                    'target': target_value,
                    'reversible': False,
                })

            elif action_type == 'restrict_user' and target_value:
                actions.append({
                    'action_type': 'restrict_user',
                    'command': f'net user {target_value} /active:no',
                    'command_parts': ['net', 'user', target_value, '/active:no'],
                    'justification': f'Disable user account "{target_value}".',
                    'target': target_value,
                    'reversible': True,
                    'undo_command': f'net user {target_value} /active:yes',
                })

            elif action_type == 'isolate_network':
                actions.append({
                    'action_type': 'isolate_network',
                    'command': "netsh interface set interface 'Ethernet' disable",
                    'command_parts': ['netsh', 'interface', 'set', 'interface', 'Ethernet', 'disable'],
                    'justification': 'EMERGENCY: Disable network interface to isolate host.',
                    'target': 'network',
                    'reversible': True,
                    'undo_command': "netsh interface set interface 'Ethernet' enable",
                })

            elif action_type == 'dump_process' and target_value:
                actions.append({
                    'action_type': 'dump_process',
                    'command': f'procdump.exe -ma {target_value} C:\\sentinel_dumps\\',
                    'command_parts': ['procdump.exe', '-ma', str(target_value), 'C:\\sentinel_dumps\\'],
                    'justification': f'Capture full memory dump of process PID {target_value}.',
                    'target': target_value,
                    'reversible': False,
                })

            elif action_type == 'notify':
                actions.append({
                    'action_type': 'notify',
                    'command': 'echo ' + rule_action.get('message', 'Alert'),
                    'command_parts': ['echo', rule_action.get('message', 'Alert')],
                    'justification': 'Log notification.',
                    'target': 'notification',
                    'reversible': False,
                })

        return actions

    def _resolve_target(self, alert: dict, target_field: str) -> str:
        if not target_field:
            return ''
        return str(alert.get(target_field, ''))
