"""
SENTINEL-X macOS Responder — macOS-specific mitigation actions.
Uses pfctl, kill, chmod, dscl, networksetup.
"""
import logging

logger = logging.getLogger("sentinel.response.macos")


class MacOSResponder:
    """Generate macOS-specific response commands."""

    def build_actions(self, alert) -> list[dict]:
        actions = []

        for rule_action in alert.get('response_actions', []):
            action_type = rule_action.get('type', '')
            target_value = self._resolve_target(alert, rule_action.get('target_field'))

            if action_type == 'block_ip' and target_value:
                actions.append({
                    'action_type': 'block_ip',
                    'command': f'pfctl -t blocklist -T add {target_value}',
                    'command_parts': ['pfctl', '-t', 'blocklist', '-T', 'add', target_value],
                    'justification': f'Block IP {target_value} via PF firewall blocklist table.',
                    'target': target_value,
                    'reversible': True,
                    'undo_command': f'pfctl -t blocklist -T delete {target_value}',
                })

            elif action_type == 'kill_process' and target_value:
                actions.append({
                    'action_type': 'kill_process',
                    'command': f'kill -9 {target_value}',
                    'command_parts': ['kill', '-9', str(target_value)],
                    'justification': f'Forcefully terminate process PID {target_value}.',
                    'target': target_value,
                    'reversible': False,
                })

            elif action_type == 'restrict_user' and target_value:
                actions.append({
                    'action_type': 'restrict_user',
                    'command': f"dscl . -passwd /Users/{target_value} ''",
                    'command_parts': ['dscl', '.', '-passwd', f'/Users/{target_value}', ''],
                    'justification': f'Reset password for user "{target_value}" to prevent access.',
                    'target': target_value,
                    'reversible': False,
                })

            elif action_type == 'isolate_network':
                actions.append({
                    'action_type': 'isolate_network',
                    'command': "networksetup -setnetworkserviceenabled 'Wi-Fi' off && "
                              "networksetup -setnetworkserviceenabled 'Ethernet' off",
                    'command_parts': ['bash', '-c',
                                     "networksetup -setnetworkserviceenabled 'Wi-Fi' off && "
                                     "networksetup -setnetworkserviceenabled 'Ethernet' off"],
                    'justification': 'EMERGENCY: Disable all network interfaces to isolate host.',
                    'target': 'network',
                    'reversible': True,
                    'undo_command': "networksetup -setnetworkserviceenabled 'Wi-Fi' on && "
                                  "networksetup -setnetworkserviceenabled 'Ethernet' on",
                })

            elif action_type == 'dump_process' and target_value:
                actions.append({
                    'action_type': 'dump_process',
                    'command': f'sample {target_value} 5 -file /tmp/sentinel_sample_{target_value}.txt',
                    'command_parts': ['sample', str(target_value), '5', '-file',
                                     f'/tmp/sentinel_sample_{target_value}.txt'],
                    'justification': f'Sample process PID {target_value} for 5 seconds for analysis.',
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
