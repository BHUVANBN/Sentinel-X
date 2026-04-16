"""
SENTINEL-X Response Engine
Generates OS-aware mitigation commands and handles execution after user approval.
NEVER executes automatically — all actions require explicit user approval.
"""
import logging
import platform
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from response.linux_responder import LinuxResponder
from response.windows_responder import WindowsResponder
from response.macos_responder import MacOSResponder

logger = logging.getLogger("sentinel.response")


@dataclass
class ResponseAction:
    """A proposed response action awaiting user approval."""
    action_id: str
    alert_id: str
    action_type: str
    command: str
    command_parts: list[str]
    justification: str
    target: str
    reversible: bool = False
    undo_command: Optional[str] = None
    status: str = 'pending'  # pending | approved | skipped | executed | failed


@dataclass
class ExecutionResult:
    """Result of executing an approved response action."""
    success: bool
    output: str = ''
    error: str = ''
    executed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ResponseEngine:
    """
    Response engine that generates OS-specific mitigation actions.

    Key design principle: NEVER auto-execute.
    All actions are proposed to the user and require explicit approval.
    """

    def __init__(self):
        self._platform = platform.system().lower()
        self._responder = self._get_responder()
        self._history: list[ResponseAction] = []
        logger.info(f"Response engine initialized for platform: {self._platform}")

    def _get_responder(self):
        """Get the platform-specific responder."""
        responders = {
            'linux': LinuxResponder,
            'windows': WindowsResponder,
            'darwin': MacOSResponder,
        }
        responder_class = responders.get(self._platform, LinuxResponder)
        return responder_class()

    def suggest(self, alert_data: dict) -> list[ResponseAction]:
        """
        Generate suggested response actions for an alert.

        Args:
            alert_data: Dictionary with alert details and response_actions from the rule.

        Returns:
            List of ResponseAction objects with platform-specific commands.
        """
        raw_actions = self._responder.build_actions(alert_data)
        actions = []

        for raw in raw_actions:
            action = ResponseAction(
                action_id=str(uuid.uuid4()),
                alert_id=alert_data.get('alert_id', ''),
                action_type=raw['action_type'],
                command=raw['command'],
                command_parts=raw.get('command_parts', []),
                justification=raw.get('justification', ''),
                target=raw.get('target', ''),
                reversible=raw.get('reversible', False),
                undo_command=raw.get('undo_command'),
            )
            actions.append(action)
            self._history.append(action)

        return actions

    def execute(self, action: ResponseAction) -> ExecutionResult:
        """
        Execute an approved response action.
        ONLY called after explicit user approval.
        """
        if action.status != 'approved':
            return ExecutionResult(
                success=False,
                error=f'Action must be approved before execution. Current status: {action.status}'
            )

        logger.info(f"Executing response action: {action.action_type} — {action.command}")

        try:
            result = subprocess.run(
                action.command_parts,
                capture_output=True,
                text=True,
                timeout=30,
            )

            exec_result = ExecutionResult(
                success=result.returncode == 0,
                output=result.stdout.strip(),
                error=result.stderr.strip() if result.returncode != 0 else '',
            )

            action.status = 'executed' if exec_result.success else 'failed'

            if exec_result.success:
                logger.info(f"Action executed successfully: {action.action_type}")
            else:
                logger.error(f"Action failed: {action.action_type} — {exec_result.error}")

            return exec_result

        except subprocess.TimeoutExpired:
            action.status = 'failed'
            return ExecutionResult(success=False, error='Command timed out after 30 seconds')

        except Exception as e:
            action.status = 'failed'
            return ExecutionResult(success=False, error=str(e))

    def undo(self, action: ResponseAction) -> ExecutionResult:
        """Undo a previously executed reversible action."""
        if not action.reversible or not action.undo_command:
            return ExecutionResult(success=False, error='Action is not reversible')

        logger.info(f"Undoing action: {action.action_type} — {action.undo_command}")

        try:
            result = subprocess.run(
                action.undo_command.split(),
                capture_output=True,
                text=True,
                timeout=30,
            )
            return ExecutionResult(
                success=result.returncode == 0,
                output=result.stdout.strip(),
                error=result.stderr.strip() if result.returncode != 0 else '',
            )
        except Exception as e:
            return ExecutionResult(success=False, error=str(e))

    @property
    def platform_name(self) -> str:
        return self._platform

    def get_history(self) -> list[dict]:
        """Get response action history."""
        return [
            {
                'action_id': a.action_id,
                'alert_id': a.alert_id,
                'action_type': a.action_type,
                'command': a.command,
                'justification': a.justification,
                'status': a.status,
                'reversible': a.reversible,
            }
            for a in self._history
        ]
