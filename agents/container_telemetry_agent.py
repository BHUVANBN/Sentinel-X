import asyncio
import logging
import docker
import json
from datetime import datetime, timezone
from normalizer.schema import RawEvent

logger = logging.getLogger("sentinel.agent.docker")

class ContainerTelemetryAgent:
    """
    V3.0: Streams Docker container logs and events via the Docker socket.
    Provides secondary telemetry independent of host log files.
    """

    def __init__(self, queue: asyncio.Queue, target_name: str = "sentinelx_target"):
        self.queue = queue
        self.target_name = target_name
        self._running = True
        try:
            self.client = docker.from_env()
            logger.info(f"Docker telemetry initialized for target: {self.target_name}")
        except Exception as e:
            logger.error(f"Failed to connect to Docker socket: {e}")
            self.client = None

    async def run(self):
        """Main loop: monitors container stdout/stderr and lifecycle events."""
        if not self.client:
            return

        # Start two concurrent listeners
        await asyncio.gather(
            self._stream_container_logs(),
            self._stream_lifecycle_events()
        )

    async def _stream_container_logs(self):
        """Stream stdout/stderr from the target container."""
        try:
            container = self.client.containers.get(self.target_name)
            logger.info(f"Starting log stream for {self.target_name}")
            
            # Using loop.run_in_executor because docker-py's logs() is blocking
            loop = asyncio.get_event_loop()
            
            def get_logs():
                return container.logs(stream=True, follow=True, tail=0)

            log_stream = await loop.run_in_executor(None, get_logs)
            
            for line in log_stream:
                if not self._running:
                    break
                decoded_line = line.decode().strip()
                if not decoded_line:
                    continue
                    
                await self.queue.put(RawEvent(
                    source='docker_logs',
                    event_type='container_output',
                    raw={'container_name': self.target_name, 'log': decoded_line, 'platform': 'linux'},
                    timestamp=datetime.now(timezone.utc).isoformat()
                ))
        except Exception as e:
            logger.error(f"Error streaming container logs: {e}")

    async def _stream_lifecycle_events(self):
        """Monitor container lifecycle events (start, stop, pause, unpause)."""
        try:
            filters = {'container': self.target_name, 'event': ['start', 'stop', 'pause', 'unpause', 'die']}
            logger.info(f"Monitoring Docker lifecycle events for {self.target_name}")
            
            loop = asyncio.get_event_loop()
            event_stream = await loop.run_in_executor(None, lambda: self.client.events(decode=True, filters=filters))
            
            for event in event_stream:
                if not self._running:
                    break
                    
                action = event.get('Action')
                await self.queue.put(RawEvent(
                    source='docker_events',
                    event_type=f'container_{action}',
                    raw=event,
                    timestamp=datetime.now(timezone.utc).isoformat()
                ))
        except Exception as e:
            logger.error(f"Error streaming Docker events: {e}")

    def stop(self):
        self._running = False
