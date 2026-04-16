"""
SENTINEL-X Base Agent — abstract base class for all OS monitoring agents.
Each agent must implement collect_logins(), collect_processes(), and collect_network().
"""
import asyncio
import platform
import logging
from abc import ABC, abstractmethod
from typing import AsyncGenerator

from normalizer.schema import RawEvent

logger = logging.getLogger("sentinel.agent")


class BaseAgent(ABC):
    """
    Abstract base class for OS monitoring agents.

    Each platform agent (Linux, Windows, macOS) inherits from this class
    and implements the three async generator methods to collect events.
    The run() loop handles scheduling, rate-limiting, and queue publishing.
    """

    def __init__(self, queue: asyncio.Queue, interval: float = 1.0):
        self.queue = queue
        self.interval = interval
        self.platform = platform.system().lower()
        self._running = False
        self._event_count = 0
        logger.info(f"Agent initialized for platform: {self.platform}, interval: {interval}s")

    @abstractmethod
    async def collect_logins(self) -> AsyncGenerator[RawEvent, None]:
        """Collect login/authentication events from the OS."""
        ...

    @abstractmethod
    async def collect_processes(self) -> AsyncGenerator[RawEvent, None]:
        """Collect process-related events (spawns, suspicious processes)."""
        ...

    @abstractmethod
    async def collect_network(self) -> AsyncGenerator[RawEvent, None]:
        """Collect network connection events."""
        ...

    async def run(self):
        """
        Main agent loop. Collects events from all three sources
        and publishes them to the normalization queue.
        """
        self._running = True
        logger.info(f"Agent started on {self.platform}")

        while self._running:
            try:
                # Collect from all three sources
                async for event in self.collect_logins():
                    await self.queue.put(event)
                    self._event_count += 1

                async for event in self.collect_processes():
                    await self.queue.put(event)
                    self._event_count += 1

                async for event in self.collect_network():
                    await self.queue.put(event)
                    self._event_count += 1

            except Exception as e:
                logger.error(f"Agent collection error: {e}", exc_info=True)

            await asyncio.sleep(self.interval)

    async def stop(self):
        """Stop the agent loop."""
        self._running = False
        logger.info(f"Agent stopped. Total events collected: {self._event_count}")

    @property
    def event_count(self) -> int:
        return self._event_count

    @property
    def is_running(self) -> bool:
        return self._running
