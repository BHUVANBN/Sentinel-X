"""
SENTINEL-X Entry Point
Starts the full system: OS agent + event pipeline + FastAPI server.
"""
import argparse
import asyncio
import logging
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def setup_logging(level: str = "INFO"):
    """Configure structured logging."""
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format='%(asctime)s │ %(name)-28s │ %(levelname)-8s │ %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
    )
    # Suppress noisy loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("watchdog").setLevel(logging.WARNING)


def main():
    parser = argparse.ArgumentParser(
        description='SENTINEL-X — AI-Driven Threat Detection & Response System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m sentinel                    # Start normally
  python -m sentinel --test-mode        # Start with test/simulation endpoints enabled
  python -m sentinel --port 9000        # Run on custom port
  python -m sentinel --log-level DEBUG  # Verbose logging
        """
    )
    parser.add_argument('--host', default='0.0.0.0', help='API host (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8000, help='API port (default: 8000)')
    parser.add_argument('--log-level', default='INFO', help='Log level (default: INFO)')
    parser.add_argument('--test-mode', action='store_true', help='Enable test/simulation endpoints')
    parser.add_argument('--no-agent', action='store_true', help='Start without OS monitoring agent')
    parser.add_argument('--init-db', action='store_true', help='Initialize database only, then exit')

    args = parser.parse_args()
    setup_logging(args.log_level)
    logger = logging.getLogger("sentinel")

    # Banner
    logger.info("=" * 60)
    logger.info("  SENTINEL-X  —  AI-Driven Threat Detection & Response")
    logger.info("  Version 1.0.0")
    logger.info("=" * 60)

    # Config
    from config.loader import get_config
    config = get_config()

    # DB init only mode
    if args.init_db:
        from storage.db import Database
        db = Database(config.db_url)
        db.init_db()
        logger.info("Database initialized successfully")
        return

    # Override config with CLI args
    if args.test_mode:
        os.environ['SENTINEL_TEST_MODE'] = '1'
        logger.info("Test mode enabled — simulation endpoints active")

    # Start FastAPI via uvicorn
    import uvicorn
    logger.info(f"Starting API server on {args.host}:{args.port}")

    uvicorn.run(
        "api.main:app",
        host=args.host,
        port=args.port,
        log_level=args.log_level.lower(),
        reload=False,
    )


if __name__ == '__main__':
    main()
