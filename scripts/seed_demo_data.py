#!/usr/bin/env python3
"""
Seed script to populate sample Security Events, Threat Alerts, and Incidents into the database.
"""
import sys
import os

# Add backend directory to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../backend')))

from app.database.connection import SessionLocal
from app.database.init_db import init_db
from app.schemas.security_event import SecurityEventCreate
from app.schemas.enums import EventType
from app.services.event_service import EventService
from app.core.logging import logger

def main():
    logger.info("Initializing database schema...")
    init_db()
    db = SessionLocal()

    demo_events = [
        SecurityEventCreate(
            source_ip="192.168.1.105",
            destination_ip="10.0.0.1",
            source_port=54321,
            destination_port=22,
            protocol="TCP",
            packet_count=120,
            event_type=EventType.NETWORK,
            raw_data="SSH brute force attempt log pattern"
        ),
        SecurityEventCreate(
            source_ip="45.33.32.156",
            destination_ip="10.0.0.5",
            source_port=44321,
            destination_port=80,
            protocol="TCP",
            packet_count=5000,
            event_type=EventType.NETWORK,
            raw_data="High rate HTTP GET flood stream"
        ),
        SecurityEventCreate(
            source_ip="10.0.0.22",
            destination_ip="10.0.0.1",
            source_port=59000,
            destination_port=443,
            protocol="TCP",
            packet_count=12,
            event_type=EventType.NETWORK,
            raw_data="Normal HTTPS user browsing session"
        )
    ]

    logger.info(f"Seeding {len(demo_events)} sample security events...")
    for ev_in in demo_events:
        EventService.create_event(db, ev_in)

    logger.info("Demo data seeding completed successfully!")

if __name__ == "__main__":
    main()
