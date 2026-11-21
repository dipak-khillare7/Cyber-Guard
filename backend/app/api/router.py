from fastapi import APIRouter
from app.api.routes import (
    health,
    events,
    alerts,
    incidents,
    statistics,
    detection,
    response_actions,
    auth,
    audit,
    website_assessments,
    access_requests,
)

api_router = APIRouter()

api_router.include_router(health.router)
api_router.include_router(events.router)
api_router.include_router(alerts.router)
api_router.include_router(incidents.router)
api_router.include_router(statistics.router)
api_router.include_router(detection.router)
api_router.include_router(response_actions.router)
api_router.include_router(auth.router)
api_router.include_router(audit.router)
api_router.include_router(website_assessments.router)
api_router.include_router(website_assessments.analysis_router)
api_router.include_router(access_requests.router)
