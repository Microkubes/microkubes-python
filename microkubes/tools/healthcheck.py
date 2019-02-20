"""Healthcheck
"""

from healthcheck import HealthCheck


def add_healthcheck(app):
    health = HealthCheck(app, "/healthcheck")
    health.add_check(_microservice_available)


def _microservice_available():
    return True, "OK"
