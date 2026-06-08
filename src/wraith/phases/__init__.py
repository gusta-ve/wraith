"""Importing this package registers all built-in phases."""

from . import (  # noqa: F401
    resolve,
    tcp_scan,
    http_probe,
    content_discovery,
    tech_detect,
    access_control,
)
