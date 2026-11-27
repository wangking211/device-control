"""IoT platform adapter SPI.

This package defines the product-owned boundary between Device Control and an
external IoT platform. Platform SDKs, MQTT clients and Home Assistant APIs live
only inside adapters; the core imports nothing from them.

The SPI is deliberately small and JSON-shaped so an adapter can run in-process,
in a worker, or at the edge without changing the domain.
"""

from __future__ import annotations

from .lifecycle import AdapterLifecycleManager, AdapterState, LifecycleError
from .manifest import AdapterManifest, load_manifest, verify_manifest
from .spi import (
    AdapterError,
    AdapterHealth,
    AdapterPlugin,
    CapabilityMapping,
    DiscoveredDevice,
    DiscoveryPage,
    ExecutionResult,
    Observation,
    PlatformConfig,
    TelemetryPoint,
)

__all__ = [
    "AdapterError",
    "AdapterHealth",
    "AdapterLifecycleManager",
    "AdapterManifest",
    "AdapterPlugin",
    "AdapterState",
    "CapabilityMapping",
    "DiscoveredDevice",
    "DiscoveryPage",
    "ExecutionResult",
    "LifecycleError",
    "Observation",
    "PlatformConfig",
    "TelemetryPoint",
    "load_manifest",
    "verify_manifest",
]
