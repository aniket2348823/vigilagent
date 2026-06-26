"""
OpenTelemetry tracing configuration for deep system integration.

This module provides distributed tracing capabilities for observability
across all integrated components.
"""

import logging
import os
from contextlib import contextmanager
from typing import Optional

logger = logging.getLogger(__name__)

# Try to import OpenTelemetry, but make it optional
try:
    from opentelemetry import trace
    from opentelemetry.exporter.jaeger.thrift import JaegerExporter
    from opentelemetry.exporter.zipkin.json import ZipkinExporter
    from opentelemetry.sdk.resources import SERVICE_NAME, Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter

    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False
    trace = None  # type: ignore
    TracerProvider = None  # type: ignore
    # OpenTelemetry is an OPTIONAL observability dependency and tracing is off by
    # default (TRACING_ENABLED=false). Log at DEBUG so a normal install/import is
    # silent on stderr (avoids false-alarm noise, e.g. PowerShell NativeCommandError).
    logger.debug("OpenTelemetry not available - tracing disabled")


class TracingConfig:
    """Configuration for OpenTelemetry tracing"""

    def __init__(self):
        self.enabled = os.getenv("TRACING_ENABLED", "false").lower() == "true"
        self.service_name = os.getenv("SERVICE_NAME", "vigilagent")
        self.exporter_type = os.getenv("TRACING_EXPORTER", "console")  # console, jaeger, zipkin
        self.jaeger_endpoint = os.getenv("JAEGER_ENDPOINT", "http://localhost:14268/api/traces")
        self.zipkin_endpoint = os.getenv("ZIPKIN_ENDPOINT", "http://localhost:9411/api/v2/spans")
        self.sample_rate = float(os.getenv("TRACING_SAMPLE_RATE", "1.0"))


_tracer_provider: Optional["TracerProvider"] = None
_tracer = None


def init_tracing(config: TracingConfig | None = None) -> None:
    """
    Initialize OpenTelemetry tracing.

    Args:
        config: Optional tracing configuration. If None, loads from environment.
    """
    global _tracer_provider, _tracer

    if not OTEL_AVAILABLE:
        logger.debug("OpenTelemetry not installed - tracing disabled")
        return

    if config is None:
        config = TracingConfig()

    if not config.enabled:
        logger.info("Tracing disabled by configuration")
        return

    # Create resource with service name
    resource = Resource(attributes={SERVICE_NAME: config.service_name})

    # Create tracer provider
    _tracer_provider = TracerProvider(resource=resource)

    # Configure exporter based on type
    if config.exporter_type == "jaeger":
        try:
            exporter = JaegerExporter(
                collector_endpoint=config.jaeger_endpoint,
            )
            logger.info(f"Jaeger exporter configured: {config.jaeger_endpoint}")
        except Exception as e:
            logger.error(f"Failed to configure Jaeger exporter: {e}")
            exporter = ConsoleSpanExporter()
    elif config.exporter_type == "zipkin":
        try:
            exporter = ZipkinExporter(
                endpoint=config.zipkin_endpoint,
            )
            logger.info(f"Zipkin exporter configured: {config.zipkin_endpoint}")
        except Exception as e:
            logger.error(f"Failed to configure Zipkin exporter: {e}")
            exporter = ConsoleSpanExporter()
    else:
        exporter = ConsoleSpanExporter()
        logger.info("Console exporter configured")

    # Add span processor
    _tracer_provider.add_span_processor(BatchSpanProcessor(exporter))

    # Set as global tracer provider
    trace.set_tracer_provider(_tracer_provider)

    # Get tracer
    _tracer = trace.get_tracer(__name__)

    logger.info(f"Tracing initialized: service={config.service_name}, exporter={config.exporter_type}")


def get_tracer() -> "trace.Tracer":
    """
    Get the global tracer instance.

    Returns:
        Tracer instance, or a no-op tracer if tracing is disabled
    """
    global _tracer

    if not OTEL_AVAILABLE:
        # Return a no-op tracer
        return NoOpTracer()

    if _tracer is None:
        # Initialize with defaults if not already initialized
        init_tracing()
        if _tracer is None:
            return NoOpTracer()

    return _tracer


@contextmanager
def trace_span(name: str, attributes: dict | None = None):
    """
    Context manager for creating a trace span.

    Args:
        name: Span name
        attributes: Optional span attributes

    Example:
        with trace_span("process_vulnerability", {"vuln_type": "XSS"}):
            # Do work
            pass
    """
    if not OTEL_AVAILABLE or _tracer is None:
        # No-op if tracing not available
        yield None
        return

    with _tracer.start_as_current_span(name) as span:
        if attributes:
            for key, value in attributes.items():
                span.set_attribute(key, str(value))
        yield span


class NoOpTracer:
    """No-op tracer for when OpenTelemetry is not available"""

    @contextmanager
    def start_as_current_span(self, name: str, **kwargs):
        """No-op span context manager"""
        yield NoOpSpan()


class NoOpSpan:
    """No-op span for when OpenTelemetry is not available"""

    def set_attribute(self, key: str, value: str) -> None:
        """No-op set attribute"""
        pass

    def set_status(self, status) -> None:
        """No-op set status"""
        pass

    def record_exception(self, exception: Exception) -> None:
        """No-op record exception"""
        pass


def shutdown_tracing() -> None:
    """Shutdown tracing and flush remaining spans"""
    global _tracer_provider

    if _tracer_provider is not None:
        _tracer_provider.shutdown()
        logger.info("Tracing shutdown complete")
