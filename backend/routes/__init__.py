"""API Routes Blueprint Registration."""
from .analyze import analyze_bp
from .reports import reports_bp
from .statistics import statistics_bp

__all__ = ["analyze_bp", "reports_bp", "statistics_bp"]
