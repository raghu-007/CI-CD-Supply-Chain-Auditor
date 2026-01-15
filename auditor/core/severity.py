"""
Severity levels for security findings.

Provides a consistent way to categorize and compare severity across all checks.
Based on CVSS-like scoring methodology adapted for CI/CD security.
"""

from __future__ import annotations

from enum import IntEnum


# Severity metadata - defined outside the enum to avoid issues
_SEVERITY_DESCRIPTIONS: dict[int, str] = {
    0: "Informational finding with no direct security impact",
    1: "Low severity - best practice violation or minor risk",
    2: "Medium severity - moderate risk requiring specific conditions",
    3: "High severity - significant security risk, exploitation likely",
    4: "Critical severity - immediate exploitation possible with high impact",
}

_SEVERITY_COLORS: dict[int, str] = {
    0: "blue",
    1: "green",
    2: "yellow",
    3: "orange",
    4: "red",
}

_SEVERITY_ICONS: dict[int, str] = {
    0: "ℹ️",
    1: "⚠️",
    2: "🟡",
    3: "🟠",
    4: "🔴",
}


class Severity(IntEnum):
    """
    Severity levels for security findings.
    
    Levels are based on potential impact:
    - CRITICAL: Immediate exploitation possible, high impact
    - HIGH: Significant security risk, exploitation likely
    - MEDIUM: Moderate risk, conditions required for exploitation
    - LOW: Minor risk, best practice violation
    - INFO: Informational, no direct security impact
    
    Using IntEnum allows direct comparison: Severity.CRITICAL > Severity.HIGH
    """
    
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    
    @property
    def description(self) -> str:
        """Get human-readable description of this severity level."""
        return _SEVERITY_DESCRIPTIONS.get(self.value, "Unknown severity")
    
    @property
    def color(self) -> str:
        """Get color associated with this severity for UI display."""
        return _SEVERITY_COLORS.get(self.value, "gray")
    
    @property
    def icon(self) -> str:
        """Get emoji icon for this severity level."""
        return _SEVERITY_ICONS.get(self.value, "❓")
    
    @classmethod
    def from_string(cls, value: str) -> "Severity":
        """
        Parse severity from string (case-insensitive).
        
        Args:
            value: String representation (e.g., "high", "HIGH", "High")
        
        Returns:
            Corresponding Severity enum value
        
        Raises:
            ValueError: If string doesn't match any severity level
        """
        normalized = value.upper().strip()
        
        try:
            return cls[normalized]
        except KeyError:
            valid = ", ".join(s.name for s in cls)
            raise ValueError(
                f"Invalid severity '{value}'. Valid values: {valid}"
            ) from None
    
    def __str__(self) -> str:
        """Return lowercase name for string representation."""
        return self.name.lower()
    
    def __repr__(self) -> str:
        """Return detailed representation."""
        return f"Severity.{self.name}"


def severity_at_or_above(threshold: Severity) -> list[Severity]:
    """
    Get all severity levels at or above the threshold.
    
    Args:
        threshold: Minimum severity level
    
    Returns:
        List of severity levels >= threshold
    """
    return [s for s in Severity if s >= threshold]


def severity_summary(severities: list[Severity]) -> dict[str, int]:
    """
    Create a summary count of severities.
    
    Args:
        severities: List of severity values
    
    Returns:
        Dict mapping severity name to count
    """
    counts = {s.name.lower(): 0 for s in Severity}
    for s in severities:
        counts[s.name.lower()] += 1
    return counts
