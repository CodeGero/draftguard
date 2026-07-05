"""Output reporters for configuration drift findings.

Supports multiple output formats:
- Rich table (default terminal output)
- JSON (machine-readable)
- Markdown (documentation/reports)
- Summary (compact one-line stats)
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, TextIO

from .differ import ComparisonResult
from .rules import Finding, Severity


class BaseReporter:
    """Base class for output reporters."""

    def report(self, result: ComparisonResult, file: Optional[TextIO] = None) -> str:
        """Generate a report string."""
        raise NotImplementedError

    def report_audit(self, findings: List[Finding], env_name: str,
                     file: Optional[TextIO] = None) -> str:
        """Generate an audit report string."""
        raise NotImplementedError


class RichReporter(BaseReporter):
    """Rich terminal output with colors, tables, and panels."""

    def report(self, result: ComparisonResult, file: Optional[TextIO] = None) -> str:
        """Generate a rich-formatted terminal report."""
        try:
            from rich.console import Console
            from rich.panel import Panel
            from rich.table import Table
            from rich.text import Text
        except ImportError:
            return self._fallback_report(result)

        console = Console(file=file, highlight=False)

        # Header panel
        title = Text(
            f"🔍 DraftGuard: {result.env_source} → {result.env_target}",
            style="bold white",
        )
        console.print(Panel(title, border_style="blue"))

        # Summary table
        summary_table = Table(title="Summary", show_header=True, header_style="bold")
        summary_table.add_column("Severity", style="bold")
        summary_table.add_column("Count", justify="right")
        summary_table.add_column("Status")

        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "WARNING", "INFO"]
        for sev_name in severity_order:
            count = result.summary.get(sev_name, 0)
            sev = Severity(sev_name)
            status = "❌ FAIL" if count > 0 and sev.level >= Severity.HIGH.level else "✅ OK"
            style = sev.color
            summary_table.add_row(
                f"[{style}]{sev.emoji} {sev_name}[/{style}]",
                str(count),
                status if count > 0 else status,
            )

        console.print(summary_table)
        console.print()

        # Findings table
        if result.findings:
            findings_table = Table(
                title=f"Findings ({len(result.findings)} issues)",
                show_header=True,
                header_style="bold",
                show_lines=True,
            )
            findings_table.add_column("Severity", style="bold", width=10)
            findings_table.add_column("Category", width=15)
            findings_table.add_column("Key", style="cyan", width=30)
            findings_table.add_column("Message", width=50)

            for f in result.findings:
                sev = f.severity
                findings_table.add_row(
                    f"[{sev.color}]{sev.emoji} {sev.value}[/{sev.color}]",
                    f.category.value,
                    f.key,
                    f.message,
                )

            console.print(findings_table)
        else:
            console.print("[green]✅ No drift detected! All configurations are in sync.[/green]")

        return ""

    def report_audit(self, findings: List[Finding], env_name: str,
                     file: Optional[TextIO] = None) -> str:
        """Generate a rich-formatted audit report."""
        try:
            from rich.console import Console
            from rich.panel import Panel
            from rich.table import Table
            from rich.text import Text
        except ImportError:
            return self._fallback_audit(findings, env_name)

        console = Console(file=file, highlight=False)

        title = Text(f"🔍 DraftGuard Audit: {env_name}", style="bold white")
        console.print(Panel(title, border_style="blue"))

        if not findings:
            console.print("[green]✅ No issues found![/green]")
            return ""

        sev_counts: Dict[str, int] = {}
        for f in findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

        summary_table = Table(title="Summary", show_header=True, header_style="bold")
        summary_table.add_column("Severity", style="bold")
        summary_table.add_column("Count", justify="right")
        for sev_name in ["CRITICAL", "HIGH", "MEDIUM", "WARNING", "INFO"]:
            count = sev_counts.get(sev_name, 0)
            if count > 0:
                sev = Severity(sev_name)
                summary_table.add_row(
                    f"[{sev.color}]{sev.emoji} {sev_name}[/{sev.color}]",
                    str(count),
                )
        console.print(summary_table)
        console.print()

        findings_table = Table(
            title=f"Findings ({len(findings)} issues)",
            show_header=True,
            header_style="bold",
            show_lines=True,
        )
        findings_table.add_column("Severity", width=10)
        findings_table.add_column("Key", style="cyan", width=30)
        findings_table.add_column("Message", width=60)

        for f in findings:
            sev = f.severity
            findings_table.add_row(
                f"[{sev.color}]{sev.emoji}[/{sev.color}]",
                f.key,
                f.message,
            )

        console.print(findings_table)
        return ""

    def _fallback_report(self, result: ComparisonResult) -> str:
        """Plain text fallback when rich is not available."""
        lines = [
            f"=== DraftGuard: {result.env_source} -> {result.env_target} ===",
            "",
            "Summary:",
        ]
        for sev_name in ["CRITICAL", "HIGH", "MEDIUM", "WARNING", "INFO"]:
            count = result.summary.get(sev_name, 0)
            lines.append(f"  {sev_name}: {count}")
        lines.append("")
        lines.append(f"Findings ({len(result.findings)} issues):")
        for f in result.findings:
            lines.append(
                f"  [{f.severity.value}] {f.category.value}: {f.key} — {f.message}"
            )
        return "\n".join(lines) + "\n"

    def _fallback_audit(self, findings: List[Finding], env_name: str) -> str:
        """Plain text fallback for audit."""
        lines = [
            f"=== DraftGuard Audit: {env_name} ===",
            f"Findings ({len(findings)} issues):",
        ]
        for f in findings:
            lines.append(f"  [{f.severity.value}] {f.key} — {f.message}")
        return "\n".join(lines) + "\n"


class JsonReporter(BaseReporter):
    """JSON output reporter for machine consumption."""

    def report(self, result: ComparisonResult, file: Optional[TextIO] = None) -> str:
        """Generate a JSON report."""
        data: Dict[str, Any] = {
            "tool": "draftguard",
            "comparison": {
                "source": result.env_source,
                "target": result.env_target,
            },
            "summary": result.summary,
            "total_findings": result.total_findings,
            "findings": [f.to_dict() for f in result.findings],
            "configs_source": [str(c.filepath) for c in result.configs_source],
            "configs_target": [str(c.filepath) for c in result.configs_target],
        }
        output = json.dumps(data, indent=2, default=str)
        if file:
            file.write(output + "\n")
        return output

    def report_audit(self, findings: List[Finding], env_name: str,
                     file: Optional[TextIO] = None) -> str:
        """Generate a JSON audit report."""
        data = {
            "tool": "draftguard",
            "audit": {"environment": env_name},
            "total_findings": len(findings),
            "findings": [f.to_dict() for f in findings],
        }
        output = json.dumps(data, indent=2, default=str)
        if file:
            file.write(output + "\n")
        return output


class MarkdownReporter(BaseReporter):
    """Markdown output reporter for documentation."""

    def report(self, result: ComparisonResult, file: Optional[TextIO] = None) -> str:
        """Generate a Markdown report."""
        lines = [
            "# 🔍 DraftGuard Report",
            "",
            f"**Comparison:** `{result.env_source}` → `{result.env_target}`",
            "",
            f"**Total findings:** {result.total_findings}",
            "",
            "## Summary",
            "",
            "| Severity | Count | Status |",
            "|----------|------:|--------|",
        ]

        for sev_name in ["CRITICAL", "HIGH", "MEDIUM", "WARNING", "INFO"]:
            count = result.summary.get(sev_name, 0)
            sev = Severity(sev_name)
            status = "❌ FAIL" if count > 0 and sev.level >= Severity.HIGH.level else "✅ OK"
            lines.append(f"| {sev.emoji} **{sev_name}** | {count} | {status} |")

        if result.findings:
            lines.extend([
                "",
                "## Findings",
                "",
                "| Severity | Category | Key | Message |",
                "|----------|----------|-----|---------|",
            ])
            for f in result.findings:
                lines.append(
                    f"| {f.severity.emoji} | {f.category.value} | `{f.key}` | {f.message} |"
                )

        if result.configs_source or result.configs_target:
            lines.extend([
                "",
                "## Config Files",
                "",
                f"**{result.env_source}:** "
                f"{', '.join(str(c.filepath) for c in result.configs_source)}",
                "",
                f"**{result.env_target}:** "
                f"{', '.join(str(c.filepath) for c in result.configs_target)}",
            ])

        output = "\n".join(lines) + "\n"
        if file:
            file.write(output)
        return output

    def report_audit(self, findings: List[Finding], env_name: str,
                     file: Optional[TextIO] = None) -> str:
        """Generate a Markdown audit report."""
        lines = [
            "# 🔍 DraftGuard Audit",
            "",
            f"**Environment:** `{env_name}`",
            "",
            f"**Total findings:** {len(findings)}",
            "",
        ]

        if findings:
            lines.extend([
                "| Severity | Key | Message |",
                "|----------|-----|---------|",
            ])
            for f in findings:
                lines.append(
                    f"| {f.severity.emoji} | `{f.key}` | {f.message} |"
                )

        output = "\n".join(lines) + "\n"
        if file:
            file.write(output)
        return output


class SummaryReporter(BaseReporter):
    """Compact one-line summary reporter."""

    def report(self, result: ComparisonResult, file: Optional[TextIO] = None) -> str:
        """Generate a compact summary line."""
        parts = [f"draftguard: {result.env_source}→{result.env_target}"]
        for sev_name in ["CRITICAL", "HIGH", "MEDIUM", "WARNING", "INFO"]:
            count = result.summary.get(sev_name, 0)
            if count > 0:
                parts.append(f"{sev_name}={count}")
        output = " ".join(parts)
        if file:
            file.write(output + "\n")
        return output

    def report_audit(self, findings: List[Finding], env_name: str,
                     file: Optional[TextIO] = None) -> str:
        """Generate a compact audit summary."""
        sev_counts: Dict[str, int] = {}
        for f in findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

        parts = [f"draftguard audit {env_name}"]
        for sev_name in ["CRITICAL", "HIGH", "MEDIUM", "WARNING", "INFO"]:
            count = sev_counts.get(sev_name, 0)
            if count > 0:
                parts.append(f"{sev_name}={count}")
        output = " ".join(parts)
        if file:
            file.write(output + "\n")
        return output


def get_reporter(format: str) -> BaseReporter:
    """Factory function to get a reporter by format name."""
    reporters = {
        "table": RichReporter(),
        "rich": RichReporter(),
        "json": JsonReporter(),
        "markdown": MarkdownReporter(),
        "md": MarkdownReporter(),
        "summary": SummaryReporter(),
        "short": SummaryReporter(),
    }
    return reporters.get(format.lower(), RichReporter())
