"""Command-line interface for DraftGuard.

Usage:
    draftguard scan [DIR]          Scan directory tree for config files and compare envs
    draftguard compare DIR1 DIR2   Compare two specific config sets
    draftguard audit DIR [ENV]     Audit a single environment for issues
    draftguard diff DIR1 DIR2      Show detailed diff between environments

Options:
    --envs TEXT            Environments to check [default: dev,prod]
    --format FORMAT        Output format (table, json, markdown, summary)
    --fail-on SEVERITY     Exit with error if findings at or above severity
    -o, --output FILE      Write report to file
    -r, --recursive        Recurse into subdirectories [default: true]
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional, Tuple

import click

from . import __version__
from .differ import Differ
from .parser import ConfigParser
from .reporters import get_reporter
from .rules import Severity
from .scanner import ConfigScanner


def _parse_envs(ctx, param, value: Optional[str]) -> List[str]:
    """Parse --envs comma-separated list."""
    if not value:
        return ["dev", "prod"]
    return [e.strip() for e in value.split(",")]


def _parse_severity(value: str) -> Severity:
    """Parse a severity string."""
    mapping = {
        "critical": Severity.CRITICAL,
        "crit": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "med": Severity.MEDIUM,
        "warning": Severity.WARNING,
        "warn": Severity.WARNING,
        "info": Severity.INFO,
    }
    v = value.lower()
    if v not in mapping:
        raise click.BadParameter(f"Invalid severity: {value}. "
                                 f"Choose from: critical, high, medium, warning, info")
    return mapping[v]


def _print_banner() -> None:
    """Print the DraftGuard banner."""
    try:
        from rich.console import Console
        from rich.text import Text
        console = Console()
        banner = Text("""╔══════════════════════════════════════════════════╗
║         🔍 KRYPTORIOUS DRAFTGUARD v{}          ║
║   Detect config drift before it causes outages  ║
╚══════════════════════════════════════════════════╝""".format(__version__),
                      style="bold cyan")
        console.print(banner)
    except ImportError:
        click.echo(f"Kryptorious DraftGuard v{__version__}")


@click.group(invoke_without_command=True)
@click.version_option(__version__, prog_name="draftguard")
@click.pass_context
def main(ctx: click.Context) -> None:
    """Kryptorious DraftGuard — Environment Configuration Drift Detection.

    Detect missing keys, value mismatches, type drift, default leakage,
    and secret exposure across dev/staging/prod environments.
    """
    if ctx.invoked_subcommand is None:
        _print_banner()
        click.echo()
        click.echo(ctx.get_help())
        click.echo()


@main.command("scan")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path),
                default=Path.cwd())
@click.option("--envs", "-e", callback=_parse_envs, default="dev,prod",
              help="Comma-separated environments to compare (default: dev,prod)")
@click.option("--format", "-f", "output_format", default="table",
              type=click.Choice(["table", "json", "markdown", "md", "summary"]),
              help="Output format")
@click.option("--fail-on", default=None, help="Exit code 1 if findings at or above this severity")
@click.option("--output", "-o", "output_file", type=click.Path(path_type=Path),
              help="Write report to file")
@click.option("--recursive/--no-recursive", "-r", default=True,
              help="Recurse into subdirectories")
def scan_command(
    directory: Path,
    envs: List[str],
    output_format: str,
    fail_on: Optional[str],
    output_file: Optional[Path],
    recursive: bool,
) -> None:
    """Scan a directory tree for config files and compare environments.

    DIR is the root directory to scan (defaults to current directory).

    Examples:
        draftguard scan .
        draftguard scan /app --envs dev,staging,prod
        draftguard scan . --format json -o report.json
    """
    is_json = output_format == "json"
    if not is_json:
        _print_banner()
        click.echo()

    parser = ConfigParser()
    scanner = ConfigScanner(parser=parser)
    differ = Differ(parser=parser, scanner=scanner)

    if not is_json:
        click.echo(f"📂 Scanning: {directory}")
    configs = scanner.scan(directory, recursive=recursive)

    if not configs:
        if not is_json:
            click.echo("⚠️  No config files found.")
        sys.exit(0)

    # Group by environment
    groups = scanner.group_by_environment(configs)

    if not is_json:
        click.echo(f"   Found {len(configs)} config files across {len(groups)} environments:")
        for env_name, cfgs in sorted(groups.items()):
            click.echo(f"     • {env_name}: {len(cfgs)} file(s) "
                       f"({', '.join(c.filepath.name for c in cfgs)})")
        click.echo()

    if len(envs) < 2:
        click.echo("❌ Need at least 2 environments to compare. Use --envs or audit command.")
        sys.exit(1)

    # Use first two envs as source/target
    source_env = envs[0]
    target_env = envs[1]

    source_configs = groups.get(source_env, [])
    target_configs = groups.get(target_env, [])

    if not source_configs:
        click.echo(f"⚠️  No config files found for environment '{source_env}'")
        click.echo(f"   Available environments: {', '.join(sorted(groups.keys()))}")
        sys.exit(1)

    if not target_configs:
        click.echo(f"⚠️  No config files found for environment '{target_env}'")
        click.echo(f"   Available environments: {', '.join(sorted(groups.keys()))}")
        sys.exit(1)

    # Run comparison
    result = differ.compare_environments(source_env, target_env, source_configs, target_configs)

    # Generate report
    reporter = get_reporter(output_format)
    report = reporter.report(result)

    # Rich reporter prints itself; others return a string to print
    if output_format in ("table",) and report == "":
        pass  # RichReporter printed directly
    else:
        click.echo(report)

    if output_file:
        output_file.write_text(report, encoding="utf-8")
        click.echo(f"\n✅ Report written to: {output_file}")

    # Determine exit code
    exit_code = 0
    if fail_on:
        threshold = _parse_severity(fail_on)
        has_failures = any(
            Severity(sev).level >= threshold.level
            for sev in result.summary
            if result.summary.get(sev, 0) > 0
        )
        if has_failures:
            exit_code = 1

    if exit_code != 0:
        sys.exit(exit_code)


@main.command("compare")
@click.argument("dir1", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.argument("dir2", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--envs", "-e", callback=_parse_envs, default=None,
              help="Environment labels for the two directories (default: inferred from paths)")
@click.option("--format", "-f", "output_format", default="table",
              type=click.Choice(["table", "json", "markdown", "md", "summary"]),
              help="Output format")
@click.option("--fail-on", default=None, help="Exit code 1 if findings at or above this severity")
@click.option("--output", "-o", "output_file", type=click.Path(path_type=Path),
              help="Write report to file")
def compare_command(
    dir1: Path,
    dir2: Path,
    envs: Optional[List[str]],
    output_format: str,
    fail_on: Optional[str],
    output_file: Optional[Path],
) -> None:
    """Compare config files from two directories.

    DIR1 and DIR2 are paths to environment config directories.

    Examples:
        draftguard compare ./envs/dev ./envs/prod
        draftguard compare ./dev ./staging --envs development,staging
    """
    is_json = output_format == "json"
    if not is_json:
        _print_banner()
        click.echo()

    if envs and len(envs) >= 2:
        source_env, target_env = envs[0], envs[1]
    else:
        source_env = dir1.name
        target_env = dir2.name

    parser = ConfigParser()
    scanner = ConfigScanner(parser=parser)
    differ = Differ(parser=parser, scanner=scanner)

    if not is_json:
        click.echo(f"📂 Scanning source: {dir1}")
    source_configs = scanner.scan(dir1, recursive=True)
    if not is_json:
        click.echo(f"   Found {len(source_configs)} config file(s)")

    if not is_json:
        click.echo(f"📂 Scanning target: {dir2}")
    target_configs = scanner.scan(dir2, recursive=True)
    if not is_json:
        click.echo(f"   Found {len(target_configs)} config file(s)")
        click.echo()

    if not source_configs or not target_configs:
        click.echo("❌ Both directories must contain config files.")
        sys.exit(1)

    result = differ.compare_environments(source_env, target_env, source_configs, target_configs)

    reporter = get_reporter(output_format)
    report = reporter.report(result)

    if output_format in ("table",) and report == "":
        pass
    else:
        click.echo(report)

    if output_file:
        output_file.write_text(report, encoding="utf-8")
        click.echo(f"\n✅ Report written to: {output_file}")

    exit_code = 0
    if fail_on:
        threshold = _parse_severity(fail_on)
        has_failures = any(
            Severity(sev).level >= threshold.level
            for sev in result.summary
            if result.summary.get(sev, 0) > 0
        )
        if has_failures:
            exit_code = 1

    if exit_code != 0:
        sys.exit(exit_code)


@main.command("audit")
@click.argument("directory", type=click.Path(exists=True, file_okay=False, path_type=Path),
                default=Path.cwd())
@click.option("--env", "-e", default=None, help="Environment to audit "
              "(default: auto-detect from directory)")
@click.option("--format", "-f", "output_format", default="table",
              type=click.Choice(["table", "json", "markdown", "md", "summary"]),
              help="Output format")
@click.option("--fail-on", default=None, help="Exit code 1 if findings at or above this severity")
@click.option("--output", "-o", "output_file", type=click.Path(path_type=Path),
              help="Write report to file")
def audit_command(
    directory: Path,
    env: Optional[str],
    output_format: str,
    fail_on: Optional[str],
    output_file: Optional[Path],
) -> None:
    """Audit a single environment for configuration issues.

    Checks for empty values, default placeholders, and weak secrets.

    Examples:
        draftguard audit .
        draftguard audit ./prod --env production
    """
    is_json = output_format == "json"
    if not is_json:
        _print_banner()
        click.echo()

    parser = ConfigParser()
    scanner = ConfigScanner(parser=parser)
    differ = Differ(parser=parser, scanner=scanner)

    if not is_json:
        click.echo(f"📂 Auditing: {directory}")
    configs = scanner.scan(directory, recursive=True)

    if not configs:
        if not is_json:
            click.echo("⚠️  No config files found.")
        sys.exit(0)

    env_name = env or configs[0].env_name
    if not is_json:
        click.echo(f"   Environment: {env_name}")
        click.echo(f"   Config files: {len(configs)}")
        click.echo()

    findings = differ.audit_environment(env_name, configs)

    reporter = get_reporter(output_format)
    report = reporter.report_audit(findings, env_name)

    if output_format in ("table",) and report == "":
        pass
    else:
        click.echo(report)

    if output_file:
        output_file.write_text(report, encoding="utf-8")
        click.echo(f"\n✅ Report written to: {output_file}")

    exit_code = 0
    if fail_on:
        threshold = _parse_severity(fail_on)
        has_failures = any(
            f.severity.level >= threshold.level for f in findings
        )
        if has_failures:
            exit_code = 1

    if exit_code != 0:
        sys.exit(exit_code)


@main.command("diff")
@click.argument("dir1", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.argument("dir2", type=click.Path(exists=True, file_okay=False, path_type=Path))
@click.option("--format", "-f", "output_format", default="table",
              type=click.Choice(["table", "json", "markdown", "md"]),
              help="Output format")
@click.option("--output", "-o", "output_file", type=click.Path(path_type=Path),
              help="Write report to file")
def diff_command(
    dir1: Path,
    dir2: Path,
    output_format: str,
    output_file: Optional[Path],
) -> None:
    """Show detailed key-by-key diff between two config directories.

    Examples:
        draftguard diff ./dev ./prod
        draftguard diff ./staging ./prod --format markdown
    """
    is_json = output_format == "json"
    if not is_json:
        _print_banner()
        click.echo()

    parser = ConfigParser()
    scanner = ConfigScanner(parser=parser)
    differ = Differ(parser=parser, scanner=scanner)

    if not is_json:
        click.echo(f"📂 Scanning: {dir1}")
    configs1 = scanner.scan(dir1, recursive=True)

    if not is_json:
        click.echo(f"📂 Scanning: {dir2}")
    configs2 = scanner.scan(dir2, recursive=True)

    if not configs1 or not configs2:
        click.echo("❌ Both directories must contain config files.")
        sys.exit(1)

    # Merge configs
    merged1 = scanner.merge_env_configs(configs1)
    merged2 = scanner.merge_env_configs(configs2)

    diffs = differ.diff_values(
        merged1.values, merged2.values,
        env_source=dir1.name, env_target=dir2.name,
    )

    if not is_json:
        click.echo(f"🔍 Diff: {dir1.name} ↔ {dir2.name}")
        click.echo(f"   Keys in {dir1.name}: {len(merged1.values)}")
        click.echo(f"   Keys in {dir2.name}: {len(merged2.values)}")
        click.echo(f"   Differences: {len(diffs)}")
        click.echo()

    # Display diff
    if output_format == "json":
        import json

        diff_data = {
            "source": str(dir1),
            "target": str(dir2),
            "differences": [
                {"status": status, "key": key, "source_value": sv, "target_value": tv}
                for status, key, sv, tv in diffs
            ],
        }
        output = json.dumps(diff_data, indent=2, default=str)
        click.echo(output)
    elif output_format in ("markdown", "md"):
        lines = [
            f"# Diff: `{dir1.name}` ↔ `{dir2.name}`",
            "",
            "| Status | Key | Source | Target |",
            "|--------|-----|--------|--------|",
        ]
        for status, key, sv, tv in diffs:
            sv_str = f"`{sv}`" if sv else "—"
            tv_str = f"`{tv}`" if tv else "—"
            icon = {"added": "➕", "removed": "➖", "changed": "🔄"}.get(status, "•")
            lines.append(f"| {icon} {status} | `{key}` | {sv_str} | {tv_str} |")
        output = "\n".join(lines) + "\n"
        click.echo(output)
    else:
        # Table format
        try:
            from rich.console import Console
            from rich.table import Table
            console = Console()
            table = Table(title=f"Diff: {dir1.name} ↔ {dir2.name}",
                          show_header=True, header_style="bold")
            table.add_column("Status", style="bold", width=10)
            table.add_column("Key", style="cyan", width=35)
            table.add_column(str(dir1.name), width=30)
            table.add_column(str(dir2.name), width=30)

            for status, key, sv, tv in diffs:
                color = {"added": "green", "removed": "red", "changed": "yellow"}.get(status, "")
                sv_str = str(sv)[:28] if sv else "—"
                tv_str = str(tv)[:28] if tv else "—"
                table.add_row(
                    f"[{color}]{status}[/{color}]",
                    key,
                    sv_str,
                    tv_str,
                )
            console.print(table)
        except ImportError:
            for status, key, sv, tv in diffs:
                click.echo(f"  [{status}] {key}: {sv} → {tv}")

    if output_file:
        output_file.write_text(output if 'output' in dir() else "", encoding="utf-8")
