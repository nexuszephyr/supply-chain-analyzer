"""Command-line interface for the Supply Chain Security Analyzer."""

import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from .core.analyzer import Analyzer
from .core.config import Config
from .reporters.console import ConsoleReporter
from .reporters.json_reporter import JsonReporter
from .reporters.html_reporter import HtmlReporter


console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="supply-chain-analyzer")
def main():
    """Supply Chain Security Analyzer - Scan dependencies for security issues."""
    pass


@main.command()
@click.argument("project_path", type=click.Path(exists=True))
@click.option("--format", "-f", "output_format", 
              type=click.Choice(["console", "json", "html"]), 
              default="console",
              help="Output format")
@click.option("--output", "-o", "output_file",
              type=click.Path(),
              help="Output file path (for json/html format)")
@click.option("--config", "-c", "config_file",
              type=click.Path(exists=True),
              help="Path to configuration file")
@click.option("--severity", "-s",
              type=click.Choice(["low", "medium", "high", "critical"]),
              default="low",
              help="Minimum severity to report")
@click.option("--no-typosquat", is_flag=True,
              help="Skip typosquatting checks")
def scan(project_path: str, output_format: str, output_file: Optional[str],
         config_file: Optional[str], severity: str, no_typosquat: bool):
    """
    Perform a full security scan on a project.
    
    PROJECT_PATH: Path to the project directory to scan
    """
    try:
        # Load config
        config = Config()
        if config_file:
            config = Config.load_from_file(Path(config_file))
        
        config.min_severity = severity
        config.check_typosquatting = not no_typosquat
        
        # Run scan
        analyzer = Analyzer(config)
        result = analyzer.scan(project_path)
        
        # Output results
        if output_format == "json":
            reporter = JsonReporter()
            output = reporter.report(result, Path(output_file) if output_file else None)
            if not output_file:
                click.echo(output)
        elif output_format == "html":
            reporter = HtmlReporter()
            output_path = Path(output_file) if output_file else Path("report.html")
            reporter.report(result, output_path)
            console.print(f"[green]HTML report saved to: {output_path}[/green]")
        else:
            reporter = ConsoleReporter()
            reporter.report(result)
        
        # Exit with error code if issues found
        sys.exit(1 if result.has_issues else 0)
        
    except FileNotFoundError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error during scan: {e}[/red]")
        sys.exit(1)


@main.command()
@click.argument("project_path", type=click.Path(exists=True))
@click.option("--severity", "-s",
              type=click.Choice(["low", "medium", "high", "critical"]),
              default="low",
              help="Minimum severity to report")
def vuln(project_path: str, severity: str):
    """
    Scan only for vulnerabilities.
    
    PROJECT_PATH: Path to the project directory to scan
    """
    try:
        config = Config()
        config.min_severity = severity
        
        analyzer = Analyzer(config)
        result = analyzer.scan_vulnerabilities_only(project_path)
        
        reporter = ConsoleReporter()
        reporter.report(result)
        
        sys.exit(1 if result.total_vulnerabilities > 0 else 0)
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@main.command()
@click.argument("project_path", type=click.Path(exists=True))
@click.option("--threshold", "-t", type=float, default=0.85,
              help="Similarity threshold (0-1)")
def typosquat(project_path: str, threshold: float):
    """
    Check for typosquatting attacks.
    
    PROJECT_PATH: Path to the project directory to scan
    """
    try:
        config = Config()
        config.typosquat_threshold = threshold
        
        analyzer = Analyzer(config)
        result = analyzer.scan_typosquatting_only(project_path)
        
        reporter = ConsoleReporter()
        reporter.report(result)
        
        sys.exit(1 if result.typosquat_matches else 0)
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@main.command()
@click.argument("project_path", type=click.Path(exists=True))
@click.option("--allow", "-a", multiple=True,
              help="Allowed license SPDX IDs (can be specified multiple times)")
@click.option("--block", "-b", multiple=True,
              help="Blocked license SPDX IDs (can be specified multiple times)")
def license(project_path: str, allow: tuple, block: tuple):
    """
    Check license compliance.
    
    PROJECT_PATH: Path to the project directory to scan
    """
    try:
        config = Config()
        if allow:
            config.allowed_licenses = set(allow)
        if block:
            config.blocked_licenses = set(block)
        
        analyzer = Analyzer(config)
        result = analyzer.scan_licenses_only(project_path)
        
        reporter = ConsoleReporter()
        reporter.report(result)
        
        sys.exit(1 if result.license_issues else 0)
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@main.command()
@click.argument("project_path", type=click.Path(exists=True))
@click.option("--min-score", "-m", type=float, default=40.0,
              help="Minimum acceptable maturity score (0-100)")
@click.option("--detailed", "-d", is_flag=True,
              help="Show detailed factor breakdown")
def maturity(project_path: str, min_score: float, detailed: bool):
    """
    Check package maturity scores (Project Maturity Index).
    
    PROJECT_PATH: Path to the project directory to scan
    """
    try:
        config = Config()
        config.check_reputation = True
        
        analyzer = Analyzer(config)
        result = analyzer.scan_maturity_only(project_path)
        
        # Display results
        if not result.maturity_scores:
            console.print("[yellow]No dependencies found to check.[/yellow]")
            sys.exit(0)
        
        from rich.table import Table
        from rich import box
        
        # PMI maturity labels
        MATURITY_COLORS = {
            "mature": "green bold",
            "established": "green",
            "emerging": "yellow",
            "early-stage": "red",
        }
        
        table = Table(title="📊 Project Maturity Index (PMI)", box=box.ROUNDED)
        table.add_column("Package", style="cyan")
        table.add_column("Score", justify="right")
        table.add_column("Maturity")
        if detailed:
            table.add_column("Age", justify="right")
            table.add_column("Docs", justify="right")
            table.add_column("Activity", justify="right")
            table.add_column("Adoption", justify="right")
        
        low_score_packages = []
        
        for name, score in result.maturity_scores.items():
            score_color = "green" if score.overall_score >= 80 else ("yellow" if score.overall_score >= 40 else "red")
            maturity_level = getattr(score, 'maturity_level', 'emerging')
            maturity_color = MATURITY_COLORS.get(maturity_level, "white")
            
            if score.overall_score < min_score:
                low_score_packages.append((name, score.overall_score))
            
            row = [
                name,
                f"[{score_color}]{score.overall_score:.0f}[/{score_color}]",
                f"[{maturity_color}]{maturity_level.upper()}[/{maturity_color}]",
            ]
            
            if detailed:
                factors = score.factors
                row.extend([
                    f"{factors.get('age', 0):.0f}",
                    f"{factors.get('documentation', 0):.0f}",
                    f"{factors.get('activity', 0):.0f}",
                    f"{factors.get('adoption', 0):.0f}",
                ])
            
            table.add_row(*row)
        
        console.print(table)
        
        if low_score_packages:
            console.print(f"\n[yellow]⚠️  {len(low_score_packages)} package(s) below minimum score of {min_score}:[/yellow]")
            for name, score in low_score_packages:
                console.print(f"  [dim]• {name}: {score:.0f}/100[/dim]")
            sys.exit(1)
        else:
            console.print(f"\n[green]✅ All packages meet minimum maturity score of {min_score}[/green]")
            sys.exit(0)
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@main.command()
@click.argument("project_path", type=click.Path(exists=True))
@click.option("--detailed", "-d", is_flag=True,
              help="Show detailed component breakdown")
def security(project_path: str, detailed: bool):
    """
    Check Security Exposure Scores (SES) based on vulnerabilities.
    
    PROJECT_PATH: Path to the project directory to scan
    """
    try:
        config = Config()
        analyzer = Analyzer(config)
        result = analyzer.scan(project_path)
        
        # Display results
        if not result.ses_scores:
            if not result.vulnerabilities:
                console.print("[green]✅ No vulnerabilities found - no security exposure![/green]")
            else:
                console.print("[yellow]No SES scores calculated.[/yellow]")
            sys.exit(0)
        
        from rich.table import Table
        from rich import box
        
        # SES level colors
        SES_COLORS = {
            "minimal": "green bold",
            "low": "green",
            "moderate": "yellow",
            "high": "red",
            "critical": "red bold",
        }
        
        table = Table(title="🔒 Security Exposure Score (SES)", box=box.ROUNDED)
        table.add_column("Package", style="cyan")
        table.add_column("SES", justify="right")
        table.add_column("Level")
        table.add_column("Action")
        if detailed:
            table.add_column("Severity", justify="right")
            table.add_column("Exploit", justify="right")
            table.add_column("CVEs")
        
        has_issues = False
        
        for name, score in result.ses_scores.items():
            if score.ses_score >= 4:
                has_issues = True
            
            level_color = SES_COLORS.get(score.ses_level, "white")
            
            row = [
                name,
                f"{score.ses_score:.1f}/10",
                f"[{level_color}]{score.ses_level.upper()}[/{level_color}]",
                score.action,
            ]
            
            if detailed:
                components = score.components
                row.extend([
                    f"{components.get('severity', 0):.0f}",
                    f"{components.get('exploitability', 0):.0f}",
                    ", ".join(score.vulnerabilities[:3]) or "-",
                ])
            
            table.add_row(*row)
        
        console.print(table)
        
        if has_issues:
            console.print("\n[yellow]⚠️  Security exposure detected. Review actions above.[/yellow]")
            sys.exit(1)
        else:
            console.print("\n[green]✅ All packages have minimal security exposure.[/green]")
            sys.exit(0)
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@main.command()
@click.option("--output", "-o", "output_file",
              type=click.Path(),
              default=".sca.yaml",
              help="Output configuration file path")
def init(output_file: str):
    """
    Initialize a configuration file.
    """
    try:
        config = Config()
        config.save_to_file(Path(output_file))
        console.print(f"[green]Configuration file created: {output_file}[/green]")
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


@main.command()
@click.argument("project_path", type=click.Path(exists=True))
@click.option("--depth", "-d", type=int, default=3,
              help="Maximum depth to traverse (default: 3)")
def tree(project_path: str, depth: int):
    """
    Show dependency tree with transitive dependencies.
    
    PROJECT_PATH: Path to the project directory to scan
    """
    try:
        from .scanners.dependency_tree import DependencyTreeScanner
        from .parsers.pip_parser import PipParser
        from .core.models import Ecosystem
        
        config = Config()
        parser = PipParser()
        tree_scanner = DependencyTreeScanner(config)
        
        # Parse dependencies
        project = Path(project_path)
        dependencies = []
        
        if (project / "requirements.txt").exists():
            dependencies.extend(parser.parse(project / "requirements.txt"))
        if (project / "pyproject.toml").exists():
            dependencies.extend(parser.parse_pyproject(project / "pyproject.toml"))
        
        if not dependencies:
            console.print("[yellow]No dependencies found[/yellow]")
            sys.exit(0)
        
        console.print(f"\n[bold blue]Dependency Tree[/bold blue] (depth: {depth})\n")
        
        # Build and display tree
        dep_tree = tree_scanner.build_tree(dependencies, max_depth=depth)
        ascii_tree = tree_scanner.format_tree_ascii(dep_tree)
        console.print(ascii_tree)
        
        # Show stats
        stats = tree_scanner.get_stats(dep_tree)
        console.print(f"\n[dim]Direct: {stats['direct_count']} | Transitive: {stats['transitive_count']} | Max Depth: {stats['max_depth']}[/dim]")
        
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()

