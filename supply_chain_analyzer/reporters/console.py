"""Console output reporter with colored output."""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from ..core.models import ScanResult, Severity


class ConsoleReporter:
    """Reporter that outputs results to the console with rich formatting."""
    
    SEVERITY_COLORS = {
        Severity.CRITICAL: "red bold",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.UNKNOWN: "white",
    }
    
    def __init__(self):
        """Initialize the console reporter."""
        self.console = Console()
    
    def report(self, result: ScanResult) -> None:
        """Print the scan results to the console."""
        self._print_header(result)
        self._print_summary(result)
        
        if result.vulnerabilities:
            self._print_vulnerabilities(result)
        
        if result.typosquat_matches:
            self._print_typosquats(result)
        
        if result.license_issues:
            self._print_license_issues(result)
        
        if result.reputation_scores:
            self._print_reputation_scores(result)
        
        self._print_footer(result)
    
    def _print_header(self, result: ScanResult) -> None:
        """Print the report header."""
        self.console.print()
        self.console.print(Panel.fit(
            "[bold blue]Supply Chain Security Analyzer[/bold blue]\n"
            f"[dim]Scan completed at {result.scan_time.strftime('%Y-%m-%d %H:%M:%S')}[/dim]",
            border_style="blue",
        ))
        self.console.print()
    
    def _print_summary(self, result: ScanResult) -> None:
        """Print the summary statistics."""
        table = Table(title="Scan Summary", box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Count", justify="right")
        
        table.add_row("Dependencies Scanned", str(result.total_dependencies))
        
        vuln_style = "red bold" if result.critical_vulnerabilities > 0 else "green"
        table.add_row(
            "Vulnerabilities Found",
            Text(str(result.total_vulnerabilities), style=vuln_style)
        )
        
        typo_style = "yellow" if result.typosquat_matches else "green"
        table.add_row(
            "Typosquatting Alerts",
            Text(str(len(result.typosquat_matches)), style=typo_style)
        )
        
        license_style = "yellow" if result.license_issues else "green"
        table.add_row(
            "License Issues",
            Text(str(len(result.license_issues)), style=license_style)
        )
        
        self.console.print(table)
        self.console.print()
    
    def _print_vulnerabilities(self, result: ScanResult) -> None:
        """Print vulnerability details."""
        table = Table(title="🔓 Vulnerabilities", box=box.ROUNDED)
        table.add_column("Package", style="cyan")
        table.add_column("ID", style="magenta")
        table.add_column("Severity")
        table.add_column("Summary", max_width=50)
        
        for dep_id, vulns in result.vulnerabilities.items():
            # Parse package name from dep_id (format: ecosystem:name@version)
            parts = dep_id.split(":")
            if len(parts) == 2:
                package_info = parts[1]
            else:
                package_info = dep_id
            
            for vuln in vulns:
                severity_style = self.SEVERITY_COLORS.get(vuln.severity, "white")
                table.add_row(
                    package_info,
                    vuln.id,
                    Text(vuln.severity.value.upper(), style=severity_style),
                    vuln.summary[:50] + "..." if len(vuln.summary) > 50 else vuln.summary,
                )
        
        self.console.print(table)
        self.console.print()
    
    def _print_typosquats(self, result: ScanResult) -> None:
        """Print typosquatting alerts."""
        table = Table(title="🎭 Typosquatting Alerts", box=box.ROUNDED)
        table.add_column("Suspicious Package", style="red")
        table.add_column("Similar To", style="green")
        table.add_column("Similarity", justify="right")
        table.add_column("Method")
        table.add_column("Risk", style="yellow")
        
        for match in result.typosquat_matches:
            risk_style = "red bold" if match.risk_level == "high" else "yellow"
            table.add_row(
                match.suspicious_package,
                match.legitimate_package,
                f"{match.similarity_score:.1%}",
                match.detection_method,
                Text(match.risk_level.upper(), style=risk_style),
            )
        
        self.console.print(table)
        self.console.print()
    
    def _print_license_issues(self, result: ScanResult) -> None:
        """Print license compliance issues."""
        table = Table(title="📜 License Issues", box=box.ROUNDED)
        table.add_column("Package", style="cyan")
        table.add_column("License", style="yellow")
        table.add_column("Type")
        
        for dep, license_info in result.license_issues:
            license_type = "Copyleft" if license_info.is_copyleft else "Non-Permissive"
            table.add_row(
                f"{dep.name}@{dep.version}",
                license_info.spdx_id,
                license_type,
            )
        
        self.console.print(table)
        self.console.print()
    
    def _print_reputation_scores(self, result: ScanResult) -> None:
        """Print package maturity scores (PMI)."""
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
        table.add_column("Factors", max_width=40)
        
        for name, score in result.maturity_scores.items():
            # Color code the score
            if score.overall_score >= 80:
                score_style = "green"
            elif score.overall_score >= 40:
                score_style = "yellow"
            else:
                score_style = "red"
            
            # Get maturity level
            maturity_level = getattr(score, 'maturity_level', 'emerging')
            maturity_style = MATURITY_COLORS.get(maturity_level, "white")
            
            # Show factors
            factors = score.factors
            if factors:
                factors_str = ", ".join(f"{k}:{v:.0f}" for k, v in factors.items())
            else:
                factors_str = "-"
            
            table.add_row(
                name,
                Text(f"{score.overall_score:.0f}/100", style=score_style),
                Text(maturity_level.upper(), style=maturity_style),
                factors_str,
            )
        
        self.console.print(table)
        self.console.print()
    
    def _print_footer(self, result: ScanResult) -> None:
        """Print the report footer."""
        if result.has_issues:
            self.console.print(Panel(
                "[yellow]⚠️  Security issues found. Please review the above findings.[/yellow]",
                border_style="yellow",
            ))
        else:
            self.console.print(Panel(
                "[green]✅ No security issues found![/green]",
                border_style="green",
            ))
        self.console.print()
