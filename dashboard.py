# dashboard.py

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

console = Console()

def print_banner():
    console.print(Panel("🦊 [bold cyan]ShadowFox AI Orkestrator[/bold cyan]", border_style="bold green"))

def show_phase(phase_name, status="Pokrećem..."):
    console.print(f"[bold white]{phase_name}[/bold white] → [yellow]{status}[/yellow]")

def success_phase(phase_name):
    console.print(f"[green]✔ {phase_name} završeno[/green]")

def error_phase(phase_name, err):
    console.print(f"[red]✖ {phase_name} neuspešno:[/red] {err}")
