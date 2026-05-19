"""Display helpers using Rich for terminal output."""

from rich.console import Console
from rich.table import Table

console = Console()


def display_projects_table(projects: dict) -> None:
    """Display a table of GistSafe projects and their environments."""
    if not projects:
        console.print("[yellow]No GistSafe projects found")
        return

    table = Table(title="Available GistSafe Projects")
    table.add_column("Project", style="cyan")
    table.add_column("Environments", style="green")
    table.add_column("Gist URL", style="blue")

    for project, data in sorted(projects.items()):
        environments = ", ".join(sorted(data["environments"].keys()))
        table.add_row(project, environments, data["gist_url"])

    console.print("\n[bold]Found GistSafe Projects:[/bold]")
    console.print(table)


def display_secrets_table(project: str, environment: str, secrets: dict) -> None:
    """Display decrypted secrets in a formatted table."""
    table = Table(title=f"Secrets for {project} - {environment}")
    table.add_column("Key", style="cyan")
    table.add_column("Value", style="green")

    for key, value in secrets.items():
        table.add_row(key, value)

    console.print(table)


def display_injection_table(project: str, environment: str, secrets: dict) -> None:
    """Display injected environment variables with masked values."""
    table = Table(title=f"Injected Environment Variables for {project} - {environment}")
    table.add_column("Environment Variable", style="cyan")
    table.add_column("Value", style="green")

    for key, value in secrets.items():
        display_value = value if len(value) <= 12 else f"{value[:4]}...{value[-4:]}"
        table.add_row(key.upper(), display_value)

    console.print(table)
