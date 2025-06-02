# vuln_mapper.py

def build_vulnerability_map(report_data):
    rows = []

    # RECON
    recon = report_data.get("recon", {})
    if recon.get("open_ports"):
        rows.append(("RECON", "✅", "Open Ports", str(recon["open_ports"]), "-"))
    else:
        rows.append(("RECON", "❌", "-", "-", "-"))

    # MUTATE
    mutations = report_data.get("mutated", [])
    if mutations:
        top = sorted(mutations, key=lambda m: m.bypass_score, reverse=True)[0]
        rows.append(("MUTATE", "✅", "XSS Obfuscation", top.mutated, top.bypass_score))
    else:
        rows.append(("MUTATE", "❌", "-", "-", "-"))

    # JWT
    jwt = report_data.get("jwt", {})
    if jwt and "demo" not in str(jwt):
        rows.append(("JWT", "✅", "Token Manipulation", str(jwt), "-"))
    else:
        rows.append(("JWT", "❌", "-", "-", "-"))

    # EXPORT
    rows.append(("REPORT", "✅", "Sačuvan", "shadowfox_report.pdf", "-"))

    return rows

def print_vuln_table(rows):
    from rich.table import Table
    from rich.console import Console
    console = Console()

    table = Table(title="🛡️ ShadowFox Vulnerability Map")

    table.add_column("Faza", style="cyan", no_wrap=True)
    table.add_column("Status", style="bold")
    table.add_column("Tip", style="magenta")
    table.add_column("Detalj", overflow="fold")
    table.add_column("Score", justify="right")

    for row in rows:
        table.add_row(*[str(c) for c in row])

    console.print(table)
