import typer

from src.cli import service

app = typer.Typer(pretty_exceptions_show_locals=False)
app.add_typer(service.app, name="auth")


if __name__ == "__main__":
    app()
