import typer
import uvicorn

from src.config.base import settings

app = typer.Typer(pretty_exceptions_enable=False)


@app.command()
def run():
    uvicorn.run(
        "src.api:app",  # noqa: E231
        host=settings.host,
        port=settings.port,
        reload=settings.reload,
        log_level="debug",
        access_log=False,
    )


if __name__ == "__main__":
    app()
