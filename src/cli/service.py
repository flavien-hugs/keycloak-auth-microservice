import typer
import uvicorn

app = typer.Typer()


@app.command()
def runserver():
    uvicorn.run(
        "src.services.auth:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="debug",
        access_log=False,
    )


if __name__ == "__main__":
    runserver()
