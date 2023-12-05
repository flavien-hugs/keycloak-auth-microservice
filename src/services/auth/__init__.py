from src.services import AppAPI
from src.services.auth import api


app = AppAPI(
    title="Auth API", openapi_url="/api/auth/openapi.json", docs_url="/api/auth/docs"
)

# add the routers
app.include_router(api.router)


@app.get("/")
async def read_root() -> dict:
    return {"message": "App API"}
