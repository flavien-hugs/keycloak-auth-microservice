from src import AppAPI
from src.api import auth, users, groups, roles


app = AppAPI(
    title="Auth API", openapi_url="/api/auth/openapi.json", docs_url="/api/auth/docs"
)

# add the routers
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(groups.router)
app.include_router(roles.router)


@app.get("/")
async def read_root() -> dict:
    return {"message": "App API"}
