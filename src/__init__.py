from fastapi import FastAPI, APIRouter


def router_factory(**kwargs) -> APIRouter:
    router = APIRouter(**kwargs)
    return router


class AppAPI(FastAPI):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
