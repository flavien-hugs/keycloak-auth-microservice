from pydantic import BaseSettings, Field


class APPBaseSettings(BaseSettings):

    port: int = Field(default=8000, env="APP_PORT")
    host: str = Field(default="0.0.0.0", env="APP_HOST")
    reload: bool = Field(default=True, env="APP_RELOAD")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = APPBaseSettings()
