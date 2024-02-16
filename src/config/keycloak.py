from pydantic import Field
from .base import APPBaseSettings


class KeyCloakSettings(APPBaseSettings):
    server_url: str = Field(..., env="KEYCLOAK_SERVER_URL")
    admin_username: str = Field(..., env="KEYCLOAK_USER")
    admin_password: str = Field(..., env="KEYCLOAK_PASSWORD")
    admin_realm_name: str = Field(..., env="KEYCLOAK_ADMIN_REALM_NAME")
    admin_client_id: str = Field(..., env="KEYCLOAK_ADMIN_CLIENT_ID")
    admin_secret_key: str = Field(..., env="KEYCLOAK_ADMIN_SECRET_KEY")
    authorization_url: str = Field(..., env="KEYCLOAK_AUTHORIZATION_URL")
    token_endpoint: str = Field(..., env="KEYCLOAK_TOKEN_ENDPOINT")


settings = KeyCloakSettings()
