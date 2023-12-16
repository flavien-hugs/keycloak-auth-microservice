from starlette import status
from starlette.requests import Request

from fastapi import HTTPException
from fastapi.security import HTTPBearer
from keycloak import KeycloakOpenID, KeycloakOpenIDConnection, KeycloakAdmin, exceptions

from src.config.keycloak import settings as keycloak_env


def get_keycloak_openid() -> KeycloakOpenID:
    try:
        openid = KeycloakOpenID(
            server_url=f"{keycloak_env.server_url}/auth/",
            realm_name=keycloak_env.admin_realm_name,
            client_id=keycloak_env.admin_client_id,
            client_secret_key=keycloak_env.admin_secret_key,
            verify=True,
        )
        openid.well_known()
    except (exceptions.KeycloakConnectionError, exceptions.KeycloakError) as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(err),
        ) from err
    return openid


def get_keycloak_admin() -> KeycloakAdmin:
    try:
        conn = KeycloakOpenIDConnection(
            server_url=f"{keycloak_env.server_url}/auth/",
            username=keycloak_env.admin_username,
            password=keycloak_env.admin_password,
            realm_name=keycloak_env.admin_realm_name,
            client_id=keycloak_env.admin_client_id,
            client_secret_key=keycloak_env.admin_secret_key,
            verify=True,
        )
        keycloak_admin = KeycloakAdmin(connection=conn)
    except (exceptions.KeycloakConnectionError, exceptions.KeycloakError) as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(err),
        ) from err
    return keycloak_admin


def user_login(username: str, password: str) -> dict:
    try:
        keycloak_openid = get_keycloak_openid()
        token = keycloak_openid.token(username=username, password=password)
        userinfo = keycloak_openid.userinfo(token["access_token"])
    except (
        exceptions.KeycloakConnectionError,
        exceptions.KeycloakAuthenticationError,
    ) as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=str(err)
        ) from err
    return {"token": token, "user_info": userinfo}


def user_logout(refresh_token: str) -> dict[str, str]:
    try:
        token = get_keycloak_openid().logout(refresh_token)
    except exceptions.KeycloakInvalidTokenError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)
        ) from err
    return token


def user_refresh_token(refresh_token: str) -> dict[str, str]:
    try:
        token = get_keycloak_openid().refresh_token(refresh_token)
    except exceptions.KeycloakInvalidTokenError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(err)
        ) from err
    return token


class AuthTokenBearer(HTTPBearer):
    async def validate_token(self, token: str):
        if not (get_keycloak_openid().introspect(token))["active"]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="The access token is expired",
            )

    async def __call__(self, request: Request):
        if auth := await super().__call__(request=request):
            if not auth.scheme.lower() == "bearer":
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Schéma d'authentification non valide.",
                )

            await self.validate_token(auth.credentials)
            return auth.credentials

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="An access token is expected but has not been provided",
        )


get_current_user = AuthTokenBearer()


def check_group(token: str, group: str) -> bool:
    token_info = get_keycloak_openid().userinfo(token)
    if token_info["active"]:
        return "groups" in token_info and group in token_info["groups"]
    return False
