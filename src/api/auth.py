from fastapi import Security, HTTPException, Depends, Body, status

from src import router_factory
from src.model import schema
from src.utils import deps

from keycloak import exceptions

router = router_factory(
    prefix="/api/auth",
    tags=["Auth"],
    responses={404: {"description": "Not found"}},
)


@router.post("/login", summary="Login", status_code=status.HTTP_200_OK)
def login(payload: schema.LoginModel = Body(...)):
    return deps.user_login(payload.username, payload.password)


@router.put(
    "/change-password/{id}",
    dependencies=[Security(deps.get_current_user)],
    summary="Change password",
    status_code=status.HTTP_200_OK,
)
def change_passwaord(id: str, payload: schema.ChangePasswordUser = Body(...)):
    try:
        response = deps.get_keycloak_admin().set_user_password(
            user_id=id, password=payload.password, temporary=True
        )
    except exceptions.KeycloakPutError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.post(
    "/logout",
    dependencies=[Depends(deps.get_current_user)],
    summary="Logout",
    status_code=status.HTTP_200_OK,
)
async def logout(payload: schema.LogoutUser = Body(...)):
    return deps.user_logout(payload.refresh_token)
