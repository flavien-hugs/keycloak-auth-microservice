from fastapi import Security, HTTPException, Body, status

from src import router_factory
from src.model import schema
from src.utils import deps

from keycloak import exceptions

router = router_factory(
    prefix="/api/roles",
    tags=["Roles"],
    responses={404: {"description": "Not found"}},
)


@router.post(
    "",
    dependencies=[Security(deps.get_current_user)],
    summary="Create roles",
    status_code=status.HTTP_201_CREATED,
)
async def create_roles(payload: schema.BaseRoleSchema = Body(...)):
    try:
        payload = {
            "name": payload.name,
            "description": payload.description,
            "composite": payload.composite,
            "clientRole": payload.client_role,
        }
        ret = deps.get_keycloak_admin().create_realm_role(payload=payload)
    except exceptions.KeycloakPostError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    response = deps.get_keycloak_admin().get_realm_role(role_name=ret)
    return response


@router.get(
    "",
    dependencies=[Security(deps.get_current_user)],
    summary="Get all roles",
    status_code=status.HTTP_200_OK,
)
async def get_roles():
    return deps.get_keycloak_admin().get_realm_roles()


@router.get(
    "/{role_name}",
    dependencies=[Security(deps.get_current_user)],
    summary="Get single role",
    status_code=status.HTTP_200_OK,
)
async def get_role(role_name: str):
    try:
        response = deps.get_keycloak_admin().get_realm_role(role_name=role_name)
    except exceptions.KeycloakGetError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.put(
    "/{role_name}",
    dependencies=[Security(deps.get_current_user)],
    summary="Update role",
    status_code=status.HTTP_200_OK,
)
async def update_role(role_name: str, payload: schema.UpdateRoleSchema):
    try:
        role_payload = {
            "name": payload.name,
            "description": payload.description,
            "composite": payload.composite,
            "clientRole": payload.client_role,
        }
        response = deps.get_keycloak_admin().update_realm_role(
            role_name=role_name, payload=role_payload
        )
    except exceptions.KeycloakPutError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.delete(
    "/{role_name}",
    dependencies=[Security(deps.get_current_user)],
    summary="Delete role",
    status_code=status.HTTP_200_OK,
)
async def delete_role(role_name: str):
    try:
        response = deps.get_keycloak_admin().delete_realm_role(role_name=role_name)
    except exceptions.KeycloakDeleteError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response
