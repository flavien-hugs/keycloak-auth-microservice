from fastapi import Security, HTTPException, Body, status

from src import router_factory
from src.model import schema
from src.utils import deps

from keycloak import exceptions

router = router_factory(
    prefix="/api/groups",
    tags=["Groups"],
    responses={404: {"description": "Not found"}},
)


@router.post(
    "",
    dependencies=[Security(deps.get_current_user)],
    summary="Create new group",
    status_code=status.HTTP_201_CREATED,
)
async def create(payload: schema.GroupSchemaBase = Body(...)):
    try:
        keycloak_admin = deps.get_keycloak_admin()
        payload = {"name": payload.name, "subGroups": payload.subgroups}
        ret = keycloak_admin.create_group(payload=payload)
    except exceptions.KeycloakPostError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err

    response = keycloak_admin.get_group(group_id=ret)
    return response


@router.get(
    "",
    dependencies=[Security(deps.get_current_user)],
    summary="Get all groups",
    status_code=status.HTTP_200_OK,
)
def get_groups():
    return deps.get_keycloak_admin().get_groups()


@router.get(
    "/{id}",
    dependencies=[Security(deps.get_current_user)],
    summary="Get single group",
    status_code=status.HTTP_200_OK,
)
async def get_group(id: str):
    try:
        response = deps.get_keycloak_admin().get_group(group_id=id)
    except exceptions.KeycloakGetError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.put(
    "/{id}",
    dependencies=[Security(deps.get_current_user)],
    summary="Update group",
    status_code=status.HTTP_200_OK,
)
def update_group(id: str, payload: schema.GroupSchemaBase = Body(...)):
    try:
        update_payload = {"name": payload.name, "subGroups": payload.subgroups}
        response = deps.get_keycloak_admin().update_group(
            group_id=id, payload=update_payload
        )
    except exceptions.KeycloakPutError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.delete(
    "/{id}",
    dependencies=[Security(deps.get_current_user)],
    summary="Delete group",
    status_code=status.HTTP_200_OK,
)
def delete_group(id: str):
    try:
        response = deps.get_keycloak_admin().delete_group(group_id=id)
    except exceptions.KeycloakDeleteError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.get(
    "/{id}/roles",
    dependencies=[Security(deps.get_current_user)],
    summary="Get all roles in group",
    status_code=status.HTTP_200_OK,
)
def get_group_realm_roles(id: str):
    try:
        response = deps.get_keycloak_admin().get_group_realm_roles(group_id=id)
    except exceptions.KeycloakGetError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.put(
    "/{id}/assign-roles",
    dependencies=[Security(deps.get_current_user)],
    summary="Assign roles in group",
    status_code=status.HTTP_200_OK,
)
def assign_group_realm_roles(id: str, payload: schema.RoleSchema):
    try:
        response = deps.get_keycloak_admin().assign_group_realm_roles(
            group_id=id, roles=payload
        )
    except exceptions.KeycloakPutError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response
