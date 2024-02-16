from fastapi import Security, HTTPException, Body, status

from src import router_factory
from src.model import schema
from src.utils import deps

from keycloak import exceptions

router = router_factory(
    prefix="/api/users",
    tags=["Users"],
    responses={404: {"description": "Not found"}},
)


@router.post(
    "",
    summary="Create new user",
    status_code=status.HTTP_201_CREATED,
)
async def create_user(data: schema.UserModel = Body(...)):
    try:
        payload = {
            "email": data.email,
            "username": data.username,
            "firstName": data.firstname,
            "lastName": data.lastname,
            "enabled": True,
            "emailVerified": True,
            "credentials": [{"type": "password", "value": data.password}],
            "attributes": {"locale": ["fr"]},
        }
        keycloak_admin = deps.get_keycloak_admin()
        new_user = keycloak_admin.create_user(payload, exist_ok=False)
        response = keycloak_admin.get_user(new_user)
    except exceptions.KeycloakPostError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.get(
    "/{id}",
    dependencies=[Security(deps.get_current_user)],
    summary="Get Single User",
    status_code=status.HTTP_200_OK,
)
async def get_user(id: str):
    try:
        user = deps.get_keycloak_admin().get_user(id)
    except exceptions.KeycloakGetError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return user


@router.get(
    "",
    dependencies=[Security(deps.get_current_user)],
    summary="Get all users",
    status_code=status.HTTP_200_OK,
)
async def get_users():
    users = deps.get_keycloak_admin().get_users({})
    data = [user for user in users]
    return data


@router.patch(
    "/{id}",
    dependencies=[Security(deps.get_current_user)],
    summary="Update user information",
    status_code=status.HTTP_200_OK,
)
def update_user(id: str, payload: schema.UserBaseModel = Body(...)):
    try:
        update_data = {
            "email": payload.email,
            "lastName": payload.lastname,
            "firstName": payload.firstname,
        }
        keycloak_admin = deps.get_keycloak_admin()
        response = keycloak_admin.update_user(user_id=id, payload=update_data)
    except exceptions.KeycloakPutError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.delete(
    "/{id}",
    dependencies=[Security(deps.get_current_user)],
    summary="Delete User",
    status_code=status.HTTP_200_OK,
)
async def delete_user(id: str):
    try:
        response = deps.get_keycloak_admin().delete_user(user_id=id)
    except exceptions.KeycloakDeleteError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.get(
    "/{id}/roles",
    dependencies=[Security(deps.get_current_user)],
    summary="Get roles of user",
    status_code=status.HTTP_200_OK,
)
async def get_roles_of_user(id: str):
    try:
        response = deps.get_keycloak_admin().get_realm_roles_of_user(user_id=id)
    except exceptions.KeycloakGetError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.get(
    "/{id}/groups",
    dependencies=[Security(deps.get_current_user)],
    summary="Get groups of user",
    status_code=status.HTTP_200_OK,
)
async def get_groups_of_user(id: str):
    try:
        response = deps.get_keycloak_admin().get_user_groups(user_id=id)
    except exceptions.KeycloakGetError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.put(
    "/{id}/assign-roles",
    dependencies=[Security(deps.get_current_user)],
    summary="Assign roles to user",
    status_code=status.HTTP_200_OK,
)
def assign_role_to_user(id: str, payload: schema.RoleSchema = Body(...)):
    try:
        response = deps.get_keycloak_admin().assign_realm_roles(
            user_id=id, roles=payload
        )
    except exceptions.KeycloakPutError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.put(
    "/{id}/remove-roles",
    dependencies=[Security(deps.get_current_user)],
    summary="Remove roles to user",
    status_code=status.HTTP_200_OK,
)
def remove_role_to_user(id: str, payload: schema.RoleSchema = Body(...)):
    try:
        response = deps.get_keycloak_admin().delete_realm_roles_of_user(
            user_id=id, roles=payload
        )
    except exceptions.KeycloakPutError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.put(
    "/{id}/assign-group/{group_id}",
    dependencies=[Security(deps.get_current_user)],
    summary="Assign group to user",
    status_code=status.HTTP_200_OK,
)
def assign_group_to_user(id: str, group_id: str):
    try:
        response = deps.get_keycloak_admin().group_user_add(
            user_id=id, group_id=group_id
        )
    except exceptions.KeycloakPutError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.put(
    "/{id}/remove-group/{group_id}",
    dependencies=[Security(deps.get_current_user)],
    summary="Remove user in group",
    status_code=status.HTTP_200_OK,
)
def remove_user_to_group(id: str, group_id: str):
    try:
        response = deps.get_keycloak_admin().group_user_remove(
            user_id=id, group_id=group_id
        )

        print("response --> ", response)
    except exceptions.KeycloakPutError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response
