from fastapi import Security, HTTPException, Depends, Body

from src.services import router_factory
from src.services.auth import schema
from src.utils import deps

from keycloak import KeycloakAdmin, exceptions

router = router_factory(
    prefix="/api/auth",
    tags=["Auth"],
    responses={404: {"description": "Not found"}},
)


@router.get("/@ping")
def ping():
    return {"msg": "pong !"}


@router.post("/login", summary="Login")
def login(payload: schema.LoginModel = Body(...)):
    ret = deps.user_login(payload.username, payload.password)
    return ret


@router.post("/users", summary="Create new user")
async def create_user(data: schema.AuthModel = Body(...)):
    try:
        payload = {
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
    "/users/{user_id}",
    dependencies=[Security(deps.get_current_user)],
    summary="Get Single User",
)
async def get_user(user_id: str):
    try:
        user = deps.get_keycloak_admin().get_user(user_id)
    except exceptions.KeycloakGetError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return user


@router.get(
    "/users", dependencies=[Security(deps.get_current_user)], summary="Get all users"
)
async def get_users():
    users = deps.get_keycloak_admin().get_users({})
    data = [user for user in users]
    return data


@router.delete(
    "/users/{user_id}",
    dependencies=[Security(deps.get_current_user)],
    summary="Delete User",
)
async def delete_user(user_id: str):
    try:
        response = deps.get_keycloak_admin().delete_user(user_id=user_id)
    except exceptions.KeycloakDeleteError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.get(
    "/users/{user_id}/roles",
    dependencies=[Security(deps.get_current_user)],
    summary="Get roles of user",
)
async def get_roles_of_user(user_id: str):
    try:
        response = deps.get_keycloak_admin().get_realm_roles_of_user(user_id=user_id)
    except exceptions.KeycloakGetError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.get(
    "/users/{user_id}/groups",
    dependencies=[Security(deps.get_current_user)],
    summary="Get groups of user",
)
async def get_groups_of_user(user_id: str):
    try:
        response = deps.get_keycloak_admin().get_user_groups(user_id=user_id)
    except exceptions.KeycloakGetError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.put(
    "/users/{user_id}/assign-roles",
    dependencies=[Security(deps.get_current_user)],
    summary="Assign roles to user",
)
def assign_role_to_user(user_id: str, payload: schema.RoleSchema = Body(...)):
    try:
        response = deps.get_keycloak_admin().assign_realm_roles(
            user_id=user_id, roles=payload
        )
    except exceptions.KeycloakPutError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.put(
    "/users/{user_id}/remove-roles",
    dependencies=[Security(deps.get_current_user)],
    summary="Remove roles to user",
)
def remove_role_to_user(user_id: str, payload: schema.RoleSchema = Body(...)):
    try:
        response = deps.get_keycloak_admin().delete_realm_roles_of_user(
            user_id=user_id, roles=payload
        )
    except exceptions.KeycloakPutError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.put(
    "/users/{user_id}/assign-group/{groupe_id}",
    dependencies=[Security(deps.get_current_user)],
    summary="Assign group to user",
)
def assign_group_to_user(user_id: str, groupe_id: str):
    try:
        response = deps.get_keycloak_admin().group_user_add(
            user_id=user_id, group_id=groupe_id
        )
    except exceptions.KeycloakPutError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.put(
    "/users/{user_id}/remove-group/{group_id}",
    dependencies=[Security(deps.get_current_user)],
    summary="Remove user in group",
)
def group_user_remove(user_id: str, group_id: str):
    try:
        response = deps.get_keycloak_admin().group_user_remove(
            user_id=user_id, group_id=group_id
        )
    except exceptions.KeycloakPutError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.post(
    "/groups",
    dependencies=[Security(deps.get_current_user)],
    summary="Create new group",
)
async def create_group(payload: schema.GroupSchemaBase = Body(...)):
    try:
        keycloak_admin = deps.get_keycloak_admin()
        payload = {"name": payload.name, "subGroups": payload.subgroups}
        ret = keycloak_admin.create_group(payload=payload)
    except exceptions.KeycloakPostError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err

    response = keycloak_admin.get_group(group_id=ret)
    return response


@router.get(
    "/groups", dependencies=[Security(deps.get_current_user)], summary="Get all groups"
)
async def get_groups():
    return deps.get_keycloak_admin().get_groups()


@router.get(
    "/groups/{group_id}/roles",
    dependencies=[Security(deps.get_current_user)],
    summary="Get all roles in group",
)
def get_group_realm_roles(group_id: str):
    try:
        response = deps.get_keycloak_admin().get_group_realm_roles(group_id=group_id)
    except exceptions.KeycloakGetError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.put(
    "/groups/{group_id}/assign-roles",
    dependencies=[Security(deps.get_current_user)],
    summary="Assign roles in group",
)
def assign_group_realm_roles(group_id: str, payload: schema.RoleSchema):
    try:
        response = deps.get_keycloak_admin().assign_group_realm_roles(
            group_id=group_id, roles=payload
        )
    except exceptions.KeycloakPutError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.get(
    "/groups/{group_id}",
    dependencies=[Security(deps.get_current_user)],
    summary="Get single group",
)
async def get_group(group_id: str):
    try:
        response = deps.get_keycloak_admin().get_group(group_id=group_id)
    except exceptions.KeycloakGetError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.put(
    "/groups/{group_id}",
    dependencies=[Security(deps.get_current_user)],
    summary="Update group",
)
def update_group(group_id: str, payload: schema.GroupSchemaBase = Body(...)):
    try:
        update_payload = {"name": payload.name, "subGroups": payload.subgroups}
        response = deps.get_keycloak_admin().update_group(
            group_id=group_id, payload=update_payload
        )
    except exceptions.KeycloakPutError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.delete(
    "/groups/{group_id}",
    dependencies=[Security(deps.get_current_user)],
    summary="Delete group",
)
def delete_group(group_id: str):
    try:
        response = deps.get_keycloak_admin().delete_group(group_id=group_id)
    except exceptions.KeycloakDeleteError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.get(
    "/roles", dependencies=[Security(deps.get_current_user)], summary="Get all roles"
)
async def get_roles():
    return deps.get_keycloak_admin().get_realm_roles()


@router.post(
    "/roles", dependencies=[Security(deps.get_current_user)], summary="Create roles"
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
    "/roles/{role_name}",
    dependencies=[Security(deps.get_current_user)],
    summary="Get single role",
)
async def get_role(role_name: str):
    try:
        response = deps.get_keycloak_admin().get_realm_role(role_name=role_name)
    except exceptions.KeycloakGetError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.put(
    "/roles/{role_name}",
    dependencies=[Security(deps.get_current_user)],
    summary="Update role",
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
    "/roles/{role_name}",
    dependencies=[Security(deps.get_current_user)],
    summary="Delete role",
)
async def delete_role(role_name: str):
    try:
        response = deps.get_keycloak_admin().delete_realm_role(role_name=role_name)
    except exceptions.KeycloakDeleteError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.post("/logout", dependencies=[Depends(deps.get_current_user)])
async def logout_user(payload: schema.LogoutUser):
    return deps.user_logout(payload.refresh_token)
