from fastapi import Security, HTTPException, Depends, Body

from src.services import router_factory
from src.services.auth import schema
from src.services.commun import deps

from keycloak import KeycloakAdmin, exceptions

router = router_factory(
    prefix="/api/auth",
    tags=["Auth"],
    responses={404: {"description": "Not found"}},
)


@router.get("/@ping")
def ping():
    return {"msg": "healthy"}


@router.post("/login", summary="Login")
def login(
    payload: schema.LoginModel,
    keycloak_admin: KeycloakAdmin = Depends(deps.get_keycloak_admin),
):
    ret = deps.user_login(payload.username, payload.password)
    return ret


@router.post("/users", summary="Create new user")
async def create_user(
    user: schema.AuthModel,
    keycloak_admin: KeycloakAdmin = Depends(deps.get_keycloak_admin),
):
    try:
        payload = {
            "username": user.username,
            "firstName": user.firstname,
            "lastName": user.lastname,
            "enabled": True,
            "emailVerified": True,
            "credentials": [{"type": "password", "value": user.password}],
            "attributes": {"locale": ["fr"], "loan_users": True},
        }
        new_user = keycloak_admin.create_user(payload, exist_ok=False)
        response = keycloak_admin.get_user(new_user)
    except exceptions.KeycloakPostError as err:
        raise HTTPException(status_code=400, detail=str(err)) from err
    return response


@router.get(
    "/users/{user_id}",
    dependencies=[Security(deps.get_current_user)],
    summary="Get Single User",
)
async def get_user(
    user_id: str,
    keycloak_admin: KeycloakAdmin = Depends(deps.get_keycloak_admin),
):
    try:
        user = keycloak_admin.get_user(user_id)
    except exceptions.KeycloakGetError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return user


@router.get(
    "/users", dependencies=[Security(deps.get_current_user)], summary="Get all users"
)
async def get_users(keycloak_admin: KeycloakAdmin = Depends(deps.get_keycloak_admin)):
    users = keycloak_admin.get_users({})
    data = [user for user in users if "loan_users" in user.get("attributes", {})]
    return data


@router.delete(
    "/users/{user_id}",
    dependencies=[Security(deps.get_current_user)],
    summary="Delete User",
)
async def delete_user(
    user_id: str, keycloak_admin: KeycloakAdmin = Depends(deps.get_keycloak_admin)
):
    try:
        response = keycloak_admin.delete_user(user_id=user_id)
    except exceptions.KeycloakDeleteError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.get(
    "/users/{user_id}/roles",
    dependencies=[Security(deps.get_current_user)],
    summary="Get roles of user",
)
async def get_roles_of_user(
    user_id: str, keycloak_admin: KeycloakAdmin = Depends(deps.get_keycloak_admin)
):
    try:
        response = keycloak_admin.get_realm_roles_of_user(user_id=user_id)
    except exceptions.KeycloakGetError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.get(
    "/users/{user_id}/groups",
    dependencies=[Security(deps.get_current_user)],
    summary="Get groups of user",
)
async def get_groups_of_user(
    user_id: str, keycloak_admin: KeycloakAdmin = Depends(deps.get_keycloak_admin)
):
    try:
        response = keycloak_admin.get_user_groups(user_id=user_id)
    except exceptions.KeycloakGetError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.put(
    "/users/{user_id}/assign-roles",
    dependencies=[Security(deps.get_current_user)],
    summary="Assign roles to user",
)
def assign_role_to_user(
    user_id: str,
    payload: schema.RoleSchema,
    keycloak_admin: KeycloakAdmin = Depends(deps.get_keycloak_admin),
):
    try:
        response = keycloak_admin.assign_realm_roles(user_id=user_id, roles=payload)
    except exceptions.KeycloakPutError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.put(
    "/users/{user_id}/assign-group",
    dependencies=[Security(deps.get_current_user)],
    summary="Assign group to user",
)
def assign_group_to_user(
    user_id: str,
    group_id: str,
    keycloak_admin: KeycloakAdmin = Depends(deps.get_keycloak_admin),
):
    try:
        payload = {"group_id": group_id}
        response = keycloak_admin.group_user_add(user_id=user_id, **payload)
    except exceptions.KeycloakPutError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.delete(
    "/users/{user_id}/remove-group",
    dependencies=[Security(deps.get_current_user)],
    summary="Remove user in group",
)
def group_user_remove(
    user_id: str,
    group_id: str,
    keycloak_admin: KeycloakAdmin = Depends(deps.get_keycloak_admin),
):
    try:
        payload = {"group_id": group_id}
        response = keycloak_admin.group_user_remove(user_id=user_id, **payload)
    except exceptions.KeycloakDeleteError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.post(
    "/groups",
    dependencies=[Security(deps.get_current_user)],
    summary="Create new group",
)
async def create_group(
    payload: schema.GroupSchema,
    keycloak_admin: KeycloakAdmin = Depends(deps.get_keycloak_admin),
):
    try:
        payload = {"name": payload.name, "subGroups": payload.subgroups}
        ret = keycloak_admin.create_group(payload=payload)
        response = keycloak_admin.get_group(group_id=ret)
    except exceptions.KeycloakPostError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.get(
    "/groups", dependencies=[Security(deps.get_current_user)], summary="Get all groups"
)
async def get_groups(keycloak_admin: KeycloakAdmin = Depends(deps.get_keycloak_admin)):
    return keycloak_admin.get_groups()


@router.get(
    "/groups/{group_id}/roles",
    dependencies=[Security(deps.get_current_user)],
    summary="Get all roles in group",
)
def get_group_realm_roles(
    group_id: str, keycloak_admin: KeycloakAdmin = Depends(deps.get_keycloak_admin)
):
    try:
        response = keycloak_admin.get_group_realm_roles(group_id=group_id)
    except exceptions.KeycloakGetError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.put(
    "/groups/{group_id}/assign-roles",
    dependencies=[Security(deps.get_current_user)],
    summary="Assign roles in group",
)
def assign_group_realm_roles(
    group_id: str,
    payload: schema.RoleSchema,
    keycloak_admin: KeycloakAdmin = Depends(deps.get_current_user),
):
    try:
        response = keycloak_admin.assign_group_realm_roles(
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
async def get_group(
    group_id: str, keycloak_admin: KeycloakAdmin = Depends(deps.get_keycloak_admin)
):
    try:
        response = keycloak_admin.get_group(group_id=group_id)
    except exceptions.KeycloakGetError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.put(
    "/groups/{group_id}",
    dependencies=[Security(deps.get_current_user)],
    summary="Update group",
)
def update_group(
    group_id: str,
    payload: schema.GroupSchema = Body(...),
    keycloak_admin: KeycloakAdmin = Depends(deps.get_keycloak_admin),
):
    try:
        update_payload = {"name": payload.name, "subGroups": payload.subgroups}
        response = keycloak_admin.update_group(
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
def delete_group(
    group_id: str, keycloak_admin: KeycloakAdmin = Depends(deps.get_keycloak_admin)
):
    try:
        response = keycloak_admin.delete_group(group_id=group_id)
    except exceptions.KeycloakDeleteError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.get(
    "/roles", dependencies=[Security(deps.get_current_user)], summary="Get all roles"
)
async def get_roles(keycloak_admin: KeycloakAdmin = Depends(deps.get_keycloak_admin)):
    return keycloak_admin.get_realm_roles()


@router.post(
    "/roles", dependencies=[Security(deps.get_current_user)], summary="Create roles"
)
async def create_roles(
    payload: schema.BaseRoleSchema,
    keycloak_admin: KeycloakAdmin = Depends(deps.get_keycloak_admin),
):
    try:
        payload = {
            "name": payload.name,
            "description": payload.description,
            "composite": payload.composite,
            "clientRole": payload.client_role,
        }
        ret = keycloak_admin.create_realm_role(payload=payload)
        response = keycloak_admin.get_realm_role(role_name=ret)
    except exceptions.KeycloakPostError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.get(
    "/roles/{role_name}",
    dependencies=[Security(deps.get_current_user)],
    summary="Get single role",
)
async def get_role_by_name(
    role_name: str, keycloak_admin: KeycloakAdmin = Depends(deps.get_keycloak_admin)
):
    try:
        response = keycloak_admin.get_realm_role(role_name=role_name)
    except exceptions.KeycloakGetError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response


@router.put(
    "/roles/{role_name}",
    dependencies=[Security(deps.get_current_user)],
    summary="Update role",
)
async def update_role(
    role_name: str,
    payload: schema.UpdateRoleSchema,
    keycloak_admin: KeycloakAdmin = Depends(deps.get_keycloak_admin),
):
    try:
        role_payload = {
            "name": payload.name,
            "description": payload.description,
            "composite": payload.composite,
            "clientRole": payload.client_role,
        }
        response = keycloak_admin.update_realm_role(
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
async def delete_role(
    role_name: str, keycloak_admin: KeycloakAdmin = Depends(deps.get_keycloak_admin)
):
    try:
        response = keycloak_admin.delete_realm_role(role_name=role_name)
    except exceptions.KeycloakDeleteError as err:
        raise HTTPException(status_code=err.response_code, detail=str(err)) from err
    return response
