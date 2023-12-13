from unittest import mock
from fastapi import status
from keycloak import exceptions


def test_ping(http_client_auth):
    response = http_client_auth.get("/api/auth/@ping")
    assert response.status_code == status.HTTP_200_OK
    response_json = response.json()
    assert "msg" in response_json
    assert response_json == {"msg": "pong !"}


def test_login_success(http_client_auth, mocker):
    mock_keycloak_openid = mocker.patch("src.utils.deps.KeycloakOpenID")
    mock_keycloak_open_con = mocker.patch("src.utils.deps.KeycloakOpenIDConnection")

    mock_token = mock.MagicMock()
    mock_openid_instance = mock_keycloak_openid.return_value
    mock_openid_instance.token.return_value = mock_token
    mock_openid_instance.userinfo.return_value = {"sub": "0123456"}

    mock_open_con_instance = mock_keycloak_open_con.return_value

    mock_response = mock.MagicMock()
    mock_open_con_instance.raw_get.return_value = mock_response

    payload = {
        "username": "incubtek",
        "password": "incubtek",
    }
    response = http_client_auth.post("/api/auth/login", json=payload)
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"token": {}, "user_info": {"sub": "0123456"}}
    mock_openid_instance.token.assert_called_once_with(
        username=payload["username"], password=payload["password"]
    )


def test_create_user_success(http_client_auth, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value

    payload = {
        "username": "john",
        "firstname": "John",
        "lastname": "Doe",
        "email": "flavienhugs@pm.me",
        "password": "password",
    }

    response = http_client_auth.post("/api/auth/users", json=payload)
    assert response.status_code == status.HTTP_200_OK
    mock_keycloak_instance.create_user.assert_called_once_with(
        {
            "username": "john",
            "firstName": "John",
            "lastName": "Doe",
            "email": "flavienhugs@pm.me",
            "enabled": True,
            "emailVerified": True,
            "credentials": [{"type": "password", "value": "password"}],
            "attributes": {"locale": ["fr"]},
        },
        exist_ok=False,
    )
    mock_keycloak_instance.get_user.assert_called_once_with(
        mock_keycloak_instance.create_user.return_value
    )
    mock_keycloak_instance.create_user.assert_called_once()


def test_create_user_failure(http_client_auth, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value

    payload = {
        "username": "john",
        "firstname": "John",
        "lastname": "Doe",
        "email": "flavienhugs@pm.me",
        "password": "password",
    }

    mock_keycloak_instance.create_user.side_effect = exceptions.KeycloakPostError(
        response_code=status.HTTP_400_BAD_REQUEST, error_message="User creation failed"
    )

    response = http_client_auth.post("/api/auth/users", json=payload)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json() == {"detail": "400: User creation failed"}

    mock_keycloak_instance.create_user.assert_called_once_with(
        {
            "username": "john",
            "firstName": "John",
            "lastName": "Doe",
            "email": "flavienhugs@pm.me",
            "enabled": True,
            "emailVerified": True,
            "credentials": [{"type": "password", "value": "password"}],
            "attributes": {"locale": ["fr"]},
        },
        exist_ok=False,
    )
    mock_keycloak_instance.get_user.assert_not_called()


def test_get_users(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_admin.get_users.return_value = mock.MagicMock()
    response = http_client_auth.get("/api/auth/users", headers=authorization)
    assert response.status_code == 200
    assert response.json() == []


def test_get_user_success(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value
    mock_user = mock.MagicMock()
    mock_keycloak_instance.get_user.return_value = mock_user

    response = http_client_auth.get("/api/auth/users/0123", headers=authorization)
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {}

    mock_keycloak_instance.get_user.assert_called_once_with("0123")


def test_get_user_failure(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value

    mock_keycloak_instance.get_user.side_effect = exceptions.KeycloakGetError(
        response_code=status.HTTP_404_NOT_FOUND, error_message="User not found"
    )

    response = http_client_auth.get("/api/auth/users/0123", headers=authorization)

    mock_keycloak_instance.get_user.assert_called_once_with("0123")
    mock_keycloak_instance.get_user.assert_called_once()

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": "404: User not found"}


def test_update_user_success(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value

    payload = {"lastname": "Wick", "firstname": "Hugs", "email": "flavien@pm.me"}

    user_id = "0123456"
    response = http_client_auth.patch(
        f"/api/auth/users/{user_id}", json=payload, headers=authorization
    )

    mock_keycloak_instance.update_user.assert_called_once_with(
        user_id=user_id,
        payload={
            "lastName": payload["lastname"],
            "firstName": payload["firstname"],
            "email": payload["email"]
        },
    )
    mock_keycloak_instance.update_user.assert_called_once()
    assert response.status_code == status.HTTP_200_OK


def test_update_user_failure(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value

    mock_keycloak_instance.update_user.side_effect = exceptions.KeycloakPutError(
        response_code=status.HTTP_400_BAD_REQUEST, error_message="User update failed"
    )

    user_id = "0123456"
    payload = {"lastname": "Wick", "firstname": "Hugs", "email": "flavien@pm.me"}

    response = http_client_auth.patch(
        f"/api/auth/users/{user_id}", json=payload, headers=authorization
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json() == {"detail": "400: User update failed"}

    mock_keycloak_instance.update_user.assert_called_once_with(
        user_id=user_id,
        payload={
            "lastName": payload["lastname"],
            "firstName": payload["firstname"],
            "email": payload["email"]
        }
    )
    mock_keycloak_instance.get_user.assert_not_called()


def test_update_user_passwaord_success(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value

    payload = {"password": "change-password"}

    user_id = "0123456"
    response = http_client_auth.put(
        f"/api/auth/change-password/{user_id}", json=payload, headers=authorization
    )

    mock_keycloak_instance.set_user_password.assert_called_once_with(
        user_id=user_id,
        password=payload["password"],
        temporary=True
    )
    mock_keycloak_instance.set_user_password.assert_called_once()
    assert response.status_code == status.HTTP_200_OK


def test_update_user_passwaord_failure(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value

    mock_keycloak_instance.set_user_password.side_effect = exceptions.KeycloakPutError(
        response_code=status.HTTP_400_BAD_REQUEST, error_message="Change user password failed"
    )

    user_id = "0123456"
    payload = {"password": "change-password"}

    response = http_client_auth.put(
        f"/api/auth/change-password/{user_id}", json=payload, headers=authorization
    )
    mock_keycloak_instance.set_user_password.assert_called_once_with(
        user_id=user_id,
        password=payload["password"],
        temporary=True
    )
    mock_keycloak_instance.set_user_password.assert_called_once()

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json() == {"detail": "400: Change user password failed"}


def test_delete_user_success(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value

    user_id = "0123456"
    response = http_client_auth.delete(
        f"/api/auth/users/{user_id}", headers=authorization
    )
    mock_keycloak_instance.delete_user.assert_called_once_with(user_id=user_id)
    mock_keycloak_instance.delete_user.assert_called_once()
    assert response.status_code == status.HTTP_200_OK


def test_delete_user_failure(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value

    user_id = "123456"

    mock_keycloak_instance.delete_user.side_effect = exceptions.KeycloakDeleteError(
        response_code=status.HTTP_404_NOT_FOUND, error_message="User not found"
    )

    response = http_client_auth.delete(
        f"/api/auth/users/{user_id}", headers=authorization
    )

    mock_keycloak_instance.delete_user.assert_called_once_with(user_id=user_id)
    mock_keycloak_instance.delete_user.assert_called_once()

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": "404: User not found"}


def test_get_roles_of_user_success(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value
    mock_keycloak_instance.get_realm_roles_of_user.return_value = ["role1", "role2"]

    user_id = "0123456"
    response = http_client_auth.get(
        f"/api/auth/users/{user_id}/roles", headers=authorization
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == ["role1", "role2"]

    mock_keycloak_instance.get_realm_roles_of_user.assert_called_once_with(
        user_id=user_id
    )


def test_get_roles_of_user_failure(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value
    mock_keycloak_instance.get_realm_roles_of_user.side_effect = (
        exceptions.KeycloakGetError(
            response_code=status.HTTP_404_NOT_FOUND, error_message="User not found"
        )
    )

    user_id = "0123456"
    response = http_client_auth.get(
        f"/api/auth/users/{user_id}/roles", headers=authorization
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": "404: User not found"}

    mock_keycloak_instance.get_realm_roles_of_user.assert_called_once_with(
        user_id=user_id
    )


def test_get_groups_of_user_success(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value
    mock_keycloak_instance.get_groups_of_user.return_value = {"group_1", "group_2"}

    user_id = "0123456"
    response = http_client_auth.get(
        f"/api/auth/users/{user_id}/groups", headers=authorization
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {}

    mock_keycloak_instance.get_user_groups.assert_called_once_with(user_id=user_id)


def test_get_groups_of_user_failure(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value
    mock_keycloak_instance.get_user_groups.side_effect = exceptions.KeycloakGetError(
        response_code=status.HTTP_404_NOT_FOUND, error_message="User not found"
    )

    user_id = "0123456"
    response = http_client_auth.get(
        f"/api/auth/users/{user_id}/groups", headers=authorization
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": "404: User not found"}

    mock_keycloak_instance.get_user_groups.assert_called_once_with(user_id=user_id)


def test_remove_role_to_user_success(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value

    user_id = "0123456"
    roles_payload = {"roles": ["role1", "role2"]}
    response = http_client_auth.put(
        f"/api/auth/users/{user_id}/remove-roles",
        json=roles_payload,
        headers=authorization,
    )
    assert response.status_code == status.HTTP_200_OK

    mock_keycloak_instance.delete_realm_roles_of_user.assert_called_once_with(
        user_id=user_id, roles=roles_payload
    )


def test_remove_role_to_user_failure(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value
    mock_keycloak_instance.delete_realm_roles_of_user.side_effect = (
        exceptions.KeycloakPutError(
            response_code=status.HTTP_400_BAD_REQUEST,
            error_message="Remove role failed",
        )
    )

    user_id = "0123456"
    roles_payload = {"roles": ["role1", "role2"]}
    response = http_client_auth.put(
        f"/api/auth/users/{user_id}/remove-roles",
        json=roles_payload,
        headers=authorization,
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json() == {"detail": "400: Remove role failed"}

    mock_keycloak_instance.delete_realm_roles_of_user.assert_called_once_with(
        user_id=user_id, roles=roles_payload
    )


def test_assign_role_to_user_success(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value
    mock_keycloak_instance.assign_realm_roles.return_value = {"success": True}

    user_id = "0123456"
    roles_payload = {"roles": ["role1", "role2"]}
    response = http_client_auth.put(
        f"/api/auth/users/{user_id}/assign-roles",
        json=roles_payload,
        headers=authorization,
    )
    assert response.status_code == status.HTTP_200_OK
    mock_keycloak_instance.assign_realm_roles.assert_called_once_with(
        user_id=user_id, roles=roles_payload
    )


def test_assign_role_to_user_failure(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value
    mock_keycloak_instance.assign_realm_roles.side_effect = exceptions.KeycloakPutError(
        response_code=status.HTTP_400_BAD_REQUEST,
        error_message="Role assignment failed",
    )
    user_id = "0123456"
    roles_payload = {"roles": ["role1", "role2"]}
    response = http_client_auth.put(
        f"/api/auth/users/{user_id}/assign-roles",
        json=roles_payload,
        headers=authorization,
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json() == {"detail": "400: Role assignment failed"}

    mock_keycloak_instance.assign_realm_roles.assert_called_once_with(
        user_id=user_id, roles=roles_payload
    )


def test_assign_group_to_user_success(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value

    user_id = "0123456"
    group_id = "0123456789"

    response = http_client_auth.put(
        f"/api/auth/users/{user_id}/assign-group/{group_id}", headers=authorization
    )
    assert response.status_code == status.HTTP_200_OK
    mock_keycloak_instance.group_user_add.assert_called_once_with(
        user_id=user_id, group_id=group_id
    )


def test_assign_group_to_user_failure(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value
    mock_keycloak_instance.group_user_add.side_effect = exceptions.KeycloakPutError(
        response_code=status.HTTP_400_BAD_REQUEST,
        error_message="Group assignment failed",
    )

    user_id = "0123456"
    group_id = "0123456789"

    response = http_client_auth.put(
        f"/api/auth/users/{user_id}/assign-group/{group_id}", headers=authorization
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    mock_keycloak_instance.group_user_add.assert_called_once_with(
        user_id=user_id, group_id=group_id
    )


def test_group_user_remove_success(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value

    user_id = "0123456"
    group_id = "0123456789"

    response = http_client_auth.put(
        f"/api/auth/users/{user_id}/remove-group/{group_id}", headers=authorization
    )
    assert response.status_code == status.HTTP_200_OK
    mock_keycloak_instance.group_user_remove.assert_called_once_with(
        user_id=user_id, group_id=group_id
    )


def test_group_user_remove_failure(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value
    mock_keycloak_instance.group_user_remove.side_effect = exceptions.KeycloakPutError(
        response_code=status.HTTP_400_BAD_REQUEST, error_message="Group remove failed"
    )

    user_id = "0123456"
    group_id = "0123456789"

    response = http_client_auth.put(
        f"/api/auth/users/{user_id}/remove-group/{group_id}", headers=authorization
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    mock_keycloak_instance.group_user_remove.assert_called_once_with(
        user_id=user_id, group_id=group_id
    )


def test_create_group_success(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value

    payload = {"name": "group_name", "subGroups": []}
    response = http_client_auth.post(
        "/api/auth/groups", json=payload, headers=authorization
    )
    assert response.status_code == status.HTTP_200_OK

    mock_keycloak_instance.create_group.assert_called_once_with(payload=payload)
    mock_keycloak_instance.get_group.assert_called_once_with(
        group_id=mock_keycloak_instance.create_group.return_value
    )
    mock_keycloak_instance.create_group.assert_called_once()


def test_create_group_failure(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value
    mock_keycloak_instance.create_group.side_effect = exceptions.KeycloakPostError(
        response_code=status.HTTP_400_BAD_REQUEST, error_message="Group creation failed"
    )

    payload = {"name": "group_name", "subGroups": []}

    response = http_client_auth.post(
        "/api/auth/groups", json=payload, headers=authorization
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json() == {"detail": "400: Group creation failed"}

    mock_keycloak_instance.create_group.assert_called_once_with(payload=payload)
    mock_keycloak_instance.get_group.assert_not_called()


def test_get_groups(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_admin.get_groups.return_value = mock.MagicMock()
    response = http_client_auth.get("/api/auth/groups", headers=authorization)
    assert response.status_code == 200
    assert response.json() == {}


def test_get_group_success(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value
    mock_keycloak_instance.get_group.return_value = "010101"

    response = http_client_auth.get("/api/auth/groups/010101", headers=authorization)
    assert response.status_code == status.HTTP_200_OK

    mock_keycloak_instance.get_group.assert_called_once_with(group_id="010101")


def test_get_group_failure(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value

    mock_keycloak_instance.get_group.side_effect = exceptions.KeycloakGetError(
        response_code=status.HTTP_404_NOT_FOUND, error_message="Group not found"
    )

    response = http_client_auth.get("/api/auth/groups/0123456", headers=authorization)

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": "404: Group not found"}

    mock_keycloak_instance.get_group.assert_called_once_with(group_id="0123456")


def test_get_group_realm_roles_success(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value

    group_id = "0123456789"

    response = http_client_auth.get(
        f"/api/auth/groups/{group_id}/roles", headers=authorization
    )
    assert response.status_code == status.HTTP_200_OK
    mock_keycloak_instance.get_group_realm_roles.assert_called_once_with(
        group_id=group_id
    )


def test_get_group_realm_roles_failure(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value
    mock_keycloak_instance.get_group_realm_roles.side_effect = (
        exceptions.KeycloakGetError(
            response_code=status.HTTP_404_NOT_FOUND,
            error_message="Group realm roles not found",
        )
    )

    group_id = "0123456"
    response = http_client_auth.get(
        f"/api/auth/groups/{group_id}/roles", headers=authorization
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": "404: Group realm roles not found"}

    mock_keycloak_instance.get_group_realm_roles.assert_called_once_with(
        group_id=group_id
    )


def test_assign_group_realm_roles_success(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value

    group_id = "0123456789"
    roles_payload = {"roles": ["role1", "role2"]}

    response = http_client_auth.put(
        f"/api/auth/groups/{group_id}/assign-roles",
        json=roles_payload,
        headers=authorization,
    )
    assert response.status_code == status.HTTP_200_OK
    mock_keycloak_instance.assign_group_realm_roles.assert_called_once_with(
        group_id=group_id, roles=roles_payload
    )


def test_assign_group_realm_roles_failure(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value
    mock_keycloak_instance.assign_group_realm_roles.side_effect = (
        exceptions.KeycloakPutError(
            response_code=status.HTTP_400_BAD_REQUEST,
            error_message="Assign group realm roles failed",
        )
    )

    group_id = "0123456789"
    roles_payload = {"roles": ["role1", "role2"]}

    response = http_client_auth.put(
        f"/api/auth/groups/{group_id}/assign-roles",
        json=roles_payload,
        headers=authorization,
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    mock_keycloak_instance.assign_group_realm_roles.assert_called_once_with(
        group_id=group_id, roles=roles_payload
    )


def test_update_group_success(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value

    group_id = "0123456"
    payload = {"name": "new group name", "subGroups": []}
    response = http_client_auth.put(
        f"/api/auth/groups/{group_id}", json=payload, headers=authorization
    )

    assert response.status_code == status.HTTP_200_OK
    mock_keycloak_instance.update_group.assert_called_once_with(
        group_id=group_id, payload={"name": "new group name", "subGroups": []}
    )


def test_update_group_failure(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value
    mock_keycloak_instance.update_group.side_effect = exceptions.KeycloakPutError(
        response_code=status.HTTP_400_BAD_REQUEST, error_message="Group update failed"
    )

    group_id = "0123456"
    payload = {"name": "new group name", "subGroups": []}
    response = http_client_auth.put(
        f"/api/auth/groups/{group_id}", json=payload, headers=authorization
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json() == {"detail": "400: Group update failed"}
    mock_keycloak_instance.update_group.assert_called_once_with(
        group_id=group_id, payload={"name": "new group name", "subGroups": []}
    )


def test_delete_group_success(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value
    mock_keycloak_instance.delete_group.return_value = {"status": True}

    group_id = "012346"
    response = http_client_auth.delete(
        f"/api/auth/groups/{group_id}", headers=authorization
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"status": True}

    mock_keycloak_instance.delete_group.assert_called_once_with(group_id=group_id)


def test_delete_group_failure(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value
    mock_keycloak_instance.delete_group.side_effect = exceptions.KeycloakDeleteError(
        response_code=status.HTTP_404_NOT_FOUND, error_message="Group not Found"
    )

    group_id = "012346"
    response = http_client_auth.delete(
        f"/api/auth/groups/{group_id}", headers=authorization
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": "404: Group not Found"}


def test_create_roles_success(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value

    payload = {
        "name": "new_roles",
        "description": "New roles",
        "composite": False,
        "clientRole": False,
    }
    response = http_client_auth.post(
        "/api/auth/roles", json=payload, headers=authorization
    )
    assert response.status_code == status.HTTP_200_OK

    mock_keycloak_instance.create_realm_role.assert_called_once_with(payload=payload)
    mock_keycloak_instance.get_realm_role.assert_called_once_with(
        role_name=mock_keycloak_instance.create_realm_role.return_value
    )
    mock_keycloak_instance.create_realm_role.assert_called_once()


def test_create_roles_failure(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value
    mock_keycloak_instance.create_realm_role.side_effect = exceptions.KeycloakPostError(
        response_code=status.HTTP_400_BAD_REQUEST, error_message="Role creation failed"
    )

    payload = {
        "name": "new_roles",
        "description": "New roles",
        "composite": False,
        "clientRole": False,
    }

    response = http_client_auth.post(
        "/api/auth/roles", json=payload, headers=authorization
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json() == {"detail": "400: Role creation failed"}

    mock_keycloak_instance.create_realm_role.assert_called_once_with(payload=payload)
    mock_keycloak_instance.get_realm_role.assert_not_called()


def test_get_roles(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_admin.get_realm_roles.return_value = mock.MagicMock()
    response = http_client_auth.get("/api/auth/roles", headers=authorization)
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {}


def test_get_role_success(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value
    mock_keycloak_instance.get_realm_role.return_value = "admin"

    response = http_client_auth.get("/api/auth/roles/admin", headers=authorization)
    assert response.status_code == status.HTTP_200_OK

    mock_keycloak_instance.get_realm_role.assert_called_once_with(role_name="admin")


def test_get_role_failure(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value

    mock_keycloak_instance.get_realm_role.side_effect = exceptions.KeycloakGetError(
        response_code=status.HTTP_404_NOT_FOUND, error_message="Role name not found"
    )

    role_name = "admin"
    response = http_client_auth.get(
        f"/api/auth/roles/{role_name}", headers=authorization
    )

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": "404: Role name not found"}

    mock_keycloak_instance.get_realm_role.assert_called_once_with(role_name=role_name)


def test_update_role_success(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value

    role_name = "admin"
    role_payload = {
        "name": "administrateur",
        "description": "Updated role description",
        "composite": True,
        "clientRole": False,
    }
    response = http_client_auth.put(
        f"/api/auth/roles/{role_name}", json=role_payload, headers=authorization
    )

    assert response.status_code == status.HTTP_200_OK
    mock_keycloak_instance.update_realm_role.assert_called_once_with(
        role_name=role_name, payload=role_payload
    )


def test_update_role_failure(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value
    mock_keycloak_instance.update_realm_role.side_effect = exceptions.KeycloakPutError(
        response_code=status.HTTP_400_BAD_REQUEST, error_message="Update role failed"
    )

    role_name = "example_role"
    role_payload = {
        "name": "updated_role",
        "description": "Updated role description",
        "composite": True,
        "clientRole": False,
    }
    response = http_client_auth.put(
        f"/api/auth/roles/{role_name}", json=role_payload, headers=authorization
    )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json() == {"detail": "400: Update role failed"}
    mock_keycloak_instance.update_realm_role.assert_called_once_with(
        role_name=role_name, payload=role_payload
    )


def test_delete_role_success(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value
    mock_keycloak_instance.delete_realm_role.return_value = {"status": True}

    role_name = "example_role_name"
    response = http_client_auth.delete(
        f"/api/auth/roles/{role_name}", headers=authorization
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"status": True}

    mock_keycloak_instance.delete_realm_role.assert_called_once_with(
        role_name=role_name
    )


def test_delete_role_failure(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value
    mock_keycloak_instance.delete_realm_role.side_effect = (
        exceptions.KeycloakDeleteError(
            response_code=status.HTTP_404_NOT_FOUND, error_message="Role not Found"
        )
    )

    role_name = "example_role_name"
    response = http_client_auth.delete(
        f"/api/auth/roles/{role_name}", headers=authorization
    )
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": "404: Role not Found"}


def test_logout_user(http_client_auth, authorization, mocker):
    mock_keycloak_logout = mocker.patch("src.utils.deps.user_logout")
    mock_keycloak_logout.return_value = {"message": "Logout successful"}

    response = http_client_auth.post(
        "/api/auth/logout", json={"refresh_token": "1235647"}, headers=authorization
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"message": "Logout successful"}
    mock_keycloak_logout.assert_called_once()
    mock_keycloak_logout.assert_called_once_with("1235647")


def test_refresh_token(http_client_auth, authorization, mocker):
    mock_refresh_token = mocker.patch("src.utils.deps.user_refresh_token")
    mock_refresh_token.return_value = {"message": "Refresh Token successful"}

    response = http_client_auth.post(
        "/api/auth/refresh-token", json={"refresh_token": "01235647"}, headers=authorization
    )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"message": "Refresh Token successful"}
    mock_refresh_token.assert_called_once()
    mock_refresh_token.assert_called_once_with("01235647")
