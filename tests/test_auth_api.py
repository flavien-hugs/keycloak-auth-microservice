import pytest
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
    assert response.json() == {'token': {}, 'user_info': {'sub': '0123456'}}
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
        "password": "password",
    }

    response = http_client_auth.post("/api/auth/users", json=payload)
    assert response.status_code == status.HTTP_200_OK
    mock_keycloak_instance.create_user.assert_called_once_with(
        {
            "username": "john",
            "firstName": "John",
            "lastName": "Doe",
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

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": "404: User not found"}

    mock_keycloak_instance.get_user.assert_called_once_with("0123")


def test_delete_user_success(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value

    user_id = "0123456"
    response = http_client_auth.delete(f"/api/auth/users/{user_id}", headers=authorization)

    assert response.status_code == status.HTTP_200_OK
    mock_keycloak_instance.delete_user.assert_called_once_with(user_id=user_id)


def test_delete_user_with_not_authorization(http_client_auth, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value

    user_id = "0123456"
    response = http_client_auth.delete(f"/api/auth/users/{user_id}")
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_delete_user_failure(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_instance = mock_keycloak_admin.return_value

    user_id = "123456"

    mock_keycloak_instance.delete_user.side_effect = exceptions.KeycloakDeleteError(
        response_code=status.HTTP_404_NOT_FOUND, error_message="User not found"
    )

    response = http_client_auth.delete(f"/api/auth/users/{user_id}", headers=authorization)

    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json() == {"detail": "404: User not found"}

    mock_keycloak_instance.delete_user.assert_called_once_with(user_id=user_id)
