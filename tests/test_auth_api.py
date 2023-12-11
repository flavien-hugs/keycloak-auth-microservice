import pytest
from unittest import mock


def test_ping(http_client_auth):
    response = http_client_auth.get("/api/auth/@ping")
    assert response.status_code == 200
    assert response.json() == {"msg": "pong !"}


@pytest.mark.parametrize("username, password", [("incubtek", "incubtek"), ("ricva", "ricva")])
def test_login_success(http_client_auth, mocker, username, password):
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
        "username": username,
        "password": password,
    }
    response = http_client_auth.post("/api/auth/login", json=payload)
    assert response.status_code == 200
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
    assert response.status_code == 200
    mock_keycloak_instance.create_user.assert_called_once_with(
        {
            "username": "john",
            "firstName": "John",
            "lastName": "Doe",
            "enabled": True,
            "emailVerified": True,
            "credentials": [{"type": "password", "value": "password"}],
            "attributes": {"locale": ["fr"], },
        },
        exist_ok=False,
    )
    mock_keycloak_instance.get_user.assert_called_once_with(
        mock_keycloak_instance.create_user.return_value
    )
    mock_keycloak_instance.create_user.assert_called_once()


def test_get_users(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_admin.get_users.return_value = mock.MagicMock()
    response = http_client_auth.get("/api/auth/users", headers=authorization)
    assert response.status_code == 200
    assert response.json() == []


def test_get_user(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_admin.get_user.return_value = mock.MagicMock()
    response = http_client_auth.get("/api/auth/users/0123", headers=authorization)
    assert response.status_code == 200
    assert response.json() == {}


def test_get_user_not_found(http_client_auth, authorization, mocker):
    mock_keycloak_admin = mocker.patch("src.utils.deps.get_keycloak_admin")
    mock_keycloak_admin.get_user.return_value = None
    response = http_client_auth.get("/api/auth/users/0123", headers=authorization)
    assert response.status_code == 200
    assert response.json() == {}
