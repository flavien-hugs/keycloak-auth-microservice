import pytest
from unittest import mock
from keycloak import exceptions
from fastapi import HTTPException, status


@mock.patch("src.utils.deps.KeycloakOpenID")
def test_get_keycloak_openid(mock_keycloak_open_id):
    from src.utils.deps import get_keycloak_openid
    from src.config.keycloak import settings as keycloak_env

    mock_instance = mock_keycloak_open_id.return_value
    instance = get_keycloak_openid()
    assert mock_keycloak_open_id.call_args.kwargs == {
        "server_url": f"{keycloak_env.server_url}/auth/",
        "realm_name": keycloak_env.admin_realm_name,
        "client_id": keycloak_env.admin_client_id,
        "client_secret_key": keycloak_env.admin_secret_key,
        "verify": True,
    }
    mock_instance.well_known.assert_called()
    assert instance is mock_instance


@mock.patch("src.utils.deps.KeycloakOpenID")
def test_user_login_success(mock_keycloak_openid_conn):
    from src.utils.deps import user_login

    mock_openid_instance = mock_keycloak_openid_conn.return_value

    mock_token = mock.MagicMock()
    mock_user_info = mock.MagicMock()

    mock_openid_instance.token.return_value = mock_token
    mock_openid_instance.userinfo.return_value = mock_user_info

    username = "username"
    password = "password"
    result = user_login(username, password)
    assert result == {"token": mock_token, "user_info": mock_user_info}

    mock_keycloak_openid_conn.assert_called_once()
    mock_openid_instance.token.assert_called_once_with(
        username=username, password=password
    )
    mock_openid_instance.userinfo.assert_called_once_with(mock_token["access_token"])


@mock.patch("src.utils.deps.KeycloakOpenID")
def test_user_login_failure(mock_keycloak_openid_conn):
    from src.utils.deps import user_login

    mock_openid_instance = mock_keycloak_openid_conn.return_value
    mock_openid_instance.token.side_effect = exceptions.KeycloakAuthenticationError(
        "Authentication error"
    )

    username = "username"
    password = "password"

    with pytest.raises(HTTPException) as e:
        user_login(username, password)

    assert e.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert str(e.value.detail) == "Authentication error"

    mock_keycloak_openid_conn.assert_called_once()
    mock_openid_instance.token.assert_called_once_with(
        username=username, password=password
    )


@pytest.mark.asyncio
@mock.patch("src.utils.deps.KeycloakOpenID")
async def test_authorization_bearer_valid_token(
    mock_keycloak_openid_conn, mock_request
):
    from src.utils.deps import AuthTokenBearer

    mock_auth = mock.Mock()
    mock_token = mock.MagicMock()
    mock_auth.credentials = mock_token

    mock_openid_instance = mock_keycloak_openid_conn.return_value
    mock_openid_instance.introspect.return_value = {"active": True}
    mock_request.headers.get.return_value = f"Bearer {mock_token}"

    auth_token_bearer = AuthTokenBearer()
    result = await auth_token_bearer(mock_request)

    assert result == f"{mock_token}"

    mock_keycloak_openid_conn.assert_called_once()
    mock_openid_instance.introspect.assert_called_once_with(f"{mock_token}")


@pytest.mark.asyncio
@mock.patch("src.utils.deps.KeycloakOpenID")
async def test_authorization_bearer_expired_token(
    mock_keycloak_openid_conn, mock_request
):
    from src.utils.deps import AuthTokenBearer

    mock_auth = mock.MagicMock()
    mock_token = mock.MagicMock()
    mock_auth.credentials = mock_token

    mock_openid_instance = mock_keycloak_openid_conn.return_value
    mock_openid_instance.introspect.return_value = {"active": False}

    mock_request.headers.get.return_value = f"Bearer {mock_token}"

    auth_token_bearer = AuthTokenBearer()

    with pytest.raises(HTTPException) as context:
        await auth_token_bearer(mock_request)

    assert context.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert context.value.detail == "The access token is expired"

    mock_keycloak_openid_conn.assert_called_once()
    mock_keycloak_openid_conn.return_value.introspect.assert_called_once_with(
        f"{mock_token}"
    )
