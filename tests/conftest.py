import pytest
from unittest import mock
from fastapi import Request
from fastapi.testclient import TestClient


@pytest.fixture()
def mock_get_keycloak_openid():
    with mock.patch("src.utils.deps.KeycloakOpenID") as mock_keycloak_openid:
        mock_instance = mock_keycloak_openid.return_value
        mock_instance.decode_token.return_value = {
            "sub": "0123456789",
            "username": "fofo",
        }
        yield mock_instance


@pytest.fixture()
def mock_request():
    return mock.MagicMock(spec=Request)


@pytest.fixture()
def authorization(mock_get_keycloak_openid):
    return {"Authorization": "Bearer 123"}


@pytest.fixture()
def http_client_auth():
    from src.services.auth import app

    client = TestClient(app)
    return client
