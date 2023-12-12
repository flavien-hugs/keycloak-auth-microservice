# Auth Microservice with Keycloak

This project is a microservice for authentication using FastAPI and python-keycloak.
It leverages the power of Keycloak for secure and robust authentication.

### What is keycloak

[Keycloak](https://www.keycloak.org) is an open-source Identity and Access Management solution. It provides features such as Single Sign-On (SSO), user federation, and centralized authentication management.

## Run Project

To run the project locally, follow these steps:

1. Activate environment
```shell
poetry shell
```

2. Install dependencies
```shell
poetry install
```

3. Run the server
```shell
poetry run app auth runserver
or app auth runserver
or make run
```

## Run tests
Execute the following commands to run tests and check code coverage:

1. Run tests
```shell
poetry run coverage run -m pytest -v tests
```

2. Check code test coverage
```shell
poetry run coverage report -m
```

# Routes

| Endpoint              | Description                    |
|-----------------------|--------------------------------|
| GET `/api/auth/@ping`     | Test if server running         |
| POST `/api/auth/create`    | Register a new user            |
| POSt `/api/auth/login`     | Authenticate and obtain a token|
| POSt `/api/auth/logout`     | Logout the currently authenticated user |
| GET `/api/auth/users`     | Get all users |
| GET `/api/auth/users/{user_id}`| Get user profile information   |
| DELETE `/api/auth/users/{user_id}`| Delete user   |
| PATCH `/api/auth/users/{user_id}`| Update user information   |

Feel free to explore and extend the functionality by adding more routes and features to suit your authentication needs.

# Contributing

Contributions are welcome! If you have any ideas or improvements, please open an issue or submit a pull request.
