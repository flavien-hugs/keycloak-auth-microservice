from typing import Optional
from pydantic import BaseModel


class AuthModel(BaseModel):
    username: str
    password: str
    firstname: Optional[str] = None
    lastname: Optional[str] = None


class LoginModel(BaseModel):
    username: str
    password: str


class RoleSchema(BaseModel):
    roles: list = []


class BaseRoleSchema(BaseModel):
    name: str
    description: Optional[str] = None
    composite: bool = False
    client_role: bool = False


class UpdateRoleSchema(BaseRoleSchema):
    ...


class RoleSchemaOut(BaseRoleSchema):
    id: str


class GroupSchema(BaseModel):
    name: str
    subgroups: Optional[list] = []
