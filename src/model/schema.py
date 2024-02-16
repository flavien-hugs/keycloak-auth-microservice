from typing import Optional
from pydantic import BaseModel, EmailStr


class UserBaseModel(BaseModel):
    lastname: Optional[str] = None
    firstname: Optional[str] = None
    email: Optional[EmailStr] = None


class UserModel(UserBaseModel):
    username: str
    password: str


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


class GroupSchemaBase(BaseModel):
    name: str
    subgroups: Optional[list] = []


class LogoutUser(BaseModel):
    refresh_token: str


class ChangePasswordUser(BaseModel):
    password: str
