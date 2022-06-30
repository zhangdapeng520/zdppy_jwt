#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2022/6/30 10:16
# @Author  : 张大鹏
# @Github  : https://github.com/zhangdapeng520
# @File    : main.py
# @Software: PyCharm
# @Description: 文档描述
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2022/6/30 10:06
# @Author  : 张大鹏
# @Github  : https://github.com/zhangdapeng520
# @File    : jwt.py
# @Software: PyCharm
# @Description: 文档描述
# !/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2022/6/30 10:01
# @Author  : 张大鹏
# @Github  : https://github.com/zhangdapeng520
# @File    : jwt.py
# @Software: PyCharm
# @Description: 文档描述
from datetime import datetime, timedelta
from typing import Union
from zdppy_api import Depends, Api, HTTPException, status
from zdppy_api.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from zdppy_jwt.jose import JWTError, jwt
from zdppy_jwt.passlib.context import CryptContext
from pydantic import BaseModel

# 生成秘钥的方式：openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

fake_users_db = {
    "zhangdapeng": {
        "username": "zhangdapeng",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",  # 明文密码是secret
        "disabled": False,
    }
}


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Union[str, None] = None


class User(BaseModel):
    username: str
    email: Union[str, None] = None
    full_name: Union[str, None] = None
    disabled: Union[bool, None] = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = Api()


def verify_password(plain_password, hashed_password):
    """
    校验密码
    :param plain_password: 明文密码
    :param hashed_password: hash密码
    :return:
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    """
    获取用户
    :param db:
    :param username:
    :return:
    """
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    """
    校验用户名和密码
    :param fake_db:
    :param username:
    :param password:
    :return:
    """
    # 获取用户
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: Union[timedelta, None] = None):
    """
    创建用于设定 JWT 令牌签名算法的变量 「ALGORITHM」，并将其设置为 "HS256"。
    创建一个设置令牌过期时间的变量。
    定义一个将在令牌端点中用于响应的 Pydantic 模型。
    创建一个生成新的访问令牌的工具函数。
    :param data:
    :param expires_delta:
    :return:
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    """
    更新依赖项:
    更新 get_current_user 以接收与之前相同的令牌，但这次使用的是 JWT 令牌。
    解码接收到的令牌，对其进行校验，然后返回当前用户。
    如果令牌无效，立即返回一个 HTTP 错误。
    :param token:
    :return:
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    更新 /token 路径操作
    使用令牌的过期时间创建一个 timedelta 对象。
    创建一个真实的 JWT 访问令牌并返回它。
    :param form_data:
    :return:
    """
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me/", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user


@app.get("/users/me/items/")
async def read_own_items(current_user: User = Depends(get_current_active_user)):
    return [{"item_id": "Foo", "owner": current_user.username}]


if __name__ == '__main__':
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8888)
