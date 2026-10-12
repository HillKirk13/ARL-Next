import functools
from flask import request
from app.config import Config
from . import gen_md5, random_choices
from .conn import conn_db

salt = 'arlsalt!@#'
MAX_CONCURRENT_TOKENS = 3

def user_login(username=None, password=None):
    if not username or not password:
        return

    query = {"username": username, "password": gen_md5(salt + password)}
    user_data = conn_db('user').find_one(query)

    if user_data:
        new_token = gen_md5(random_choices(50))
        item = {
            "username": username,
            "token": new_token,
            "type": "login"
        }

        # 获取历史 tokens 列表，支持最多 3 个设备同时在线
        tokens = user_data.get("tokens")
        if not isinstance(tokens, list):
            tokens = []
        old_token = user_data.get("token")
        if old_token and isinstance(old_token, str) and old_token not in tokens:
            tokens.append(old_token)

        # 追加新设备 token
        if new_token not in tokens:
            tokens.append(new_token)

        # 保持最多 3 个设备同时在线，超出时剔除最早登录的设备 (FIFO)
        if len(tokens) > MAX_CONCURRENT_TOKENS:
            tokens = tokens[-MAX_CONCURRENT_TOKENS:]

        conn_db('user').update_one(
            {"_id": user_data["_id"]},
            {"$set": {"tokens": tokens, "token": new_token}}
        )

        return item


def user_login_header():
    token = request.headers.get("Token") or request.args.get("token") or request.cookies.get("arl_token")

    if not Config.AUTH:
        return True

    item = {
        "username": "ARL-API",
        "token": Config.API_KEY,
        "type": "api"
    }

    if not token:
        return False

    if token == Config.API_KEY:
        return item

    # 支持匹配 tokens 列表中的任意一个有效 token，或单 token 字段
    data = conn_db('user').find_one({"$or": [{"tokens": token}, {"token": token}]})
    if data:
        item["username"] = data.get("username")
        item["token"] = token
        item["type"] = "login"
        return item

    return False


def user_logout(token):
    if not token:
        token = request.headers.get("Token") or request.args.get("token") or request.cookies.get("arl_token")
    if token and user_login_header():
        user_data = conn_db('user').find_one({"$or": [{"tokens": token}, {"token": token}]})
        if user_data:
            tokens = user_data.get("tokens", [])
            if isinstance(tokens, list) and token in tokens:
                tokens = [t for t in tokens if t != token]
            else:
                tokens = []
            latest_token = tokens[-1] if tokens else None
            conn_db('user').update_one(
                {"_id": user_data["_id"]},
                {"$set": {"tokens": tokens, "token": latest_token}}
            )


def user_refresh_token(token):
    if not token:
        token = request.headers.get("Token") or request.args.get("token") or request.cookies.get("arl_token")
    if token and user_login_header():
        new_token = gen_md5(random_choices(50))
        user_data = conn_db('user').find_one({"$or": [{"tokens": token}, {"token": token}]})
        if user_data:
            tokens = user_data.get("tokens", [])
            if not isinstance(tokens, list):
                tokens = []
            if token in tokens:
                tokens = [new_token if t == token else t for t in tokens]
            else:
                tokens.append(new_token)
            tokens = tokens[-MAX_CONCURRENT_TOKENS:]
            conn_db('user').update_one(
                {"_id": user_data["_id"]},
                {"$set": {"tokens": tokens, "token": new_token}}
            )
            return new_token
    return None


def change_pass(token, old_password, new_password):
    if not token:
        token = request.headers.get("Token") or request.args.get("token") or request.cookies.get("arl_token")
    query = {
        "$or": [{"tokens": token}, {"token": token}],
        "password": gen_md5(salt + old_password)
    }
    data = conn_db('user').find_one(query)
    if data:
        conn_db('user').update_one(
            {"_id": data["_id"]},
            {"$set": {"password": gen_md5(salt + new_password)}}
        )
        return True
    else:
        return False


def auth(func):
    ret = {
        "message": "not login",
        "code": 401,
        "data": {}
    }

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if Config.AUTH and not user_login_header():
            return ret

        return func(*args, **kwargs)

    return wrapper