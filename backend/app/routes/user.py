from flask import request, make_response
from flask_restx import fields, Namespace
from app.utils import get_logger
from app import utils
from . import ARLResource
from app import modules

ns = Namespace('user', description="管理员登录认证")

logger = get_logger()

login_fields = ns.model('LoginARL', {
    'username': fields.String(required=True, description="用户名"),
    'password': fields.String(required=True, description="密码"),
})

COOKIE_MAX_AGE = 30 * 24 * 3600  # 30 天

def set_auth_cookie(response, token):
    response.set_cookie(
        "arl_token",
        token,
        max_age=COOKIE_MAX_AGE,
        path="/",
        samesite="Lax"
    )

def clear_auth_cookie(response):
    response.set_cookie(
        "arl_token",
        "",
        max_age=0,
        path="/",
        samesite="Lax"
    )

@ns.route('/login')
class LoginARL(ARLResource):
    @ns.expect(login_fields)
    def post(self):
        """
        用户登录
        """
        args = self.parse_args(login_fields)
        login_res = utils.user_login(**args)
        data = build_data(login_res)
        resp = make_response(data)
        if login_res and "token" in login_res:
            set_auth_cookie(resp, login_res["token"])
        return resp


@ns.route('/logout')
class LogoutARL(ARLResource):
    def get(self):
        """
        用户退出
        """
        token = request.headers.get("Token") or request.cookies.get("arl_token")
        utils.user_logout(token)
        resp = make_response(build_data({}))
        clear_auth_cookie(resp)
        return resp


@ns.route('/refresh_token')
class RefreshTokenARL(ARLResource):
    @utils.auth
    def post(self):
        """
        刷新当前用户的 Token
        """
        token = request.headers.get("Token") or request.cookies.get("arl_token")
        new_token = utils.user_refresh_token(token)
        if new_token:
            resp = make_response(build_data({"token": new_token}))
            set_auth_cookie(resp, new_token)
            return resp
        return build_data(None)


change_pass_fields = ns.model('ChangePassARL', {
    'old_password': fields.String(required=True, description="旧密码"),
    'new_password': fields.String(required=True, description="新密码"),
    'check_password': fields.String(required=True, description="确认密码"),
})


@ns.route('/change_pass')
class ChangePassARL(ARLResource):
    @ns.expect(change_pass_fields)
    def post(self):
        """
        密码修改
        """
        args = self.parse_args(change_pass_fields)
        ret = {
            "message": "success",
            "code": 200,
            "data": {}
        }
        token = request.headers.get("Token") or request.cookies.get("arl_token")

        if args["new_password"] != args["check_password"]:
            ret["code"] = 301
            ret["message"] = "新密码和确定密码不一致"
            return ret

        if not args["new_password"]:
            ret["code"] = 302
            ret["message"] = "新密码不能为空"
            return ret

        if utils.change_pass(token, args["old_password"], args["new_password"]):
            utils.user_logout(token)
            resp = make_response(ret)
            clear_auth_cookie(resp)
            return resp
        else:
            ret["message"] = "旧密码错误"
            ret["code"] = 303

        return ret


def build_data(data):
    ret = {
        "message": "success",
        "code": 200,
        "data": {}
    }

    if data:
        ret["data"] = data
    else:
        ret["code"] = 401

    return ret