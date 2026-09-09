#!/usr/bin/env python3
"""ARL-Next MCP Server (纯标准库实现, stdio JSON-RPC 传输)。

与原 Node 版本功能等价，提供 6 个工具：
search_assets / search_vulns / get_dashboard_summary /
get_tasks / search_icp_tasks / search_icp_assets

无需任何第三方依赖，适配离线环境。
"""

import json
import math
import os
import ssl
import sys
import urllib.parse
import urllib.request
from urllib.error import HTTPError, URLError

# --- 强制 stdout/stdin 使用 UTF-8，避免中文载荷乱码 ---
for _stream in (sys.stdout, sys.stdin):
    try:
        _stream.reconfigure(encoding="utf-8")
    except Exception:
        pass

HOST = os.environ.get("ARL_HOST")
TOKEN = os.environ.get("ARL_TOKEN")

if not HOST or not TOKEN:
    sys.stderr.write("Error: Environment variables ARL_HOST and ARL_TOKEN are required.\n")
    sys.exit(1)

API_BASE = HOST.rstrip("/") + "/api"
TIMEOUT = 10

# ARL 通常使用自签名证书，这里与 Node 版一致：跳过证书校验
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE

# 容易导致载荷过大的无用字段
_TRIM_KEYS = {
    "body", "header", "headers", "favicon", "raw_data",
    "html", "icon", "cert_raw", "ssl_cert",
    "options",
}


def log(msg):
    sys.stderr.write(msg + "\n")
    sys.stderr.flush()


def api_get(path, params=None):
    """对 ARL 后端发起 GET 请求并返回解析后的 JSON。"""
    url = API_BASE + path
    if params:
        clean = {k: v for k, v in params.items() if v is not None}
        if clean:
            url += "?" + urllib.parse.urlencode(clean)
    req = urllib.request.Request(
        url, headers={"Token": TOKEN, "Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=_SSL_CTX) as resp:
            raw = resp.read().decode("utf-8", "replace")
    except HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", "replace")
        except Exception:
            pass
        raise RuntimeError("HTTP %s %s %s" % (e.code, e.reason, detail))
    except URLError as e:
        raise RuntimeError("URL Error: %s" % getattr(e, "reason", e))
    return json.loads(raw) if raw else None


def trim_payload(data):
    """过滤大字段并截断超长字符串，避免上下文膨胀。"""
    if data is None:
        return data
    if isinstance(data, list):
        return [trim_payload(x) for x in data]
    if isinstance(data, dict):
        out = {}
        for k, v in data.items():
            if k in _TRIM_KEYS:
                continue
            if isinstance(v, str) and len(v) > 500:
                out[k] = v[:500] + "...[TRUNCATED]"
            else:
                out[k] = trim_payload(v)
        return out
    return data


def format_response(data):
    trimmed = trim_payload(data)
    s = json.dumps(trimmed, ensure_ascii=False, indent=2)
    if (
        isinstance(data, dict)
        and data.get("page")
        and data.get("size")
        and data.get("total") is not None
    ):
        total_pages = math.ceil(data["total"] / data["size"]) or 1
        s += (
            "\n\n[System Note: 当前显示第 %d 页，共 %d 页 (总计 %d 条数据)。"
            "如果需要查看更多数据，请在下一次调用此 Tool 时传入参数 page=%d]"
            % (data["page"], total_pages, data["total"], data["page"] + 1)
        )
    return s


# --- 工具定义（与 Node 版 inputSchema 完全一致） ---
TOOLS = [
    {
        "name": "search_assets",
        "description": (
            "在 ARL-Next 资产库中搜索发现的资产。当你需要查询网站(site)、IP、域名(domain)、"
            "证书(cert)、开放端口/协议服务(service)时使用此工具。必需参数: assetType。"
            "支持通过 query 参数模糊搜索组件名称（例如 query='nginx' 或 '1.1.1.1'）。"
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "assetType": {
                    "type": "string",
                    "description": (
                        "要搜索的资产类型。可选值：'site' (网站), 'ip' (IP地址), "
                        "'domain' (域名), 'cert' (证书), 'service' (开放端口/服务), 'asset_wih' (WIH信息)"
                    ),
                    "enum": ["site", "ip", "domain", "cert", "service", "asset_wih"],
                },
                "query": {
                    "type": "string",
                    "description": "模糊搜索关键词（例如 'nginx', '1.1.1.1', 'example.com'）",
                },
                "page": {"type": "number", "description": "页码 (默认 1)"},
                "size": {"type": "number", "description": "单页数据量 (默认 10，最大 50)"},
            },
            "required": ["assetType"],
        },
    },
    {
        "name": "search_vulns",
        "description": "在 ARL 漏洞库中搜索和查询系统发现的安全漏洞。支持按危险等级(vuln_severity)过滤，或按漏洞名称(query)模糊搜索。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "漏洞名称或详细信息的模糊搜索关键词。"},
                "vuln_severity": {
                    "type": "string",
                    "description": "按严重级别过滤。",
                    "enum": ["critical", "high", "medium", "low"],
                },
                "page": {"type": "number", "description": "页码 (默认 1)"},
                "size": {"type": "number", "description": "单页数据量 (默认 10，最大 50)"},
            },
        },
    },
    {
        "name": "get_dashboard_summary",
        "description": "获取整个 ARL 系统当前的运行状态与统计大盘数据（包括资产总数、运行中的任务数、各类漏洞数量统计、系统性能等）。适合用于生成每日系统概览或战报。",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "get_tasks",
        "description": "获取最近的资产发现与漏洞扫描任务列表及其执行状态（运行中、已完成、等待中等）。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "page": {"type": "number", "description": "页码 (默认 1)"},
                "size": {"type": "number", "description": "单页数据量 (默认 10)"},
            },
        },
    },
    {
        "name": "search_icp_tasks",
        "description": "查询最近发起的 ICP 备案信息拉取及企业架构分析任务。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "按任务名称过滤"},
                "target": {"type": "string", "description": "按目标对象（如公司名称）过滤"},
                "status": {"type": "string", "description": "任务状态"},
                "page": {"type": "number", "description": "页码 (默认 1)"},
                "size": {"type": "number", "description": "单页数据量 (默认 10)"},
            },
        },
    },
    {
        "name": "search_icp_assets",
        "description": "深度挖掘指定 ICP 任务获取到的子资产维度数据（如公众号、小程序、软件著作、商标等）或全局查询。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "task_id": {"type": "string", "description": "关联的 ICP 任务 ID（不传则全局检索）"},
                "query_type": {
                    "type": "string",
                    "description": (
                        "查询子维度。可选：'web' (网站), 'app' (应用), 'mapp' (小程序), "
                        "'kapp' (快应用), 'invest' (投资机构), 'trademark' (商标), "
                        "'wechat' (微信公号), 'weibo' (微博)"
                    ),
                    "enum": ["web", "app", "mapp", "kapp", "invest", "trademark", "wechat", "weibo"],
                },
                "page": {"type": "number", "description": "页码 (默认 1)"},
                "size": {"type": "number", "description": "单页数据量 (默认 10，最大 50)"},
            },
            "required": ["query_type"],
        },
    },
]

_ALLOWED_ASSETS = ["site", "ip", "domain", "cert", "service", "asset_wih"]
_ALLOWED_ICP = ["web", "app", "mapp", "kapp", "invest", "trademark", "wechat", "weibo"]


def handle_tool(name, args):
    """执行工具调用，返回 (text, is_error)。"""
    args = args or {}

    if name == "search_assets":
        asset_type = args.get("assetType")
        if asset_type not in _ALLOWED_ASSETS:
            return "Error: Invalid assetType '%s'" % asset_type, True
        size = min(args.get("size", 10), 50)
        data = api_get(
            "/%s/" % asset_type,
            {"page": args.get("page", 1), "size": size, "query": args.get("query")},
        )
        return format_response(data), False

    if name == "search_vulns":
        size = min(args.get("size", 10), 50)
        data = api_get(
            "/vuln/",
            {
                "page": args.get("page", 1),
                "size": size,
                "query": args.get("query"),
                "vuln_severity": args.get("vuln_severity"),
            },
        )
        return format_response(data), False

    if name == "get_dashboard_summary":
        result = {
            "stats": api_get("/dashboard/stats"),
            "sysinfo": api_get("/dashboard/sysinfo"),
        }
        return json.dumps(result, ensure_ascii=False, indent=2), False

    if name == "get_tasks":
        size = min(args.get("size", 10), 20)
        data = api_get("/task/", {"page": args.get("page", 1), "size": size})
        return format_response(data), False

    if name == "search_icp_tasks":
        data = api_get(
            "/icp/task",
            {
                "page": args.get("page", 1),
                "size": args.get("size", 10),
                "name": args.get("name"),
                "target": args.get("target"),
                "status": args.get("status"),
            },
        )
        return format_response(data), False

    if name == "search_icp_assets":
        query_type = args.get("query_type")
        if query_type not in _ALLOWED_ICP:
            return "Error: Invalid query_type '%s'" % query_type, True
        size = min(args.get("size", 10), 50)
        data = api_get(
            "/icp/asset",
            {
                "page": args.get("page", 1),
                "size": size,
                "task_id": args.get("task_id"),
                "query_type": query_type,
            },
        )
        return format_response(data), False

    raise RuntimeError("Unknown tool: %s" % name)


# --- JSON-RPC over stdio ---
def send(msg):
    sys.stdout.write(json.dumps(msg, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def result(req_id, payload):
    send({"jsonrpc": "2.0", "id": req_id, "result": payload})


def error(req_id, code, message):
    send({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}})


def main():
    log("ARL-Next MCP Server (python) running on stdio")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        method = msg.get("method")
        req_id = msg.get("id")
        params = msg.get("params") or {}

        # 通知类消息无 id，不需要响应
        if method and method.startswith("notifications/"):
            continue

        if method == "initialize":
            result(req_id, {
                "protocolVersion": params.get("protocolVersion", "2024-11-05"),
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "arl-next-mcp", "version": "1.0.0"},
            })
        elif method == "tools/list":
            result(req_id, {"tools": TOOLS})
        elif method == "tools/call":
            try:
                text, is_error = handle_tool(params.get("name"), params.get("arguments"))
            except Exception as e:  # noqa: BLE001 - 显式捕获并回传错误
                text = "API Request Failed: %s" % e
                is_error = True
            result(req_id, {
                "content": [{"type": "text", "text": text}],
                "isError": is_error,
            })
        elif method == "ping":
            result(req_id, {})
        else:
            if req_id is not None:
                error(req_id, -32601, "Method not found: %s" % method)

    log("ARL-Next MCP Server (python) stdin closed, exiting.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
