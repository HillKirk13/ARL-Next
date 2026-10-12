#coding: utf-8

from flask import make_response, request
from flask_restx import Resource, Namespace
from bson import ObjectId
import csv
import io

from app.utils import get_logger, auth
from app import utils

ns = Namespace('mcp', description="MCP API 接口")
logger = get_logger()

@ns.route('/task_detail_export')
class MCPTaskDetailExport(Resource):
    @auth
    def get(self):
        """
        MCP专用任务数据导出接口，返回CSV格式
        """
        task_id = request.args.get('task_id', '')
        tab = request.args.get('tab', 'site')
        try:
            page = int(request.args.get('page', 1))
            limit = int(request.args.get('limit', 100))
        except ValueError:
            page = 1
            limit = 100
            
        columns_str = request.args.get('columns', '')
        columns = [c.strip() for c in columns_str.split(',') if c.strip()] if columns_str else []

        if not task_id or len(task_id) != 24:
            return {"code": 400, "message": "Invalid task_id"}, 400

        allowed_tabs = ["site", "domain", "ip", "wih", "fileleak", "vuln", "nuclei_result", "cert", "service", "url", "npoc_service", "stat_finger", "cip"]
        if tab not in allowed_tabs:
            return {"code": 400, "message": f"Unsupported tab. Allowed: {allowed_tabs}"}, 400
            
        query = {"task_id": task_id}
        skip = (page - 1) * limit
        
        projection = None
        if tab == "site":
            projection = {"favicon.data": 0, "body": 0, "header": 0, "headers": 0} # 剔除庞大且无用的字段
            
        cursor = utils.conn_db(tab).find(query, projection).skip(skip).limit(limit)
        items = list(cursor)
        
        if not items:
            response = make_response("")
            response.headers['Content-Type'] = 'text/csv'
            return response
            
        flattened_items = []
        for item in items:
            flat_item = {}
            for k, v in item.items():
                if k == '_id':
                    flat_item[k] = str(v)
                elif tab == 'ip' and k == 'port_info' and isinstance(v, list):
                    flat_item['开放端口'] = " ".join([str(p.get('port_id', '')) for p in v if 'port_id' in p])
                elif tab == 'ip' and k == 'geo_city' and isinstance(v, dict):
                    flat_item['geo'] = f"{v.get('country_name', '')}/{v.get('region_name', '')}"
                elif tab == 'ip' and k == 'geo_asn' and isinstance(v, dict):
                    flat_item['as'] = v.get('organization', '')
                elif tab == 'ip' and k == 'os_info' and isinstance(v, dict):
                    flat_item['操作系统'] = v.get('name', '')
                elif tab == 'site' and k == 'finger' and isinstance(v, list):
                    flat_item['finger'] = " ".join([f.get('name', '') for f in v if 'name' in f])
                elif tab == 'cert' and isinstance(v, dict):
                    flat_item[k] = "; ".join([f"{sub_k}:{sub_v}" for sub_k, sub_v in v.items() if sub_v])
                elif isinstance(v, list):
                    flat_item[k] = " ".join([str(i) for i in v])
                elif isinstance(v, dict):
                    # Flatten simple dicts
                    flat_item[k] = "; ".join([f"{sub_k}:{sub_v}" for sub_k, sub_v in v.items() if sub_v and not isinstance(sub_v, (dict, list))])
                else:
                    flat_item[k] = str(v)
            flattened_items.append(flat_item)
            
        if columns:
            headers = columns
        else:
            headers_set = set()
            for flat_item in flattened_items:
                headers_set.update(flat_item.keys())
            headers = sorted(list(headers_set))
            
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=headers, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(flattened_items)
        
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv; charset=utf-8'
        return response
