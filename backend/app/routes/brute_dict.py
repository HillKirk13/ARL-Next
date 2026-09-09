import uuid
import threading
from flask import request
import os
from flask_restx import Resource, Namespace, fields
from app.utils import get_logger, auth
from . import get_arl_parser
from xing.conf import Conf as npoc_conf

ns = Namespace('brute_dict', description="弱口令字典配置管理")
logger = get_logger()

DICT_DIR = os.path.join(npoc_conf.PROJECT_DIRECTORY, 'dicts')

# 请求参数定义
list_parser = get_arl_parser({}, location='args')

preview_fields = {
    'name': fields.String(required=True, description="字典文件名"),
    'limit': fields.Integer(required=False, description="限制返回的行数", default=500)
}
preview_parser = get_arl_parser(preview_fields, location='args')

search_fields = {
    'name': fields.String(required=True, description="字典文件名"),
    'keyword': fields.String(required=True, description="搜索关键词")
}
search_parser = get_arl_parser(search_fields, location='args')

append_fields = {
    'name': fields.String(required=True, description="字典文件名"),
    'content': fields.String(required=True, description="要追加的条目，多行以换行符分隔")
}
append_parser = get_arl_parser(append_fields, location='json')

delete_fields = {
    'name': fields.String(required=True, description="字典文件名"),
    'content': fields.String(required=True, description="要删除的条目，多行以换行符分隔")
}
delete_parser = get_arl_parser(delete_fields, location='json')


def get_safe_dict_path(name):
    """防止目录穿越"""
    if '..' in name or '/' in name or '\\' in name:
        return None
    if not name.endswith('.txt'):
        return None
    path = os.path.join(DICT_DIR, name)
    if not os.path.exists(path):
        return None
    return path


@ns.route('/list')
class BruteDictList(Resource):
    @auth
    @ns.expect(list_parser)
    def get(self):
        """获取弱口令字典列表（文件名 + 大小）"""
        try:
            files = []
            if os.path.exists(DICT_DIR):
                for f in os.listdir(DICT_DIR):
                    if f.endswith('.txt'):
                        size = os.path.getsize(os.path.join(DICT_DIR, f))
                        files.append({'name': f, 'size': size})
            return {'code': 200, 'message': 'success', 'data': files}
        except Exception as e:
            logger.error(f"Error listing brute dictionaries: {e}")
            return {'code': 500, 'message': str(e)}


@ns.route('/preview')
class BruteDictPreview(Resource):
    @auth
    @ns.expect(preview_parser)
    def get(self):
        """预览字典内容（限制行数）"""
        args = preview_parser.parse_args()
        name = args.get('name')
        limit = args.get('limit') or 500

        path = get_safe_dict_path(name)
        if not path:
            return {'code': 404, 'message': '文件不合法或不存在'}

        try:
            lines = []
            total = 0
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    total += 1
                    if total <= limit:
                        lines.append(stripped)
            return {
                'code': 200,
                'message': 'success',
                'data': {'lines': lines, 'total': total, 'limit': limit}
            }
        except Exception as e:
            logger.error(f"Error reading brute dictionary {name}: {e}")
            return {'code': 500, 'message': str(e)}


@ns.route('/search')
class BruteDictSearch(Resource):
    @auth
    @ns.expect(search_parser)
    def get(self):
        """搜索字典条目（关键词匹配）"""
        args = search_parser.parse_args()
        name = args.get('name')
        keyword = args.get('keyword', '').strip()

        path = get_safe_dict_path(name)
        if not path:
            return {'code': 404, 'message': '文件不合法或不存在'}

        if not keyword:
            return {'code': 400, 'message': '关键词不能为空'}

        try:
            matches = []
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    if keyword in stripped:
                        matches.append(stripped)
                        if len(matches) >= 100:
                            break
            return {
                'code': 200,
                'message': 'success',
                'data': {'matches': matches, 'keyword': keyword}
            }
        except Exception as e:
            logger.error(f"Error searching brute dictionary {name}: {e}")
            return {'code': 500, 'message': str(e)}


@ns.route('/append')
class BruteDictAppend(Resource):
    @auth
    @ns.expect(append_parser)
    def post(self):
        """向字典追加条目（自动去重）"""
        args = append_parser.parse_args()
        name = args.get('name')
        content = args.get('content', '')

        path = get_safe_dict_path(name)
        if not path:
            return {'code': 404, 'message': '文件不合法或不存在'}

        new_entries = [line.strip() for line in content.split('\n') if line.strip()]
        if not new_entries:
            return {'code': 400, 'message': '追加内容不能为空'}

        try:
            existing_set = set()
            clean_lines = []
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                raw_lines = f.readlines()
            for line in raw_lines:
                stripped = line.strip()
                if stripped and stripped not in existing_set:
                    existing_set.add(stripped)
                    clean_lines.append(stripped)

            to_append = [e for e in new_entries if e not in existing_set]

            if to_append or len(clean_lines) != len(raw_lines):
                clean_lines.extend(to_append)
                with open(path, 'w', encoding='utf-8') as f:
                    for entry in clean_lines:
                        f.write(f"{entry}\n")

            return {
                'code': 200,
                'message': 'success',
                'data': {'total_submitted': len(new_entries), 'added': len(to_append)}
            }
        except Exception as e:
            logger.error(f"Error appending to brute dictionary {name}: {e}")
            return {'code': 500, 'message': str(e)}


@ns.route('/delete_entries')
class BruteDictDelete(Resource):
    @auth
    @ns.expect(delete_parser)
    def post(self):
        """从字典中批量删除条目"""
        args = delete_parser.parse_args()
        name = args.get('name')
        content = args.get('content', '')

        path = get_safe_dict_path(name)
        if not path:
            return {'code': 404, 'message': '文件不合法或不存在'}

        entries_to_delete = set(line.strip() for line in content.split('\n') if line.strip())
        if not entries_to_delete:
            return {'code': 400, 'message': '要删除的内容不能为空'}

        try:
            retained = []
            deleted_count = 0
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    clean = line.strip()
                    if clean in entries_to_delete:
                        deleted_count += 1
                    else:
                        if clean:
                            retained.append(clean)

            with open(path, 'w', encoding='utf-8') as f:
                if retained:
                    f.write('\n'.join(retained) + '\n')

            return {
                'code': 200,
                'message': 'success',
                'data': {'total_submitted': len(entries_to_delete), 'deleted': deleted_count}
            }
        except Exception as e:
            logger.error(f"Error deleting from brute dictionary {name}: {e}")
            return {'code': 500, 'message': str(e)}


# 全局弱口令大字典上传任务进度跟踪
brute_upload_status_map = {}

def process_large_brute_dict_async(task_id, file_path_tmp, target_path):
    try:
        inserted = 0
        ignored = 0
        existing_set = set()

        if os.path.exists(target_path):
            with open(target_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    stripped = line.strip()
                    if stripped:
                        existing_set.add(stripped)

        to_write = []
        with open(file_path_tmp, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                if stripped not in existing_set:
                    existing_set.add(stripped)
                    to_write.append(stripped)
                    inserted += 1
                else:
                    ignored += 1

        if to_write:
            mode = 'a' if os.path.exists(target_path) and os.path.getsize(target_path) > 0 else 'w'
            with open(target_path, mode, encoding='utf-8') as f:
                for item in to_write:
                    f.write(f"{item}\n")

        if os.path.exists(file_path_tmp):
            os.remove(file_path_tmp)

        brute_upload_status_map[task_id] = {
            'status': 'completed',
            'inserted_lines': inserted,
            'ignored_lines': ignored,
            'message': 'success'
        }
    except Exception as e:
        logger.exception(f"Error processing large brute dict for task {task_id}: {e}")
        brute_upload_status_map[task_id] = {
            'status': 'error',
            'inserted_lines': 0,
            'ignored_lines': 0,
            'message': str(e)
        }
        if os.path.exists(file_path_tmp):
            try:
                os.remove(file_path_tmp)
            except Exception:
                pass


@ns.route('/upload_large')
class BruteDictUploadLarge(Resource):
    @auth
    def post(self):
        """
        弱口令大字典异步上传接口 (支持后台去重导入)
        """
        file_obj = request.files.get('file')
        name = request.form.get('name') or request.args.get('name')

        if not file_obj or not name:
            return {'code': 400, 'message': '缺少文件或文件名'}

        name = os.path.basename(name.strip())
        if not name.endswith('.txt') or '..' in name or '/' in name or '\\' in name:
            return {'code': 400, 'message': '文件名不合法，必须以 .txt 结尾'}

        target_path = os.path.join(DICT_DIR, name)
        task_id = str(uuid.uuid4())

        tmp_dir = os.path.join(DICT_DIR, 'tmp')
        os.makedirs(tmp_dir, exist_ok=True)
        tmp_path = os.path.join(tmp_dir, f"upload_{task_id}.tmp")

        try:
            file_obj.save(tmp_path)
        except Exception as e:
            return {'code': 500, 'message': f'保存临时文件失败: {e}'}

        brute_upload_status_map[task_id] = {
            'status': 'processing',
            'inserted_lines': 0,
            'ignored_lines': 0,
            'message': 'processing'
        }

        t = threading.Thread(target=process_large_brute_dict_async, args=(task_id, tmp_path, target_path))
        t.daemon = True
        t.start()

        return {
            'code': 200,
            'message': 'success',
            'task_id': task_id
        }


@ns.route('/upload_status')
class BruteDictUploadStatus(Resource):
    @auth
    def get(self):
        """
        查询弱口令大文件字典导入进度
        """
        task_id = request.args.get('task_id')
        if not task_id or task_id not in brute_upload_status_map:
            return {'code': 404, 'message': '任务不存在或已过期'}

        data = brute_upload_status_map[task_id]
        return {
            'code': 200,
            'message': 'success',
            'data': data
        }
