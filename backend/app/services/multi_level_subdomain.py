import os
import subprocess
import tempfile
import time
from app import utils
from app.config import Config
from app.utils import conn_db as conn
from app import modules

logger = utils.get_logger()


class MultiLevelSubdomainEngine:
    """
    多级子域名深度挖掘与防封解析引擎
    集成链路：
    1. 自动聚合当前任务子域 + 历史任务已有子域资产 (+ subfinder 被动零接触深挖)
    2. alterx 智能识别命名规律进行三四级子域智能变异
    3. puredns + massdns + 全球分布式可信 DNS 池进行防封解析与多级泛解析智能剔除
    """

    def __init__(self, base_domain, current_domains=None, task_id=None, tools_dir=None, import_history=True):
        self.base_domain = base_domain.strip().lower()
        self.current_domains = current_domains or []
        self.task_id = task_id
        self.import_history = import_history

        # 候选工具根目录
        candidates = [
            tools_dir,
            "/code/backend/tools/domain_all",
            "/root/ARL-Next/backend/app/tools/domain_all",
            "/root/tool/domainAll"
        ]
        self.tools_dir = next((d for d in candidates if d and os.path.isdir(d)), None)
        if not self.tools_dir:
            self.tools_dir = "/code/backend/tools/domain_all"

        self.subfinder_bin = os.path.join(self.tools_dir, "subfinder")
        self.alterx_bin = os.path.join(self.tools_dir, "alterx")
        self.puredns_bin = os.path.join(self.tools_dir, "puredns")
        self.resolvers_file = os.path.join(self.tools_dir, "resolvers.txt")

        # massdns 优先使用 tools 目录下的，如无则使用系统 /usr/local/bin/massdns
        self.massdns_bin = os.path.join(self.tools_dir, "massdns")
        if not os.path.exists(self.massdns_bin):
            self.massdns_bin = "/usr/local/bin/massdns"

    def collect_seeds(self):
        """收集种子子域名：当前任务发现 + 历史数据库已存 + subfinder被动补充"""
        seeds = set()

        # 1. 当前任务已经发现的子域名
        for d in self.current_domains:
            if isinstance(d, dict):
                d = d.get('domain', '')
            elif hasattr(d, 'domain'):
                d = getattr(d, 'domain', '')
            d = str(d).strip().lower()
            if d.endswith("." + self.base_domain) or d == self.base_domain:
                seeds.add(d)

        # 2. 从 MongoDB 历史资产库中自动导入属于该主域的所有已知子域名
        if self.import_history:
            try:
                # 根据根域名 (fld) 查所有历史子域名，同时匹配以该域名结尾的记录
                history_domains = set()
                try:
                    fld_domains = conn('domain').distinct('domain', {'fld': self.base_domain})
                    if fld_domains:
                        history_domains.update(fld_domains)
                except Exception:
                    pass

                # 兜底查询
                if len(history_domains) < 5:
                    import re
                    pattern = {"$regex": re.escape("." + self.base_domain) + "$"}
                    regex_domains = conn('domain').distinct('domain', {'domain': pattern})
                    if regex_domains:
                        history_domains.update(regex_domains)

                added_history_count = 0
                for d in history_domains:
                    d = str(d).strip().lower()
                    if d.endswith("." + self.base_domain):
                        seeds.add(d)
                        added_history_count += 1
                logger.info(f"[MultiLevelSubdomain] Auto-imported {added_history_count} historical subdomains from DB for {self.base_domain}")
            except Exception as e:
                logger.warning(f"[MultiLevelSubdomain] Failed to import historical domains for {self.base_domain}: {e}")

        # 3. 运行 subfinder 被动零接触补充种子
        if os.path.exists(self.subfinder_bin):
            try:
                cmd = [self.subfinder_bin, "-d", self.base_domain, "-all", "-silent", "-duc"]
                logger.info(f"[MultiLevelSubdomain] Running subfinder: {' '.join(cmd)}")
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                stdout, _ = proc.communicate(timeout=180)
                sub_count = 0
                for line in stdout.decode('utf-8', errors='ignore').splitlines():
                    line = line.strip().lower()
                    if line.endswith("." + self.base_domain):
                        seeds.add(line)
                        sub_count += 1
                logger.info(f"[MultiLevelSubdomain] Subfinder passive added {sub_count} seeds, total seed count: {len(seeds)}")
            except Exception as e:
                logger.warning(f"[MultiLevelSubdomain] Subfinder passive discovery warning: {e}")

        # 确保根域名自身也在种子中
        seeds.add(self.base_domain)
        return list(seeds)

    def run(self):
        start_time = time.time()
        logger.info(f"[MultiLevelSubdomain] Starting multi-level subdomain engine for {self.base_domain}")

        seeds = self.collect_seeds()
        if not seeds:
            logger.warning(f"[MultiLevelSubdomain] No seeds found for {self.base_domain}")
            return []

        logger.info(f"[MultiLevelSubdomain] Total seed subdomains ready for mutation: {len(seeds)}")

        with tempfile.TemporaryDirectory() as tmpdir:
            seeds_path = os.path.join(tmpdir, "seeds.txt")
            candidates_path = os.path.join(tmpdir, "candidates.txt")
            resolved_path = os.path.join(tmpdir, "resolved.txt")

            with open(seeds_path, "w", encoding="utf-8") as f:
                for s in seeds:
                    f.write(s + "\n")

            # 4. 调用 alterx 进行规律变异
            if not os.path.exists(self.alterx_bin):
                logger.error(f"[MultiLevelSubdomain] alterx binary not found at {self.alterx_bin}")
                return []

            alterx_cmd = f"{self.alterx_bin} -silent -duc -enrich"
            logger.info(f"[MultiLevelSubdomain] Running alterx pipe: cat seeds | {alterx_cmd}")
            candidates = set()
            try:
                with open(seeds_path, "r", encoding="utf-8") as fin:
                    proc = subprocess.Popen(
                        alterx_cmd,
                        shell=True,
                        stdin=fin,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL
                    )
                    stdout, _ = proc.communicate(timeout=300)

                for line in stdout.decode('utf-8', errors='ignore').splitlines():
                    line = line.strip().lower()
                    if line and line.endswith("." + self.base_domain):
                        # 排除超长或异常字符
                        if len(line) - len(self.base_domain) < 80 and not line.startswith("."):
                            candidates.add(line)

                # 剔除已经在 seeds 中的域名，只保留新生成的候选多级域名
                candidates = candidates - set(seeds)
                logger.info(f"[MultiLevelSubdomain] alterx generated {len(candidates)} new candidates for {self.base_domain}")
            except Exception as e:
                logger.error(f"[MultiLevelSubdomain] alterx mutation failed: {e}")
                return []

            if not candidates:
                logger.info(f"[MultiLevelSubdomain] No new candidates generated by alterx for {self.base_domain}")
                return []

            # 写入待解析列表（最多保留 30000 候选，兼顾速度与全面性）
            candidate_list = list(candidates)[:30000]
            with open(candidates_path, "w", encoding="utf-8") as f:
                for c in candidate_list:
                    f.write(c + "\n")

            # 5. 调用 puredns 进行分布式防封解析 + 泛解析过滤
            if not os.path.exists(self.puredns_bin):
                logger.error(f"[MultiLevelSubdomain] puredns binary not found at {self.puredns_bin}")
                return []

            puredns_cmd = [
                self.puredns_bin, "resolve", candidates_path,
                "-r", self.resolvers_file,
                "--bin", self.massdns_bin,
                "-w", resolved_path,
                "-q"
            ]
            logger.info(f"[MultiLevelSubdomain] Running puredns: {' '.join(puredns_cmd)}")
            try:
                subprocess.run(puredns_cmd, timeout=900, check=True)
            except Exception as e:
                logger.error(f"[MultiLevelSubdomain] puredns execution failed: {e}")

            # 6. 读取解析成功的存活子域名
            live_domains = []
            if os.path.exists(resolved_path):
                with open(resolved_path, "r", encoding="utf-8") as f:
                    for line in f:
                        dom = line.strip().lower()
                        if dom and dom.endswith("." + self.base_domain):
                            live_domains.append(dom)

            live_domains = list(set(live_domains))
            elapse = time.time() - start_time
            logger.info(f"[+] MultiLevelSubdomain finished for {self.base_domain}: {len(live_domains)} valid multi-level subdomains discovered in {elapse:.2f}s")
            return live_domains
