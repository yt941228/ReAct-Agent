#!/usr/bin/env python3
import json
import logging
import os
import subprocess
import tempfile
from typing import Dict, List

import r2pipe

logger = logging.getLogger(__name__)

# Ghidra 配置（可通过环境变量覆盖）
GHIDRA_INSTALL_DIR = os.environ.get("GHIDRA_INSTALL_DIR", "/snap/ghidra/37/ghidra_12.1_PUBLIC")
GHIDRA_HEADLESS = f"{GHIDRA_INSTALL_DIR}/support/analyzeHeadless"
GHIDRA_EXPORT_FILE = "/home/yt/ghidra_functions.json"


class R2Tool:
    """radare2 工具封装（只读操作）"""

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.r2 = None

    def _open(self):
        if self.r2 is None:
            self.r2 = r2pipe.open(self.binary_path)
            self.r2.cmd("aaa")  # 自动分析

    def close(self):
        if self.r2:
            self.r2.quit()
            self.r2 = None

    def list_functions(self) -> str:
        """列出所有函数（限制50个）"""
        self._open()
        funcs = self.r2.cmdj("aflj")
        if not funcs:
            return "No functions found."
        lines = []
        for f in funcs[:50]:
            lines.append(f"{f.get('name','')} @ 0x{f.get('offset',0):x} size={f.get('size',0)}")
        return "\n".join(lines)

    def disassemble(self, func_name: str, count: int = 20) -> str:
        """反汇编指定函数的前 count 条指令"""
        self._open()
        funcs = self.r2.cmdj("aflj")
        addr = None
        for f in funcs:
            if f.get("name") == func_name:
                addr = f.get("offset")
                break
        if addr is None:
            return f"Function '{func_name}' not found."
        self.r2.cmd(f"s {addr}")
        dis = self.r2.cmd(f"pd {count}")
        return dis

    def find_strings(self) -> str:
        """查找所有可打印字符串（限制30个）"""
        self._open()
        strings = self.r2.cmdj("izzj")
        if not strings:
            return "No strings found."
        result = []
        for s in strings[:30]:
            result.append(f"0x{s['vaddr']:x}: {s['string']}")
        return "\n".join(result)

    def xrefs_to(self, target: str) -> str:
        """查找交叉引用：target 可以是地址（如 0x401234）或函数名"""
        self._open()
        try:
            addr = int(target, 16)
        except ValueError:
            # 可能是函数名
            funcs = self.r2.cmdj("aflj")
            found = None
            for f in funcs:
                if f.get("name") == target:
                    found = f.get("offset")
                    break
            if found is None:
                return f"Cannot resolve '{target}'"
            addr = found
        self.r2.cmd(f"s {addr}")
        xrefs = self.r2.cmdj("axtj")
        if not xrefs:
            return f"No xrefs to {target}"
        lines = []
        for x in xrefs[:20]:
            lines.append(f"from 0x{x['from']:x} ({x.get('type','')})")
        return "\n".join(lines)


def run_ghidra_export(binary_path: str) -> None:
    """
    使用 Ghidra headless 分析二进制文件，导出函数信息到 GHIDRA_EXPORT_FILE
    如果文件已存在则跳过；若失败则创建空 JSON 文件，不影响后续执行
    """
    if os.path.exists(GHIDRA_EXPORT_FILE) and os.path.getsize(GHIDRA_EXPORT_FILE) > 2:
        logger.info(f"Ghidra export already exists at {GHIDRA_EXPORT_FILE}")
        return

    # 确保输出目录可写
    os.makedirs(os.path.dirname(GHIDRA_EXPORT_FILE), exist_ok=True)

    # 创建临时项目目录
    project_parent = tempfile.mkdtemp(prefix="ghidra_parent_")
    project_dir = os.path.join(project_parent, "TempProject")
    os.makedirs(project_dir, exist_ok=True)

    # Ghidra Python 脚本
    script_content = '''
import json
from ghidra.program.model.listing import Function

def main():
    program = getState().getCurrentProgram()
    if program is None:
        print("No program loaded")
        return
    listing = program.getListing()
    functions = []
    for func in listing.getFunctions(True):
        name = func.getName()
        entry = str(func.getEntryPoint())
        size = func.getBody().getNumAddresses()
        functions.append({"name": name, "address": entry, "size": size})
    with open("/home/yt/ghidra_functions.json", "w") as f:
        json.dump(functions, f, indent=2)
    print("Exported %d functions" % len(functions))

if __name__ == "__main__":
    main()
'''
    script_path = "/tmp/ghidra_export.py"
    with open(script_path, "w") as f:
        f.write(script_content)

    cmd = [
        GHIDRA_HEADLESS, project_dir, "TempProject",
        "-import", binary_path,
        "-postScript", script_path,
        "-deleteProject"
    ]
    logger.info(f"Running Ghidra headless: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            logger.error(f"Ghidra headless stderr: {result.stderr}")
        else:
            logger.info("Ghidra export completed.")
        # 检查导出文件是否生成
        if not os.path.exists(GHIDRA_EXPORT_FILE) or os.path.getsize(GHIDRA_EXPORT_FILE) <= 2:
            logger.warning("Ghidra export file not created or empty.")
            with open(GHIDRA_EXPORT_FILE, "w") as f:
                json.dump([], f)
    except Exception as e:
        logger.error(f"Ghidra export failed: {e}")
        with open(GHIDRA_EXPORT_FILE, "w") as f:
            json.dump([], f)
    finally:
        # 清理临时目录
        try:
            subprocess.run(["rm", "-rf", project_parent], check=False)
        except:
            pass


def ghidra_list_functions() -> List[Dict]:
    """读取预导出的 Ghidra 函数列表（若导出失败则返回空列表）"""
    if not os.path.exists(GHIDRA_EXPORT_FILE):
        logger.warning("Ghidra export file not found. Run run_ghidra_export first.")
        return []
    with open(GHIDRA_EXPORT_FILE, "r") as f:
        return json.load(f)
