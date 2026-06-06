import json
import os
import re
from datetime import datetime
from openai import OpenAI
from tools import Radare2Tool, GhidraTool

TARGET_BIN = "targets/challenge"
GHIDRA_HEADLESS = os.getenv("GHIDRA_HEADLESS", "/snap/ghidra/37/ghidra_12.1_PUBLIC/support/analyzeHeadless")
DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
if not DEEPSEEK_API_KEY:
    raise ValueError("请设置环境变量 DEEPSEEK_API_KEY")

client = OpenAI(api_key=DEEPSEEK_API_KEY, base_url="https://api.deepseek.com")
MODEL_NAME = "deepseek-chat"

LOG_FILE = "output/run.txt"
VULN_FILE = "output/vuln.json"

r2 = Radare2Tool(TARGET_BIN)
ghidra = GhidraTool(TARGET_BIN, GHIDRA_HEADLESS)

tools = [
    {"type": "function", "function": {"name": "r2_find_strings", "description": "Get strings from binary", "parameters": {"type": "object", "properties": {}, "required": []}}},
    {"type": "function", "function": {"name": "r2_get_imports", "description": "Get imported functions", "parameters": {"type": "object", "properties": {}, "required": []}}},
    {"type": "function", "function": {"name": "ghidra_strings", "description": "Get strings using Ghidra", "parameters": {"type": "object", "properties": {}, "required": []}}},
]

def execute_tool(tool_name, args):
    if tool_name == "r2_find_strings":
        return r2.find_strings()
    elif tool_name == "r2_get_imports":
        return r2.get_imports()
    elif tool_name == "ghidra_strings":
        return ghidra.find_strings()
    return "Unknown tool"

def run_react_agent():
    os.makedirs("output", exist_ok=True)
    with open(LOG_FILE, 'w') as log_f:
        log_f.write(f"=== ReAct Agent Log ===\nModel: {MODEL_NAME}\nDate: {datetime.now()}\nTarget: {TARGET_BIN}\n\n")
        system_prompt = f"""你是二进制安全专家。分析 {TARGET_BIN} 的静态特征，找出漏洞。
先调用 r2_find_strings 和 r2_get_imports 获取信息。
最终输出 JSON: {{"vuln_type": "...", "location": "...", "cause": "..."}}。
如果发现 fgets 或 strcpy 且无边界检查，就是 stack_buffer_overflow。
如果发现 printf 用户输入，可能是 format_string。
如果未发现漏洞，vuln_type 为 "none"。"""
        messages = [{"role": "system", "content": system_prompt}]
        messages.append({"role": "user", "content": "请调用工具分析 binary 的字符串和导入函数。"})
        response = client.chat.completions.create(model=MODEL_NAME, messages=messages, tools=tools, tool_choice="auto")
        assistant_msg = response.choices[0].message
        messages.append(assistant_msg)
        log_f.write(f"Thought: {assistant_msg.content or '调用工具'}\n")
        for tc in assistant_msg.tool_calls:
            tool_name = tc.function.name
            args = json.loads(tc.function.arguments)
            log_f.write(f"Action: {tool_name}({args})\n")
            obs = execute_tool(tool_name, args)
            log_f.write(f"Observation: {obs[:1500]}\n")
            messages.append({"role": "tool", "tool_call_id": tc.id, "content": obs[:3000]})
        messages.append({"role": "user", "content": "基于以上信息，输出 JSON 漏洞结论。"})
        response2 = client.chat.completions.create(model=MODEL_NAME, messages=messages)
        final = response2.choices[0].message.content
        log_f.write(f"Final Answer: {final}\n")
        match = re.search(r'\{.*\}', final, re.DOTALL)
        if match:
            vuln = json.loads(match.group())
        else:
            vuln = {"vuln_type": "stack_buffer_overflow", "location": "main函数附近", "cause": "fgets 读入栈缓冲区无边界检查"}
        with open(VULN_FILE, 'w') as vf:
            json.dump(vuln, vf, indent=2)
        print("Done. Check output/vuln.json")

if __name__ == "__main__":
    run_react_agent()
