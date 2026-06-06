#!/usr/bin/env python3
import json
import logging
import os
import sys
from typing import Dict

from openai import OpenAI
from tool import R2Tool, ghidra_list_functions, run_ghidra_export

CHALLENGE_PATH = "/home/yt/react-agent/targets/challenge"
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY")
if not DEEPSEEK_API_KEY:
    print("Error: DEEPSEEK_API_KEY environment variable not set.")
    sys.exit(1)

LOG_FILE = "logs/run.txt"
OUTPUT_JSON = "vuln.json"
MAX_REACT_STEPS = 35   # 增加步数

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    filename=LOG_FILE,
    filemode="w",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logging.getLogger("").addHandler(console)
logger = logging.getLogger(__name__)


class ReActAgent:
    def __init__(self, binary_path: str, model: str = "deepseek-chat"):
        self.binary_path = binary_path
        self.model = model
        self.client = OpenAI(api_key=DEEPSEEK_API_KEY, base_url="https://api.deepseek.com")
        self.r2 = R2Tool(binary_path)
        self.messages = []
        self.step = 0

        self.system_prompt = f"""You are a security analyst agent for static binary vulnerability analysis.
The binary is stripped. Function names from radare2 look like 'fcn.00401216' or 'sym.imp.fgets'.
**CRITICAL**: First call r2_list_functions() to see actual function names. Then use those exact names in r2_disassemble().
Do NOT guess names like 'main', '_start', 'entry0' – they do not exist.

Tools: 
- r2_list_functions
- r2_disassemble(function_name, count)
- r2_find_strings
- r2_xrefs_to(target)
- ghidra_list_functions

Your task: Analyze {binary_path} and identify ONE security vulnerability.
When you have enough evidence, you MUST output your FINAL ANSWER as a JSON object ONLY, with no additional text before or after.
The JSON must have exactly these fields:
{{"vuln_type": "type", "location": "function name or address", "cause": "one sentence explanation"}}

Example:
{{"vuln_type": "stack_buffer_overflow", "location": "fcn.00401216", "cause": "User input read by fgets is copied with __strcpy_chk but destination size is only 16 bytes while input can be up to 100 bytes."}}

You MUST call at least one r2 tool and ghidra_list_functions.
"""

    def _call_tool(self, tool_name: str, args: Dict) -> str:
        if tool_name == "r2_list_functions":
            return self.r2.list_functions()
        elif tool_name == "r2_disassemble":
            return self.r2.disassemble(args.get("function_name", ""), args.get("count", 20))
        elif tool_name == "r2_find_strings":
            return self.r2.find_strings()
        elif tool_name == "r2_xrefs_to":
            return self.r2.xrefs_to(args.get("target", ""))
        elif tool_name == "ghidra_list_functions":
            funcs = ghidra_list_functions()
            if not funcs:
                return "Ghidra returned no functions (Python scripting not supported). Continuing analysis with radare2."
            lines = [f"{f['name']} @ {f['address']} size={f['size']}" for f in funcs[:50]]
            return "\n".join(lines)
        else:
            return f"Unknown tool: {tool_name}"

    def run(self):
        self.messages = [{"role": "system", "content": self.system_prompt}]
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "r2_list_functions",
                    "description": "List functions from radare2",
                    "parameters": {"type": "object", "properties": {}, "required": []}
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "r2_disassemble",
                    "description": "Disassemble a function by name",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "function_name": {"type": "string"},
                            "count": {"type": "integer", "default": 20}
                        },
                        "required": ["function_name"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "r2_find_strings",
                    "description": "Find strings in binary",
                    "parameters": {"type": "object", "properties": {}, "required": []}
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "r2_xrefs_to",
                    "description": "Find cross-references",
                    "parameters": {
                        "type": "object",
                        "properties": {"target": {"type": "string"}},
                        "required": ["target"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "ghidra_list_functions",
                    "description": "List functions from Ghidra",
                    "parameters": {"type": "object", "properties": {}, "required": []}
                }
            }
        ]

        while self.step < MAX_REACT_STEPS:
            self.step += 1
            logger.info(f"=== Step {self.step} ===")
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=self.messages,
                    tools=tools,
                    tool_choice="auto",
                    temperature=0.0,
                )
            except Exception as e:
                logger.error(f"API call failed: {e}")
                break

            message = response.choices[0].message
            self.messages.append(message)
            if message.content:
                logger.info(f"Thought: {message.content}")
            if message.tool_calls:
                for tc in message.tool_calls:
                    name = tc.function.name
                    args = json.loads(tc.function.arguments)
                    logger.info(f"Action: {name}({args})")
                    obs = self._call_tool(name, args)
                    logger.info(f"Observation: {obs[:500]}")
                    self.messages.append({"role": "tool", "tool_call_id": tc.id, "content": obs})
            else:
                # 无工具调用：尝试解析 JSON
                if message.content:
                    try:
                        content = message.content.strip()
                        if content.startswith("```json"):
                            content = content[7:]
                        if content.endswith("```"):
                            content = content[:-3]
                        result = json.loads(content)
                        if all(k in result for k in ("vuln_type", "location", "cause")):
                            logger.info("Final answer received from model.")
                            self.save_result(result)
                            return
                    except:
                        # 不是有效 JSON，提示模型输出 JSON
                        logger.info("Model output is not JSON, requesting JSON format.")
                        self.messages.append({
                            "role": "user",
                            "content": "Please output your final answer as a JSON object with fields vuln_type, location, cause, and nothing else."
                        })
                else:
                    # 没有任何输出，要求输出
                    self.messages.append({
                        "role": "user",
                        "content": "Please output your final vulnerability report as a JSON object."
                    })

        # 步数用尽，最后一次强制要求模型输出 JSON（不预设答案）
        logger.warning("Max steps reached, forcing final JSON from model.")
        self.messages.append({
            "role": "user",
            "content": "Based on all observations, output your final vulnerability report as a JSON object with fields vuln_type, location, cause. If you cannot determine, set vuln_type to 'unknown' and explain. Do not add any other text."
        })
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=self.messages,
                temperature=0.0,
            )
            content = response.choices[0].message.content
            try:
                if content.startswith("```json"):
                    content = content[7:]
                if content.endswith("```"):
                    content = content[:-3]
                result = json.loads(content)
                if all(k in result for k in ("vuln_type", "location", "cause")):
                    self.save_result(result)
                    return
            except:
                pass
        except Exception as e:
            logger.error(f"Final API call failed: {e}")

        # 如果模型仍然没有输出有效 JSON，则输出 unknown（不编造）
        self.save_result({
            "vuln_type": "unknown",
            "location": "unknown",
            "cause": "The agent reached the maximum number of steps and the model did not produce a valid JSON report."
        })

    def save_result(self, vuln_dict: Dict):
        with open(OUTPUT_JSON, "w") as f:
            json.dump(vuln_dict, f, indent=2)
        logger.info(f"Vulnerability report saved to {OUTPUT_JSON}")
        self.r2.close()


def main():
    if not os.path.exists(CHALLENGE_PATH):
        logger.error(f"Binary not found: {CHALLENGE_PATH}")
        sys.exit(1)
    if "GHIDRA_INSTALL_DIR" not in os.environ:
        os.environ["GHIDRA_INSTALL_DIR"] = "/snap/ghidra/37/ghidra_12.1_PUBLIC"
    run_ghidra_export(CHALLENGE_PATH)
    agent = ReActAgent(CHALLENGE_PATH)
    agent.run()
    logger.info("Agent finished. Check logs/run.txt and vuln.json")


if __name__ == "__main__":
    main()
