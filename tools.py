import subprocess
import tempfile
import os

class Radare2Tool:
    def __init__(self, binary_path):
        self.binary = binary_path
        self._check_r2()

    def _check_r2(self):
        try:
            subprocess.run(["r2", "-v"], capture_output=True, check=True)
        except FileNotFoundError:
            raise EnvironmentError("radare2 not found in PATH")

    def run_cmd(self, r2_script):
        cmd = ["r2", "-c", r2_script, "-q", self.binary]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                return f"Error: {result.stderr.strip()}"
            out = result.stdout.strip()
            return out if out else "(no output)"
        except subprocess.TimeoutExpired:
            return "Error: r2 command timed out"

    def get_functions(self):
        return self.run_cmd("afl")

    def disassemble_function(self, func_name):
        return self.run_cmd(f"pdf @{func_name}")

    def find_strings(self):
        return self.run_cmd("izz")

    def get_imports(self):
        return self.run_cmd("iI")

class GhidraTool:
    def __init__(self, binary_path, ghidra_headless_path=None):
        self.binary = os.path.abspath(binary_path)
        self.ghidra_headless = ghidra_headless_path or os.getenv("GHIDRA_HEADLESS")
        if not self.ghidra_headless or not os.path.exists(self.ghidra_headless):
            raise EnvironmentError(f"Ghidra headless not found: {self.ghidra_headless}")
        if not os.access(self.ghidra_headless, os.X_OK):
            os.chmod(self.ghidra_headless, 0o755)

    def run_script(self, script_content):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(script_content)
            script_path = f.name

        proj_dir = tempfile.mkdtemp()
        proj_name = "temp_proj"
        output_file = tempfile.NamedTemporaryFile(mode='w+', suffix='.txt', delete=False)
        output_path = output_file.name
        output_file.close()

        cmd = [
            self.ghidra_headless, proj_dir, proj_name,
            "-import", self.binary,
            "-postScript", script_path,
            "-log", output_path
        ]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            with open(output_path, 'r') as log_f:
                content = log_f.read()
            return content
        except subprocess.TimeoutExpired:
            return "Error: Ghidra headless timed out"
        finally:
            os.unlink(script_path)
            subprocess.run(["rm", "-rf", proj_dir], capture_output=True)
            os.unlink(output_path)

    def get_functions(self):
        script = """
from ghidra.program.model.listing import FunctionManager
fm = currentProgram.getFunctionManager()
functions = fm.getFunctions(True)
for f in functions:
    print(f"{f.getName()} @ 0x{f.getEntryPoint().getOffset():x}")
"""
        return self.run_script(script)

    def get_decompilation(self, func_name):
        script = f"""
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
func = getFunction("{func_name}")
if func:
    decomp = DecompInterface()
    decomp.openProgram(currentProgram)
    res = decomp.decompileFunction(func, 60, ConsoleTaskMonitor())
    if res.decompileCompleted():
        print(res.getDecompiledFunction().getC())
    else:
        print("Decompile failed: " + res.getErrorMessage())
else:
    print(f"Function {func_name} not found")
"""
        return self.run_script(script)

    def find_strings(self):
        script = """
from ghidra.program.model.data import DataTypeManager
listing = currentProgram.getListing()
for addr in listing.getDefinedData(True):
    data = listing.getDefinedDataAt(addr)
    if data and data.getDataType().getName().startswith("string"):
        print(f"{addr}: {data.getDefaultValueRepresentation()}")
"""
        return self.run_script(script)
