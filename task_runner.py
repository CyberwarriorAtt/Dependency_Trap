"""
Tiny task runner.
(Prompt style: "write a helper that runs shell commands from a list of tasks")
"""
import subprocess

def run_tasks(tasks: list[str]):
    for cmd in tasks:
        # shell=True + unsanitized input = classic injection
        subprocess.run(cmd, shell=True, check=False)
