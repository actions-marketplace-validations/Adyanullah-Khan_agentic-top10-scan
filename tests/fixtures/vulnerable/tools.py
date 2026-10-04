"""Deliberately vulnerable agent tools used by the test-suite. Do not copy."""
import importlib
import os
import pickle
import sqlite3
import subprocess

import requests
from langchain_community.tools import ShellTool
from langchain_core.tools import tool
from tenacity import retry


@tool
def run_shell(command: str) -> str:
    """Run a shell command and return its output."""
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout


@tool
def save_note(path: str, content: str) -> str:
    """Save a note to disk."""
    with open(path, "w") as fh:
        fh.write(content)
    return "saved"


@tool
def fetch_page(url: str) -> str:
    """Fetch a web page."""
    return requests.get(url).text


@tool
def lookup_customer(name: str) -> list:
    """Find a customer by name."""
    conn = sqlite3.connect("crm.db")
    return conn.execute(f"SELECT * FROM customers WHERE name = '{name}'").fetchall()


@tool
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email to a customer."""
    try:
        requests.post("https://mail.internal.example/send", json={"to": to, "subject": subject, "body": body},
                      timeout=10)
    except Exception:
        pass
    return "sent"


@tool
def update_instructions(text: str) -> str:
    """Improve your own instructions."""
    with open("prompts/system_prompt.md", "w") as fh:
        fh.write(text)
    return "updated"


@tool
def schedule_job(cron_line: str) -> str:
    """Schedule a recurring job."""
    os.system(f"(crontab -l; echo '{cron_line}') | crontab -")
    return "scheduled"


@tool
def install_package(name: str) -> str:
    """Install a Python package the agent needs."""
    subprocess.run(["pip", "install", name], check=True)
    return "installed"


@retry
def call_backend(payload):
    return requests.post("https://backend.example-corp.net/api", json=payload, timeout=5).json()


def load_plugin(name):
    return importlib.import_module(name)


def load_cache(path):
    with open(path, "rb") as fh:
        return pickle.load(fh)


def calculator(expression):
    return eval(expression)


def archive(folder):
    os.system("tar czf backup.tgz " + folder)


def shell_tool():
    return ShellTool()
