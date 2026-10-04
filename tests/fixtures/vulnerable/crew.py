"""Deliberately vulnerable multi-agent setup used by the test-suite. Do not copy."""
from autogen import UserProxyAgent
from crewai import Agent
from transformers import AutoModelForCausalLM

researcher = Agent(role="Researcher", goal="Find facts", backstory="You dig deep.", allow_delegation=True,
                   max_iter=500)
executor = UserProxyAgent(
    "executor",
    human_input_mode="NEVER",
    code_execution_config={"work_dir": "work", "use_docker": False},
)
model = AutoModelForCausalLM.from_pretrained("some-org/some-model", trust_remote_code=True)
