"""AST checks for Python agent code, with intra-procedural taint tracking.

Taint labels describe where a value came from. A value is followed through assignments, string building,
method calls and (one level of) helper-function returns within a module, and the checks fire when it reaches
a sink: a prompt, a shell, SQL, eval, a file path, an HTTP request or a long-term memory write.
"""
from __future__ import annotations

import ast
import re
from typing import Dict, FrozenSet, Iterable, Iterator, List, Optional, Set, Tuple

from .. import textutil
from ..models import FileContext, Severity, ToolInfo
from . import text_checks

USER = "user input"
EXTERNAL = "untrusted external or retrieved content"
EXTERNAL_FENCED = "delimited external content"
MODEL = "model-chosen tool argument"
LLM = "LLM output"
SECRET = "secret"
PROMPT_REPORTED = "already reported at prompt assignment"
EMPTY: FrozenSet[str] = frozenset()
UNTRUSTED = frozenset({USER, MODEL, EXTERNAL, EXTERNAL_FENCED})

AGENT_MODULES = (
    "langchain", "langchain_core", "langchain_community", "langchain_openai", "langchain_anthropic",
    "langchain_experimental", "langchain_classic", "langgraph", "crewai", "autogen", "autogen_agentchat", "autogen_ext",
    "agents", "openai", "anthropic", "llama_index", "smolagents", "pydantic_ai", "semantic_kernel", "mcp", "fastmcp",
    "haystack", "dspy", "google.adk", "google.genai", "google.generativeai", "litellm", "ollama", "agno", "letta",
    "mem0", "camel", "swarm", "instructor", "interpreter", "a2a", "strands", "bedrock_agentcore", "claude_agent_sdk",
)
TRACING_MODULES = (
    "langsmith", "langfuse", "opentelemetry", "openinference", "phoenix", "arize", "agentops", "weave", "mlflow",
    "helicone", "logfire", "traceloop", "braintrust", "openlit", "lunary", "literalai", "portkey_ai", "opik",
)

SHELL_FUNCS = {
    "os.system", "os.popen", "commands.getoutput", "commands.getstatusoutput", "subprocess.getoutput",
    "subprocess.getstatusoutput", "asyncio.create_subprocess_shell", "pty.spawn",
}
SUBPROCESS_FUNCS = {
    "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen",
    "asyncio.create_subprocess_exec", "os.execv", "os.execve", "os.execvp", "os.execvpe", "os.execl", "os.execle",
    "os.execlp", "os.execlpe", "os.spawnv", "os.spawnve", "os.spawnl", "os.spawnlp", "os.posix_spawn",
    "os.posix_spawnp",
}
EVAL_FUNCS = {"eval", "exec", "compile", "builtins.eval", "builtins.exec", "builtins.compile"}
DESER_FUNCS = {
    "pickle.load", "pickle.loads", "cPickle.load", "cPickle.loads", "_pickle.loads", "marshal.load", "marshal.loads",
    "dill.load", "dill.loads", "cloudpickle.load", "cloudpickle.loads", "shelve.open", "jsonpickle.decode",
    "pandas.read_pickle", "joblib.load", "yaml.unsafe_load", "yaml.unsafe_load_all",
}
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "request", "stream", "options"}
FS_MUTATORS = {
    "os.remove", "os.unlink", "os.rmdir", "os.removedirs", "shutil.rmtree", "shutil.move", "os.rename", "os.replace",
    "shutil.copy", "shutil.copyfile", "shutil.copy2", "shutil.copytree", "os.chmod", "os.chown", "os.truncate",
}
PATH_WRITE_METHODS = {"write_text", "write_bytes", "unlink", "rmdir", "rename", "replace", "chmod"}

LLM_SUFFIXES = (
    "completions.create", "messages.create", "responses.create", "ChatCompletion.create", "Completion.create",
    "completions.parse", "responses.parse", "messages.stream", "models.generate_content",
)
LLM_FUNCS = {"litellm.completion", "litellm.acompletion", "ollama.chat", "ollama.generate", "completion", "acompletion"}
LLM_METHODS = {
    "invoke", "ainvoke", "predict", "apredict", "generate_content", "generate_content_async", "complete",
    "acomplete", "chat", "achat", "kickoff", "kickoff_async", "run_sync", "astream", "stream_chat", "query_chat",
}
LLMISH_RE = re.compile(r"(?i)(llm|chain|agent|crew|model|runner|assistant|graph|executor|chat|gpt|claude|gemini|"
                       r"openai|anthropic|client|team|swarm|bot)")
RETRIEVER_RE = re.compile(r"(?i)(retriev|search|tool|loader|vector|store|index|wiki|tavily|serp|browser|scrape|"
                          r"crawl|fetch|kb|knowledge|docs?$|db$|collection)")
RETRIEVAL_METHODS = {
    "similarity_search", "similarity_search_with_score", "similarity_search_with_relevance_scores",
    "max_marginal_relevance_search", "get_relevant_documents", "aget_relevant_documents", "asimilarity_search",
    "retrieve", "aretrieve",
}
LOAD_METHODS = {"load", "lazy_load", "aload", "load_and_split", "alazy_load", "load_data"}
WEB_FUNCS = {"trafilatura.fetch_url", "trafilatura.extract", "urllib.request.urlopen", "newspaper.Article",
             "feedparser.parse", "wikipedia.page", "wikipedia.summary"}
USER_FUNCS = {"input", "streamlit.text_input", "streamlit.chat_input", "streamlit.text_area", "getpass.getpass",
              "click.prompt", "typer.prompt", "rich.prompt.Prompt.ask"}
REQUEST_ATTRS = {"json", "form", "args", "values", "data", "files", "get_json", "get_data", "cookies", "body", "POST",
                 "GET", "query_params", "path_params", "text", "stream"}

SECRET_ENV_RE = re.compile(r"(?i)(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|PRIVATE)")
SECRET_NAME_RE = re.compile(r"(?i)^(?!.*(max|num|count|limit|_url|_path|_file|_name|tokens$))"
                            r".*(api_?key|secret|passw(or)?d|private_?key|access_?key|auth_?token|access_token|"
                            r"bearer|credential)")
SANITIZER_RE = re.compile(r"(?i)(sanitiz|escape|quote|clean|redact|strip_tags|bleach|moderat|guard|is_safe|"
                          r"detect_injection|spotlight|fence|wrap_untrusted|delimit|scrub|neutraliz)")
VALIDATOR_RE = re.compile(r"(?i)\b\w*(sanitiz|validat|moderat|guard|is_safe|detect_injection|classif|scan_|verify_"
                          r"content|check_content|filter_content|allowlist|whitelist)\w*\s*\(")
PATH_GUARD_RE = re.compile(r"(is_relative_to|commonpath|secure_filename|safe_join|\.startswith\(\s*str\(|"
                           r"\.startswith\(\s*os\.path\.(realpath|abspath)|(?i:safe_?path|validate_?path|sandbox|"
                           r"allowed_?(root|dir)|chroot))")
URL_GUARD_RE = re.compile(r"(?i)(allow(ed)?_?(list|hosts|domains|urls)|whitelist|is_allowed|validate_url|is_safe_url|"
                          r"ipaddress\.ip_address|is_private)")
FENCE_RE = re.compile(r"<\s*/?\s*[A-Za-z_][\w\-]*\s*>|```|<<<|>>>|\bBEGIN\b|(?i:untrusted)|-----|\[/?(DOCUMENT|"
                      r"CONTEXT|DATA)\]")
SYSTEM_VAR_RE = re.compile(r"(?i)^(system_?(prompt|message|instructions?|msg|template)s?|instructions|"
                           r"developer_?(prompt|message))$")
PROMPT_VAR_RE = re.compile(r"(?i)(prompt|instruction|system_?message|backstory|persona|preamble)")
SYSTEM_KWS = {"system", "instructions", "system_prompt", "system_message", "system_instruction", "developer_message",
              "preamble", "system_template"}
USER_PROMPT_KWS = {"prompt", "input", "contents", "query", "question", "content", "inputs", "text", "message"}
TOOL_DESC_CALLS = {"Tool", "StructuredTool", "from_function", "FunctionTool", "from_defaults", "tool", "function_tool",
                   "BaseTool", "DynamicTool", "add_tool"}

TOOL_DECORATOR_RE = re.compile(r"(^|\.)(tool|function_tool|tool_plain|kernel_function|ai_function|register_tool|"
                               r"ai_callable|define_tool|register_for_llm|register_for_execution|mcp_tool|"
                               r"agent_tool)$")
ROUTE_ATTRS = {"get", "post", "put", "patch", "delete", "route", "api_route", "websocket", "on_message", "message",
               "event", "command", "http", "on_chat_start", "action", "shortcut", "slash_command"}
AUTH_RE = re.compile(r"(?i)(auth|login|jwt|token|permission|require|protected|verify|api_?key|security|current_?user|"
                     r"session|signature|admin_only)")
AUTH_BODY_RE = re.compile(r"(?i)(headers(\.get\(|\[)\s*['\"](authorization|x-api-key|api-key)|verify_token|"
                          r"current_user|get_current_user|authenticate\(|check_auth|require_auth|jwt\.decode|"
                          r"is_authenticated|compare_digest|verify_signature|verify_api_key)")
NON_TOOL_PARAMS = {"self", "cls", "ctx", "context", "run_manager", "config", "callbacks", "tool_context", "runtime",
                   "wrapper", "state", "store", "tool_call_id"}

HIGH_IMPACT_RE = re.compile(
    r"(?i)^_?(a)?(send|email|mail|sms|text_message|post(?!_?process)|publish|tweet|pay|charge|refund|transfer|wire|"
    r"withdraw|purchase|buy|sell|trade|place_order|delete|remove|drop|destroy|purge|wipe|terminate|shutdown|deploy|"
    r"merge|push|grant|revoke|book|cancel|execute_sql|run_sql|exec_sql|reset_password|close_account|"
    r"submit_payment|transfer_funds)(_|$)"
)
APPROVAL_RE = re.compile(r"(?i)(approv|confirm|interrupt\(|human_in_the_loop|human_input|hitl|consent|needs_approval|"
                         r"require[sd]?_approval|ask_user|ask_human|user_confirmation|elicit|permission)")
HITL_MODULE_RE = re.compile(r"(interrupt_before|interrupt_after|\binterrupt\(|HumanApprovalCallbackHandler|"
                            r"HumanInTheLoop|human_input\s*=\s*True|needs_approval\s*=\s*True|require_approval|"
                            r"requires_approval\s*=\s*True|ApprovalMiddleware|\.elicit\()")
SELF_MOD_RE = re.compile(r"(?i)(system[_\-]?prompt|prompts?/|instructions|agent[_\-]manifest|agents\.md|claude\.md|"
                         r"gemini\.md|\.cursorrules|\.clinerules|mcp\.json|\.claude/|\.vscode/settings|"
                         r"copilot-instructions|\.py$|\.py['\"]?$|tools?\.py|agent\.py|settings\.json|"
                         r"permissions|policy\.(ya?ml|json))")
PERSIST_RE = re.compile(r"(?i)(\bcrontab\b|systemctl\s+(enable|start|daemon-reload)|launchctl\s+(load|bootstrap)|"
                        r"\bschtasks\b|\bnohup\b|\bdisown\b|\bsetsid\b|update-rc\.d|chkconfig|"
                        r"(^|[~/\s\"'])\.(bashrc|zshrc|bash_profile|zprofile|profile)\b|LaunchAgents|LaunchDaemons|authorized_keys|/etc/cron|"
                        r"CurrentVersion\\\\?Run|Start Menu\\\\?Programs\\\\?Startup|/etc/systemd)")
INSTALL_RE = re.compile(r"(?i)\b(pip3?|uv|npm|pnpm|yarn|apt(-get)?|brew|gem|cargo|go|conda|poetry)\s+(-m\s+pip\s+)?"
                        r"(install|add|get)\b|-m\s+pip\s+install")
DANGEROUS_IMPORTS = {"*", "os", "subprocess", "sys", "shutil", "socket", "builtins", "importlib", "pickle", "ctypes",
                     "posix", "pty", "multiprocessing", "requests", "urllib", "http"}
MEMORY_WRITE_METHODS = {"add_texts", "add_documents", "aadd_texts", "aadd_documents", "upsert", "add_memory",
                        "create_memory", "put", "aput", "add", "insert", "store", "remember", "save_memory",
                        "add_embeddings", "index_documents"}
PERSISTENT_STORE_RE = re.compile(r"(?i)(vector|vectorstore|vs$|store|collection|index|kb$|knowledge|memory|mem0|"
                                 r"chroma|pinecone|qdrant|weaviate|faiss|milvus|lancedb|pgvector|redis|zep|letta|"
                                 r"long_?term|db$)")
MEMORY_CLASSES = {"ConversationBufferMemory", "ConversationBufferWindowMemory", "ConversationSummaryMemory",
                  "ConversationSummaryBufferMemory", "ConversationEntityMemory", "ConversationKGMemory",
                  "VectorStoreRetrieverMemory", "ChatMessageHistory", "InMemoryChatMessageHistory",
                  "ConversationTokenBufferMemory", "ChatMemoryBuffer", "SimpleChatStore"}
FILTER_KWS = {"filter", "where", "namespace", "metadata_filter", "expr", "filters", "partition", "tenant",
              "user_id", "search_kwargs", "pre_filter", "filter_expression"}
LIMIT_KWS = {"max_iterations": 100, "max_iter": 100, "max_consecutive_auto_reply": 100, "max_turns": 100,
             "max_round": 200, "max_rounds": 200, "max_steps": 200, "recursion_limit": 500}
DANGEROUS_TOOLS = {
    "ShellTool": "ShellTool lets the model run any shell command",
    "BashProcess": "BashProcess lets the model run any shell command",
    "PythonREPLTool": "PythonREPLTool lets the model run arbitrary Python",
    "PythonAstREPLTool": "PythonAstREPLTool lets the model run arbitrary Python",
    "PythonREPL": "PythonREPL lets the model run arbitrary Python",
    "RequestsToolkit": "RequestsToolkit lets the model send arbitrary HTTP requests",
    "RequestsGetTool": "RequestsGetTool lets the model fetch arbitrary URLs",
    "RequestsPostTool": "RequestsPostTool lets the model send arbitrary HTTP requests",
    "RequestsPutTool": "RequestsPutTool lets the model send arbitrary HTTP requests",
    "RequestsPatchTool": "RequestsPatchTool lets the model send arbitrary HTTP requests",
    "RequestsDeleteTool": "RequestsDeleteTool lets the model send arbitrary HTTP requests",
    "WriteFileTool": "WriteFileTool lets the model write files",
    "DeleteFileTool": "DeleteFileTool lets the model delete files",
    "MoveFileTool": "MoveFileTool lets the model move files",
    "create_python_agent": "create_python_agent gives the model a Python REPL",
    "create_csv_agent": "create_csv_agent executes model-written Python",
    "create_spark_dataframe_agent": "create_spark_dataframe_agent executes model-written Python",
    "SQLDatabaseToolkit": "SQLDatabaseToolkit lets the model run arbitrary SQL (use a read-only role)",
    "create_sql_agent": "create_sql_agent lets the model run arbitrary SQL (use a read-only role)",
}
DANGEROUS_LOAD_TOOLS = {"terminal", "shell", "python_repl", "requests_all", "requests_post", "requests_put",
                        "requests_patch", "requests_delete", "requests", "bash"}
SEND_TOOLS = {"GmailSendMessage", "GmailToolkit", "O365SendMessage", "O365Toolkit", "SlackSendMessage",
              "SlackToolkit", "ZapierToolkit", "GitHubToolkit", "GitLabToolkit", "JiraToolkit"}
URL_KWS = {"url", "base_url", "server_url", "endpoint", "agent_url", "agent_card_url", "mcp_url", "sse_url",
           "api_base", "host_url", "remote_url"}
AGENT_CLIENT_RE = re.compile(r"(?i)(sse_client|streamablehttp_client|streamable_http|MCPClient|MCPServer|A2A|"
                             r"RemoteA2a|AgentCard|RemoteAgent|MultiServerMCPClient|websocket|ClientSession|"
                             r"OpenAI|Anthropic|ChatOpenAI|ChatAnthropic)")
STRING_METHODS = {"format", "join", "replace", "strip", "lstrip", "rstrip", "encode", "decode", "upper", "lower",
                  "format_map", "removeprefix", "removesuffix"}
LLM_CLIENT_CLASSES = {"OpenAI", "AsyncOpenAI", "AzureOpenAI", "Anthropic", "AsyncAnthropic", "ChatOpenAI",
                      "ChatAnthropic", "AnthropicBedrock", "AsyncAzureOpenAI"}


# ── AST helpers ──────────────────────────────────────────────────────────────

def dotted(node) -> str:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        inner = dotted(node.func)
        if not inner:
            return ""
        parts.append(inner + "()")
    else:
        return ""
    return ".".join(reversed(parts))


def const_str(node) -> Optional[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def string_parts(node) -> str:
    if node is None:
        return ""
    return " ".join(n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str))


def kwarg(call: ast.Call, name: str):
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def is_const(node, value) -> bool:
    return isinstance(node, ast.Constant) and node.value is value


def int_value(node) -> Optional[int]:
    if isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
        return node.value
    return None


def last_part(name: str) -> str:
    return name.rsplit(".", 1)[-1] if name else ""


def snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def iter_local(node) -> Iterator[ast.AST]:
    """Walk a node without descending into nested functions or classes."""
    stack = [node]
    while stack:
        cur = stack.pop()
        yield cur
        for child in ast.iter_child_nodes(cur):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            stack.append(child)


class ImportMap:
    def __init__(self, tree: ast.Module):
        self.aliases: Dict[str, str] = {}
        self.modules: Set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.modules.add(a.name)
                    if a.asname:
                        self.aliases[a.asname] = a.name
                    else:
                        top = a.name.split(".")[0]
                        self.aliases.setdefault(top, top)
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                self.modules.add(node.module)
                for a in node.names:
                    self.aliases[a.asname or a.name] = f"{node.module}.{a.name}"
        # Simple module-level aliases such as `run = subprocess.run` or `sh = os.system`.
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                if isinstance(node.value, (ast.Attribute, ast.Name)):
                    resolved = self.resolve(node.value)
                    if "." in resolved and resolved.split(".")[0] in {"os", "subprocess", "pickle", "builtins",
                                                                     "marshal", "yaml", "shutil", "importlib"}:
                        self.aliases[node.targets[0].id] = resolved
                    elif resolved in EVAL_FUNCS:
                        self.aliases[node.targets[0].id] = resolved

    def resolve(self, node) -> str:
        name = dotted(node)
        if not name:
            return ""
        head, _, rest = name.partition(".")
        if head in self.aliases:
            full = self.aliases[head]
            return f"{full}.{rest}" if rest else full
        return name

    def imports_any(self, prefixes: Iterable[str]) -> bool:
        return any(m == p or m.startswith(p + ".") for m in self.modules for p in prefixes)


# ── Module analysis ──────────────────────────────────────────────────────────

class ModuleAnalyzer:
    def __init__(self, ctx: FileContext, tree: ast.Module):
        self.ctx = ctx
        self.tree = tree
        self.source = ctx.text
        self.lines = ctx.lines
        self.imports = ImportMap(tree)
        self.is_agent_module = self.imports.imports_any(AGENT_MODULES)
        self.summaries: Dict[str, FrozenSet[str]] = {}
        self.llm_block_cache: Dict[int, bool] = {}
        self.reporting = False
        self.reported: Set[Tuple[str, int]] = set()
        self.tool_refs: Set[str] = set()
        self.mem0_names: Set[str] = set()
        self.functions: List[Tuple[ast.AST, Optional[ast.ClassDef]]] = []
        self.module_hitl = bool(HITL_MODULE_RE.search(self.source))
        self.router_auth = bool(re.search(r"(APIRouter|FastAPI|Blueprint)\([^)]*dependencies\s*=", self.source)) or \
            "before_request" in self.source or "add_middleware(Auth" in self.source
        self._collect()

    # ---- collection
    def _collect(self) -> None:
        def visit(node, cls):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.functions.append((child, cls))
                    visit(child, None)
                elif isinstance(child, ast.ClassDef):
                    visit(child, child)
                else:
                    visit(child, cls)

        visit(self.tree, None)
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Call):
                last = last_part(self.imports.resolve(node.func))
                if last in {"Tool", "StructuredTool", "from_function", "FunctionTool", "from_defaults",
                            "register_function", "add_tool", "tool", "function_tool"}:
                    for arg in node.args[:1]:
                        if isinstance(arg, ast.Name):
                            self.tool_refs.add(arg.id)
                    for k in node.keywords:
                        if k.arg in ("func", "fn", "coroutine", "function") and isinstance(k.value, ast.Name):
                            self.tool_refs.add(k.value.id)
                tools_kw = kwarg(node, "tools") or kwarg(node, "functions")
                if isinstance(tools_kw, (ast.List, ast.Tuple)):
                    for elt in tools_kw.elts:
                        if isinstance(elt, ast.Name):
                            self.tool_refs.add(elt.id)
            elif isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
                resolved = self.imports.resolve(node.value.func)
                if resolved.startswith("mem0.") or (resolved.endswith("from_config") and "mem0" in resolved):
                    for t in node.targets:
                        name = dotted(t)
                        if name:
                            self.mem0_names.add(name)
        self.route_handlers = {id(f) for f, _ in self.functions if self._is_route(f)}
        self.has_routes = bool(self.route_handlers)

    def _decorator_names(self, func) -> List[str]:
        names = []
        for dec in func.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            names.append(self.imports.resolve(target) or dotted(target))
        return names

    def _is_tool_class(self, cls: Optional[ast.ClassDef]) -> bool:
        if cls is None:
            return False
        for base in cls.bases:
            name = self.imports.resolve(base)
            if name.endswith("BaseTool") or last_part(name) == "Tool":
                return True
        return False

    def is_tool(self, func, cls) -> bool:
        if any(TOOL_DECORATOR_RE.search(n) for n in self._decorator_names(func)):
            return True
        if cls is None and func.name in self.tool_refs:
            return True
        return self._is_tool_class(cls) and func.name in {"_run", "_arun", "run", "forward", "__call__", "execute"}

    def _is_route(self, func) -> bool:
        if func.name == "lambda_handler":
            return True
        for dec in func.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            if isinstance(target, ast.Attribute) and target.attr in ROUTE_ATTRS:
                if not TOOL_DECORATOR_RE.search(dotted(target)):
                    return True
            if isinstance(target, ast.Name) and target.id == "api_view":
                return True
        return False

    def tool_name(self, func, cls) -> str:
        if cls is not None and self._is_tool_class(cls):
            for stmt in cls.body:
                if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                    targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                    if any(isinstance(t, ast.Name) and t.id == "name" for t in targets) and const_str(stmt.value):
                        return const_str(stmt.value)
            return snake(cls.name)
        return func.name

    def segment(self, node) -> str:
        """Source lines spanned by a node (whole lines; ast.get_source_segment re-splits the file on every call)."""
        if node is None or not hasattr(node, "lineno"):
            return ""
        return "\n".join(self.lines[node.lineno - 1:getattr(node, "end_lineno", node.lineno) or node.lineno])

    # ---- reporting
    def report(self, rule_id: str, node, message: str, severity: Optional[Severity] = None) -> None:
        if not self.reporting:
            return
        line = getattr(node, "lineno", 1)
        key = (rule_id, line)
        if key in self.reported:
            return
        self.reported.add(key)
        self.ctx.report(rule_id, line, message, severity=severity, column=getattr(node, "col_offset", 0) + 1)

    # ---- driver
    def run(self) -> None:
        # Two passes so helper-function return taint (e.g. def fetch(url): return requests.get(url).text) is known.
        for final in (False, True):
            self.reporting = final
            module_body = []
            for stmt in self.tree.body:
                if isinstance(stmt, ast.ClassDef):
                    module_body.extend(s for s in stmt.body if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)))
                elif not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    module_body.append(stmt)
            FunctionAnalyzer(self, None, None, module_body).run()
            for func, cls in self.functions:
                fa = FunctionAnalyzer(self, func, cls, func.body)
                fa.run()
                keep = frozenset(fa.returns & {EXTERNAL, LLM, USER, SECRET})
                if keep:
                    self.summaries[func.name] = keep
        self.reporting = True
        self._function_level_checks()
        self._module_level_checks()

    def _function_level_checks(self) -> None:
        for func, cls in self.functions:
            decorators = self._decorator_names(func)
            for dec, name in zip(func.decorator_list, decorators):
                call = dec if isinstance(dec, ast.Call) else None
                if name in ("tenacity.retry", "retrying.retry"):
                    stop_kws = ("stop",) if name.startswith("tenacity") else ("stop_max_attempt_number", "stop_max_delay")
                    if call is None or not any(kwarg(call, k) is not None for k in stop_kws):
                        self.report("ATS-ASI08-03", dec, f"@{last_part(name)} without a stop condition retries forever.")
                elif name in ("backoff.on_exception", "backoff.on_predicate"):
                    if call is None or (kwarg(call, "max_tries") is None and kwarg(call, "max_time") is None):
                        self.report("ATS-ASI08-03", dec, f"@{name} without max_tries/max_time retries forever.")
            if not self.is_tool(func, cls):
                continue
            src = self.segment(func)
            display = self.tool_name(func, cls)
            self.ctx.project.tools.append(ToolInfo(self.ctx.rel, func.lineno, display,
                                                   bool(re.search(r"\b(log|logger|logging|structlog|tracer|span|"
                                                                  r"audit)\b", src))))
            doc = ast.get_docstring(func, clean=False)
            if doc and func.body and isinstance(func.body[0], ast.Expr):
                text_checks.check_prompt_text(self.ctx, doc, func.body[0].lineno, "tool-description")
            if HIGH_IMPACT_RE.search(snake(display)) or HIGH_IMPACT_RE.search(func.name):
                dec_src = " ".join(self.segment(d) for d in func.decorator_list)
                cls_src = self.segment(cls) if cls is not None else ""
                if not (self.module_hitl or APPROVAL_RE.search(src) or APPROVAL_RE.search(dec_src)
                        or APPROVAL_RE.search(cls_src)):
                    self.report("ATS-ASI09-01", func, f"Tool '{display}' performs a high-impact action with no "
                                "human approval or confirmation step.")
        for node in ast.walk(self.tree):
            if isinstance(node, ast.ClassDef) and self._is_tool_class(node):
                for stmt in node.body:
                    if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                        targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                        if any(isinstance(t, ast.Name) and t.id == "description" for t in targets):
                            text = const_str(stmt.value)
                            if text:
                                text_checks.check_prompt_text(self.ctx, text, stmt.value.lineno, "tool-description")

    def _module_level_checks(self) -> None:
        for stmt in self.tree.body:
            if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Call) and self.has_routes:
                resolved = self.imports.resolve(stmt.value.func)
                last = last_part(resolved)
                if last in MEMORY_CLASSES or (resolved.startswith("mem0.") and last in ("Memory", "MemoryClient")):
                    self.report("ATS-ASI06-02", stmt, f"{last} is created once at module level in a web service, so "
                                "every user and session shares (and can poison) the same memory.")
        # The OpenAI Agents SDK traces runs by default unless tracing is explicitly disabled.
        agents_sdk_tracing = self.imports.imports_any(("agents",)) and "set_tracing_disabled(True)" not in self.source \
            and "tracing_disabled=True" not in self.source
        if agents_sdk_tracing or self.imports.imports_any(TRACING_MODULES) or re.search(
                r"LANGCHAIN_TRACING_V2|LANGSMITH_TRACING|OTEL_EXPORTER|@traceable|@observe|callbacks\s*=\s*\[",
                self.source):
            self.ctx.project.tracing_signals.append(self.ctx.rel)


class FunctionAnalyzer:
    def __init__(self, mod: ModuleAnalyzer, func, cls, body):
        self.mod = mod
        self.ctx = mod.ctx
        self.func = func
        self.cls = cls
        self.body = body
        self.env: Dict[str, FrozenSet[str]] = {}
        self.returns: Set[str] = set()
        self.is_tool = bool(func is not None and mod.is_tool(func, cls))
        self.is_route = bool(func is not None and id(func) in mod.route_handlers)
        self.src = mod.segment(func) if func is not None else ""
        self.has_validator = bool(VALIDATOR_RE.search(self.src))
        self.has_path_guard = bool(PATH_GUARD_RE.search(self.src))
        self.has_url_guard = bool(URL_GUARD_RE.search(self.src))
        self.saw_llm_call = False
        self.llm_loop_depth = 0
        if func is not None:
            params = [a.arg for a in func.args.posonlyargs + func.args.args + func.args.kwonlyargs]
            if func.args.vararg:
                params.append(func.args.vararg.arg)
            if func.args.kwarg:
                params.append(func.args.kwarg.arg)
            if self.is_tool:
                for p in params:
                    if p not in NON_TOOL_PARAMS:
                        self.env[p] = frozenset({MODEL})
            elif self.is_route:
                for p in params:
                    if p not in ("self", "cls", "context"):
                        self.env[p] = frozenset({USER})

    def report(self, rule_id, node, message, severity=None):
        self.mod.report(rule_id, node, message, severity)

    # ---- driver
    def run(self) -> None:
        self.visit_block(self.body, nested=False)
        if self.is_route and self.saw_llm_call and self.mod.reporting and not self._route_has_auth():
            self.report("ATS-ASI07-03", self.func, f"Route '{self.func.name}' runs an LLM/agent call with no visible "
                        "authentication check.")

    def _route_has_auth(self) -> bool:
        if self.mod.router_auth:
            return True
        for dec in self.func.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            if AUTH_RE.search(dotted(target)):
                return True
            if isinstance(dec, ast.Call) and any(AUTH_RE.search(ast.unparse(k.value)) for k in dec.keywords
                                                 if k.arg in ("dependencies",)):
                return True
        args = self.func.args
        for node in args.defaults + args.kw_defaults + [a.annotation for a in args.args + args.kwonlyargs]:
            if node is not None and re.search(r"(Depends|Security)\(", ast.unparse(node)) and AUTH_RE.search(ast.unparse(node)):
                return True
        return bool(AUTH_BODY_RE.search(self.src))

    def visit_block(self, stmts, nested: bool) -> None:
        for stmt in stmts:
            self.visit_stmt(stmt, nested)

    def visit_stmt(self, s, nested: bool) -> None:
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        if isinstance(s, ast.If):
            self.scan_header(s.test)
            self.visit_block(s.body, True)
            self.visit_block(s.orelse, True)
        elif isinstance(s, (ast.For, ast.AsyncFor)):
            self.scan_header(s.iter)
            self.assign(s.target, self.taint(s.iter), True)
            llm_loop = self._contains_llm_call(s.body)
            self.llm_loop_depth += llm_loop
            self.visit_block(s.body, True)
            self.llm_loop_depth -= llm_loop
            self.visit_block(s.orelse, True)
        elif isinstance(s, ast.While):
            self.scan_header(s.test)
            if self.mod.reporting:
                self.check_while(s)
            llm_loop = self._contains_llm_call(s.body)
            self.llm_loop_depth += llm_loop
            self.visit_block(s.body, True)
            self.llm_loop_depth -= llm_loop
            self.visit_block(s.orelse, True)
        elif isinstance(s, (ast.With, ast.AsyncWith)):
            for item in s.items:
                self.scan_header(item.context_expr)
                if item.optional_vars is not None:
                    self.assign(item.optional_vars, self.taint(item.context_expr), nested)
            self.visit_block(s.body, nested)
        elif isinstance(s, ast.Try) or type(s).__name__ == "TryStar":
            self.visit_block(s.body, True)
            for handler in s.handlers:
                self.check_handler(handler)
                if handler.name:
                    self.env.pop(handler.name, None)
                self.visit_block(handler.body, True)
            self.visit_block(s.orelse, True)
            self.visit_block(s.finalbody, nested)
        elif type(s).__name__ == "Match":
            self.scan_header(s.subject)
            for case in s.cases:
                self.visit_block(case.body, True)
        else:
            if self.mod.reporting:
                self.scan(s)
            if isinstance(s, ast.Assign):
                t = self.taint(s.value)
                for target in s.targets:
                    t = self.check_prompt_variable(target, s.value, t)
                    self.assign(target, t, nested)
            elif isinstance(s, ast.AnnAssign) and s.value is not None:
                t = self.check_prompt_variable(s.target, s.value, self.taint(s.value))
                self.assign(s.target, t, nested)
            elif isinstance(s, ast.AugAssign):
                key = dotted(s.target)
                if key:
                    self.env[key] = self.env.get(key, EMPTY) | self.taint(s.value)
            elif isinstance(s, ast.Return) and s.value is not None:
                self.returns |= self.taint(s.value)

    def assign(self, target, t: FrozenSet[str], nested: bool) -> None:
        if isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self.assign(elt, t, nested)
            return
        if isinstance(target, ast.Starred):
            self.assign(target.value, t, nested)
            return
        if isinstance(target, ast.Subscript):
            key = dotted(target.value)
            if key:
                self.env[key] = self.env.get(key, EMPTY) | t
            return
        key = dotted(target)
        if not key:
            return
        if nested:
            self.env[key] = self.env.get(key, EMPTY) | t
        else:
            self.env[key] = t

    # ---- taint evaluation
    def taint(self, node) -> FrozenSet[str]:
        if node is None:
            return EMPTY
        if isinstance(node, ast.Name):
            t = self.env.get(node.id, EMPTY)
            return t | {SECRET} if SECRET_NAME_RE.search(node.id) else t
        if isinstance(node, ast.Attribute):
            key = dotted(node)
            if key in self.env:
                return self.env[key]
            if SECRET_NAME_RE.search(node.attr):
                return frozenset({SECRET})
            base = dotted(node.value)
            if base in ("request", "flask.request") and node.attr in REQUEST_ATTRS:
                return frozenset({USER})
            if self.mod.imports.resolve(node) == "sys.argv":
                return frozenset({USER})
            return self.taint(node.value)
        if isinstance(node, ast.Subscript):
            if self.mod.imports.resolve(node.value) == "os.environ":
                key = const_str(node.slice)
                if key and SECRET_ENV_RE.search(key):
                    return frozenset({SECRET})
                return EMPTY
            return self.taint(node.value)
        if isinstance(node, ast.Call):
            return self.call_taint(node)
        if isinstance(node, ast.Await):
            return self.taint(node.value)
        if isinstance(node, ast.NamedExpr):
            t = self.taint(node.value)
            self.assign(node.target, t, True)
            return t
        if isinstance(node, (ast.JoinedStr, ast.BinOp)):
            t = self._union(ast.iter_child_nodes(node))
            return self._fence(node, t)
        if isinstance(node, ast.FormattedValue):
            return self.taint(node.value)
        if isinstance(node, (ast.BoolOp, ast.IfExp, ast.List, ast.Tuple, ast.Set, ast.Dict, ast.Starred)):
            return self._union(c for c in ast.iter_child_nodes(node) if not isinstance(c, ast.expr_context))
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp, ast.Lambda)):
            out: Set[str] = set()
            for sub in ast.walk(node):
                if isinstance(sub, ast.Name):
                    out |= self.env.get(sub.id, EMPTY)
                elif isinstance(sub, ast.Call):
                    out |= self._call_sources(sub)
            return frozenset(out)
        return EMPTY

    def _union(self, nodes) -> FrozenSet[str]:
        out: Set[str] = set()
        for n in nodes:
            out |= self.taint(n)
        return frozenset(out)

    @staticmethod
    def _fence(node, t: FrozenSet[str]) -> FrozenSet[str]:
        if EXTERNAL in t and FENCE_RE.search(string_parts(node)):
            return (t - {EXTERNAL}) | {EXTERNAL_FENCED}
        return t

    def _names(self, call: ast.Call) -> Tuple[str, str, str, str]:
        name = self.mod.imports.resolve(call.func)
        method = call.func.attr if isinstance(call.func, ast.Attribute) else ""
        receiver = dotted(call.func.value) if isinstance(call.func, ast.Attribute) else ""
        return name, last_part(name), method, receiver

    def is_llm_call(self, call: ast.Call) -> bool:
        name, last, method, receiver = self._names(call)
        if name.endswith(LLM_SUFFIXES) or name in LLM_FUNCS:
            return True
        recv_last = last_part(receiver.replace("()", ""))
        if method in LLM_METHODS:
            return not RETRIEVER_RE.search(recv_last)
        if method in ("run", "arun", "call", "acall", "run_sync", "stream", "generate", "agenerate", "batch"):
            return bool(LLMISH_RE.search(recv_last)) and not RETRIEVER_RE.search(recv_last)
        return False

    def _call_sources(self, call: ast.Call) -> FrozenSet[str]:
        name, last, method, receiver = self._names(call)
        recv_last = last_part(receiver.replace("()", ""))
        out: Set[str] = set()
        if name in USER_FUNCS:
            out.add(USER)
        if receiver in ("request", "flask.request") and method in REQUEST_ATTRS:
            out.add(USER)
        if name in ("os.getenv", "os.environ.get") and call.args and SECRET_ENV_RE.search(const_str(call.args[0]) or ""):
            out.add(SECRET)
        if self.is_llm_call(call):
            out.add(LLM)
            self.saw_llm_call = True
        elif (self._is_http(name, last, method, receiver) or name in WEB_FUNCS
              or ("loader" in receiver.lower() and method in LOAD_METHODS)
              or (method in RETRIEVAL_METHODS)
              or (method in ("invoke", "ainvoke", "run", "arun", "search", "query", "results") and
                  RETRIEVER_RE.search(recv_last))
              or (recv_last == "page" and method in ("content", "inner_text", "text_content", "inner_html"))):
            out.add(EXTERNAL)
        callee = name if not method else ""
        if callee in self.mod.summaries:
            out |= self.mod.summaries[callee]
        elif receiver == "self" and method in self.mod.summaries:
            out |= self.mod.summaries[method]
        return frozenset(out)

    def call_taint(self, call: ast.Call) -> FrozenSet[str]:
        name, last, method, receiver = self._names(call)
        if last in ("int", "float", "bool", "len", "hash", "isinstance", "id", "type") or \
                SANITIZER_RE.search(last or method):
            return EMPTY
        src = self._call_sources(call)
        if LLM in src:
            return src
        out: Set[str] = set()
        for a in call.args:
            out |= self.taint(a)
        for k in call.keywords:
            out |= self.taint(k.value)
        if isinstance(call.func, ast.Attribute):
            out |= self.taint(call.func.value)
        # Secrets only survive string operations; an object built with a key (a client, a response) is not a secret.
        if method not in STRING_METHODS and last not in ("str", "repr"):
            out.discard(SECRET)
        t = frozenset(out | src)
        if method == "format":
            t = self._fence(call.func.value, t)
        return t

    @staticmethod
    def _is_http(name, last, method, receiver) -> bool:
        if name.startswith(("requests.", "httpx.", "aiohttp.")) and last in HTTP_METHODS:
            return True
        if name in ("urllib.request.urlopen", "urlopen", "urllib.request.Request"):
            return True
        recv_last = last_part(receiver.replace("()", "")).lower()
        return method in HTTP_METHODS and bool(re.search(r"(session|http|requests|httpx|aiohttp)$", recv_last))

    # ---- scanning
    def scan_header(self, node) -> None:
        if self.mod.reporting:
            self.scan(node)

    def scan(self, node) -> None:
        for sub in iter_local(node):
            if isinstance(sub, ast.Call):
                self.check_call(sub)
            elif isinstance(sub, ast.Dict):
                self.check_dict(sub)
            elif isinstance(sub, ast.Tuple):
                self.check_tuple(sub)

    def _contains_llm_call(self, stmts) -> bool:
        key = id(stmts)
        cache = self.mod.llm_block_cache
        if key not in cache:
            cache[key] = any(isinstance(sub, ast.Call) and self.is_llm_call(sub)
                             for stmt in stmts for sub in iter_local(stmt))
        return cache[key]

    def check_while(self, s: ast.While) -> None:
        if not (is_const(s.test, True) or (isinstance(s.test, ast.Constant) and s.test.value == 1)):
            return
        has_exit = has_input = False
        for stmt in s.body:
            for sub in iter_local(stmt):
                if isinstance(sub, (ast.Break, ast.Return, ast.Raise)):
                    has_exit = True
                elif isinstance(sub, ast.Call):
                    name = self.mod.imports.resolve(sub.func)
                    if name in ("sys.exit", "exit", "quit", "os._exit"):
                        has_exit = True
                    if name in USER_FUNCS:
                        has_input = True
        if self._contains_llm_call(s.body) and not has_exit and not has_input:
            self.report("ATS-ASI08-01", s, "while True loop around LLM calls has no exit condition or iteration cap.")

    def check_handler(self, handler: ast.ExceptHandler) -> None:
        if not (self.is_tool or self.llm_loop_depth):
            return
        broad = handler.type is None or dotted(handler.type) in ("Exception", "BaseException")
        silent = all(isinstance(b, (ast.Pass, ast.Continue)) or
                     (isinstance(b, ast.Expr) and isinstance(b.value, ast.Constant)) for b in handler.body)
        if broad and silent:
            where = "tool" if self.is_tool else "agent loop"
            self.report("ATS-ASI08-04", handler, f"Exceptions in this {where} are caught and silently ignored.")

    def check_prompt_variable(self, target, value, t: FrozenSet[str]) -> FrozenSet[str]:
        name = dotted(target).rsplit(".", 1)[-1] if dotted(target) else ""
        if not name:
            return t
        if SYSTEM_VAR_RE.match(name):
            if self.prompt_sink(value, "system", f"system prompt variable '{name}'"):
                return t | {PROMPT_REPORTED}
        elif PROMPT_VAR_RE.search(name):
            text = const_str(value)
            if text is not None:
                if self.mod.reporting:
                    text_checks.check_prompt_text(self.ctx, text, value.lineno, "prompt")
            elif isinstance(value, (ast.JoinedStr, ast.BinOp)) or (isinstance(value, ast.Call) and
                                                                  dotted(value.func).endswith(".format")):
                if EXTERNAL in t:
                    self.report("ATS-ASI01-01", value, f"Untrusted external or retrieved content is inserted into prompt '{name}' "
                                "without delimiters marking it as data.", Severity.MEDIUM)
                    return (t - {EXTERNAL}) | {EXTERNAL_FENCED}
        return t

    def prompt_sink(self, value, kind: str, where: str) -> bool:
        """Check a value that becomes prompt text. Returns True if something was reported."""
        if value is None:
            return False
        text = const_str(value)
        if text is not None:
            if self.mod.reporting:
                text_checks.check_prompt_text(self.ctx, text, value.lineno, "prompt")
            return False
        t = self.taint(value)
        if PROMPT_REPORTED in t:
            return False
        hit = False
        if kind == "system":
            if t & {USER, MODEL}:
                label = " and ".join(sorted(t & {USER, MODEL}))
                self.report("ATS-ASI01-02", value, f"{label.capitalize()} is interpolated into the {where}.")
                hit = True
            if EXTERNAL in t or EXTERNAL_FENCED in t:
                self.report("ATS-ASI01-01", value, f"Untrusted external or retrieved content is placed in the {where}; content in "
                            "the system prompt carries developer authority.", Severity.HIGH)
                hit = True
        elif EXTERNAL in t:
            self.report("ATS-ASI01-01", value, f"Untrusted external or retrieved content reaches the {where} without delimiters "
                        "marking it as data.", Severity.MEDIUM)
            hit = True
        if SECRET in t:
            self.report("ATS-ASI03-02", value, f"A secret value is placed into the {where}.")
            hit = True
        return hit

    def check_tuple(self, node: ast.Tuple) -> None:
        if len(node.elts) != 2:
            return
        role = const_str(node.elts[0])
        if role in ("system", "developer"):
            self.prompt_sink(node.elts[1], "system", "system prompt template")
        elif role in ("human", "user"):
            self.prompt_sink(node.elts[1], "user", "prompt template")

    def check_dict(self, node: ast.Dict) -> None:
        items = {const_str(k): v for k, v in zip(node.keys, node.values) if k is not None and const_str(k)}
        role = const_str(items.get("role"))
        if role in ("system", "developer") and "content" in items:
            self.prompt_sink(items["content"], "system", "system message")
        elif role == "user":
            for key in ("content", "parts"):
                if key in items and not isinstance(items[key], (ast.List, ast.Dict)):
                    self.prompt_sink(items[key], "user", "user message")
        if const_str(items.get("require_approval")) == "never":
            self.report("ATS-ASI09-02", node, "Hosted tool configured with require_approval: 'never'.", Severity.MEDIUM)
        if is_const(items.get("use_docker"), False):
            self.report("ATS-ASI05-04", node, "Code execution configured with use_docker=False runs model-written code "
                        "directly on the host.")
        for key in ("url", "server_url", "endpoint"):
            url = const_str(items.get(key))
            if url and ("transport" in items or "type" in items or "headers" in items) and \
                    textutil.is_remote_plain_http(url):
                self.report("ATS-ASI07-01", node, f"MCP/agent server configured over plaintext HTTP ({url}).")
        limit = int_value(items.get("recursion_limit"))
        if limit is not None and limit > LIMIT_KWS["recursion_limit"]:
            self.report("ATS-ASI08-01", node, f"recursion_limit={limit} is far above typical limits.")

    def check_call(self, call: ast.Call) -> None:
        name, last, method, receiver = self._names(call)
        recv_last = last_part(receiver.replace("()", ""))
        if self.is_llm_call(call):
            self.saw_llm_call = True
        arg0 = call.args[0] if call.args else None

        # ── code execution ──
        if name in EVAL_FUNCS and arg0 is not None and not isinstance(arg0, ast.Constant):
            t = self.taint(arg0)
            if LLM in t:
                self.report("ATS-ASI05-02", call, f"LLM output is passed to {last}().")
            elif t & {EXTERNAL, EXTERNAL_FENCED}:
                self.report("ATS-ASI04-02", call, f"Downloaded/external content is executed with {last}().",
                            Severity.CRITICAL)
            elif t & {USER, MODEL}:
                label = " and ".join(sorted(t & {USER, MODEL}))
                self.report("ATS-ASI05-01", call, f"{last}() evaluates {label}.", Severity.CRITICAL)
            else:
                self.report("ATS-ASI05-01", call, f"{last}() evaluates a dynamic string.")

        shell_kw = kwarg(call, "shell")
        is_shell = name in SHELL_FUNCS or (name in SUBPROCESS_FUNCS and shell_kw is not None and
                                           not is_const(shell_kw, False) and not is_const(shell_kw, None))
        if is_shell or name in SUBPROCESS_FUNCS:
            cmd = arg0 if arg0 is not None else (kwarg(call, "args") or kwarg(call, "cmd"))
            t = self.taint(cmd) | self._union(call.args[1:]) if name.startswith("os.exec") else self.taint(cmd)
            cmd_text = string_parts(cmd)
            if LLM in t:
                self.report("ATS-ASI05-02", call, f"LLM output reaches {name}().")
            elif self.is_tool:
                tainted = t & UNTRUSTED
                self.report("ATS-ASI02-01", call,
                            f"Tool runs an OS command via {name}()" + (" built from model-chosen arguments." if tainted
                                                                        else "."),
                            Severity.CRITICAL if tainted else Severity.HIGH if is_shell else Severity.MEDIUM)
            elif is_shell:
                tainted = t & UNTRUSTED
                self.report("ATS-ASI05-03", call, f"{name}() runs a shell command" +
                            (f" containing {', '.join(sorted(tainted))}." if tainted else "."),
                            Severity.CRITICAL if tainted else Severity.HIGH)
            elif t & {USER, EXTERNAL}:
                self.report("ATS-ASI05-03", call, f"{name}() receives {', '.join(sorted(t & {USER, EXTERNAL}))} as "
                            "command arguments.", Severity.MEDIUM)
            self.check_command_text(call, cmd_text, t)

        # ── SQL ──
        if method in ("execute", "executemany", "executescript", "exec_driver_sql") or \
                (method == "run" and re.search(r"(?i)(db|sql|database)$", recv_last)):
            if method == "run" or re.search(r"(?i)(cur|cursor|conn|connection|db|database|session|engine|sql|con|"
                                            r"client)$", recv_last):
                query = arg0 if arg0 is not None else (kwarg(call, "query") or kwarg(call, "sql") or
                                                       kwarg(call, "statement"))
                if isinstance(query, ast.Call) and last_part(dotted(query.func)) == "text" and query.args:
                    query = query.args[0]
                if query is not None:
                    t = self.taint(query)
                    built = isinstance(query, (ast.JoinedStr, ast.BinOp)) or (
                        isinstance(query, ast.Call) and dotted(query.func).endswith(".format"))
                    if LLM in t:
                        self.report("ATS-ASI02-04", call, "LLM-generated SQL is executed directly.", Severity.CRITICAL)
                    elif built and t & UNTRUSTED:
                        self.report("ATS-ASI02-04", call, f"SQL is built by string formatting from "
                                    f"{', '.join(sorted(t & UNTRUSTED))}.")
                    elif self.is_tool and MODEL in t:
                        self.report("ATS-ASI02-04", call, "Tool executes a SQL string supplied directly by the model.")

        # ── network ──
        if self._is_http(name, last, method, receiver):
            url = arg0 if arg0 is not None else kwarg(call, "url")
            t = self.host_taint(url)
            if self.is_tool and t & {MODEL, LLM} and not self.has_url_guard:
                self.report("ATS-ASI02-03", call, "Tool requests a URL chosen by the model with no host allowlist.")
            elif self.is_route and USER in t and not self.has_url_guard:
                self.report("ATS-ASI02-03", call, "Request handler fetches a user-supplied URL with no host allowlist.")
            if self.is_tool and name.startswith("requests.") and kwarg(call, "timeout") is None:
                self.report("ATS-ASI08-02", call, f"{name}() in a tool has no timeout and can hang the agent.")
            if self.is_tool and name in ("urllib.request.urlopen", "urlopen") and kwarg(call, "timeout") is None \
                    and len(call.args) < 3:
                self.report("ATS-ASI08-02", call, "urlopen() in a tool has no timeout and can hang the agent.")

        # ── file system ──
        if name in ("open", "io.open", "builtins.open", "codecs.open") and arg0 is not None:
            mode_node = call.args[1] if len(call.args) > 1 else kwarg(call, "mode")
            mode = const_str(mode_node) or "r"
            write = any(c in mode for c in "wax+")
            t = self.taint(arg0)
            if self.is_tool and t & {MODEL, LLM, USER} and not self.has_path_guard:
                self.report("ATS-ASI02-02", call, f"Tool opens a model-controlled path for {'writing' if write else 'reading'} "
                            "without confining it to an allowed directory.", Severity.HIGH if write else Severity.MEDIUM)
            if write:
                self.check_self_modification(call, arg0, t)
                self.check_persistence_path(call, arg0)
        if name in FS_MUTATORS and call.args:
            t = self._union(call.args[:2])
            if self.is_tool and t & {MODEL, LLM, USER} and not self.has_path_guard:
                self.report("ATS-ASI02-02", call, f"Tool calls {name}() on a model-controlled path.")
            if len(call.args) > 1 and last in ("move", "copy", "copyfile", "copy2", "copytree", "rename", "replace"):
                self.check_self_modification(call, call.args[1], t)
        # str.replace/rename take two arguments; Path.replace/rename take one.
        if method in PATH_WRITE_METHODS and isinstance(call.func, ast.Attribute) and \
                not (method in ("replace", "rename") and len(call.args) != 1):
            t = self.taint(call.func.value)
            if self.is_tool and t & {MODEL, LLM, USER} and not self.has_path_guard:
                self.report("ATS-ASI02-02", call, f"Tool calls .{method}() on a model-controlled path.")
            if method in ("write_text", "write_bytes"):
                self.check_self_modification(call, call.func.value, t | self._union(call.args))
                self.check_persistence_path(call, call.func.value)

        # ── deserialization / supply chain ──
        if name in DESER_FUNCS:
            t = self._union(call.args)
            self.report("ATS-ASI05-05", call, f"{name}() can execute code embedded in the data.",
                        Severity.CRITICAL if t & UNTRUSTED else None)
        if name in ("yaml.load", "yaml.load_all"):
            loader = kwarg(call, "Loader") or (call.args[1] if len(call.args) > 1 else None)
            if loader is None or not dotted(loader).endswith(("SafeLoader", "CSafeLoader", "BaseLoader")):
                self.report("ATS-ASI05-05", call, f"{name}() without SafeLoader can construct arbitrary objects.")
        if name == "torch.load" and is_const(kwarg(call, "weights_only"), False):
            self.report("ATS-ASI05-05", call, "torch.load(weights_only=False) unpickles arbitrary objects.")
        if name == "numpy.load" and is_const(kwarg(call, "allow_pickle"), True):
            self.report("ATS-ASI05-05", call, "numpy.load(allow_pickle=True) can execute code.", Severity.MEDIUM)
        if is_const(kwarg(call, "allow_dangerous_deserialization"), True):
            self.report("ATS-ASI05-05", call, "allow_dangerous_deserialization=True unpickles the stored index.")
        if is_const(kwarg(call, "trust_remote_code"), True):
            self.report("ATS-ASI04-02", call, "trust_remote_code=True executes Python shipped with the model repository.")
        if name.endswith("hub.pull") and const_str(arg0) is not None and ":" not in const_str(arg0):
            self.report("ATS-ASI04-02", call, f"Prompt '{const_str(arg0)}' is pulled from a hub without a pinned "
                        "commit hash.", Severity.MEDIUM)
        if last in ("load_prompt", "load_chain") and const_str(arg0) and re.match(r"(https?|lc)://", const_str(arg0)):
            self.report("ATS-ASI04-02", call, f"{last}() loads a remote definition at runtime.", Severity.MEDIUM)
        if name in ("importlib.import_module", "__import__", "builtins.__import__") and arg0 is not None and \
                const_str(arg0) is None:
            t = self.taint(arg0)
            if t & {LLM, MODEL, USER, EXTERNAL}:
                self.report("ATS-ASI04-06", call, f"{last}() loads a module named by "
                            f"{', '.join(sorted(t & {LLM, MODEL, USER, EXTERNAL}))}.", Severity.HIGH)
            else:
                self.report("ATS-ASI04-06", call, f"{last}() loads a module whose name is computed at runtime; make "
                            "sure the name can only come from a fixed allowlist.", Severity.LOW)
        if name.startswith("pip.") and last == "main":
            if self.is_tool or self.mod.is_agent_module:
                self.report("ATS-ASI10-03", call, "pip.main() installs packages at runtime.")

        # ── dangerous tools & unsandboxed execution ──
        if last in DANGEROUS_TOOLS:
            self.report("ATS-ASI02-05", call, DANGEROUS_TOOLS[last] + ".",
                        Severity.MEDIUM if "sql" in last.lower() else None)
        if last == "FileManagementToolkit":
            root = kwarg(call, "root_dir")
            if root is None or const_str(root) in ("/", "~", "C:\\"):
                self.report("ATS-ASI02-05", call, "FileManagementToolkit without a confined root_dir gives the model "
                            "access to the whole file system.")
        if last in ("load_tools", "load_huggingface_tool") and isinstance(arg0, (ast.List, ast.Tuple)):
            bad = sorted({const_str(e) for e in arg0.elts} & DANGEROUS_LOAD_TOOLS)
            if bad:
                self.report("ATS-ASI02-05", call, f"load_tools enables dangerous tools: {', '.join(bad)}.")
        if last in SEND_TOOLS and not self.mod.module_hitl:
            self.report("ATS-ASI09-01", call, f"{last} lets the agent send messages or change external systems with "
                        "no human approval step.", Severity.MEDIUM if last.endswith("Toolkit") else None)
        if is_const(kwarg(call, "allow_dangerous_requests"), True):
            self.report("ATS-ASI02-05", call, "allow_dangerous_requests=True lets the model send arbitrary HTTP requests.")
        if is_const(kwarg(call, "allow_dangerous_code"), True):
            self.report("ATS-ASI05-04", call, "allow_dangerous_code=True executes model-written Python on the host.")
        if last == "LocalCommandLineCodeExecutor":
            self.report("ATS-ASI05-04", call, "LocalCommandLineCodeExecutor runs model-written code directly on the host.")
        if is_const(kwarg(call, "allow_code_execution"), True) and const_str(kwarg(call, "code_execution_mode")) == "unsafe":
            self.report("ATS-ASI05-04", call, "CrewAI code_execution_mode='unsafe' runs code without the Docker sandbox.")
        if last == "CodeAgent" and name.startswith("smolagents"):
            imports = kwarg(call, "additional_authorized_imports")
            granted = {const_str(e) for e in imports.elts} if isinstance(imports, (ast.List, ast.Tuple)) else set()
            executor = const_str(kwarg(call, "executor_type")) or "local"
            if granted & DANGEROUS_IMPORTS:
                self.report("ATS-ASI05-04", call, f"CodeAgent authorizes dangerous imports: "
                            f"{', '.join(sorted(granted & DANGEROUS_IMPORTS))}.")
            elif executor == "local":
                self.report("ATS-ASI05-04", call, "CodeAgent executes model-written Python in-process (local "
                            "executor); use executor_type='docker'/'e2b'/'modal'.", Severity.MEDIUM)
        if last == "LocalPythonExecutor":
            self.report("ATS-ASI05-04", call, "LocalPythonExecutor runs model-written Python in-process.", Severity.MEDIUM)
        if "PALChain" in name or last in ("CPALChain", "LLMSymbolicMathChain"):
            self.report("ATS-ASI05-04", call, f"{last} executes model-generated code.")

        # ── approval bypass ──
        if const_str(kwarg(call, "human_input_mode")) == "NEVER":
            code_cfg = kwarg(call, "code_execution_config")
            if code_cfg is not None and not is_const(code_cfg, False):
                self.report("ATS-ASI09-02", call, "human_input_mode='NEVER' with code execution enabled runs code with "
                            "no human review.")
        for key in ("auto_approve", "auto_run", "auto_confirm"):
            if is_const(kwarg(call, key), True):
                self.report("ATS-ASI09-02", call, f"{key}=True removes human approval.")
        for key in ("approval_mode", "require_approval", "approval_policy"):
            if const_str(kwarg(call, key)) in ("never", "auto", "none"):
                self.report("ATS-ASI09-02", call, f"{key}='{const_str(kwarg(call, key))}' removes human approval.",
                            Severity.MEDIUM)

        # ── limits, timeouts, retries ──
        for key, threshold in LIMIT_KWS.items():
            node = kwarg(call, key)
            if node is None:
                continue
            value = int_value(node)
            if is_const(node, None):
                self.report("ATS-ASI08-01", call, f"{key}=None removes the agent's iteration limit.")
            elif value is not None and value > threshold:
                self.report("ATS-ASI08-01", call, f"{key}={value} is far above typical limits (>{threshold}); a "
                            "runaway or hijacked loop can run for a long time.")
        if (last in LLM_CLIENT_CLASSES or name.startswith("httpx.")) and is_const(kwarg(call, "timeout"), None):
            self.report("ATS-ASI08-02", call, f"{last}(timeout=None) can hang indefinitely.")
        retries = int_value(kwarg(call, "max_retries"))
        if retries is not None and retries > 10:
            self.report("ATS-ASI08-03", call, f"max_retries={retries} amplifies load when a dependency fails.",
                        Severity.LOW)

        # ── privilege, transport, memory ──
        if is_const(kwarg(call, "allow_delegation"), True):
            self.report("ATS-ASI03-07", call, "allow_delegation=True lets this agent hand work to any agent in the crew.")
        verify = kwarg(call, "verify")
        if is_const(verify, False):
            self.report("ATS-ASI02-06", call, "verify=False disables TLS certificate verification.")
        if name == "ssl._create_unverified_context":
            self.report("ATS-ASI02-06", call, "ssl._create_unverified_context() disables certificate checks.")
        host = const_str(kwarg(call, "host"))
        if host in ("0.0.0.0", "::") and (self.mod.is_agent_module or self.saw_llm_call):
            self.report("ATS-ASI07-04", call, f"Agent service binds to {host} (all interfaces).")
        for k in call.keywords:
            if k.arg in URL_KWS and textutil.is_remote_plain_http(const_str(k.value) or ""):
                if AGENT_CLIENT_RE.search(name or "") or self.mod.is_agent_module:
                    self.report("ATS-ASI07-01", call, f"Agent/LLM connection uses plaintext HTTP ({const_str(k.value)}).")
        if AGENT_CLIENT_RE.search(last or "") and textutil.is_remote_plain_http(const_str(arg0) or ""):
            self.report("ATS-ASI07-01", call, f"{last} connects over plaintext HTTP ({const_str(arg0)}).")
        if receiver in self.mod.mem0_names and method in ("add", "search", "get_all", "delete_all", "update"):
            if not any(kwarg(call, k) is not None for k in ("user_id", "agent_id", "run_id")):
                self.report("ATS-ASI06-02", call, f"mem0 {method}() without user_id/agent_id/run_id reads or writes "
                            "memory shared by everyone.")
        if self.is_route and method in RETRIEVAL_METHODS | {"as_retriever"}:
            kws = {k.arg for k in call.keywords}
            search_kwargs = kwarg(call, "search_kwargs")
            has_filter = bool(kws & FILTER_KWS - {"search_kwargs"}) or (
                isinstance(search_kwargs, ast.Dict) and any(const_str(k) in FILTER_KWS for k in search_kwargs.keys))
            if not has_filter:
                self.report("ATS-ASI06-03", call, f"{method}() in a request handler has no tenant/user filter.")
        if method in MEMORY_WRITE_METHODS and (PERSISTENT_STORE_RE.search(recv_last) or receiver in self.mod.mem0_names) \
                and not self.has_validator:
            t = self._union(call.args) | self._union(k.value for k in call.keywords)
            if t & {EXTERNAL, EXTERNAL_FENCED}:
                self.report("ATS-ASI06-01", call, f"External content is written to long-term memory via "
                            f"{recv_last}.{method}() without validation.", Severity.HIGH)
            elif t & {USER, MODEL}:
                self.report("ATS-ASI06-01", call, f"{', '.join(sorted(t & {USER, MODEL})).capitalize()} is written to "
                            f"long-term memory via {recv_last}.{method}() without validation.")

        # ── prompts ──
        if last in ("SystemMessage", "SystemMessagePromptTemplate", "DeveloperMessage") or \
                "SystemMessagePromptTemplate" in name:
            self.prompt_sink(arg0 if arg0 is not None else kwarg(call, "content"), "system", "system message")
        elif last in ("HumanMessage", "UserMessage", "HumanMessagePromptTemplate"):
            self.prompt_sink(arg0 if arg0 is not None else kwarg(call, "content"), "user", "user message")
        for k in call.keywords:
            if k.arg in SYSTEM_KWS or (last == "Agent" and k.arg in ("role", "goal", "backstory")):
                if not isinstance(k.value, (ast.List, ast.Dict)):
                    self.prompt_sink(k.value, "system", f"'{k.arg}' prompt")
            elif k.arg == "description" and (last in TOOL_DESC_CALLS or TOOL_DECORATOR_RE.search(name or "")):
                text = const_str(k.value)
                if text and self.mod.reporting:
                    text_checks.check_prompt_text(self.ctx, text, k.value.lineno, "tool-description")
        if self.is_llm_call(call):
            candidates = list(call.args) + [k.value for k in call.keywords if k.arg in USER_PROMPT_KWS]
            for value in candidates:
                if isinstance(value, (ast.Name, ast.JoinedStr, ast.BinOp, ast.Attribute, ast.Subscript, ast.Call)):
                    self.prompt_sink(value, "user", "LLM prompt")

    def host_taint(self, url) -> FrozenSet[str]:
        """Taint of the scheme/host part of a URL expression (a fixed host with a model-chosen path is not SSRF)."""
        head = url
        while isinstance(head, ast.BinOp) and isinstance(head.op, ast.Add):
            head = head.left
        if isinstance(head, ast.JoinedStr) and head.values:
            head = head.values[0]
        if isinstance(head, ast.Call) and isinstance(head.func, ast.Attribute) and head.func.attr == "format":
            head = head.func.value
        text = const_str(head)
        if text is not None:
            # "https://api.example.com/..." fixes the host; "https://" leaves it to whatever follows.
            if re.match(r"https?://[^/{}\s]+/", text) or (text and not text.lower().startswith("http")):
                return EMPTY
            return self.taint(url)
        if isinstance(head, ast.FormattedValue):
            return self.taint(head.value)
        return self.taint(url)

    def check_command_text(self, call, cmd_text: str, t: FrozenSet[str]) -> None:
        if PERSIST_RE.search(cmd_text):
            if self.is_tool or LLM in t:
                self.report("ATS-ASI10-02", call, "Agent tool can install a persistence mechanism "
                            f"({PERSIST_RE.search(cmd_text).group(0)}).")
            elif self.mod.is_agent_module:
                self.report("ATS-ASI10-02", call, "Agent code invokes a persistence mechanism "
                            f"({PERSIST_RE.search(cmd_text).group(0)}).", Severity.MEDIUM)
        if INSTALL_RE.search(cmd_text) and (self.is_tool or LLM in t):
            self.report("ATS-ASI10-03", call, "Agent tool installs packages at runtime.")

    def check_persistence_path(self, call, path_node) -> None:
        text = string_parts(path_node)
        m = PERSIST_RE.search(text)
        if m and (self.is_tool or self.mod.is_agent_module):
            self.report("ATS-ASI10-02", call, f"Agent code writes to a persistence location ({m.group(0)}).",
                        Severity.HIGH if self.is_tool else Severity.MEDIUM)

    def check_self_modification(self, call, path_node, t: FrozenSet[str]) -> None:
        refs_file = any(isinstance(n, ast.Name) and n.id == "__file__" for n in ast.walk(path_node))
        text = string_parts(path_node) + " " + (dotted(path_node) if not isinstance(path_node, ast.Call) else "")
        if (refs_file or SELF_MOD_RE.search(text)) and (self.is_tool or LLM in t):
            target = "its own source file" if refs_file else f"'{textutil.truncate(text, 60)}'"
            self.report("ATS-ASI10-01", call, f"Agent code can overwrite {target} at runtime.")


def analyze(ctx: FileContext) -> None:
    try:
        tree = ast.parse(ctx.text, filename=ctx.rel)
    except (SyntaxError, ValueError):
        return
    analyzer = ModuleAnalyzer(ctx, tree)
    analyzer.run()
    if analyzer.is_agent_module:
        ctx.project.is_agent_project = True
