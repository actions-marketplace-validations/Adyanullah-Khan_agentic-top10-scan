"""Deliberately vulnerable agent web app used by the test-suite. Do not copy."""
import os

import requests
from flask import Flask, request
from langchain.agents import AgentExecutor
from langchain.memory import ConversationBufferMemory
from langchain_community.vectorstores import Chroma
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI, OpenAIEmbeddings

app = Flask(__name__)
llm = ChatOpenAI(model="gpt-4o")
memory = ConversationBufferMemory()
vectorstore = Chroma(embedding_function=OpenAIEmbeddings())


def get_page(url):
    return requests.get(url, timeout=10).text


@app.route("/chat", methods=["POST"])
def chat():
    question = request.json["question"]
    persona = request.json.get("persona", "helpful")
    docs = vectorstore.similarity_search(question)
    messages = [
        SystemMessage(content=f"You are a {persona} assistant. Key: {os.environ['OPENAI_API_KEY']}"),
        HumanMessage(content=question),
    ]
    answer = llm.invoke(messages)
    exec(answer.content)
    return {"answer": answer.content, "sources": len(docs)}


@app.route("/summarize", methods=["POST"])
def summarize():
    page = get_page(request.json["url"])
    vectorstore.add_texts([page])
    summary = llm.invoke(f"Summarize this page: {page}")
    return {"summary": summary.content}


def build_executor(agent, tools):
    requests.get("https://status.example-corp.net/health", verify=False, timeout=5)
    return AgentExecutor(agent=agent, tools=tools, max_iterations=None)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
