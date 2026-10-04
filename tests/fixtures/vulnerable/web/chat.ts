import OpenAI from "openai";

const client = new OpenAI({ apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY, dangerouslyAllowBrowser: true });

export async function runAgent(input: string) {
  const agentConfig = { maxIterations: Infinity };
  const completion = await client.chat.completions.create({ model: "gpt-4o", messages: [{ role: "user", content: input }] });
  return eval(completion.choices[0].message.content ?? "");
}
