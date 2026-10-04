import OpenAI from "openai";

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

export async function POST(req: Request) {
  const { question } = await req.json();
  const completion = await client.chat.completions.create({
    model: "gpt-4o",
    messages: [{ role: "user", content: String(question) }],
  });
  return Response.json({ answer: completion.choices[0].message.content, maxSteps: 10 });
}
