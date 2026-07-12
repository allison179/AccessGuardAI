from google import genai

client = genai.Client(
    api_key="AQ.Ab8RN6KOgOoBJxNhLR-aVusoiSHuPs0AeC2k33dtJTa8JbWDhA"
)

response = client.models.generate_content(
    model="gemini-2.5-flash",
    contents="Reply with exactly: Hello"
)

print(response.text)