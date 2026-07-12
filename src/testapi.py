from google import genai

client = genai.Client(api_key="AQ.Ab8RN6KF0oA2EhwbvrI5BxymmiqrRrjmfc53wu9lPJ_He37YGg")

response = client.models.generate_content(
    model="gemini-2.5-flash",
    contents="Say hello."
)

print(response.text)