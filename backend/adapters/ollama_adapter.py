import httpx
from config import get_settings

settings = get_settings()

class OllamaAdapter:
    """
    Layer 11: Sends approved prompts to the target Ollama model.
    """

    async def generate(self, prompt: str, max_tokens: int = 2000) -> str:
        try:
            async with httpx.AsyncClient(timeout=120.0) as client:
                response = await client.post(
                    f"{settings.OLLAMA_HOST}/api/generate",
                    json={
                        "model":  settings.OLLAMA_TARGET_MODEL,
                        "prompt": prompt,
                        "stream": False,
                        "options": {
                            "num_predict": max_tokens,
                            "temperature": 0.7,
                        }
                    }
                )
                response.raise_for_status()
                return response.json().get("response", "")
        except httpx.TimeoutException:
            return "[TwinShield] LLM response timed out."
        except Exception as e:
            return f"[TwinShield] LLM error: {str(e)}"
