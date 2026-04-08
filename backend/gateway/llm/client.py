import httpx
import asyncio
import uuid
from datetime import datetime
from abc import ABC, abstractmethod
from fastapi import HTTPException
from backend.gateway.config import settings
from backend.models.responses import InferenceResponse
from backend.utils.logging import get_logger

logger = get_logger(__name__)


class BaseLLMClient(ABC):
    @abstractmethod
    async def generate(self, prompt: str, max_tokens: int = 1000, temperature: float = 0.7) -> InferenceResponse:
        pass


class OllamaClient(BaseLLMClient):
    def __init__(self):
        self.base_url = settings.ollama_base_url or "http://localhost:11434"
        self.model = settings.ollama_model
        self.max_retries = 3

    async def _get_available_model(self) -> str:
        """
        If the configured model isn't available, fall back to the first
        model that is. Logs a warning so it's obvious what happened.
        """
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.get(f"{self.base_url}/api/tags")
            if r.status_code == 200:
                models = [m["name"] for m in r.json().get("models", [])]
                if not models:
                    raise HTTPException(
                        status_code=503,
                        detail=(
                            "Ollama has no models pulled. "
                            "Run: ollama pull llama3  (or any model you prefer)"
                        ),
                    )
                if self.model not in models:
                    fallback = models[0]
                    logger.warning(
                        "Configured model '%s' not found in Ollama. "
                        "Available: %s. Falling back to '%s'. "
                        "Set OLLAMA_MODEL in .env to silence this.",
                        self.model, models, fallback,
                    )
                    return fallback
                return self.model
        except HTTPException:
            raise
        except Exception as e:
            logger.warning("Could not query Ollama model list: %s — using configured model '%s'", e, self.model)
            return self.model

    async def generate(self, prompt: str, max_tokens: int = 1000, temperature: float = 0.7) -> InferenceResponse:
        model = await self._get_available_model()
        url = f"{self.base_url}/api/generate"
        payload = {
            "model": model,
            "prompt": prompt,
            "temperature": temperature,
            "stream": False,
            "options": {"num_predict": max_tokens},
        }

        for attempt in range(self.max_retries):
            try:
                async with httpx.AsyncClient(timeout=120.0) as client:
                    response = await client.post(url, json=payload)

                if response.status_code == 200:
                    result = response.json()
                    return InferenceResponse(
                        response=result["response"],
                        tool_calls=[],
                        metadata={"model": model, "attempts": attempt + 1},
                        request_id=str(uuid.uuid4()),
                        timestamp=datetime.utcnow(),
                    )
                elif response.status_code == 404:
                    raise HTTPException(
                        status_code=503,
                        detail=(
                            f"Ollama model '{model}' not found. "
                            f"Run: ollama pull {model}"
                        ),
                    )
                else:
                    logger.error("Ollama returned %s: %s", response.status_code, response.text)
                    raise HTTPException(status_code=503, detail=f"Ollama error {response.status_code}: {response.text}")

            except HTTPException:
                raise
            except (httpx.ConnectError, httpx.TimeoutException) as e:
                logger.warning("Ollama connection attempt %d failed: %s", attempt + 1, e)
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                else:
                    raise HTTPException(
                        status_code=503,
                        detail=(
                            "Cannot reach Ollama at "
                            f"{self.base_url}. Is it running? "
                            "Start it with: ollama serve"
                        ),
                    )
            except Exception as e:
                logger.error("Unexpected OllamaClient error: %s", e)
                raise HTTPException(status_code=500, detail=f"Unexpected LLM error: {e}")


def get_llm_client() -> BaseLLMClient:
    if settings.llm_provider == "ollama":
        return OllamaClient()
    else:
        raise ValueError(f"Unsupported LLM provider: {settings.llm_provider}")