from pydantic import BaseModel, Field
from typing import Optional, List


class IncomingRequest(BaseModel):
    client_id: str = Field(..., min_length=1, max_length=128, description="User/session/IP identifier")
    payload: str = Field(..., min_length=1, max_length=8000, description="Raw incoming text/prompt to evaluate")


class LayerResult(BaseModel):
    layer: str
    score: float  # 0 = benign, 1 = malicious
    verdict: str
    details: dict = {}


class PipelineResponse(BaseModel):
    client_id: str
    final_verdict: str          # ALLOW / BLOCK
    fused_confidence: float
    used_twin_reviewer: bool
    layers: List[LayerResult]
    safe_output: Optional[str] = None
    trace_id: str
