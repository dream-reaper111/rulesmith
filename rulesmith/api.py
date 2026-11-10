"""Authenticated, stateless rule precheck API; no deployment capability."""

from __future__ import annotations

import hmac
import os
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from .core import LINTERS, RuleError

app = FastAPI(title="RuleSmith", version="0.1.0")


async def authorized(authorization: Annotated[str | None, Header()] = None) -> None:
    configured = os.environ.get("RULESMITH_API_TOKEN", "")
    if len(configured) < 32:
        raise HTTPException(503, "API token not configured securely")
    supplied = authorization.removeprefix("Bearer ") if authorization else ""
    if not hmac.compare_digest(supplied, configured):
        raise HTTPException(401, "invalid token")


class RuleInput(BaseModel):
    kind: Literal["sigma", "yara", "suricata"]
    content: str = Field(min_length=1, max_length=262144)


@app.get("/health")
async def health():
    return {"status": "running", "persistence": "not configured", "deployment": "disabled"}


@app.post("/v1/lint")
async def lint_rule(body: RuleInput, _: Annotated[None, Depends(authorized)]):
    try:
        return LINTERS[body.kind](body.content.encode("utf-8"))
    except RuleError as exc:
        raise HTTPException(422, str(exc)) from exc
