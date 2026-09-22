"""HTTP 路由。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from app.schemas import (
    DocumentResponse,
    PolicyCreateRequest,
    PolicyResponse,
    RestoreRequest,
    RestoreResponse,
    SubmitRequest,
    SubmitResponse,
)
from app.services.document_service import DocumentService

router = APIRouter()


def get_service(request: Request) -> DocumentService:
    return request.app.state.service


@router.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@router.post("/policies", response_model=PolicyResponse, status_code=201)
async def create_policy(
    payload: PolicyCreateRequest,
    service: DocumentService = Depends(get_service),
) -> dict:
    """创建自动脱敏策略（创建后不可变）；正则必须可编译且拒绝空匹配。"""
    return await service.create_policy(payload)


@router.get("/policies/{policy_id}", response_model=PolicyResponse)
async def get_policy(
    policy_id: str,
    service: DocumentService = Depends(get_service),
) -> dict:
    """查询自动脱敏策略。"""
    return await service.get_policy(policy_id)


@router.post("/documents", response_model=SubmitResponse, status_code=201)
async def submit(
    payload: SubmitRequest,
    service: DocumentService = Depends(get_service),
) -> dict:
    """提交原文与敏感片段（可附 policy_id 自动生成片段），返回脱敏结果与一次性令牌。"""
    return await service.submit(payload)


@router.get("/documents/{document_id}", response_model=DocumentResponse)
async def get_document(
    document_id: str,
    service: DocumentService = Depends(get_service),
) -> dict:
    """查询脱敏文本与片段明细（不含任何原文信息，无需令牌）。"""
    return await service.get(document_id)


@router.post("/restore", response_model=RestoreResponse)
async def restore(
    payload: RestoreRequest,
    service: DocumentService = Depends(get_service),
) -> dict:
    """凭一次性令牌还原指定占位符；令牌用后作废并轮换返回新令牌。"""
    return await service.restore(payload.token, payload.placeholders)
