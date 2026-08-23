"""Endpoint principal: responde preguntas sobre el corpus OWASP."""

import time
from typing import Annotated

from fastapi import APIRouter, Depends, Request, status

from app.api.deps import Principal, rate_limit_by_user, require_scope
from app.core.errors import AppError
from app.core.logging import get_logger, get_request_id
from app.core.metrics import (
    answers,
    ask_stage_duration,
    chunks_retrieved,
    guardrail_blocks,
    llm_tokens,
    rate_limit_hits,
)
from app.guardrails.input_guard import check_question
from app.guardrails.output_guard import check_answer, cosine_similarity
from app.guardrails.scope_guard import check_scope, out_of_scope_answer
from app.rag.generate import generate_answer
from app.rag.ollama_client import OllamaError
from app.schemas import AskRequest, AskResponse, Citation, Usage

logger = get_logger("ask")

router = APIRouter(tags=["rag"])

RequireAsk = Annotated[Principal, Depends(require_scope("ask:read"))]


@router.post(
    "/ask",
    response_model=AskResponse,
    dependencies=[Depends(rate_limit_by_user)],
    summary="Preguntar sobre los documentos OWASP indexados",
)
async def ask(request: Request, payload: AskRequest, user: RequireAsk) -> AskResponse:
    """Recupera los fragmentos relevantes del corpus y responde citando la fuente."""
    started = time.perf_counter()
    settings = request.app.state.settings
    store = request.app.state.store
    client = request.app.state.ollama
    budget = request.app.state.token_budget

    # Cuota diaria de tokens: limita el costo y el abuso, no solo la cantidad de requests.
    if not budget.has_budget(user.username):
        rate_limit_hits.labels(dimension="token_budget").inc()
        raise AppError(
            code="token-budget-exhausted",
            title="Presupuesto diario agotado",
            detail="Consumiste tu cuota de tokens para hoy. Se renueva a las 00:00 UTC.",
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers={"Retry-After": "3600"},
        )

    verdict = check_question(
        payload.question, settings.min_question_chars, settings.max_question_chars
    )
    if not verdict.allowed:
        guardrail_blocks.labels(stage="input", reason=verdict.reason).inc()
        logger.info("input_blocked", user=user.username, reason=verdict.reason)
        raise AppError(
            code=f"input-{verdict.reason}",
            title="Consulta rechazada",
            detail=verdict.message,
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    # El corpus tiene alcance fijo. Una pregunta sobre otro documento de OWASP recupera
    # fragmentos parecidos igual, y el modelo la contesta de memoria: se corta antes.
    scope = check_scope(payload.question)
    if not scope.in_scope:
        guardrail_blocks.labels(stage="input", reason=f"scope_{scope.reason}").inc()
        answers.labels(grounded="false").inc()
        logger.info("out_of_scope", user=user.username, reason=scope.reason)
        return AskResponse(
            answer=out_of_scope_answer(scope.reason),
            citations=[],
            grounded=False,
            request_id=get_request_id(),
            usage=Usage(
                input_tokens=0,
                output_tokens=0,
                retrieved_chunks=0,
                latency_ms=int((time.perf_counter() - started) * 1000),
            ),
        )

    # --- Recuperacion ---
    retrieval_started = time.perf_counter()
    try:
        query_vector = (await client.embed([payload.question]))[0]
    except OllamaError as exc:
        raise AppError(
            code="llm-unavailable",
            title="Servicio de modelo no disponible",
            detail="No se pudo procesar la consulta en este momento.",
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            headers={"Retry-After": "30"},
        ) from exc

    hits = store.search(query_vector, settings.retrieval_top_k, payload.source)
    relevant = [hit for hit in hits if hit[2] >= settings.min_relevance_score]
    ask_stage_duration.labels(stage="retrieval").observe(time.perf_counter() - retrieval_started)
    chunks_retrieved.observe(len(relevant))

    # --- Generacion ---
    input_tokens = output_tokens = 0
    raw_answer = ""
    if relevant:
        generation_started = time.perf_counter()
        try:
            raw_answer, input_tokens, output_tokens = await generate_answer(
                client, payload.question, relevant
            )
        except OllamaError as exc:
            raise AppError(
                code="llm-unavailable",
                title="Servicio de modelo no disponible",
                detail="El modelo no respondio a tiempo. Reintentá en unos segundos.",
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                headers={"Retry-After": "30"},
            ) from exc
        ask_stage_duration.labels(stage="generation").observe(
            time.perf_counter() - generation_started
        )
        llm_tokens.labels(direction="input").inc(input_tokens)
        llm_tokens.labels(direction="output").inc(output_tokens)
        budget.consume(user.username, input_tokens + output_tokens)

    # --- Validacion de la salida ---
    # La respuesta se compara contra cada fragmento por separado y se toma el mejor
    # parecido: alcanza con que un fragmento la sostenga. Compararla contra los
    # cuatro concatenados diluye el puntaje de una respuesta enfocada.
    # Si el embedding falla, la respuesta se descarta: falla cerrado.
    grounding = 0.0
    if relevant and raw_answer:
        try:
            vectors = await client.embed([raw_answer] + [text for text, _, _ in relevant])
            grounding = max(cosine_similarity(vectors[0], chunk) for chunk in vectors[1:])
        except OllamaError:
            logger.warning("grounding_check_failed", user=user.username)

    checked = check_answer(raw_answer, has_hits=bool(relevant), grounding_similarity=grounding)
    if not checked.grounded and checked.reason:
        guardrail_blocks.labels(stage="output", reason=checked.reason).inc()
    answers.labels(grounded=str(checked.grounded).lower()).inc()

    citations = (
        [
            Citation(
                document=metadata.get("document", "desconocido"),
                section=metadata.get("section", "sin seccion"),
                relevance=round(score, 3),
            )
            for _text, metadata, score in relevant
        ]
        if checked.grounded
        else []
    )

    latency_ms = int((time.perf_counter() - started) * 1000)
    logger.info(
        "ask_completed",
        user=user.username,
        source=payload.source,
        retrieved=len(relevant),
        grounded=checked.grounded,
        grounding=round(grounding, 3),
        block_reason=checked.reason or None,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        latency_ms=latency_ms,
    )

    return AskResponse(
        answer=checked.answer,
        citations=citations,
        grounded=checked.grounded,
        request_id=get_request_id(),
        usage=Usage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            retrieved_chunks=len(relevant),
            latency_ms=latency_ms,
        ),
    )
