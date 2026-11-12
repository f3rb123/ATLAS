"""Credential-free failure explanations and bounded host-owned retry decisions."""

import traceback
import json


# Only fixed messages are displayed. Never include exception payloads, prompts,
# SQL parameters, provider response bodies or rejected model values in diagnostics.
KNOWN = {
    "Provider request timed out": ("provider_timeout", "The model request exceeded its timeout.", True, "SKUNK will retry with backoff."),
    "Provider transport failure": ("provider_transport", "The connection to the AI provider failed.", True, "Check VPS DNS/HTTPS connectivity if retries also fail."),
    "Provider response parse failure": ("provider_response_parse", "The provider response was not a valid completion envelope.", True, "Retry; persistent failures require a compatible provider response."),
    "Provider returned invalid structured output; reported usage was accounted": ("structured_output_invalid_accounted", "The model did not return the required JSON object.", True, "A schema correction or a new bounded attempt can recover this."),
    "authentication_failed": ("provider_authentication", "HackerAI rejected the API credential (HTTP 401).", False, "Run skunk token-set; environment token values take precedence."),
    "access_denied": ("provider_access_denied", "HackerAI denied model access (HTTP 403).", False, "Check model access and the account's provider permissions."),
    "rate_limited": ("provider_rate_limited", "HackerAI rate limited the request (HTTP 429).", True, "Wait for Retry-After; SKUNK backs off before retrying."),
    "Context size limit exceeded": ("context_limit", "The assembled role context exceeds the harness limit.", False, "Use skunk diagnose to inspect request sizes; update the harness context bounds."),
    "Role context exceeds the configured model limit even after bounded excerpting": ("context_limit", "The role context remains oversized after excerpting.", False, "Run skunk diagnose to inspect request construction."),
    "Operator/task instructions cannot fit the configured physical model context": ("context_limit", "Core instructions exceed the model's physical context window.", False, "Inspect the configured context window and instruction sizes with skunk diagnose."),
    "Conservative context/token limit exceeded": ("context_limit", "The request exceeds the configured model context bound.", False, "Use skunk diagnose to inspect the pinned model and prompt sizes."),
    "Model output limit exceeded": ("model_output_limit", "The requested output exceeds the pinned model limit.", False, "Correct the model/output configuration."),
    "Pinned provider/model version unavailable": ("model_pin_changed", "The pinned provider/model version is unavailable or changed.", False, "Start a new run after reviewing the model configuration; existing run pins stay frozen."),
    "Pinned provider/model is unavailable, changed, or unverified": ("model_pin_changed", "The pinned provider/model is unavailable, changed or unverified.", False, "Review skunk diagnose before starting a new run."),
    "Structured output capability unverified": ("model_contract_unavailable", "The model has no usable structured-response contract.", False, "Check the managed SKUNK model configuration with skunk diagnose."),
    "Test the configured provider/key before resuming research": ("provider_configuration", "The provider is not eligible for dispatch.", False, "Inspect the managed provider configuration with skunk diagnose."),
    "Run budget exhausted": ("run_budget_exhausted", "The run's monetary budget is exhausted.", False, "Review actual usage and budgets; retrying cannot raise the run budget."),
    "Campaign budget exhausted": ("campaign_budget_exhausted", "The campaign's monetary budget is exhausted.", False, "Review the campaign budget and actual usage."),
    "Monthly budget exhausted": ("monthly_budget_exhausted", "The configured monthly monetary budget is exhausted.", False, "Review the configured budget and actual usage."),
    "Role budget exhausted": ("role_budget_exhausted", "This role's monetary budget is exhausted.", False, "Review the role's configured budget and actual usage."),
    "Model call limit exhausted": ("model_call_limit", "The run reached its model-call limit.", False, "The run is incomplete; a retry cannot bypass its call limit."),
    "Tool budget exhausted": ("tool_call_limit", "The run reached its tool-call limit.", False, "The run is incomplete; a retry cannot bypass its tool limit."),
    "Global token allocation exhausted or reserved for independent validation": ("token_allocation_exhausted", "The persistent token allocation is exhausted or held for validation.", False, "Review skunk diagnose budget totals. Existing usage and uncertain holds are preserved."),
    "Provider token contract violated; operator review required": ("token_contract_violation", "Provider usage exceeded the reserved token contract.", False, "Review the persistent token ledger; retries cannot bypass this block."),
    "No authorized target response was collected; web discovery did not succeed": ("target_unreachable", "No authorized target response was collected.", True, "Retry is bounded; inspect DNS, TLS, scope and target availability if it persists."),
    "DNS resolution failed": ("dns_resolution_failed", "The VPS could not resolve a required hostname.", True, "Check VPS DNS resolution if retries also fail."),
    "TLS verification or handshake failure": ("provider_tls", "TLS verification or the provider TLS handshake failed.", False, "Check VPS CA certificates and provider TLS; verification stays enabled."),
    "Task lease lost; stale worker cannot publish or execute tools": ("task_lease_lost", "The worker lost its task lease.", False, "Inspect worker/database availability. Stale workers cannot publish results."),
}


def describe(exc):
    from pydantic import ValidationError
    from sqlalchemy.exc import OperationalError
    from .gateway import ProviderError, CapacityWait, RunInterrupted
    from .policy import Denied

    message = str(exc) if isinstance(exc, (ProviderError, Denied, ValueError)) and not isinstance(exc, ValidationError) else ""
    if isinstance(exc, CapacityWait):
        result = dict(code="dispatch_capacity_wait", message="Waiting for provider concurrency, circuit cooldown or reserved budget capacity.", retryable=False, action="The scheduler will check capacity again without sending a model request.")
    elif isinstance(exc, RunInterrupted):
        result = dict(code="run_interrupted", message="The run was paused or cancelled.", retryable=False, action="The saved run control governs any future dispatch.")
    elif isinstance(exc, ValidationError):
        result = {
            "code": "model_schema_invalid",
            "message": "A model response or typed input failed the required schema.",
            "retryable": True,
            "action": "SKUNK requests a bounded JSON correction before retrying the task.",
            "fields": [".".join(str(p) for p in error["loc"])[:100] for error in exc.errors(include_input=False)[:8]],
        }
    elif message in KNOWN:
        code, summary, retryable, action = KNOWN[message]
        result = dict(code=code, message=summary, retryable=retryable, action=action)
    elif isinstance(exc, ProviderError) and getattr(exc, "http_status", None):
        status = exc.http_status
        retryable = status in (408, 409, 425, 429) or 500 <= status <= 599
        result = {
            "code": "provider_http_" + str(status),
            "message": "The AI provider returned HTTP " + str(status) + ".",
            "retryable": retryable,
            "action": "Wait for bounded retries." if retryable else "Check model IDs and the provider request configuration with skunk diagnose.",
        }
    elif isinstance(exc, OperationalError):
        result = dict(code="database_operational_error", message="The local database could not complete an operation.", retryable=True, action="A bounded retry can recover lock contention; inspect disk space and database availability if it persists.")
        name = getattr(exc.orig, "sqlite_errorname", None)
        if name in {"SQLITE_BUSY", "SQLITE_BUSY_SNAPSHOT", "SQLITE_LOCKED", "SQLITE_FULL", "SQLITE_READONLY", "SQLITE_IOERR", "SQLITE_CANTOPEN"}:
            result["database_error"] = name
            result["retryable"] = name in {"SQLITE_BUSY", "SQLITE_BUSY_SNAPSHOT", "SQLITE_LOCKED"}
    elif isinstance(exc, (TimeoutError, ConnectionError)):
        result = dict(code="connection_or_timeout", message="A bounded network/tool operation timed out or lost its connection.", retryable=True, action="SKUNK retries with backoff; scope and request quotas stay enforced.")
    elif isinstance(exc, Denied):
        result = dict(code="policy_denied", message="An execution-layer policy or authorization check denied this task.", retryable=False, action="Inspect the denied tool event and frozen scope. Retry does not bypass policy.")
    elif isinstance(exc, ProviderError):
        result = dict(code="provider_configuration_or_response", message="Provider configuration or response validation prevented dispatch/completion.", retryable=False, action="Run skunk diagnose to inspect model bindings and request sizes.")
    else:
        result = dict(code="internal_" + type(exc).__name__, message="An internal " + type(exc).__name__ + " stopped this task.", retryable=False, action="Run skunk diagnose and share the failure code/location; no secret values are included.")
    if getattr(exc, "http_status", None):
        result["http_status"] = exc.http_status
    if getattr(exc, "retry_after", None) is not None:
        result["retry_after_seconds"] = min(300, max(0, exc.retry_after))
    if getattr(exc, "error_parameter", None):
        result["request_parameter"] = exc.error_parameter
    if isinstance(exc, ValidationError) and isinstance(getattr(exc, "response_metadata", None), dict):
        result["response_metadata"] = exc.response_metadata
    if isinstance(exc, NameError) and getattr(exc, "name", None):
        result["missing_name"] = exc.name[:80]
    if isinstance(exc, KeyError) and exc.args and isinstance(exc.args[0], str) and exc.args[0] in {"result", "response", "body", "pages", "scope", "model_id", "provider_id", "budget_limit", "policy_id", "campaign_id", "skill_id", "status", "summary"}:
        result["missing_field"] = exc.args[0]
    frames = traceback.extract_tb(exc.__traceback__) if exc.__traceback__ else []
    own = [frame for frame in frames if "/atlas/" in frame.filename]
    if own:
        frame = own[-1]
        result["location"] = frame.filename.rsplit("/", 1)[-1] + ":" + str(frame.lineno) + ":" + frame.name
    return result


def allowed(run):
    value = run.value()
    return value.get("harness") == "skunk/1" and value.get("retry_policy", {}).get("retry_unknown_billing") is True


def attempts(run, task=None):
    floor = json.loads(task.payload).get("resume_attempt_floor", 0) if task is not None and allowed(run) else 0
    return max(0, int(floor)) + min(5, max(1, int(run.value().get("retry_policy", {}).get("max_attempts", 4))))


def retry_delay(run, task, diagnostic):
    if not allowed(run) or not diagnostic.get("retryable") or task.attempts >= attempts(run, task):
        return None
    floor = max(0, int(json.loads(task.payload).get("resume_attempt_floor", 0)))
    return max(min(60, 4 * 2 ** min(4, max(0, task.attempts - floor - 1))), diagnostic.get("retry_after_seconds", 0))
