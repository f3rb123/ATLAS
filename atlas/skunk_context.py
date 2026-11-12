"""Byte-bounded evidence packing with intact JSON validation contracts."""

import json


def size(value):
    return len(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def text_excerpt(value, limit):
    value = str(value)
    raw = value.encode("utf-8")
    marker = " [excerpt truncated]"
    if len(raw) <= limit:
        return value
    return raw[:max(0, limit - len(marker))].decode("utf-8", errors="ignore") + marker


def compact_schema(value):
    """Remove annotations, never field names, required lists, enums or constraints."""
    if not isinstance(value, dict):
        return value
    result = {}
    for key, item in value.items():
        if key in {"title", "description", "examples", "$comment"}:
            continue
        if key in {"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"} and isinstance(item, dict):
            result[key] = {name: compact_schema(schema) for name, schema in item.items()}
        elif key in {"anyOf", "allOf", "oneOf", "prefixItems"} and isinstance(item, list):
            result[key] = [compact_schema(schema) for schema in item]
        elif key in {"items", "additionalProperties", "unevaluatedProperties", "contains", "propertyNames", "if", "then", "else", "not"} and isinstance(item, dict):
            result[key] = compact_schema(item)
        else:
            result[key] = item
    return result


def excerpt(value, width, length, fields, depth=0):
    if isinstance(value, str):
        if value.startswith(("http://", "https://")) and len(value.encode("utf-8")) <= 4096:
            return value
        return text_excerpt(value, width)
    if depth >= 7 and isinstance(value, (dict, list)):
        return "[Nested evidence retained in its original artifact]"
    if isinstance(value, list):
        return [excerpt(item, width, length, fields, depth + 1) for item in value[:length]]
    if isinstance(value, dict):
        priority = {"id", "record_id", "artifact_id", "url", "source_url", "sha256", "status", "capability", "claim"}
        pairs = sorted(value.items(), key=lambda item: item[0] not in priority)
        return {text_excerpt(key, 100): item if key in {"id", "record_id", "artifact_id", "sha256", "hash"} and isinstance(item, str) and len(item) <= 128 else excerpt(item, width, length, fields, depth + 1) for key, item in pairs[:fields]}
    return value


def fit(value, budget):
    for width, length, fields in ((1500, 8, 24), (800, 4, 16), (320, 3, 12), (120, 2, 8), (48, 1, 4)):
        selected = excerpt(value, width, length, fields)
        if size(selected) <= budget:
            return selected
    return [] if isinstance(value, list) else {"excerpt_omitted": True, "reason": "Original evidence remains in the local artifact store"}


def bounded_context(context, max_bytes=34000):
    """Fit the exact serialized context; contracts are selected whole, not clipped."""
    task = context.get("task", {})
    operator = context.get("operator_instructions", "")
    result = {
        "operator_instructions": operator,
        "task": {key: text_excerpt(task[key], 4000 if key == "instructions" else 2000)
                 for key in ("id", "role", "instructions", "question", "reason") if key in task},
        "bounded_context": "Evidence excerpts only. Full artifacts remain local. Tool schemas below are intact; the catalog lists other available typed tools. Invalid-argument feedback prioritizes that tool's full schema on the next round. Frozen policy is enforced independently.",
    }
    if size(result) + 512 > max_bytes:
        raise ValueError("Operator/task instructions cannot fit the configured physical model context")
    for key in ("reasoning_round", "constraint", "campaign", "policy"):
        if key in context:
            available = max_bytes - size(result) - 512
            if available >= 256:
                result[key] = fit(context[key], min(3000 if key in ("campaign", "policy") else 1000, available))
    # Preserve the exact target URL instead of truncating it as prose.
    if isinstance(result.get("campaign"), dict) and context.get("campaign", {}).get("target_url"):
        candidate = {**result["campaign"], "target_url": context["campaign"]["target_url"]}
        if size({**result, "campaign": candidate}) + 512 <= max_bytes:
            result["campaign"] = candidate

    memory = context.get("knowledge", {})
    tools = {name: {"risk": spec.get("risk"), "input": compact_schema(spec.get("input", {}))}
             for name, spec in context.get("tool_capabilities", {}).items()}
    knowledge_tools = {name: compact_schema(schema) for name, schema in memory.get("capabilities", {}).items()}
    catalog = sorted(set(tools) | set(knowledge_tools))
    if size({**result, "tool_catalog": catalog}) + 256 <= max_bytes:
        result["tool_catalog"] = catalog
    role = str(task.get("role", ""))
    preferred = ["knowledge.search", "knowledge.retrieve"]
    if role in {"report", "deep-research", "vulnerability-research"}:
        preferred += ["knowledge.search_reports", "knowledge.get_source", "store_research_note"]
    elif role.startswith("recon") or role in {"javascript", "content-discovery"}:
        preferred += ["web.request", "web.crawl", "scanner.run", "store_research_note"]
    else:
        preferred += ["web.experiment", "web.request", "web.check", "store_research_note"]
    preferred += ["read_file_range", "search_text", "search_symbols", "mark_hypothesis_status", "link_attack_chain"]
    recent = [item.get("capability") for item in context.get("knowledge_tool_results", []) if item.get("schema_hint")]
    order = list(dict.fromkeys([*recent, *preferred, *catalog]))
    schema_room = max(0, max_bytes - size(result) - min(6500, max_bytes // 4) - 256)
    chosen, knowledge_chosen = {}, {}
    for name in order:
        if name in knowledge_tools:
            trial = {**knowledge_chosen, name: knowledge_tools[name]}
            if size({"tool_capabilities": chosen, "knowledge_capabilities": trial}) <= schema_room:
                knowledge_chosen = trial
        elif name in tools:
            trial = {**chosen, name: tools[name]}
            if size({"tool_capabilities": trial, "knowledge_capabilities": knowledge_chosen}) <= schema_room:
                chosen = trial
    if chosen:
        result["tool_capabilities"] = chosen
    result["knowledge"] = {"policy_version": memory.get("policy_version"), "trust": "untrusted_attributed_knowledge", "capabilities": knowledge_chosen}
    omitted = []

    def add_section(name, value, target=None, cap=3500):
        available = max_bytes - size(result) - 384
        if available < 160:
            omitted.append(name)
            return
        selected = fit(value, min(cap, available))
        if target is None:
            trial = {**result, name: selected}
        else:
            trial = {**result, target: {**result[target], name: selected}}
        if size(trial) + 256 <= max_bytes:
            result.update(trial)
        else:
            omitted.append(name)

    for name in ("model_output_repair", "knowledge_tool_results", "discovery", "related_discoveries", "assigned_questions", "web_observations", "pending_candidates", "known_findings", "shared_observations", "source"):
        if name in context:
            add_section(name, context[name], cap=6000 if name == "related_discoveries" else 5000 if name == "model_output_repair" else 3500)
    for name in ("availability", "task_research", "skills"):
        if name in memory:
            add_section(name, memory[name], target="knowledge", cap=2500)
    handled = {"task", "operator_instructions", "knowledge", "tool_capabilities", "tool_catalog", "bounded_context", "omitted_context_sections", "reasoning_round", "constraint", "campaign", "policy"} | set(result)
    for key, value in context.items():
        if key not in handled:
            add_section(key, value, cap=1600)
    if omitted:
        note = [text_excerpt(name, 60) for name in omitted[:12]]
        if size({**result, "omitted_context_sections": note}) <= max_bytes:
            result["omitted_context_sections"] = note
    if size(result) > max_bytes:
        raise ValueError("Operator/task instructions cannot fit the configured physical model context")
    return result
