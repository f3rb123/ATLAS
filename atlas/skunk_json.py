"""Decode a single, unambiguous JSON object; never repair or invent evidence."""

import json
import re


def object_response(content):
    warnings = []
    if not isinstance(content, str):
        return None, ["structured_object_required"]
    candidate = content.strip()
    # Some reasoning providers include a completed thinking block in content.
    # It is not part of the answer and is never searched for tool arguments.
    if candidate.startswith("<think>"):
        end = candidate.find("</think>")
        if end < 0 or "<think>" in candidate[7:end]:
            return None, ["invalid_structured_json"]
        candidate = candidate[end + len("</think>"):].strip()
        warnings.append("completed_thinking_prefix_removed")
    fenced = re.fullmatch(r"```(?:json)?[ \t]*\r?\n([\s\S]*?)\r?\n```", candidate)
    if fenced:
        candidate = fenced.group(1)
        warnings.append("exact_json_fence_normalized")
    elif "```" in candidate:
        # Permit a single JSON fence with a short plain-text introduction or
        # conclusion. Braces, alternate fences or quoted JSON are ambiguous.
        fences = list(re.finditer(r"```json[ \t]*\r?\n([\s\S]*?)\r?\n```", candidate))
        if len(fences) != 1:
            return None, warnings + ["invalid_structured_json"]
        match = fences[0]
        outside = candidate[:match.start()] + candidate[match.end():]
        if len(outside) > 512 or any(char in outside for char in "{}[]`"):
            return None, warnings + ["ambiguous_structured_json"]
        candidate = match.group(1)
        warnings.append("single_json_fence_normalized")

    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON property")
            result[key] = value
        return result

    def invalid_constant(_):
        raise ValueError("Non-finite JSON constant")

    try:
        value = json.loads(candidate, object_pairs_hook=unique_pairs, parse_constant=invalid_constant)
    except (ValueError, TypeError, RecursionError):
        return None, warnings + ["invalid_structured_json"]
    if not isinstance(value, dict):
        return None, warnings + ["structured_object_required"]
    return value, warnings
