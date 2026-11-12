"""Host-owned SKUNK accounting policy. Model/tool input cannot change this mode."""


def default_policy():
    return {
        "version": 1, "mode": "tracking_only", "authority": "host-owner",
        "authorization": "Owner explicitly requested no local token or spending caps",
        "token_limits_enforced": False, "spending_limits_enforced": False,
    }


def tracking_only(run):
    if run is None:
        return False
    value = run.value()
    policy = value.get("usage_policy", {})
    return bool(value.get("harness") == "skunk/1" and policy.get("version") == 1
        and policy.get("mode") == "tracking_only" and policy.get("authority") == "host-owner")
