"""Read measurement-time machine context without inventing missing observations."""
from datetime import datetime
import math


def nonnegative(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def snapshot(value, platform):
    if not isinstance(value, dict) or value.get("platform") != platform:
        raise ValueError("snapshot platform unavailable or mismatched")
    stamp = value.get("observed_at")
    if not isinstance(stamp, str) or datetime.fromisoformat(stamp).tzinfo is None:
        raise ValueError("snapshot timestamp unavailable")
    result = {"observed_at": stamp, "platform": platform}
    for key in ("load", "available_memory"):
        metric = value.get(key)
        if not isinstance(metric, dict) or metric.get("state") not in {
                "measured", "absent", "unreadable", "unsupported"}:
            raise ValueError("snapshot metric unavailable or invalid")
        result[key] = {"state": metric["state"]}
        if metric["state"] != "measured":
            continue
        if key == "load":
            cpus, load, per_cpu = (metric.get(name) for name in
                                   ("logical_cpus", "one_minute", "per_cpu"))
            if (platform == "win32" or type(cpus) is not int or cpus < 1
                    or not nonnegative(load) or not nonnegative(per_cpu)
                    or not math.isclose(per_cpu, load / cpus, rel_tol=1e-12, abs_tol=1e-12)):
                raise ValueError("load observation invalid")
            result[key].update(logical_cpus=cpus, one_minute=load, per_cpu=per_cpu)
        else:
            size, method = metric.get("bytes"), metric.get("method")
            if (type(size) is not int or size < 0 or not isinstance(method, str)
                    or not method.strip()):
                raise ValueError("available-memory observation invalid")
            result[key].update(bytes=size, method=method)
    return result


def observation(row, platform):
    if "machine_context" not in row:
        return {"state": "absent", "load_qualification": "UNKNOWN"}
    try:
        value = row["machine_context"]
        if not isinstance(value, dict) or value.get("schema") != "se.budget-machine-context/v1":
            raise ValueError("machine-context schema invalid")
        before, after = (snapshot(value.get(key), platform) for key in ("before", "after"))
        if datetime.fromisoformat(before["observed_at"]) > datetime.fromisoformat(after["observed_at"]):
            raise ValueError("snapshot timestamps reversed")
        threshold = value.get("load_per_cpu_threshold")
        if not nonnegative(threshold) or threshold == 0:
            raise ValueError("load threshold invalid")
        loads = [sample["load"].get("per_cpu") for sample in (before, after)]
        above = (True if any(load is not None and load > threshold for load in loads)
                 else False if all(load is not None for load in loads) else None)
        if "above_load_threshold" not in value or value["above_load_threshold"] is not above:
            raise ValueError("load threshold flag differs from observations")
        return {"state": "readable", "before": before, "after": after,
                "load_per_cpu_threshold": threshold, "above_load_threshold": above,
                "load_qualification": "ABOVE LOAD THRESHOLD" if above is True
                else "WITHIN LOAD THRESHOLD" if above is False else "UNKNOWN"}
    except (ValueError, TypeError, OverflowError):
        return {"state": "unreadable", "load_qualification": "UNKNOWN"}


def text(value):
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(
        ">", "&gt;").replace("|", "&#124;").replace("\n", " ").replace("\r", " ")


def endpoint(sample):
    load, memory = sample["load"], sample["available_memory"]
    load_text = (f"{load['one_minute']:g} / {load['logical_cpus']} CPUs = {load['per_cpu']:g} per CPU"
                 if load["state"] == "measured" else load["state"].upper())
    memory_text = (f"{memory['bytes']} bytes ({memory['method']})"
                   if memory["state"] == "measured" else memory["state"].upper())
    return text(f"{sample['observed_at']}; load: {load_text}; available memory: {memory_text}")


def render(budgets):
    lines = ["Budget figures and measurement-time machine context:", "",
             "Load uses the one-minute average divided by logical CPUs; the stated threshold is shown per probe.",
             "Before/after snapshots bracket each measurement; they do not bound transient load inside it.",
             "High-load figures remain visible with their original budget verdict. Missing context is not a quiet-machine observation.",
             "", "| Budget | Probe | Verdict | Figures | Before | After | Load qualification |",
             "| --- | --- | --- | --- | --- | --- | --- |"]
    for budget in budgets:
        for probe in budget["probes"]:
            if not probe["numbers"]:
                continue
            context = probe["machine_context"]
            if context["state"] == "readable":
                before, after = (endpoint(context[key]) for key in ("before", "after"))
                qualification = context["load_qualification"] + f" (threshold {context['load_per_cpu_threshold']:g})"
            else:
                before = after = context["state"].upper()
                qualification = "UNKNOWN"
            identity = f"{probe['platform']} / {probe['surface']} / {probe['label']}"
            figures = "; ".join(f"{key}={value}" for key, value in probe["numbers"].items())
            lines.append("| " + " | ".join((text(budget["id"]), text(identity), text(probe["probe_result"]), text(figures),
                                            before, after, text(qualification))) + " |")
    return lines + [""]
