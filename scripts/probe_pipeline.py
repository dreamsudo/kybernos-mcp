#!/usr/bin/env python3
"""Run the verified adversarial corpus against a LIVE pipeline (regression check).

Loads tests/corpus/probe_corpus.json (2,800+ pipeline probes, each with a
ground-truth `verdict` established by tests/../verify against the real pipeline)
and replays them over HTTP. A live stack that disagrees with the recorded
verdict = a regression (a control changed behavior).

Usage:
  # bring the stack up, then point --base at the ingress service:
  python scripts/probe_pipeline.py --base http://localhost:8443
  # k8s:  kubectl -n mcp-secure port-forward svc/service-ingress 8443:8443
"""
import argparse
import json
import os
import re
import sys
import httpx

CORPUS = os.path.join(os.path.dirname(__file__), "..", "tests", "corpus", "probe_corpus.json")
REPEAT = re.compile(r"<REPEAT:(.):(\d+)>")


def expand(v):
    if isinstance(v, str):
        m = REPEAT.search(v)
        return v[:m.start()] + m.group(1) * min(int(m.group(2)), 20000) + v[m.end():] if m else v
    if isinstance(v, dict):
        return {k: expand(x) for k, x in v.items()}
    if isinstance(v, list):
        return [expand(x) for x in v]
    return v


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:8443", help="ingress base URL")
    ap.add_argument("--limit", type=int, default=0, help="cap probes (0 = all)")
    ap.add_argument("--category", default="", help="filter to one category")
    args = ap.parse_args()

    corpus = json.load(open(CORPUS))
    probes = corpus["pipeline_probes"]
    if args.category:
        probes = [p for p in probes if p.get("category") == args.category]
    if args.limit:
        probes = probes[: args.limit]

    print(f"=== replaying {len(probes)} verified probes -> {args.base} ===")
    regressions, ran = [], 0
    from collections import Counter
    cat_fail = Counter()
    try:
        with httpx.Client(base_url=args.base, timeout=20) as c:
            for p in probes:
                payload = expand(p["payload"])
                try:
                    r = c.post("/process", json={"principal": p["principal"], "resource": p["resource"], "payload": payload})
                except httpx.ConnectError:
                    print(f"  ERROR: cannot reach {args.base}. Is the stack up / port-forwarded?")
                    sys.exit(2)
                live = "ALLOW" if r.status_code == 200 else "BLOCK"
                ran += 1
                if live != p["verdict"]:
                    regressions.append((p, live))
                    cat_fail[p.get("category")] += 1
    except KeyboardInterrupt:
        pass

    print(f"\nran {ran} probes | {len(regressions)} regressions vs recorded ground truth")
    if regressions:
        print("\nregressions (recorded -> live):")
        for cat, n in cat_fail.most_common():
            print(f"  {cat}: {n}")
        for p, live in regressions[:25]:
            print(f"  [{p.get('category')}] {p.get('name')}: recorded={p['verdict']} live={live}  {json.dumps(p['payload'])[:70]}")
    sys.exit(1 if regressions else 0)


if __name__ == "__main__":
    main()
