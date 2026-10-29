import json

exp = json.load(open("/tests/expected.json"))
try:
    got = json.load(open("/app/report.json"))
    if not isinstance(got, dict):
        raise ValueError("report is not a JSON object")
except Exception as e:
    print(f"no usable report: {e}")
    got = {}


def norm(v):
    if isinstance(v, str):
        return v.strip()
    if isinstance(v, list):
        return [x.strip() if isinstance(x, str) else x for x in v]
    return v


score = 0
for k, want in exp.items():
    ok = norm(got.get(k)) == want
    score += ok
    print(f"{'PASS' if ok else 'FAIL'} {k}")
reward = score / len(exp)
print(f"reward {reward:.3f}")
with open("/logs/verifier/reward.txt", "w") as f:
    f.write(f"{reward:.4f}\n")
