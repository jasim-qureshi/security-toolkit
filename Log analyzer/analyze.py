import argparse
import re
from datetime import datetime, timedelta
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # save charts to files, no window needed
import matplotlib.pyplot as plt
import pandas as pd

# Matches lines like:
# Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2
LINE_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2}) .*?"
    r"(?P<event>Failed password|Accepted password|Accepted publickey) for "
    r"(?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

# Matches "message repeated 5 times" lines, which stand for several events
REPEAT_RE = re.compile(r"message repeated (\d+) times")

BRUTE_COLS = ["ip", "total_failures", "max_in_window", "users_tried", "first_seen", "last_seen"]
SUSPICIOUS_COLS = ["ip", "user", "success_time", "failures_before"]


def parse_log(path, year):
    rows = []
    total = 0
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            total += 1
            m = LINE_RE.match(line)
            if not m:
                continue
            ts = " ".join(m.group("ts").split())
            try:
                when = datetime.strptime(f"{ts} {year}", "%b %d %H:%M:%S %Y")
            except ValueError:
                continue
            status = "failed" if m.group("event") == "Failed password" else "success"
            repeat = REPEAT_RE.search(line)
            count = int(repeat.group(1)) if repeat else 1
            for _ in range(count):
                rows.append(
                    {"time": when, "status": status, "user": m.group("user"), "ip": m.group("ip")}
                )
    return total, pd.DataFrame(rows, columns=["time", "status", "user", "ip"])


def detect_bruteforce(df, threshold, window_min):
    """Flag IPs with >= threshold failed logins inside any window of window_min minutes."""
    window = timedelta(minutes=window_min)
    findings = []
    failed = df[df["status"] == "failed"]
    for ip, group in failed.groupby("ip"):
        times = sorted(group["time"])
        start = 0
        best = 0
        for end in range(len(times)):
            while times[end] - times[start] > window:
                start += 1
            best = max(best, end - start + 1)
        if best >= threshold:
            findings.append(
                {
                    "ip": ip,
                    "total_failures": len(times),
                    "max_in_window": best,
                    "users_tried": group["user"].nunique(),
                    "first_seen": times[0],
                    "last_seen": times[-1],
                }
            )
    result = pd.DataFrame(findings, columns=BRUTE_COLS)
    return result.sort_values("total_failures", ascending=False)


def detect_success_after_failures(df, threshold, window_min):
    """Flag successful logins preceded by many failures from the same IP."""
    window = timedelta(minutes=window_min)
    failed = df[df["status"] == "failed"]
    rows = []
    for _, s in df[df["status"] == "success"].iterrows():
        prior = failed[
            (failed["ip"] == s["ip"])
            & (failed["time"] < s["time"])
            & (failed["time"] >= s["time"] - window)
        ]
        if len(prior) >= threshold:
            rows.append(
                {
                    "ip": s["ip"],
                    "user": s["user"],
                    "success_time": s["time"],
                    "failures_before": len(prior),
                }
            )
    return pd.DataFrame(rows, columns=SUSPICIOUS_COLS)


def save_chart(df, out_dir, top):
    counts = df[df["status"] == "failed"]["ip"].value_counts().head(top)
    if counts.empty:
        return None
    plt.figure(figsize=(9, 5))
    plt.barh(counts.index[::-1], counts.values[::-1])
    plt.xlabel("Failed logins")
    plt.title(f"Top {len(counts)} IPs by failed SSH logins")
    plt.tight_layout()
    path = out_dir / "top_failed_ips.png"
    plt.savefig(path, dpi=150)
    plt.close()
    return path


def main():
    parser = argparse.ArgumentParser(description="SSH log analyzer")
    parser.add_argument(
        "--file", default=str(Path(__file__).parent / "sample_auth.log"), help="Log file"
    )
    parser.add_argument("--top", type=int, default=10, help="How many results to show")
    parser.add_argument("--threshold", type=int, default=5, help="Failures needed to flag")
    parser.add_argument("--window", type=int, default=10, help="Window in minutes")
    parser.add_argument(
        "--year", type=int, default=2024, help="Assumed year (syslog lines have none)"
    )
    parser.add_argument(
        "--out", default=str(Path(__file__).parent / "output"), help="Output folder"
    )
    args = parser.parse_args()

    if not Path(args.file).exists():
        print(f"File not found: {args.file}")
        return

    total, df = parse_log(args.file, args.year)
    if df.empty:
        print(f"Lines read: {total}. No login events matched. Check the log format.")
        return

    failed = df[df["status"] == "failed"]
    success = df[df["status"] == "success"]
    print(f"Lines read: {total}")
    print(f"Failed logins: {len(failed)}")
    print(f"Successful logins: {len(success)}")

    print("\nTop IPs by failed logins:")
    for ip, count in failed["ip"].value_counts().head(args.top).items():
        print(f"  {ip:<20} {count}")

    print("\nMost targeted usernames:")
    for user, count in failed["user"].value_counts().head(args.top).items():
        print(f"  {user:<20} {count}")

    brute = detect_bruteforce(df, args.threshold, args.window)
    print(
        f"\n[T1110 Brute Force] IPs with {args.threshold}+ failures "
        f"within {args.window} min: {len(brute)}"
    )
    for _, r in brute.head(args.top).iterrows():
        print(
            f"  {r['ip']:<20} total={r['total_failures']}  "
            f"peak={r['max_in_window']}  users_tried={r['users_tried']}"
        )

    suspicious = detect_success_after_failures(df, args.threshold, args.window)
    print(
        f"\n[T1110 then T1078 Valid Accounts] Successful logins after "
        f"{args.threshold}+ failures: {len(suspicious)}"
    )
    for _, r in suspicious.head(args.top).iterrows():
        print(
            f"  {r['ip']:<20} user={r['user']}  "
            f"failures_before={r['failures_before']}  at {r['success_time']}"
        )

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    brute.to_csv(out_dir / "brute_force.csv", index=False)
    suspicious.to_csv(out_dir / "suspicious_success.csv", index=False)
    chart = save_chart(df, out_dir, args.top)
    print(f"\nReports saved in: {out_dir}")
    if chart:
        print(f"Chart: {chart}")


if __name__ == "__main__":
    main()