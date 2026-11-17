from datetime import datetime, timedelta

import pandas as pd

import analyze


def write_log(tmp_path, lines):
    path = tmp_path / "test.log"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def make_df(ip, n, step_min=1, status="failed"):
    start = datetime(2024, 12, 10, 7, 0, 0)
    rows = [
        {"time": start + timedelta(minutes=i * step_min), "status": status, "user": "root", "ip": ip}
        for i in range(n)
    ]
    return pd.DataFrame(rows, columns=["time", "status", "user", "ip"])


def test_parse_failed_login(tmp_path):
    path = write_log(
        tmp_path,
        ["Dec 10 06:55:48 LabSZ sshd[1]: Failed password for invalid user webmaster from 1.2.3.4 port 38926 ssh2"],
    )
    total, df = analyze.parse_log(path, 2024)
    assert total == 1
    assert len(df) == 1
    assert df.iloc[0]["status"] == "failed"
    assert df.iloc[0]["user"] == "webmaster"
    assert df.iloc[0]["ip"] == "1.2.3.4"


def test_parse_accepted_login(tmp_path):
    path = write_log(
        tmp_path,
        ["Dec 10 06:56:00 LabSZ sshd[2]: Accepted password for root from 1.2.3.4 port 1 ssh2"],
    )
    _, df = analyze.parse_log(path, 2024)
    assert len(df) == 1
    assert df.iloc[0]["status"] == "success"


def test_repeated_message_counts_each_event(tmp_path):
    path = write_log(
        tmp_path,
        ["Dec 10 07:13:56 LabSZ sshd[3]: message repeated 5 times: [ Failed password for root from 5.36.59.76 port 42393 ssh2]"],
    )
    _, df = analyze.parse_log(path, 2024)
    assert len(df) == 5


def test_unrelated_line_is_ignored(tmp_path):
    path = write_log(
        tmp_path,
        ["Dec 10 06:55:48 LabSZ sshd[1]: Connection closed by 1.2.3.4 [preauth]"],
    )
    total, df = analyze.parse_log(path, 2024)
    assert total == 1
    assert df.empty


def test_bruteforce_flagged():
    df = make_df("9.9.9.9", 5)
    result = analyze.detect_bruteforce(df, threshold=5, window_min=10)
    assert len(result) == 1
    assert result.iloc[0]["ip"] == "9.9.9.9"


def test_below_threshold_not_flagged():
    df = make_df("9.9.9.9", 4)
    result = analyze.detect_bruteforce(df, threshold=5, window_min=10)
    assert len(result) == 0


def test_slow_failures_not_flagged():
    # 5 failures, but 60 minutes apart: never 5 inside a 10-minute window
    df = make_df("9.9.9.9", 5, step_min=60)
    result = analyze.detect_bruteforce(df, threshold=5, window_min=10)
    assert len(result) == 0


def test_success_after_failures_flagged():
    failures = make_df("9.9.9.9", 5)
    success = pd.DataFrame(
        [{"time": datetime(2024, 12, 10, 7, 6, 0), "status": "success", "user": "root", "ip": "9.9.9.9"}]
    )
    df = pd.concat([failures, success], ignore_index=True)
    result = analyze.detect_success_after_failures(df, threshold=5, window_min=10)
    assert len(result) == 1
    assert result.iloc[0]["failures_before"] == 5


def test_success_from_other_ip_not_flagged():
    failures = make_df("9.9.9.9", 5)
    success = pd.DataFrame(
        [{"time": datetime(2024, 12, 10, 7, 6, 0), "status": "success", "user": "root", "ip": "8.8.8.8"}]
    )
    df = pd.concat([failures, success], ignore_index=True)
    result = analyze.detect_success_after_failures(df, threshold=5, window_min=10)
    assert len(result) == 0