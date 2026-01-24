import argparse
import csv
import os
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Dict, Tuple


#matches lines like this 
# Jan 23 10:01:12 server sshd[1234]: Failed password for invalid user admin from 192.168.1.10 port 54432 ssh2
FAILED_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password for\s+"
    r"(?:(?:invalid user)\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
)


MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
}


@dataclass
class FailedAttempt:
    timestamp: datetime
    host: str
    username: str
    ip: str
    raw: str


def parse_failed_attempts(log_path: str, year: int) -> List[FailedAttempt]:
    attempts: List[FailedAttempt] = []

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.rstrip("\n")
            m = FAILED_RE.match(line)
            if not m:
                continue

            mon = MONTHS.get(m.group("mon"))
            day = int(m.group("day"))
            hh, mm, ss = map(int, m.group("time").split(":"))
            ts = datetime(year, mon, day, hh, mm, ss)

            attempts.append(
                FailedAttempt(
                    timestamp=ts,
                    host=m.group("host"),
                    username=m.group("user"),
                    ip=m.group("ip"),
                    raw=line
                )
            )

    # Ensure sorted by time (useful for sliding window)
    attempts.sort(key=lambda x: x.timestamp)
    return attempts


def detect_bruteforce(
    attempts: List[FailedAttempt],
    threshold: int,
    window_minutes: int
) -> List[Dict]:
    """
    Flags IPs with >= threshold failed attempts within a rolling window_minutes period.
    """
    if not attempts:
        return []

    by_ip: Dict[str, List[FailedAttempt]] = {}
    for a in attempts:
        by_ip.setdefault(a.ip, []).append(a)

    alerts: List[Dict] = []
    window = timedelta(minutes=window_minutes)

    for ip, events in by_ip.items():
        i = 0
        for j in range(len(events)):
            while events[j].timestamp - events[i].timestamp > window:
                i += 1
            count = j - i + 1
            if count >= threshold:
                first_seen = events[i].timestamp
                last_seen = events[j].timestamp
                alerts.append({
                    "ip": ip,
                    "failures_in_window": count,
                    "window_minutes": window_minutes,
                    "first_seen": first_seen.isoformat(sep=" "),
                    "last_seen": last_seen.isoformat(sep=" "),
                })
                break  # One alert per IP is fine for MVP

    # Highest failure count first
    alerts.sort(key=lambda x: x["failures_in_window"], reverse=True)
    return alerts


def top_counts(attempts: List[FailedAttempt]) -> Tuple[List[Tuple[str, int]], List[Tuple[str, int]]]:
    ip_counts: Dict[str, int] = {}
    user_counts: Dict[str, int] = {}

    for a in attempts:
        ip_counts[a.ip] = ip_counts.get(a.ip, 0) + 1
        user_counts[a.username] = user_counts.get(a.username, 0) + 1

    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
    top_users = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)
    return top_ips, top_users


def write_csv_events(attempts: List[FailedAttempt], out_path: str) -> None:
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["timestamp", "host", "username", "ip", "raw_line"])
        for a in attempts:
            w.writerow([a.timestamp.isoformat(sep=" "), a.host, a.username, a.ip, a.raw])


def write_csv_alerts(alerts: List[Dict], out_path: str) -> None:
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["ip", "failures_in_window", "window_minutes", "first_seen", "last_seen"])
        w.writeheader()
        for row in alerts:
            w.writerow(row)


def main():
    parser = argparse.ArgumentParser(description="Detect SSH brute-force attempts from Linux auth logs.")
    parser.add_argument("--input", required=True, help="Path to auth log file (e.g., data/sample_auth.log)")
    parser.add_argument("--threshold", type=int, default=8, help="Failures within window to flag an IP (default: 8)")
    parser.add_argument("--window", type=int, default=10, help="Rolling window in minutes (default: 10)")
    parser.add_argument("--year", type=int, default=datetime.now().year, help="Year to assume for log timestamps")
    parser.add_argument("--outdir", default="output", help="Output directory (default: output)")
    args = parser.parse_args()

    attempts = parse_failed_attempts(args.input, year=args.year)
    alerts = detect_bruteforce(attempts, threshold=args.threshold, window_minutes=args.window)
    top_ips, top_users = top_counts(attempts)

    events_csv = os.path.join(args.outdir, "events.csv")
    alerts_csv = os.path.join(args.outdir, "alerts.csv")
    write_csv_events(attempts, events_csv)
    write_csv_alerts(alerts, alerts_csv)

    print("\n=== Linux Auth Log Monitor (MVP) ===")
    print(f"Input: {args.input}")
    print(f"Parsed failed attempts: {len(attempts)}")
    print(f"Brute-force rule: >= {args.threshold} failures within {args.window} minutes\n")

    print("Top IPs (failed attempts):")
    for ip, c in top_ips[:10]:
        print(f"  {ip:15}  {c}")

    print("\nTop usernames targeted:")
    for user, c in top_users[:10]:
        print(f"  {user:15}  {c}")

    print("\nAlerts (possible brute-force):")
    if not alerts:
        print("  None flagged.")
    else:
        for a in alerts:
            print(f"  IP {a['ip']} -> {a['failures_in_window']} failures "
                  f"({a['first_seen']} to {a['last_seen']})")

    print(f"\nWrote: {events_csv}")
    print(f"Wrote: {alerts_csv}\n")


if __name__ == "__main__":
    main()
