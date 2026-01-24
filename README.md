# linux-auth-log-monitor

Security monitoring project that detects SSH brute-force attempts by analyzing Linux authentication logs.

## Why I Built This

To better understand how security teams analyze authentication logs and detect brute-force attacks in real environments. It also helped me practice writing detection logic and working with real-world log formats.

## How It Works

1. Reads authentication log line by line
2. Matches SSH failure patterns using regex
3. Groups events by IP address
4. Applies a sliding time window
5. Flags IPs exceeding failure threshold
