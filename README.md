# 🕵️‍♂️ Windows Security Log Analyzer

> "Because Windows logs don't read themselves... yet."  

A **professional-grade Windows security log analyzer** designed for pentesters, SOC analysts, and those who enjoy watching failed logins pile up like a stack overflow of human error.  

This tool digs deep into Windows event logs, hunting for suspicious activity, failed logins, and anomalies that scream **"something shady is happening here."**  

---

## Features 🔥

- **Automated Log Parsing**: Reads `.log` and `.csv` files from any directory, extracts timestamps, usernames, IP addresses, and event IDs.  
- **Failed Login Detection**: Identifies brute-force attempts, wrong passwords, locked accounts, disabled users, and general chaos.  
- **Suspicious Pattern Detection**:  
  - Brute-force attacks  
  - Multiple failed logins from the same IP  
  - Off-hours activity (because hackers don't sleep, and neither do you)  
  - Account enumeration attempts  
  - Basic geographical anomalies  
- **Visual Dashboard**:  
  - Timeline of failed logins  
  - Pie chart of failure categories  
  - Top attacking IPs & most targeted accounts  
  - Hourly activity distribution  
  - IP class distribution  
  - Suspicious pattern overview  
- **Export Results**: CSV, Excel, JSON — choose your poison.

---

## Installation ⚡

```bash
git clone https://github.com/yourusername/WindowsSecurityLogAnalyzer.git
cd WindowsSecurityLogAnalyzer
pip install -r requirements.txt
```
Python 3.9+ recommended. Works best with a decent cup of coffee and a dark terminal theme.

## Usage 🧰
```bash
from analyzer import analyze_windows_logs, create_sample_logs

# Optional: create sample logs for testing
create_sample_logs(output_dir='./logs/', num_entries=500)

# Run the analyzer
analyzer = analyze_windows_logs(log_dir='./logs/', log_pattern='*.log')

# Visualize findings (optional)
analyzer.visualize_findings(save_figures=True)

# Export results
analyzer.export_results(format='csv')
```
## Why This Exists 🤔

Windows logs are like gossiping coworkers — full of hints, patterns, and secrets — if you know how to listen. This tool turns raw log chaos into actionable intelligence.

Pentesters: Quickly identify weak spots and suspicious behaviors.

SOC Analysts: Visualize anomalies in minutes instead of hours.

Curious Hackers: Because staring at logs is secretly fun.


## Contributing 💀


Feel free to fork, break, fix, and submit PRs. Make it better. Make it darker. Make it even more hacker-ish.

## License 📝


MIT License — because sharing is caring, even in the shadows.


## Disclaimer ⚠️

This tool is for educational and defensive purposes only. Using it for illegal hacking is your problem, not mine.

"With great power comes great responsibility… and a lot of logs."
