To speed things up, I built a lightweight Network Forensic & Triage Dashboard designed to automate raw .pcap parsing and get straight to the actionable insights. 🛡️💻

What it handles under the hood:

⚡ Instant Parsing: Loads and processes .pcap / .pcapng files without the manual hassle.

📊 Protocol Breakdown: Gives an immediate view of Layer-4 traffic distribution (TCP vs. UDP vs. Others).

🎯 Threat Hunting: Instantly surfaces the Top 5 Most Active IPs ("Top Talkers") and targeted ports.

Why build it?
Instead of endless scrolling through thousands of lines in Wireshark, this dashboard highlights traffic spikes and unusual open ports in seconds. It’s built to make rapid triage and egress auditing much cleaner for security workflows.

Tech Stack:

Language: Python

DPI Engine: Scapy

GUI: CustomTkinter (went with a sleek, neon-green terminal aesthetic 🟩)

Concepts: OOP & Network Forensics
