import os
import threading
from collections import Counter
import customtkinter as ctk
from tkinter import filedialog, messagebox
from scapy.all import rdpcap, IP, TCP, UDP

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green")


class CyberForensicDashboard(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("PCAP Forensic Analyzer")
        self.geometry("800x600")

        self.full_file_path = None

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self.setup_ui()

    def setup_ui(self):
        self.header = ctk.CTkLabel(
            self,
            text="NETWORK FORENSIC ANALYZER v1.0",
            font=("Orbitron", 22, "bold")
        )
        self.header.grid(row=0, column=0, pady=20, sticky="ew")

        self.file_frame = ctk.CTkFrame(self)
        self.file_frame.grid(row=1, column=0, padx=20, pady=10, sticky="ew")

        self.file_entry = ctk.CTkEntry(
            self.file_frame,
            placeholder_text="Select PCAP file...",
            width=520
        )
        self.file_entry.grid(row=0, column=0, padx=(15, 10), pady=12)

        self.browse_btn = ctk.CTkButton(
            self.file_frame,
            text="BROWSE PCAP",
            command=self.browse_file,
            fg_color="#00FF66",
            hover_color="#00AA44",
            text_color="#000000",
            font=("Arial", 12, "bold")
        )
        self.browse_btn.grid(row=0, column=1, padx=(0, 15), pady=12)

        self.output_box = ctk.CTkTextbox(
            self,
            width=760,
            height=350,
            font=("Consolas", 12),
            text_color="#00FF66",
            fg_color="#050505"
        )
        self.output_box.grid(row=2, column=0, padx=20, pady=15, sticky="nsew")
        self.output_box.configure(state="disabled")

        self.status_label = ctk.CTkLabel(
            self,
            text="Status: Ready",
            anchor="w",
            font=("Consolas", 11)
        )
        self.status_label.grid(row=3, column=0, padx=20, pady=(0, 10), sticky="ew")

    def browse_file(self):
        filename = filedialog.askopenfilename(
            initialdir="/",
            title="Select PCAP File",
            filetypes=(("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*"))
        )

        if filename:
            self.full_file_path = filename
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, os.path.basename(filename))
            self.start_analysis()

    def start_analysis(self):
        if not self.full_file_path or not os.path.exists(self.full_file_path):
            messagebox.showerror("Error", "Select a valid PCAP file!")
            return

        self.browse_btn.configure(state="disabled")
        self.status_label.configure(text="Analyzing PCAP file...")

        self.output_box.configure(state="normal")
        self.output_box.delete("1.0", "end")
        self.output_box.insert("1.0", "Parsing packets, please wait...\n")
        self.output_box.configure(state="disabled")

        thread = threading.Thread(
            target=self.run_analysis,
            args=(self.full_file_path,),
            daemon=True
        )
        thread.start()

    def run_analysis(self, file_path):
        try:
            packets = rdpcap(file_path)

            ip_sources = []
            ports = []
            protocols = Counter()

            for packet in packets:
                if packet.haslayer(IP):
                    ip_sources.append(packet[IP].src)

                    if packet.haslayer(TCP):
                        protocols['TCP'] += 1
                        ports.append(packet[TCP].dport)
                    elif packet.haslayer(UDP):
                        protocols['UDP'] += 1
                        ports.append(packet[UDP].dport)
                    else:
                        protocols['Other'] += 1

            top_ips = Counter(ip_sources).most_common(5)
            top_ports = Counter(ports).most_common(5)

            report = [
                "==========================================",
                "      NETWORK TRIAGE FORENSIC REPORT      ",
                "==========================================",
                f"\n[+] File: {os.path.basename(file_path)}",
                f"[+] Total Packets: {len(packets):,}",
                "\n--- Protocol Breakdown ---"
            ]

            for proto, count in protocols.items():
                report.append(f"  > {proto:<5}: {count:,} packets")

            report.append("\n--- Top 5 IP Talkers ---")
            for ip, count in top_ips:
                report.append(f"  [>] {ip:<15}: {count:,} requests")

            report.append("\n--- Top 5 Destination Ports ---")
            for port, count in top_ports:
                report.append(f"  [>] Port {port:<5}: {count:,} hits")

            report.append("\n==========================================")
            report.append("          End of Report                   ")

            output_text = "\n".join(report)
            self.after(0, self.update_results, output_text, len(packets))

        except Exception as e:
            self.after(0, self.handle_error, str(e))

    def update_results(self, text, packet_count):
        self.output_box.configure(state="normal")
        self.output_box.delete("1.0", "end")
        self.output_box.insert("end", text)
        self.output_box.configure(state="disabled")

        self.status_label.configure(text=f"Analysis Complete: Processed {packet_count:,} packets.")
        self.browse_btn.configure(state="normal")

    def handle_error(self, err):
        messagebox.showerror("Error", f"Failed to parse file: {err}")
        self.status_label.configure(text="Status: Failed")
        self.browse_btn.configure(state="normal")


if __name__ == "__main__":
    app = CyberForensicDashboard()
    app.mainloop()