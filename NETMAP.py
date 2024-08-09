import socket
import datetime
import threading
from tkinter import *
import tkinter as tk
from tkinter import Menu
from tkinter import ttk, filedialog
import tkinter.messagebox as msgbox
from fpdf import FPDF
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from getmac import getmac
import  os
import json
import sys
from PIL import Image, ImageTk

service_names = {
    21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS", 69: "TFTP", 80: "HTTP", 110: "POP3", 
    123: "NTP", 143: "IMAP", 163: "SNMP VIEWS", 179: "BGP", 264: "BGMP", 389: "IDAP", 427: "SLP", 443: "HTTPS", 
    445: "MS DS SMB", 465: "SMTP over SSL/TLS", 489: "IKEV2", 497: "DANTZ", 514: "SYSLOG" , 560: "RMonitor", 691: "Microsoft exchange", 
    873: "RSYNC", 902: "VMware server", 989: "FTPS over TLS/SSL", 993: "IMAPS over SSL/TLS", 995: "POP3 over TLS/SSL", 1025:"Microsoft RPC", 
    1080: "SOCKS Proxy", 1194: "Open VPN", 3306: "MySQL", 3389: "RDP MS terminal server", 5432: "Postgre SQL", 8080: "HTTP Proxy"
}

port_risks = {
        21: "Risks of FTP: Anonymous FTP access, Weak password encryption, Insecure data transmission",
        22: "Risks of SSH: Weak password policy, Unpatched vulnerabilities in SSH daemon, Man-in-the-middle attacks",
        23: "Risks of TELNET: Insecure data transmission, Weak password policy, Lack of encryption",
        25: "Risks of SMTP: Spamming, Phishing, Email spoofing, Insecure data transmission",
        53: "Risks of DNS: DNS spoofing, DNS cache poisoning, DNS amplification attacks",
        69: "Risks of TFTP: Insecure data transmission, Lack of authentication, Unauthorized access",
        80: "Risks of HTTP: Insecure data transmission, Man-in-the-middle attack, Cross-site scripting (XSS)",
        110: "Risks of POP3: Insecure data transmission, Weak password policy, Man-in-the-middle attacks",
        123: "Risks of NTP: Amplification attacks, Stratum-level attacks, Replay attacks",
        143: "Risks of IMAP: Insecure data transmission, Weak password policy, Man-in-the-middle attacks",
        163: "Risks of SNMP VIEWS: Unauthorized access, SNMP community string disclosure, SNMP reflection attacks",
        179: "Risks of BGP: Route hijacking, Prefix hijacking, BGP session hijacking",
        264: "Risks of BGMP: Amplification attacks, Reflection attacks, Unauthorized access",
        389: "Risks of IDAP: Unauthorized access, Directory traversal attacks, LDAP injection",
        427: "Risks of SLP: Amplification attacks, Reflection attacks, Unauthorized access",
        443: "Risks of HTTPS: Insecure data transmission, Man-in-the-middle attacks, SSL/TLS vulnerabilities",
        445: "Risks of MS DS SMB: SMB relay attacks, SMB signing attacks, EternalBlue exploit",
        465: "Risks of SMTP over SSL/TLS: nsecure data transmission, Man-in-the-middle attacks, SSL/TLS vulnerabilities",
        489: "Risks of IKEV2: Man-in-the-middle attacks, IKEv2 vulnerabilities, Denial-of-service attacks",
        497: "Risks of DANTZ: Unauthorized access, Data theft, Denial-of-service attacks",
        514: "Risks of SYSLOG: Unauthorized access, Log injection, Log tampering",
        560: "Risks of RMonitor: Unauthorized access, Data theft, Denial-of-service attacks",
        691: "Risks of Microsoft exchange: Unauthorized access, Data theft, Denial-of-service attacks",
        873: "Risks of RSYNC: Unauthorized access, Data theft, Denial-of-service attacks",
        902: "Risks of VMware server: Unauthorized access, Data theft, Denial-of-service attacks",
        989: "Risks of FTPS over TLS/SSL: Insecure data transmission, Man-in-the-middle attacks, SSL/TLS vulnerabilities",
        993: "Risks of IMAPS over SSL/TLS: Insecure data transmission, Man-in-the-middle attacks, SSL/TLS vulnerabilities",
        995: "Risks of POP3 over TLS/SSL: Insecure data transmission, Man-in-the-middle attacks, SSL/TLS vulnerabilities",
        1025:"Risks of Microsoft RPC: Unauthorized access, Data theft, Denial-of-service attacks",
        1080:"Risks of SOCKS Proxy: Unauthorized access, Data theft, Denial-of-service attacks",
        1194:"Risks of Open VPN: Insecure data transmission, Man-in-the-middle attacks, VPN vulnerabilities",
        3306:"Risks of MySQL: Unauthorized access, SQL injection, Data theft",
        3389:"Risks of RDP MS terminal server: Unauthorized access, Data theft, Denial-of-service attacks",
        5432:"Risks of Postgre SQL: Unauthorized access, SQL injection, Data theft",
        8080:"Risks of HTTP Proxy: Insecure data transmission, Man-in-the-middle attacks, Cross-site scripting (XSS)"
    }

port_mitigation = {
    21: "Mitigation of FTP: Disable anonymous FTP access, Use strong passwords, Enable encryption",
    22: "Mitigation of SSH: Implement strong password policy, Patch vulnerabilities in SSH daemon, Use SSH keys for authentication",
    23: "Mitigation of TELNET: Disable TELNET service, Use SSH instead, Implement strong password policy",
    25: "Mitigation of SMTP: Implement spam filtering, Implement DMARC, Implement SPF",
    53: "Mitigation of DNS: Implement DNSSEC, Implement DNS filtering, Implement DNSSEC validation",
    69: "Mitigation of TFTP: Implement strong password policy, Enable encryption, Implement TFTP server",
    80: "Mitigation of HTTP: Implement HTTPS, Implement HSTS, Implement CSP",
    110: "Mitigation of POP3: Implement strong password policy, Enable encryption, Implement POP3 server",
    123: "Mitigation of NTP: Implement strong password policy, Enable encryption, Implement NTP server",
    143: "Mitigation of IMAP: Implement strong password policy, Enable encryption, Implement IMAP server",
    163: "Mitigation of SNMP VIEWS: Implement strong password policy, Enable encryption, Implement SNMP server",
    179: "Mitigation of BGP: Implement strong password policy, Enable encryption, Implement BGP server",
    264: "Mitigation of BGMP: Implement strong password policy, Enable encryption, Implement BGMP server",
    389: "Mitigation of IDAP: Implement strong password policy, Enable encryption, Implement IDAP server",
    427: "Mitigation of SLP: Implement strong password policy, Enable encryption, Implement SLP server",
    443: "Mitigation of HTTPS: Implement HTTPS, Implement HSTS, Implement CSP",
    445: "Mitigation of MS DS SMB: Implement strong password policy, Enable encryption, Implement SMB server",
    465: "Mitigation of SMTP over SSL/TLS: Implement SMTP over SSL/TLS, Implement DMARC, Implement SPF",
    489: "Mitigation of IKEV2: Implement strong password policy, Enable encryption, Implement IKEV2 server",
    497: "Mitigation of DANTZ: Implement strong password policy, Enable encryption, Implement DANTZ server",
    514: "Mitigation of SYSLOG: Implement strong password policy, Enable encryption, Implement SYSLOG server",
    560: "Mitigation of RMonitor: Implement strong password policy, Enable encryption, Implement RMonitor server",
    691: "Mitigation of Microsoft exchange: Implement strong password policy, Enable encryption, Implement Microsoft exchange server",
    873: "Mitigation of RSYNC: Implement strong password policy, Enable encryption, Implement RSYNC server",
    902: "Mitigation of VMware server: Implement strong password policy, Enable encryption, Implement VMware server",
    989: "Mitigation of FTPS over TLS/SSL: Implement FTPS over TLS/SSL, Implement strong password policy, Enable encryption",
    993: "Mitigation of IMAPS over SSL/TLS: Implement IMAPS over SSL/TLS, Implement strong password policy, Enable encryption",
    995: "Mitigation of POP3 over TLS/SSL: Implement POP3 over TLS/SSL, Implement strong password policy, Enable encryption",
    1025: "Mitigation of Microsoft RPC: Implement strong password policy, Enable encryption, Implement Microsoft RPC server",
    1080: "Mitigation of SOCKS Proxy: Implement strong password policy, Enable encryption, Implement SOCKS Proxy server",
    1194: "Mitigation of Open VPN: Implement Open VPN, Implement strong password policy, Enable encryption",
    3306: "Mitigation of MySQL: Implement strong password policy, Enable encryption, Implement MySQL server",
    3389: "Mitigation of RDP MS terminal server: Implement strong password policy, Enable encryption, Implement RDP MS terminal server",
    5432: "Mitigation of Postgre SQL: Implement strong password policy, Enable encryption, Implement Postgre SQL server",
    8080: "Mitigation of HTTP Proxy: Implement HTTP Proxy, Implement strong password policy, Enable encryption"
}

port_rate = {
    21: 2, 22: 3, 23: 4, 25: 4, 53: 2, 69: 5, 80: 3, 110: 2, 123: 3, 
    143: 3, 163: 2, 179: 4, 264: 4, 389: 3, 427: 3, 443: 3, 445: 3, 
    465: 3, 489: 3, 514: 2, 560: 3, 691: 3, 873: 3, 902: 2, 989: 3, 
    993: 3, 995: 3, 1025: 3, 1080: 3, 1194: 3, 3306: 2, 3389: 3, 
    5432: 2, 8080: 2
}

scan_results = []

def display_open_ports(open_ports, target_ip, current_datetime, hostname, mac_address):
    result_text.config(state="normal")
    result_text.delete("1.0")
    if hostname:
        result_text.insert(tk.END, f"Started scan on {target_ip} ({hostname}) at {current_datetime}\nMAC address: {mac_address}\n")
    else:
        result_text.insert(tk.END, f"Started scan on {target_ip} at {current_datetime}\nMAC address: {mac_address}\n")

    for port in open_ports:
        service_name = service_names.get(port, "Unknown")
        result_text.insert(tk.END, f"Discovered Open port {port}: {service_name}\n")

    result_text.config(state="disabled")

    scan_results.append({
    'target_ip': target_ip,
    'current_datetime': current_datetime,
    'mac_address': mac_address,
    'hostname': hostname,  
    'open_ports': open_ports  
})

    open_ports = scan_all_ports(target_ip)

# Save results to PDF file
def save_pdf():
    if not validate_input():
        return

    target_ip = target_ip_entry.get()
    open_ports = scan_all_ports(target_ip)
    hostname = get_hostname_from_ip(target_ip)
    current_datetime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    mac_address = get_mac_from_ip(target_ip)
    file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF format", "*.pdf"), ("HTML format", "*.html"), ("CSV format", "*.csv"), ("JSON format", "*.json")])

    if file_path:
        file_format = file_path.split(".")[-1]

        if file_format == "pdf":
            pdf = FPDF()
            pdf.set_auto_page_break(True)
            pdf.add_page()
            pdf.set_font("Arial", size=15, style="B")
            pdf.cell(200, 10, txt=f"Netmap Scan Report for {target_ip}", ln=True, align="C")
            pdf.ln(10)
            pdf.set_font("Arial", size=10)
            pdf.cell(200, 10, txt=f"Started scan on {target_ip} at {current_datetime}", ln=True, align="L")
            for port in open_ports:
                service_name = service_names.get(port, "Unknown")
                pdf.cell(200, 10, txt=f"Discovered Open port {port}: {service_name}", ln=True, align="L")

            pdf.ln(10)
            pdf.set_font("Arial", size=10, style="B")
            pdf.cell(200, 10, txt="Risks associated with open ports:", ln=True, align="L")

            for port in open_ports:
                if port in port_risks:
                    pdf.set_font("Arial", size=10)
                    pdf.cell(200, 10, txt=f"Port {port}: {port_risks[port]}", ln=True, align="L")

            pdf.ln(10)
            pdf.set_font("Arial", size=10, style="B")
            pdf.cell(200, 10, txt="Mitigation for open ports:", ln=True, align="L")
            pdf.ln(5)
            pdf.set_font("Arial", size=10, style="I")
            pdf.cell(200, 10, txt="These are general mitigations and you would need a comprehensive analysis of open ports and risks associated with it", ln=True, align="L")
            pdf.ln(5)
            for port in open_ports:
                if port in port_mitigation:
                    pdf.set_font("Arial", size=10)
                    pdf.cell(200, 10, txt=f"Port {port}: {port_mitigation[port]}", ln=True, align="L")

            pdf.add_page()
            pdf.set_font("Arial", size=15, style="B")
            pdf.cell(200, 10, txt="Heatmap of Port Risks", ln=True, align="C")
            pdf.ln(10)

            pivot_table = pd.DataFrame(port_rate.items(), columns=['Port', 'Risk']).pivot_table(values='Risk', index='Port', aggfunc='sum')

            # Create the heatmap
            plt.figure(figsize=(10, 10))
            sns.heatmap(pivot_table, annot=True, fmt="d", cmap='RdYlGn')
            plt.title('Heatmap of Port Risks')
            plt.tight_layout()
            plt.savefig("heatmap.png")
            plt.close()

            # Add the heatmap to the PDF
            pdf.image("heatmap.png", x=10, y=10, w=190, h=190)

            pdf.output(file_path, "F")
            print(f"Scan results saved to {file_path}")
            msgbox.showinfo("Success!!!!", "\nScan results have been successfully saved.")

        elif file_format == "html":
            # HTML report generation 
            html_report = f"<html><body><h1>Netmap Scan Report for {target_ip}</h1><p>Started scan on {target_ip} at {current_datetime}</p><table><tr><th>Port</th><th>Service</th></tr>"
            for port in open_ports:
                service_name = service_names.get(port, "Unknown")
                html_report += f"<tr><td>Open {port}</td><td>{service_name}</td></tr>"
            html_report += "</table></body></html>"
            with open(file_path, "w") as html_file:
                html_file.write(html_report)
            print(f"Scan results saved to {file_path}")
            msgbox.showinfo("Success!!!!", "\nScan results have been successfully saved.")

        elif file_format == "csv":
            # CSV report generation
            csv_report = "Port,Service\n"
            for port in open_ports:
                service_name = service_names.get(port, "Unknown")
                csv_report += f"{port},{service_name}\n"
            with open(file_path, "w") as csv_file:
                csv_file.write(csv_report)
            print(f"Scan results saved to {file_path}")
            msgbox.showinfo("Success!!!!", "\nScan results have been successfully saved.")

        elif file_format == "json":
            # JSON report generation 
            json_report = {"target_ip": target_ip, "open_ports": []}
            for port in open_ports:
                service_name = service_names.get(port, "Unknown")
                json_report["open_ports"].append({"port": port, "service": service_name})
            with open(file_path, "w") as json_file:
                json.dump(json_report, json_file, indent=4)
            print(f"Scan results saved to {file_path}")
            msgbox.showinfo("Success!!!!", "\nScan results have been successfully saved.")

        else:
            print("Invalid file format selected.")


def display_risks(open_ports):
    result_text.config(state="normal")
    result_text.insert(tk.END, "\nRisks associated with open ports:\n")

    for port in open_ports:
        if port in port_risks:
            result_text.insert(tk.END, f"Port {port}: {port_risks[port]}\n")

    result_text.config(state="disabled")

     # Save risks to PDF file
    file_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
    if file_path:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=10)
        pdf.cell(200, 10, txt="Risks associated with open ports:", ln=True, align="L")
        for port in open_ports:
            if port in port_risks:
                pdf.cell(200, 10, txt=f"Port {port}: {port_risks[port]}", ln=True, align="L")
        pdf.output(file_path, "F")
        print(f"Scan risks saved to {file_path}")

def scan_port_threaded(port, target_ip, open_ports, lock):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    
    try:
        sock.connect((target_ip, port))
        print(f"Discovered open port {port} on {target_ip}")
        with lock:
            open_ports.append((port))
    except socket.timeout:
        print(f"Timeout connecting to {target_ip}:{port}")
    except socket.error as e:
        print(f"Error connecting to {target_ip}:{port}: {e}")
    finally:
        sock.close()

def scan_all_ports(target_ip):
    open_ports = []
    lock = threading.Lock()

    threads = []
    for port in range(1, 9000):
        t = threading.Thread(target=scan_port_threaded, args=(port, target_ip, open_ports, lock))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    return open_ports

def generate_heatmap(open_ports):
    # Create a DataFrame from the open_ports list
    df = pd.DataFrame(open_ports, columns=['Port', 'Severity'])

    # Create a pivot table
    pivot_table = df.pivot_table(values='Severity', index='Port', aggfunc='sum')

    # Create a heatmap
    plt.figure(figsize=(10, 10))
    sns.heatmap(pivot_table, annot=True, fmt="d", cmap='RdYlGn')
    plt.title('Heatmap of Open Ports on')
    plt.tight_layout()
    plt.show()

class ProgressBar(ttk.Frame):
    def __init__(self, master, **kwargs):
        ttk.Frame.__init__(self, master, **kwargs)
        self.progress_bar = ttk.Progressbar(self, orient="horizontal", length=200, mode="determinate")
        self.progress_bar.pack(fill="x", expand=True)
        self.progress_bar_label = ttk.Label(self, text="")
        self.progress_bar_label.pack(fill="x", expand=True)

    def set_progress(self, value):
        self.progress_bar['value'] = value

    def set_label(self, text):
        self.progress_bar_label['text'] = text

class StatusLabel(ttk.Label):
    def __init__(self, master, **kwargs):
        ttk.Label.__init__(self, master, **kwargs)
        self['text'] = ""

    def set_text(self, text):
        self['text'] = text

def get_hostname_from_ip(target_ip):
    try:
        hostname = socket.gethostbyaddr(target_ip)[0]
        return hostname
    except socket.herror:
        return None

def get_ip_from_url(url):
    try:
        url_parts = url.split(":")
        hostname = url_parts[0]
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror as e:
        print(f"Error resolving hostname {hostname}: {e}")
        return None

def validate_input():
    target_ip = target_ip_entry.get()
    if not target_ip:
        msgbox.showerror("Error", "Please enter a valid IP address or URL.")
        return False
    return True

def get_mac_from_ip(ip):
    mac = getmac.get_mac_address(ip=ip)
    return mac

def open_cli_mode():
    command = f'start cmd /k "cd ENTER YOUR FILE PATH && python cli.py"'
    os.system(command)

def start_scan():
    if not validate_input():
        return
    
    target_ip = target_ip_entry.get()
    
    if not target_ip:
        print("Please enter a valid IP address.")
        return
    
    # Check if target_ip is a URL
    if target_ip.startswith("http://") or target_ip.startswith("https://"):
        target_ip = get_ip_from_url(target_ip)

    if not target_ip:
        print("Please enter a valid IP address or URL.")
        return

    # Disable UI elements
    enable_ui(False)

    # Clear previous results
    result_text.delete("1.0", tk.END)

    # Create progress bar 
    progress_bar = ProgressBar(window)
    progress_bar.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="w")
    status_label = StatusLabel(window)
    status_label.grid(row=3, column=0, columnspan=2, padx=10, pady=10, sticky="w")

    # Get current date and time
    current_datetime = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Get the MAC address from the IP address
    mac_address = get_mac_from_ip(target_ip)
    result_text.insert(tk.END, f"MAC Address: {mac_address}\n")


    # Get the hostname from the IP address
    hostname = get_hostname_from_ip(target_ip)
    if hostname:
        result_text.insert(tk.END, f"Hostname: {hostname}\n")

    # Start scan
    print(f"Started scan of {target_ip} at {current_datetime}...")

    # Start scan in a separate thread
    threading.Thread(target=lambda: scan_and_update_gui(target_ip, current_datetime, progress_bar, mac_address), daemon=True).start()

def scan_and_update_gui(target_ip, current_datetime, progress_bar, mac_address):
    open_ports = scan_all_ports(target_ip)

    # Update progress bar
    progress_bar.set_label("Scanning...")
    progress_bar.set_progress(0)
    for port in range(1, 9000):
        progress_bar.set_progress(int((port / 9000) * 100))

    # Display results
    hostname = get_hostname_from_ip(target_ip)
    display_open_ports(open_ports, target_ip, current_datetime, hostname, mac_address)

    # Update progress bar
    progress_bar.set_label("Scan complete!")
    progress_bar.set_progress(100)

def show_history(scan_results):
    history_window = tk.Toplevel(window)
    history_window.title("Scan Results History")

    history_text = tk.Text(history_window, height=15, width=40)
    history_text.pack(fill="both", expand=True)

    for result in scan_results:
        history_text.insert(tk.END, f"Scan on {result['target_ip']} ({result['hostname']}) at {result['current_datetime']}\n")
        for port in result["open_ports"]:
            service_name = service_names.get(port, "Unknown")
            history_text.insert(tk.END, f"  Discovered Open port {port}: {service_name}\n")
        history_text.insert(tk.END, "\n")

    history_text.config(state="disabled")

def new_scan():
    # Clear the previous scan results
    result_text.delete("1.0", tk.END)

    # Clear the target IP entry
    target_ip_entry.delete(0, tk.END)

    # Enable the UI elements
    enable_ui(True)

def open_scan():
    file_path = filedialog.askopenfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])

    if file_path:
        with open(file_path, "r") as file:
            scan_results = file.read()

        result_text.delete("1.0", tk.END)
        result_text.insert(tk.END, scan_results)

        # Disable the UI elements
        enable_ui(False)


def enable_ui(enable):
    target_ip_entry.config(state="normal" if enable else "disabled")
    scan_button.config(state="normal")

# Create GUI
window = tk.Tk()
window.title("Port Scanner")
window.resizable(True, True)  

ttk.Style().theme_use("xpnative")

# Set the window background color
window.configure(bg="#F5F5F5")

image = Image.open("ENTER FILE PATH")
image_icon = ImageTk.PhotoImage(image)
window.iconphoto(False, image_icon)

window.title("Netmap")

menu_bar = Menu(window)

file_menu = Menu(menu_bar, tearoff=0)
file_menu.add_command(label="New", command=new_scan) 
file_menu.add_command(label="Open", command=open_scan)
file_menu.add_command(label="Logout", command=lambda: logout_confirmation(window))

def logout_confirmation(window):
    if msgbox.askyesno("Logout", "Are you sure you want to log out? All unsaved data will be lost."):
        window.destroy()
        sys.exit() 

menu_bar.add_cascade(label="Options", menu=file_menu)

window.config(menu=menu_bar)

# Frame for input fields
input_frame = ttk.LabelFrame(window, text="Target IP", padding=(10, 5, 10, 5))
input_frame.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

target_ip_label = ttk.Label(input_frame, text="Enter the target IP address:")
target_ip_label.grid(row=0, column=0, padx=5, pady=5, sticky="w")

target_ip_entry = ttk.Entry(input_frame, width=30)
target_ip_entry.grid(row=0, column=1, padx=5, pady=5, sticky="e")

# Frame for buttons
button_frame = ttk.Frame(window, padding=(5, 5, 5, 5))
button_frame.grid(row=0, column=2, padx=5, pady=5, sticky="nsew")

scan_button = ttk.Button(button_frame, text="Scan", command=start_scan)
scan_button.grid(row=0, column=0, padx=5, pady=5, sticky="w")

save_button = ttk.Button(button_frame, text="Generate Report", command=save_pdf)
save_button.grid(row=0, column=1, padx=5, pady=5, sticky="e")

history_button = ttk.Button(button_frame, text="History", command=lambda: show_history(scan_results))
history_button.grid(row=0, column=2, padx=5, pady=5, sticky="e")

cli_button = ttk.Button(button_frame, text="CLI mode", command=open_cli_mode)
cli_button.grid(row=0, column=3, padx=5, pady=5, sticky="w")

# Frame for results text widget
results_text_frame = ttk.LabelFrame(window, text="Results", padding=(10, 5, 10, 5))
results_text_frame.grid(row=1, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")

result_text = tk.Text(results_text_frame, height=15, width=40)
result_text.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")

scrollbar = tk.Scrollbar(results_text_frame, orient=tk.VERTICAL, command=result_text.yview)
result_text.config(yscrollcommand=scrollbar.set)
scrollbar.grid(row=0, column=1, padx=0, pady=5, sticky="ns")

h_scrollbar = tk.Scrollbar(results_text_frame, orient=tk.HORIZONTAL, command=result_text.xview)
result_text.config(xscrollcommand=h_scrollbar.set)
h_scrollbar.grid(row=1, column=0, padx=5, pady=0, sticky="ew")

# Set the weight attribute for the row and column of results_text_frame
results_text_frame.rowconfigure(0, weight=1)
results_text_frame.columnconfigure(0, weight=1)

# Frame for progress bar and status label
progress_frame = ttk.LabelFrame(window, text="Progress", padding=(10, 5, 10, 5))
progress_frame.grid(row=2, column=0, columnspan=3, padx=5, pady=5, sticky="nsew")

progress_bar = ProgressBar(progress_frame)
progress_bar.grid(row=0, column=0, padx=5, pady=5, sticky="ew")

status_label = StatusLabel(progress_frame)
status_label.grid(row=0, column=1, padx=5, pady=5, sticky="w")

# Make the window resize with its contents
window.rowconfigure(0, weight=1)
window.rowconfigure(1, weight=3)  
window.rowconfigure(2, weight=1)
window.columnconfigure(0, weight=1)
window.columnconfigure(1, weight=1)
window.columnconfigure(2, weight=1)

window.mainloop()
