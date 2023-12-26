import tkinter as tk
from tkinter import ttk, filedialog, simpledialog
import hashlib
import os
import magic
import time
import datetime
import re
import psutil
import scapy.all as scapy


class forensictoolkit:

    def __init__(self, home):
        self.home = home
        home.title("Sasith's Forensic Tool Kit")
        self.create_buttons()

        style = ttk.Style()
        style.configure("TButton", padding=6, relief="flat", background="#98d1ce")
        style.configure("TLabel", padding=6, relief="flat", background="#f0f0f0")

    def create_buttons(self):

        buttons = [
            ("Calculate MD5 Hash", self.calculate_md5_hashvalue),
            ("Check File Integrity", self.check_integrity),
            ("Get File Metadata", self.get_file_metadata),
            ("Identify File Type", self.identify_file_type),
            ("Keyword Search", self.keyword_search),
            ("Network Packet Capture", self.open_network_packet_capture_window)
        ]

        buttons_frame = ttk.Frame(self.home, padding=(20, 10))
        buttons_frame.grid(row=0, column=0, sticky="nsew")

        ttk.Label(buttons_frame, text="Forensic Tasks", style="TLabel").grid(row=0, column=0, pady=10)

        for i, (text, command) in enumerate(buttons, start=0):
            ttk.Button(buttons_frame, text=text, command=command).grid(row=i, column=0, pady=5)

    def calculate_md5_hashvalue(self):
        file_path = self.browse_file()
        md5_hash_value = hashlib.md5()
        with open(file_path, "rb") as file:
            file_content = file.read() # explain this - why not gone with chunks.
        md5_hash_value.update(file_content)
        result = md5_hash_value.hexdigest()
        self.show_result("MD5 Hash is:", result)

    def check_integrity(self):
        file_path = self.browse_file()
        if file_path:
            md5_hash = self.calculate_file_md5(file_path) # mention seperate isolation 
            stored_hash = self.show_input_dialog("Enter the expected MD5 hash:")

            if md5_hash == stored_hash:
                self.show_result("File integrity check passed!")
            else:
                self.show_result("File integrity check failed!")

    def show_input_dialog(self, prompt):
        user_input = simpledialog.askstring("Input", prompt)
        return user_input

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        return file_path

    def calculate_file_md5(self, file_path):
        md5_hash = hashlib.md5()
        with open(file_path, "rb") as file:
            file_content = file.read()
            md5_hash.update(file_content)
        return md5_hash.hexdigest()

    def show_result(self, title, result=None):
        result_window = tk.Toplevel(self.home)
        tk.Label(result_window, text=title).pack(padx=10, pady=5)
        if result is not None:
            tk.Label(result_window, text=result).pack(padx=10, pady=5)

    def get_file_metadata(self):
        file_path = self.browse_file()
        basename = os.path.basename(file_path)
        getsize = os.path.getsize(file_path)
        getmtime = os.path.getmtime(file_path)
        getctime = os.path.getctime(file_path)

        time1 = time.ctime(getmtime)
        time1 = datetime.datetime.strptime(time1, "%a %b %d %H:%M:%S %Y")

        metadata = {

            "File Name": basename,
            "File Size (Bytes)": getsize,
            "Last Modified": time1.strftime('%Y-%m-%d %H:%M:%S'),
            "Creation Time": datetime.datetime.fromtimestamp(getctime).strftime('%Y-%m-%d %H:%M:%S'),
        }

        self.show_result("File Metadata:", metadata)

    def identify_file_type(self):
        file_path = self.browse_file()
        try:
            file_type = magic.Magic()
            detected_type = file_type.from_file(file_path)
            self.show_result("File Type Identification", f"File type is {detected_type}")
        except magic.MagicException as e:
            self.show_result("Error", f"Failed to identify file type: {e}")

    def keyword_search(self):
        keyword = simpledialog.askstring("Keyword Search", "Enter the keyword to search:")
        path = self.browse_file()  # Allow the user to select file or folder
        result = self.keyword_search_function(keyword, path)
        self.show_result(f"Occurrences of '{keyword}' in '{path}': {result['count']} times\n", result['sentences'])

    def keyword_search_function(self, keyword, path):
        result = {'count': 0, 'sentences': []}

        if os.path.isfile(path):
            # Search in a single file
            with open(path, 'r', errors='ignore') as file:
                content = file.read()
                matches = re.findall(fr'\b{re.escape(keyword)}\b', content, flags=re.IGNORECASE)
                result['count'] = len(matches)
                result['sentences'] = [sentence.strip() for sentence in
                                       re.split(r'(?<!\w\.\w.)(?<![A-Z][a-z]\.)(?<=\.|\?)\s', content) if
                                       keyword.lower() in sentence.lower()]
                
        elif os.path.isdir(path):
            # Search in all files within a folder
            for root, _, files in os.walk(path):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    with open(file_path, 'r', errors='ignore') as file:
                        content = file.read()
                        matches = re.findall(fr'\b{re.escape(keyword)}\b', content, flags=re.IGNORECASE)
                        result['count'] += len(matches)
                        result['sentences'] += [sentence.strip() for sentence in
                                               re.split(r'(?<!\w\.\w.)(?<![A-Z][a-z]\.)(?<=\.|\?)\s', content) if
                                               keyword.lower() in sentence.lower()]

        return result

    def open_network_packet_capture_window(self):
        network_capture_window = tk.Toplevel(self.home)
        network_capture_window.title("Network Packet Capture")

        ttk.Label(network_capture_window, text="Select Network Interface:").pack(pady=2)

        interface_var = tk.StringVar()
        interface_combobox = ttk.Combobox(network_capture_window, textvariable=interface_var, state="readonly")
        interface_combobox.pack(pady=5)
        self.update_interface_list(interface_combobox)

        ttk.Button(network_capture_window, text="Start Live Packet Capture", command=lambda: self.start_sniffing(interface_var)).pack(pady=10)
        ttk.Button(network_capture_window, text="Save Packet Capture", command=lambda: self.save_packets(interface_var)).pack(pady=10)

    def update_interface_list(self, combobox):
        interfaces = list(psutil.net_if_addrs().keys())
        combobox['values'] = interfaces
        if interfaces:
            combobox.set(interfaces[0])

    def start_sniffing(self, interface_var):
        interface = interface_var.get()
        count = int(simpledialog.askstring("Packet Count", "Enter the number of packets to sniff:"))
        packets = self.sniff_packets(interface, count)
        self.analyze_packets(packets)

    def sniff_packets(self, interface, count):
        print(f"\n[*] Sniffing {count} packets on interface {interface}...\n")
        packets = scapy.sniff(iface=interface, count=count)
        return packets

    def analyze_packets(self, packets):
        for packet in packets:
            self.print_packet_info(packet)

    def print_packet_info(self, packet):
        print(f"\n[+] Captured Packet:")
        print(packet.show())

    def save_packets(self, interface_var):
        interface = interface_var.get()
        count = int(simpledialog.askstring("Packet Count", "Enter the number of packets to sniff:"))
        output_file = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
        if output_file:
            packets = self.sniff_packets(interface, count)
            print(f"\n[*] Saving packets to {output_file}...\n")
            scapy.wrpcap(output_file, packets)
            print("Packet Capture Completed and File is Saved")

if __name__ == "__main__":
    root = tk.Tk()
    app = forensictoolkit(root)
    root.mainloop()