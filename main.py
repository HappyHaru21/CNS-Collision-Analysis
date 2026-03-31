import tkinter as tk
from tkinter import scrolledtext, filedialog
import random
import math
import time
import threading
import os

class ToyFeistelCipher:
    def __init__(self, block_size_bits=32):
        self.block_size = block_size_bits
        self.half_block = block_size_bits // 2
        self.mask = (1 << self.half_block) - 1
        self.subkeys = []

    def generate_keys(self):
        self.subkeys = [random.getrandbits(self.half_block) for _ in range(8)]
        return self.subkeys

    def _round_function(self, right_half, subkey):
        mixed = (right_half ^ subkey) 
        mixed = (mixed * 3 + 7) & self.mask 
        return (mixed << 1 | mixed >> (self.half_block - 1)) & self.mask

    def encrypt(self, plaintext_int):
        left = (plaintext_int >> self.half_block) & self.mask
        right = plaintext_int & self.mask
        for subkey in self.subkeys:
            temp = right
            right = left ^ self._round_function(right, subkey)
            left = temp
        return (right << self.half_block) | left

class CryptoProjectGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Collision Analysis Tool")
        self.root.geometry("1100x700")
        self.root.configure(bg="#F0F0F0")
        
        self.results_32bit = []
        self.results_128bit = []
        self.payload_path = None

        self.setup_ui()

    def setup_ui(self):
        main_frame = tk.Frame(self.root, bg="#F0F0F0")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Sidebar (Controls)
        sidebar = tk.Frame(main_frame, bg="#FFFFFF", width=250, highlightthickness=1, highlightbackground="#D3D3D3")
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)

        tk.Label(sidebar, text="Controls", font=("Arial", 14, "bold"), bg="#FFFFFF", fg="#333333").pack(pady=(20, 15), padx=15, anchor="w")

        def create_btn(text, cmd):
            btn = tk.Button(sidebar, text=text, command=cmd, bg="#E8E8E8", fg="#000000",
                            font=("Arial", 10), relief=tk.FLAT, bd=1, pady=8, cursor="hand2", anchor="w", padx=15)
            btn.pack(fill=tk.X, padx=15, pady=5)
            btn.bind("<Enter>", lambda e, b=btn: b.config(bg="#D0D0D0"))
            btn.bind("<Leave>", lambda e, b=btn: b.config(bg="#E8E8E8"))
            return btn

        self.btn_file = create_btn("Load Payload", self.load_payload)
        self.btn_keys = create_btn("Generate Keys", self.generate_keys)
        
        tk.Frame(sidebar, bg="#E0E0E0", height=1).pack(fill=tk.X, padx=15, pady=10) 
        
        self.btn_attack = create_btn("Run 32-bit Test", lambda: self.start_batch_thread(32))
        self.btn_prevent = create_btn("Run 128-bit Test", lambda: self.start_batch_thread(128))

        tk.Frame(sidebar, bg="#E0E0E0", height=1).pack(fill=tk.X, padx=15, pady=10) 
        
        self.btn_graphs = create_btn("Show Telemetry Graphs", self.show_graphs)
        self.btn_graphs.config(state=tk.DISABLED)

        # Status Display
        status_frame = tk.Frame(sidebar, bg="#FFFFFF")
        status_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=15, pady=20)
        tk.Label(status_frame, text="Status:", font=("Arial", 9), bg="#FFFFFF", fg="#666666").pack(anchor="w")
        self.status_label = tk.Label(status_frame, text="Ready", font=("Arial", 10, "bold"), bg="#FFFFFF", fg="#000000")
        self.status_label.pack(anchor="w")

        # Main Content (Log)
        content = tk.Frame(main_frame, bg="#F0F0F0", padx=20, pady=20)
        content.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        tk.Label(content, text="Output Log", bg="#F0F0F0", fg="#333333", font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 5))
        
        self.log_area = scrolledtext.ScrolledText(content, wrap=tk.WORD, font=("Consolas", 10), 
                                                  bg="#FFFFFF", fg="#000000", relief=tk.SOLID, bd=1,
                                                  padx=10, pady=10)
        self.log_area.pack(fill=tk.BOTH, expand=True)

        self.log_area.tag_config('info', foreground='#000000') 
        self.log_area.tag_config('error', foreground='#CC0000') 
        self.log_area.tag_config('success', foreground='#006600') 

    def log(self, message, tag="info"):
        self.root.after(0, self._safe_log, message, tag)

    def _safe_log(self, message, tag):
        self.log_area.insert(tk.END, message + "\n", tag)
        self.log_area.see(tk.END)

    def set_status(self, text, color="#000000"):
        self.status_label.config(text=text, fg=color)

    def load_payload(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            if os.path.getsize(file_path) > 0:
                self.payload_path = file_path
                self.log(f"Payload loaded: {os.path.basename(file_path)} ({os.path.getsize(file_path)} bytes)", "success")
            else:
                self.log("Selected file is empty. Engine will default to PRNG.", "error")

    def generate_keys(self):
        self.set_status("Generating Keys...", "#0000CC")
        self.log("\nGenerating subkeys for both architectures...", "info")
        
        # 32-bit architecture keys (16-bit subkeys)
        self.log("\n[32-bit Architecture Keys]:", "info")
        temp_cipher_32 = ToyFeistelCipher(32)
        keys_32 = temp_cipher_32.generate_keys()
        for i, k in enumerate(keys_32):
            self.log(f"  Round {i+1} Key: 0x{k:04x}", "info")
            
        # 128-bit architecture keys (64-bit subkeys)
        self.log("\n[128-bit Architecture Keys]:", "info")
        temp_cipher_128 = ToyFeistelCipher(128)
        keys_128 = temp_cipher_128.generate_keys()
        for i, k in enumerate(keys_128):
            self.log(f"  Round {i+1} Key: 0x{k:016x}", "info")
            
        self.log("\nKeys generated successfully in memory.", "success")
        self.set_status("Keys Ready", "#006600")

    def start_batch_thread(self, block_size):
        self.btn_attack.config(state=tk.DISABLED)
        self.btn_prevent.config(state=tk.DISABLED)
        self.set_status(f"Testing {block_size}-bit...", "#CC6600")
        threading.Thread(target=self.run_batch_test, args=(block_size,), daemon=True).start()

    def calculate_theoretical_probability(self, blocks_captured, block_size_bits):
        N = 2 ** block_size_bits
        try:
            prob = 1 - math.exp(-((blocks_captured ** 2) / (2 * N)))
            return prob * 100
        except OverflowError:
            return 100.0

    def run_batch_test(self, block_size):
        num_tests = 20
        bytes_per_block = block_size // 8

        self.log(f"\nStarting {num_tests} tests for {block_size}-bit architecture.")
        
        if block_size == 32:
            self.results_32bit = []
            target_blocks = 65536
        else:
            self.results_128bit = []
            target_blocks = 50000 

        theo_prob = self.calculate_theoretical_probability(target_blocks, block_size)
        self.log(f"Theoretical collision probability at {target_blocks} blocks: {theo_prob:.4f}%")

        cipher = ToyFeistelCipher(block_size)
        cipher.generate_keys()
        
        limit = 100000 if block_size == 32 else 50000

        for test_idx in range(1, num_tests + 1):
            seen_ciphertexts = set()
            prev_ciphertext = random.getrandbits(block_size)
            collision_found = False
            blocks_generated = 0
            start_time = time.time()
            
            if self.payload_path:
                file_source = open(self.payload_path, 'rb')
            else:
                file_source = None

            while blocks_generated < limit:
                blocks_generated += 1
                
                if file_source:
                    chunk = file_source.read(bytes_per_block)
                    if len(chunk) < bytes_per_block:
                        file_source.seek(0)
                        chunk += file_source.read(bytes_per_block - len(chunk))
                    plaintext = int.from_bytes(chunk, 'big')
                else:
                    plaintext = random.getrandbits(block_size)

                xor_input = plaintext ^ prev_ciphertext
                ciphertext = cipher.encrypt(xor_input)
                
                if ciphertext in seen_ciphertexts:
                    latency = time.time() - start_time
                    self.log(f"Test {test_idx}: Collision at block {blocks_generated} ({latency:.4f}s)", "error")
                    if block_size == 32:
                        self.results_32bit.append((blocks_generated, latency, True))
                    collision_found = True
                    break
                    
                seen_ciphertexts.add(ciphertext)
                prev_ciphertext = ciphertext
            
            if file_source:
                file_source.close()

            if not collision_found:
                latency = time.time() - start_time
                self.log(f"Test {test_idx}: No collisions after {limit} blocks.", "success")
                if block_size == 128:
                    self.results_128bit.append((blocks_generated, latency, False))

        self.log("Batch execution finished.")
        
        self.root.after(0, lambda: self.btn_attack.config(state=tk.NORMAL))
        self.root.after(0, lambda: self.btn_prevent.config(state=tk.NORMAL))
        self.root.after(0, lambda: self.btn_graphs.config(state=tk.NORMAL))
        self.root.after(0, lambda: self.set_status("Test Complete", "#006600"))

    def show_graphs(self):
        if not self.results_32bit or not self.results_128bit:
            self.log("Error: Must run both 32-bit and 128-bit tests before generating graphs.", "error")
            return

        self.log("\nGenerating graphs in external window...", "info")
        
        import matplotlib.pyplot as plt
        
        plt.style.use('default')
        
        tests_32 = len(self.results_32bit)
        tests_128 = len(self.results_128bit)

        collisions_32 = sum(1 for r in self.results_32bit if r[2])
        success_rate_32 = (collisions_32 / tests_32) * 100
        success_rate_128 = 0 
        
        confidentiality_32 = 100 - success_rate_32
        confidentiality_128 = 100 - success_rate_128

        avg_time_32 = sum(r[1] for r in self.results_32bit) / tests_32
        avg_time_128 = sum(r[1] for r in self.results_128bit) / tests_128

        total_time_32 = sum(r[1] for r in self.results_32bit)
        total_blocks_32 = sum(r[0] for r in self.results_32bit)
        latency_10k_32 = (total_time_32 / total_blocks_32) * 10000

        total_time_128 = sum(r[1] for r in self.results_128bit)
        total_blocks_128 = sum(r[0] for r in self.results_128bit)
        latency_10k_128 = (total_time_128 / total_blocks_128) * 10000

        fig, axs = plt.subplots(2, 2, figsize=(10, 7))
        fig.canvas.manager.set_window_title('Telemetry Data')
        fig.suptitle('Block Size Analysis Results', fontsize=14)

        axs[0, 0].bar(['32-bit', '128-bit'], [success_rate_32, success_rate_128], color=['#CC0000', '#006600'])
        axs[0, 0].set_title('Collision Rate (%)', fontsize=10)
        axs[0, 0].set_ylim(0, 100)

        axs[0, 1].plot([32, 128], [avg_time_32, avg_time_128], marker='o', color='#0033CC')
        axs[0, 1].set_title('Avg Execution Time (s)', fontsize=10)
        axs[0, 1].set_xticks([32, 128])

        axs[1, 0].bar(['32-bit', '128-bit'], [confidentiality_32, confidentiality_128], color=['#CC0000', '#006600'])
        axs[1, 0].set_title('Security Integrity (%)', fontsize=10)
        axs[1, 0].set_ylim(0, 100)

        axs[1, 1].bar(['32-bit', '128-bit'], [latency_10k_32, latency_10k_128], color=['#666666', '#333333'])
        axs[1, 1].set_title('Latency (per 10k blocks)', fontsize=10)

        plt.tight_layout()
        plt.show()

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoProjectGUI(root)
    root.mainloop()