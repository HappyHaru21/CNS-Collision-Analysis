import tkinter as tk
from tkinter import scrolledtext, filedialog
import random
import math
import time
import threading
import os
import matplotlib.pyplot as plt

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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
        return ((mixed << 1) | (mixed >> (self.half_block - 1))) & self.mask

    def encrypt(self, plaintext_int):
        left = (plaintext_int >> self.half_block) & self.mask
        right = plaintext_int & self.mask

        for subkey in self.subkeys:
            temp = right
            right = left ^ self._round_function(right, subkey)
            left = temp

        return (right << self.half_block) | left

class Speck32Cipher:
    def __init__(self):
        self.block_size_bits = 32
        self.keys = []

    def ROR(self, x, r):
        return ((x >> r) | (x << (16 - r))) & 0xFFFF

    def ROL(self, x, r):
        return ((x << r) | (x >> (16 - r))) & 0xFFFF

    def generate_keys(self):
        key = [random.getrandbits(16) for _ in range(4)]
        l_list = [key[1], key[2], key[3]]
        k = key[0]
        self.keys = [k]
        for i in range(21):
            new_l = (self.ROR(l_list[0], 7) + k) & 0xFFFF
            new_l ^= i
            k = self.ROL(k, 2) ^ new_l
            self.keys.append(k)
            l_list = l_list[1:] + [new_l]
        return self.keys

    def encrypt(self, plaintext_int):
        x = (plaintext_int >> 16) & 0xFFFF
        y = plaintext_int & 0xFFFF
        for k in self.keys:
            x = (self.ROR(x, 7) + y) & 0xFFFF
            x ^= k
            y = self.ROL(y, 2) ^ x
        return (x << 16) | y

class AES128Cipher:
    def __init__(self):
        self.block_size_bits = 128
        self.block_size_bytes = 16
        self.key = os.urandom(16)

    def generate_keys(self):
        self.key = os.urandom(16)
        return self.key

    def encrypt_block_ecb(self, plaintext_block_bytes):
        cipher = Cipher(algorithms.AES(self.key), modes.ECB())
        encryptor = cipher.encryptor()
        return encryptor.update(plaintext_block_bytes) + encryptor.finalize()

class ChaCha20Cipher:
    def __init__(self):
        self.key = os.urandom(32)
        self.nonce = os.urandom(16)

    def generate_keys(self):
        self.key = os.urandom(32)
        self.nonce = os.urandom(16)
        return self.key, self.nonce

class CryptoProjectGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Collision Analysis Framework | The Golden 6")
        self.root.geometry("1400x850")
        self.root.configure(bg="#F0F0F0")

        self.payload_path = None

        self.all_results = {
            "Toy Feistel (32-bit CBC)": [],
            "Speck-32 ARX (32-bit CBC)": [],
            "Toy Feistel (32-bit CTR)": [],
            "Toy Feistel (32-bit CBC + Rekey)": [],
            "AES-128 CBC": [],
            "ChaCha20 (Stream)": []
        }

        self.setup_ui()

    def setup_ui(self):
        main_frame = tk.Frame(self.root, bg="#F0F0F0")
        main_frame.pack(fill=tk.BOTH, expand=True)

        sidebar = tk.Frame(main_frame, bg="#FFFFFF", width=290, highlightthickness=1, highlightbackground="#D3D3D3")
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)

        tk.Label(sidebar, text="Controls", font=("Arial", 15, "bold"), bg="#FFFFFF", fg="#333333").pack(
            pady=(20, 15), padx=15, anchor="w"
        )

        def create_btn(text, cmd):
            btn = tk.Button(sidebar, text=text, command=cmd, bg="#E8E8E8", fg="#000000",
                            font=("Arial", 10), relief=tk.FLAT, bd=1, pady=8,
                            cursor="hand2", anchor="w", padx=15)
            btn.pack(fill=tk.X, padx=15, pady=5)
            btn.bind("<Enter>", lambda e, b=btn: b.config(bg="#D0D0D0"))
            btn.bind("<Leave>", lambda e, b=btn: b.config(bg="#E8E8E8"))
            return btn

        self.btn_file = create_btn("Load Payload", self.load_payload)
        self.btn_keys = create_btn("Generate Sample Keys", self.generate_keys)

        tk.Frame(sidebar, bg="#E0E0E0", height=1).pack(fill=tk.X, padx=15, pady=10)

        self.btn_run = create_btn("Run Full Comparative Analysis", self.start_analysis_thread)

        tk.Frame(sidebar, bg="#E0E0E0", height=1).pack(fill=tk.X, padx=15, pady=10)

        self.btn_graphs = create_btn("Show Graphs", self.show_graphs)
        self.btn_graphs.config(state=tk.DISABLED)

        self.btn_summary = create_btn("Show Summary Table", self.show_summary)
        self.btn_summary.config(state=tk.DISABLED)

        status_frame = tk.Frame(sidebar, bg="#FFFFFF")
        status_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=15, pady=20)

        tk.Label(status_frame, text="Status:", font=("Arial", 9), bg="#FFFFFF", fg="#666666").pack(anchor="w")
        self.status_label = tk.Label(status_frame, text="Ready", font=("Arial", 10, "bold"), bg="#FFFFFF", fg="#000000")
        self.status_label.pack(anchor="w")

        content = tk.Frame(main_frame, bg="#F0F0F0", padx=20, pady=20)
        content.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        tk.Label(content, text="Execution Log", bg="#F0F0F0", fg="#333333",
                 font=("Arial", 12, "bold")).pack(anchor=tk.W, pady=(0, 5))

        self.log_area = scrolledtext.ScrolledText(content, wrap=tk.WORD, font=("Consolas", 10),
                                                  bg="#FFFFFF", fg="#000000", relief=tk.SOLID, bd=1,
                                                  padx=10, pady=10)
        self.log_area.pack(fill=tk.BOTH, expand=True)

        self.log_area.tag_config('info', foreground='#000000')
        self.log_area.tag_config('error', foreground='#CC0000')
        self.log_area.tag_config('success', foreground='#006600')
        self.log_area.tag_config('title', foreground='#0033CC')

    def log(self, message, tag="info"):
        self.root.after(0, self._safe_log, message, tag)

    def _safe_log(self, message, tag):
        self.log_area.insert(tk.END, message + "\n", tag)
        self.log_area.see(tk.END)

    def set_status(self, text, color="#000000"):
        self.root.after(0, lambda: self.status_label.config(text=text, fg=color))

    def load_payload(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            if os.path.getsize(file_path) > 0:
                self.payload_path = file_path
                self.log(f"Payload loaded: {os.path.basename(file_path)} ({os.path.getsize(file_path)} bytes)", "success")
            else:
                self.log("Selected file is empty. Using PRNG instead.", "error")

    def generate_keys(self):
        self.log("\n========== SAMPLE KEY GENERATION ==========", "title")

        self.log("\n[Toy Feistel 32-bit Keys]", "info")
        c32 = ToyFeistelCipher(32)
        keys32 = c32.generate_keys()
        for i, k in enumerate(keys32):
            self.log(f"Round {i+1} Key: 0x{k:04x}")

        self.log("\n[Speck-32 ARX Keys]", "info")
        speck = Speck32Cipher()
        speck_keys = speck.generate_keys()
        for i, k in enumerate(speck_keys):
            self.log(f"Round {i+1} Key: 0x{k:04x}")

        self.log("\n[AES-128 Key]", "info")
        aes = AES128Cipher()
        aes_key = aes.generate_keys()
        self.log(f"AES-128 Key: 0x{aes_key.hex()}")

        self.log("\n[ChaCha20 Parameters]", "info")
        cc20 = ChaCha20Cipher()
        cc_key, cc_nonce = cc20.generate_keys()
        self.log(f"ChaCha20 Key: 0x{cc_key.hex()}")
        self.log(f"ChaCha20 Nonce: 0x{cc_nonce.hex()}")

        self.log("\nKeys generated successfully.\n", "success")

    def calculate_theoretical_probability(self, blocks_captured, block_size_bits):
        N = 2 ** block_size_bits
        try:
            prob = 1 - math.exp(-((blocks_captured ** 2) / (2 * N)))
            return prob * 100
        except OverflowError:
            return 100.0

    def get_plaintext_block(self, file_source, bytes_per_block, block_size):
        if file_source:
            chunk = file_source.read(bytes_per_block)
            if len(chunk) < bytes_per_block:
                file_source.seek(0)
                chunk += file_source.read(bytes_per_block - len(chunk))
            return int.from_bytes(chunk, 'big')
        return random.getrandbits(block_size)

    def get_plaintext_bytes(self, file_source, bytes_per_block):
        if file_source:
            chunk = file_source.read(bytes_per_block)
            if len(chunk) < bytes_per_block:
                file_source.seek(0)
                chunk += file_source.read(bytes_per_block - len(chunk))
            return chunk
        return os.urandom(bytes_per_block)

    def run_toy_test(self, mode_name, block_size, limit, rekey_interval=None):
        bytes_per_block = block_size // 8
        cipher = ToyFeistelCipher(block_size)
        cipher.generate_keys()

        start_time = time.time()
        prev_ciphertext = random.getrandbits(block_size)
        nonce = random.getrandbits(block_size)

        global_seen = set()
        segment_seen = set()

        if self.payload_path:
            file_source = open(self.payload_path, 'rb')
        else:
            file_source = None

        collision_found = False
        collision_block = None
        collision_scope = "None"

        for block_idx in range(1, limit + 1):
            plaintext = self.get_plaintext_block(file_source, bytes_per_block, block_size)

            if rekey_interval and block_idx % rekey_interval == 0:
                cipher.generate_keys()
                segment_seen = set()
                prev_ciphertext = random.getrandbits(block_size)

            if mode_name == "Toy Feistel (32-bit CTR)":
                counter_input = (nonce + block_idx) & ((1 << block_size) - 1)
                keystream = cipher.encrypt(counter_input)
                ciphertext = plaintext ^ keystream
            else:
                xor_input = plaintext ^ prev_ciphertext
                ciphertext = cipher.encrypt(xor_input)
                prev_ciphertext = ciphertext

            if mode_name == "Toy Feistel (32-bit CBC)":
                if ciphertext in global_seen:
                    collision_found = True
                    collision_block = block_idx
                    collision_scope = "Global"
                    break
                global_seen.add(ciphertext)

            elif mode_name == "Toy Feistel (32-bit CBC + Rekey)":
                if ciphertext in segment_seen:
                    collision_found = True
                    collision_block = block_idx
                    collision_scope = "Per-Key Session"
                    break
                segment_seen.add(ciphertext)

            elif mode_name == "Toy Feistel (32-bit CTR)":
                if ciphertext in global_seen:
                    collision_found = True
                    collision_block = block_idx
                    collision_scope = "Stream Repetition"
                    break
                global_seen.add(ciphertext)

        if file_source:
            file_source.close()

        latency = time.time() - start_time

        return {
            "collision": collision_found,
            "blocks": collision_block if collision_found else limit,
            "time": latency,
            "scope": collision_scope
        }

    def run_speck_test(self, limit):
        cipher = Speck32Cipher()
        cipher.generate_keys()
        
        start_time = time.time()
        prev_ciphertext = random.getrandbits(32)
        global_seen = set()
        
        if self.payload_path:
            file_source = open(self.payload_path, 'rb')
        else:
            file_source = None
            
        collision_found = False
        collision_block = None
        
        for block_idx in range(1, limit + 1):
            plaintext = self.get_plaintext_block(file_source, 4, 32)
            xor_input = plaintext ^ prev_ciphertext
            ciphertext = cipher.encrypt(xor_input)
            prev_ciphertext = ciphertext
            
            if ciphertext in global_seen:
                collision_found = True
                collision_block = block_idx
                break
                
            global_seen.add(ciphertext)
            
        if file_source:
            file_source.close()
            
        latency = time.time() - start_time
        return {
            "collision": collision_found,
            "blocks": collision_block if collision_found else limit,
            "time": latency,
            "scope": "Global"
        }

    def run_aes_test(self, limit):
        aes = AES128Cipher()
        aes.generate_keys()

        prev_ciphertext = os.urandom(16)
        seen_ciphertexts = set()

        if self.payload_path:
            file_source = open(self.payload_path, 'rb')
        else:
            file_source = None

        start_time = time.time()
        collision_found = False
        collision_block = None

        for block_idx in range(1, limit + 1):
            plaintext = self.get_plaintext_bytes(file_source, 16)
            xor_input = bytes([plaintext[i] ^ prev_ciphertext[i] for i in range(16)])
            ciphertext = aes.encrypt_block_ecb(xor_input)

            if ciphertext in seen_ciphertexts:
                collision_found = True
                collision_block = block_idx
                break

            seen_ciphertexts.add(ciphertext)
            prev_ciphertext = ciphertext

        if file_source:
            file_source.close()

        latency = time.time() - start_time

        return {
            "collision": collision_found,
            "blocks": collision_block if collision_found else limit,
            "time": latency,
            "scope": "Global"
        }

    def run_chacha20_test(self, limit):
        cc20 = ChaCha20Cipher()
        key, nonce = cc20.generate_keys()
        
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        encryptor = cipher.encryptor()

        seen_ciphertexts = set()

        if self.payload_path:
            file_source = open(self.payload_path, 'rb')
        else:
            file_source = None

        start_time = time.time()
        collision_found = False
        collision_block = None

        for block_idx in range(1, limit + 1):
            plaintext = self.get_plaintext_bytes(file_source, 16)
            ciphertext = encryptor.update(plaintext)

            if ciphertext in seen_ciphertexts:
                collision_found = True
                collision_block = block_idx
                break

            seen_ciphertexts.add(ciphertext)

        if file_source:
            file_source.close()

        latency = time.time() - start_time

        return {
            "collision": collision_found,
            "blocks": collision_block if collision_found else limit,
            "time": latency,
            "scope": "Stream Repetition"
        }

    def start_analysis_thread(self):
        self.btn_run.config(state=tk.DISABLED)
        self.btn_graphs.config(state=tk.DISABLED)
        self.btn_summary.config(state=tk.DISABLED)
        self.set_status("Running Analysis...", "#CC6600")
        threading.Thread(target=self.run_full_analysis, daemon=True).start()

    def run_full_analysis(self):
        self.log("\n========== COMPARATIVE COLLISION ANALYSIS ==========", "title")

        num_tests = 20
        for key in self.all_results:
            self.all_results[key] = []

        toy_configs = [
            ("Toy Feistel (32-bit CBC)", 32, 100000, None),
            ("Toy Feistel (32-bit CTR)", 32, 100000, None),
            ("Toy Feistel (32-bit CBC + Rekey)", 32, 100000, 20000),
        ]

        for config_name, block_size, limit, rekey_interval in toy_configs:
            self.log(f"\n--- Running: {config_name} ---", "title")
            theo_prob = self.calculate_theoretical_probability(min(limit, 65536), block_size)
            self.log(f"Theoretical probability reference: {theo_prob:.4f}%")

            collisions = 0
            for i in range(1, num_tests + 1):
                result = self.run_toy_test(config_name, block_size, limit, rekey_interval)
                self.all_results[config_name].append(result)

                if result["collision"]:
                    collisions += 1
                    self.log(f"Test {i}: Collision at block {result['blocks']} ({result['time']:.4f}s) [{result['scope']}]", "error")
                else:
                    self.log(f"Test {i}: No collision up to {result['blocks']} blocks ({result['time']:.4f}s)", "success")
            
            collision_rate = (collisions / num_tests) * 100
            self.log(f"Result -> Collision Rate for {config_name}: {collision_rate:.2f}%", "info")

        self.log(f"\n--- Running: Speck-32 ARX (32-bit CBC) ---", "title")
        theo_prob = self.calculate_theoretical_probability(min(100000, 65536), 32)
        self.log(f"Theoretical probability reference: {theo_prob:.4f}%")
        
        collisions = 0
        for i in range(1, num_tests + 1):
            result = self.run_speck_test(100000)
            self.all_results["Speck-32 ARX (32-bit CBC)"].append(result)
            if result["collision"]:
                collisions += 1
                self.log(f"Test {i}: Collision at block {result['blocks']} ({result['time']:.4f}s) [{result['scope']}]", "error")
            else:
                self.log(f"Test {i}: No collision up to {result['blocks']} blocks ({result['time']:.4f}s)", "success")
        
        collision_rate = (collisions / num_tests) * 100
        self.log(f"Result -> Collision Rate for Speck-32 ARX (32-bit CBC): {collision_rate:.2f}%", "info")

        self.log(f"\n--- Running: AES-128 CBC ---", "title")
        theo_prob = self.calculate_theoretical_probability(50000, 128)
        self.log(f"Theoretical probability reference: {theo_prob:.8f}%")

        collisions = 0
        for i in range(1, num_tests + 1):
            result = self.run_aes_test(50000)
            self.all_results["AES-128 CBC"].append(result)
            if result["collision"]:
                collisions += 1
                self.log(f"Test {i}: Collision at block {result['blocks']} ({result['time']:.4f}s) [{result['scope']}]", "error")
            else:
                self.log(f"Test {i}: No collision up to {result['blocks']} blocks ({result['time']:.4f}s)", "success")

        collision_rate = (collisions / num_tests) * 100
        self.log(f"Result -> Collision Rate for AES-128 CBC: {collision_rate:.2f}%", "info")

        self.log(f"\n--- Running: ChaCha20 (Stream) ---", "title")
        self.log(f"Theoretical probability reference: Stream cipher structure neutralizes bound.")

        collisions = 0
        for i in range(1, num_tests + 1):
            result = self.run_chacha20_test(50000)
            self.all_results["ChaCha20 (Stream)"].append(result)

            if result["collision"]:
                collisions += 1
                self.log(f"Test {i}: Collision at block {result['blocks']} ({result['time']:.4f}s) [{result['scope']}]", "error")
            else:
                self.log(f"Test {i}: No collision up to {result['blocks']} blocks ({result['time']:.4f}s)", "success")

        collision_rate = (collisions / num_tests) * 100
        self.log(f"Result -> Collision Rate for ChaCha20 (Stream): {collision_rate:.2f}%", "info")

        self.log("\n========== ANALYSIS COMPLETE ==========\n", "success")

        self.root.after(0, lambda: self.btn_run.config(state=tk.NORMAL))
        self.root.after(0, lambda: self.btn_graphs.config(state=tk.NORMAL))
        self.root.after(0, lambda: self.btn_summary.config(state=tk.NORMAL))
        self.set_status("Analysis Complete", "#006600")

    def compute_metrics(self):
        metrics = {}
        for config, results in self.all_results.items():
            if not results:
                continue
            total_tests = len(results)
            collisions = sum(1 for r in results if r["collision"])
            collision_rate = (collisions / total_tests) * 100
            security_score = 100 - collision_rate
            avg_time = sum(r["time"] for r in results) / total_tests
            avg_blocks = sum(r["blocks"] for r in results) / total_tests

            metrics[config] = {
                "collision_rate": collision_rate,
                "security_score": security_score,
                "avg_time": avg_time,
                "avg_blocks": avg_blocks
            }
        return metrics

    def show_summary(self):
        metrics = self.compute_metrics()
        if not metrics:
            self.log("Run analysis first.", "error")
            return

        self.log("\n========== SUMMARY TABLE ==========", "title")
        self.log(f"{'Mode':35s} {'Collision%':>12s} {'Security%':>12s} {'Avg Time':>12s} {'Avg Blocks':>12s}")
        self.log("-" * 95)

        for mode, m in metrics.items():
            self.log(
                f"{mode:35s} "
                f"{m['collision_rate']:12.2f} "
                f"{m['security_score']:12.2f} "
                f"{m['avg_time']:12.4f} "
                f"{m['avg_blocks']:12.2f}"
            )

    def show_graphs(self):
        metrics = self.compute_metrics()
        if not metrics:
            self.log("Run analysis first.", "error")
            return

        modes = list(metrics.keys())
        collision_rates = [metrics[m]["collision_rate"] for m in modes]
        security_scores = [metrics[m]["security_score"] for m in modes]
        avg_times = [metrics[m]["avg_time"] for m in modes]
        avg_blocks = [metrics[m]["avg_blocks"] for m in modes]

        colors = ['#E53E3E', '#DD6B20', '#D69E2E', '#38A169', '#319795', '#3182CE']

        fig, axs = plt.subplots(2, 2, figsize=(16, 11))
        fig.canvas.manager.set_window_title("Final Comparative Graphs")
        fig.suptitle("Collision Prevention Comparative Analysis", fontsize=16, fontweight='bold')

        axs[0, 0].bar(modes, collision_rates, color=colors)
        axs[0, 0].set_title("Collision Rate (%)", fontsize=12, fontweight='bold')
        axs[0, 0].set_ylabel("Percentage")
        axs[0, 0].tick_params(axis='x', rotation=45)
        axs[0, 0].set_ylim(0, 100)

        axs[0, 1].bar(modes, security_scores, color=colors)
        axs[0, 1].set_title("Security Integrity (%)", fontsize=12, fontweight='bold')
        axs[0, 1].set_ylabel("Percentage")
        axs[0, 1].tick_params(axis='x', rotation=45)
        axs[0, 1].set_ylim(0, 100)

        axs[1, 0].plot(modes, avg_times, marker='o', linewidth=2, color='#4A5568')
        axs[1, 0].set_title("Average Execution Time (s)", fontsize=12, fontweight='bold')
        axs[1, 0].set_ylabel("Seconds")
        axs[1, 0].tick_params(axis='x', rotation=45)

        axs[1, 1].bar(modes, avg_blocks, color=colors)
        axs[1, 1].set_title("Average Blocks Survived", fontsize=12, fontweight='bold')
        axs[1, 1].set_ylabel("Blocks")
        axs[1, 1].tick_params(axis='x', rotation=45)

        for ax in axs.flat:
            ax.grid(True, linestyle='--', alpha=0.5)

        plt.tight_layout(rect=[0, 0, 1, 0.96])
        plt.show()

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoProjectGUI(root)
    root.mainloop()