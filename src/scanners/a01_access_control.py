"""
Abstract Vulnerability Scanner Logic (Synchronous)
Note: This is non-functional pseudocode. Dependencies like 'http_client' 
and 'dom_parser' must be implemented.
PLACEHOLDER CODE, will also replace all the AI slop from this
"""

import re
import uuid

# ==========================================
# Vulnerability Analyzer Modules
# ==========================================

class CWE200_Analyzer:
    """Detects Exposure of Sensitive Information in response bodies."""
    def __init__(self):
        # Define regex patterns for sensitive data
        self.sensitive_patterns = {
            "aws_key": r"\b(?:AKIA|ABIA|ACCA)[0-9A-Z]{16}\b",
            "stack_trace": r"java\.lang\.[A-Za-z]+Exception",
            "db_connection": r"jdbc:mysql://[a-zA-Z0-9\.:]+",
            "private_key": r"-----BEGIN (?:RSA|OPENSSH|EC) PRIVATE KEY-----"
        }

    def analyze_response(self, response_obj):
        findings = []
        body = response_obj.text
        
        # Iterate through patterns and search the response body
        for data_type, pattern in self.sensitive_patterns.items():
            if re.search(pattern, body):
                findings.append({
                    "vulnerability": "CWE-200",
                    "type": data_type,
                    "url": response_obj.url,
                    "severity": "High"
                })
                
        return findings


class CWE201_Analyzer:
    """Detects Sensitive Information in outbound sent data."""
    def __init__(self):
        self.sensitive_terms = ["password", "token", "ssn", "api_key", "secret"]

    def analyze_outbound_request(self, request_obj):
        findings = []
        url = request_obj.url.lower()
        
        # 1. Check for unencrypted transit
        if url.startswith("http://"):
            findings.append({
                "vulnerability": "CWE-201",
                "issue": "Unencrypted HTTP used",
                "url": request_obj.url
            })
            
        # 2. Check if sensitive parameters are in the GET query string or URL path
        if request_obj.method == "GET":
            for term in self.sensitive_terms:
                if f"{term}=" in url or f"/{term}/" in url:
                    findings.append({
                        "vulnerability": "CWE-201",
                        "issue": f"Sensitive data '{term}' exposed in URL",
                        "url": request_obj.url
                    })
                    
        return findings


class CWE918_Analyzer:
    """Detects Server-Side Request Forgery via active payload injection."""
    def __init__(self, http_client, oob_listener_server):
        self.http_client = http_client
        self.oob_listener = oob_listener_server 
        self.internal_payloads = ["http://127.0.0.1", "http://169.254.169.254/latest/meta-data/"]

    def test_endpoint(self, endpoint_url, params):
        findings = []
        
        # 1. Establish a baseline for comparison
        baseline_resp = self.http_client.post(endpoint_url, data=params)
        baseline_length = len(baseline_resp.text)
        
        # 2. Out-of-Band (OOB) Testing
        unique_id = str(uuid.uuid4())
        oob_payload = f"http://{unique_id}.{self.oob_listener.domain}"
        injected_params_oob = {k: oob_payload for k in params.keys()}
        
        self.http_client.post(endpoint_url, data=injected_params_oob)
        
        # Check listener logs for external resolution 
        if self.oob_listener.received_interaction(unique_id):
            findings.append({
                "vulnerability": "CWE-918",
                "issue": "OOB Interaction Detected (Blind SSRF)",
                "url": endpoint_url
            })
            
        # 3. Internal IP Testing
        for payload in self.internal_payloads:
            injected_params_internal = {k: payload for k in params.keys()}
            resp = self.http_client.post(endpoint_url, data=injected_params_internal)
            
            # Compare response against the baseline request
            if resp.status_code == 200 and abs(len(resp.text) - baseline_length) > 100:
                 findings.append({
                    "vulnerability": "CWE-918",
                    "issue": "Internal loopback address resolved (Baseline deviation)",
                    "url": endpoint_url
                })
                
        return findings


class CWE352_Analyzer:
    """Detects Cross-Site Request Forgery via form and header analysis."""
    def __init__(self, dom_parser):
        self.dom_parser = dom_parser

    def analyze_forms_and_cookies(self, response_obj):
        findings = []
        
        # 1. Analyze Session Cookies
        cookies = response_obj.headers.get("Set-Cookie", [])
        for cookie in cookies:
            if "SameSite=None" in cookie and "Secure" not in cookie:
                 findings.append({
                    "vulnerability": "CWE-352",
                    "issue": "Insecure SameSite attribute on session cookie",
                    "url": response_obj.url
                })

        # 2. Analyze HTML Forms
        dom = self.dom_parser.parse(response_obj.text)
        forms = dom.find_all("form")
        
        for form in forms:
            method = form.get("method", "GET").upper()
            
            if method in ["POST", "PUT", "DELETE"]:
                has_token = False
                
                # Check hidden inputs for standard CSRF token names
                hidden_inputs = form.find_inputs(type="hidden")
                for input_field in hidden_inputs:
                    name = input_field.get("name").lower()
                    if "csrf" in name or "token" in name or "xsrf" in name:
                        has_token = True
                        break
                        
                if not has_token:
                    findings.append({
                        "vulnerability": "CWE-352",
                        "issue": "State-changing form missing anti-CSRF token",
                        "form_action": form.get("action")
                    })
                    
        return findings

# ==========================================
# Core Orchestrator
# ==========================================

class SynchronousOrchestrator:
    """Coordinates the execution of vulnerability modules sequentially."""
    def __init__(self, http_client, oob_listener, dom_parser):
        self.cwe200 = CWE200_Analyzer()
        self.cwe201 = CWE201_Analyzer()
        self.cwe918 = CWE918_Analyzer(http_client, oob_listener)
        self.cwe352 = CWE352_Analyzer(dom_parser)

    def scan_endpoint_sequentially(self, request_obj, response_obj):
        all_findings = []
        
        # 1. Passive Checks (No new HTTP requests generated)
        all_findings.extend(self.cwe200.analyze_response(response_obj))
        all_findings.extend(self.cwe201.analyze_outbound_request(request_obj))
        all_findings.extend(self.cwe352.analyze_forms_and_cookies(response_obj))
        
        # 2. Active Checks (Generates new HTTP requests)
        if hasattr(request_obj, 'params') and request_obj.params:
            all_findings.extend(self.cwe918.test_endpoint(request_obj.url, request_obj.params))
            
        return all_findings

    def run_full_scan(self, discovered_endpoints):
        print(f"Starting sequential scan of {len(discovered_endpoints)} endpoints...")
        
        final_results = []
        for req, resp in discovered_endpoints:
            # Execution blocks here until all modules finish analyzing this specific endpoint
            endpoint_findings = self.scan_endpoint_sequentially(req, resp)
            final_results.extend(endpoint_findings)
            
        return final_results