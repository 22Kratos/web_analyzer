import asyncio
import re
import time

from web_analyzer.scanners.base import Scanner, Finding, Severity
from web_analyzer.core.models import Target, Endpoint
from web_analyzer.core.http_client import HttpClient
from web_analyzer.core import rate_limiter


SQLI_ERROR_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR '1'='1' -- ",
    "' AND '1'='2",
]

SQLI_BOOLEAN_PAYLOADS = [
    ("' OR '1'='1", "' AND '1'='2"),
    (" OR 1=1", " AND 1=2"),
]

SQLI_TIME_PAYLOADS = [
    "' AND SLEEP({delay})-- -",          # MySQL
    "'; SELECT PG_SLEEP({delay})-- -",   # PostgreSQL
    "'; WAITFOR DELAY '0:0:{delay}'-- -", # MSSQL
]

SQL_ERRORS = [
    "SQL syntax", "mysql_", "Warning: mysql",
    "PostgreSQL.*ERROR", "pg_query",
    "Microsoft SQL Server", "Unclosed quotation mark",
    "ORA-\\d{5}", "SQLite\\.Exception",
]

CMD_PAYLOADS = ["; id", "| id", "`id`", "$(id)", "; whoami"]
CMD_OUTPUT_PATTERN = r"uid=\d+\(.+?\)\s+gid=\d+"
CMD_TIME_PAYLOADS = ["; sleep {delay}", "| sleep {delay}"]

NOSQL_PAYLOADS = ['{"$ne": null}', '{"$gt": ""}', "' || '1'=='1"]

SLEEP_SECONDS = 5
DELAY_THRESHOLD = 4


class InjectionScanner(Scanner):
    name = "Injection Scanner"

    def __init__(self, http_client: HttpClient):
        self.http = http_client

    async def scan(self, target: Target):
        findings = []
        for endpoint in target.endpoints:
            findings += await self.scan_endpoint(endpoint)
        return findings

    async def scan_endpoint(self, endpoint: Endpoint):
        findings = []
        params = {**endpoint.params, **endpoint.form_data}

        for param_name in params:
            result = await self.test_param(endpoint, param_name)
            if result:
                findings.append(result)

        return findings

    async def test_param(self, endpoint, param_name):
        # try the fast/reliable checks first, slow ones last
        result = await self.check_sql_error(endpoint, param_name)
        if result:
            return result

        result = await self.check_sql_boolean(endpoint, param_name)
        if result:
            return result

        result = await self.check_command_injection(endpoint, param_name)
        if result:
            return result

        result = await self.check_nosql(endpoint, param_name)
        if result:
            return result

        result = await self.check_sql_time(endpoint, param_name)
        if result:
            return result

        return await self.check_command_time(endpoint, param_name)


    async def check_sql_error(self, endpoint, param_name):
        for payload in SQLI_ERROR_PAYLOADS:
            response = await self.send_request(endpoint, param_name, payload)
            if not response:
                continue

            for error_pattern in SQL_ERRORS:
                if re.search(error_pattern, response.text, re.IGNORECASE):
                    return Finding(
                        title="SQL Injection (Error-Based)",
                        severity=Severity.CRITICAL,
                        endpoint=endpoint.url,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Response contained a DB error matching: {error_pattern}",
                        description=f"'{param_name}' seems to be inserted directly into a SQL query without sanitization.",
                        remediation="Use parameterized queries / prepared statements instead of building SQL with string concatenation.",
                    )
        return None

    async def check_sql_boolean(self, endpoint, param_name):
        baseline = await self.send_request(endpoint, param_name, "1")
        if not baseline:
            return None

        for true_payload, false_payload in SQLI_BOOLEAN_PAYLOADS:
            true_response = await self.send_request(endpoint, param_name, true_payload)
            false_response = await self.send_request(endpoint, param_name, false_payload)
            if not true_response or not false_response:
                continue

            # if the "true" version looks like the normal page, but the
            # "false" version looks different, the query is reacting to our logic
            true_looks_normal = self.similar_length(baseline.text, true_response.text)
            false_looks_different = not self.similar_length(baseline.text, false_response.text)

            if true_looks_normal and false_looks_different:
                return Finding(
                    title="SQL Injection (Boolean-Based Blind)",
                    severity=Severity.HIGH,
                    endpoint=endpoint.url,
                    parameter=param_name,
                    payload=f"true={true_payload} / false={false_payload}",
                    evidence="Response length changes depending on injected boolean logic.",
                    description=f"'{param_name}' appears to control a query's WHERE clause.",
                    remediation="Use parameterized queries and validate input types before using them in a query.",
                )
        return None

    async def check_sql_time(self, endpoint, param_name):
        baseline_time = await self.timed_request(endpoint, param_name, "1")
        if baseline_time is None:
            return None

        for template in SQLI_TIME_PAYLOADS:
            payload = template.format(delay=SLEEP_SECONDS)
            elapsed = await self.timed_request(endpoint, param_name, payload)
            if elapsed is None:
                continue

            if elapsed - baseline_time >= DELAY_THRESHOLD:
                return Finding(
                    title="SQL Injection (Time-Based Blind)",
                    severity=Severity.HIGH,
                    endpoint=endpoint.url,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"Baseline {baseline_time:.2f}s vs {elapsed:.2f}s with sleep payload.",
                    description=f"'{param_name}' triggers a measurable delay, likely blind SQL injection.",
                    remediation="Use parameterized queries.",
                )
        return None


    async def check_command_injection(self, endpoint, param_name):
        for payload in CMD_PAYLOADS:
            response = await self.send_request(endpoint, param_name, payload)
            if response and re.search(CMD_OUTPUT_PATTERN, response.text):
                return Finding(
                    title="OS Command Injection",
                    severity=Severity.CRITICAL,
                    endpoint=endpoint.url,
                    parameter=param_name,
                    payload=payload,
                    evidence="Response contains output that looks like the 'id' command.",
                    description=f"'{param_name}' is passed into a shell command without sanitization.",
                    remediation="Avoid building shell commands from user input. Use subprocess with argument lists, not shell=True.",
                )
        return None

    async def check_command_time(self, endpoint, param_name):
        baseline_time = await self.timed_request(endpoint, param_name, "1")
        if baseline_time is None:
            return None

        for template in CMD_TIME_PAYLOADS:
            payload = template.format(delay=SLEEP_SECONDS)
            elapsed = await self.timed_request(endpoint, param_name, payload)
            if elapsed and elapsed - baseline_time >= DELAY_THRESHOLD:
                return Finding(
                    title="OS Command Injection (Time-Based Blind)",
                    severity=Severity.HIGH,
                    endpoint=endpoint.url,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"Baseline {baseline_time:.2f}s vs {elapsed:.2f}s.",
                    description=f"'{param_name}' seems to run a sleep command server-side.",
                    remediation="Avoid shell invocation with user input entirely.",
                )
        return None


    async def check_nosql(self, endpoint, param_name):
        baseline = await self.send_request(endpoint, param_name, "some_invalid_value")
        if not baseline:
            return None

        for payload in NOSQL_PAYLOADS:
            response = await self.send_request(endpoint, param_name, payload)
            if not response:
                continue

            status_changed = response.status_code != baseline.status_code
            body_grew = len(response.text) > len(baseline.text) * 1.5

            if status_changed or body_grew:
                return Finding(
                    title="NoSQL Injection",
                    severity=Severity.HIGH,
                    endpoint=endpoint.url,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"Status went from {baseline.status_code} to {response.status_code}, body size changed too.",
                    description=f"'{param_name}' accepts NoSQL operators like $ne/$gt, which can bypass filters or logins.",
                    remediation="Type-check input before it reaches the query - reject anything that isn't a plain string/number where one is expected.",
                )
        return None


    def similar_length(self, text_a, text_b, tolerance=0.05):
        if len(text_a) == 0 and len(text_b) == 0:
            return True
        longer = max(len(text_a), len(text_b))
        diff = abs(len(text_a) - len(text_b))
        return (diff / longer) <= tolerance

    async def timed_request(self, endpoint, param_name, payload):
        start = time.monotonic()
        response = await self.send_request(endpoint, param_name, payload)
        if not response:
            return None
        return time.monotonic() - start

    async def send_request(self, endpoint, param_name, payload):
        # copy the endpoint's normal params/data, and only swap the one
        # parameter we're testing - keeps every other field valid so the
        # request doesn't fail for unrelated reasons
        params = dict(endpoint.params)
        data = dict(endpoint.form_data)

        if param_name in params:
            params[param_name] = payload
        if param_name in data:
            data[param_name] = payload

        await rate_limiter.acquire()

        try:
            return await self.http.request(
                method=endpoint.method,
                url=endpoint.url,
                params=params if endpoint.method.upper() == "GET" else None,
                data=data if endpoint.method.upper() != "GET" else None,
                headers=endpoint.headers,
                timeout=SLEEP_SECONDS + 10,
            )
        except Exception:
            return None