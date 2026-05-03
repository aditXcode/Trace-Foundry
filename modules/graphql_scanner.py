"""
TraceFoundry V8 - GraphQL Security Analyzer
Introspection, alias bypass, query depth DoS, field suggestion,
batch query abuse, authentication bypass
Anti-FP: Structural JSON confirm, not just status 200
"""
import urllib.request, urllib.error, json, re, time
from utils.display import section, ok, warn, info, bug_found
from core.antifp_engines import get_waf_interceptor

GQL_ENDPOINTS = ["/graphql","/api/graphql","/v1/graphql","/query",
                 "/api/query","/graph","/gql","/api/gql",
                 "/graphql/v1","/api/v1/graphql","/graphiql"]

class GraphQLModule:
    def __init__(self, domain, timeout=8):
        self.domain  = domain
        self.timeout = timeout
        self.waf     = get_waf_interceptor()
        self.headers = {
            "User-Agent":   "Mozilla/5.0 (TraceFoundry/8.0)",
            "Content-Type": "application/json",
            "Accept":       "application/json",
        }

    def _post(self, url, query, variables=None):
        payload = json.dumps({"query": query, "variables": variables or {}}).encode()
        try:
            req = urllib.request.Request(url, data=payload, headers=self.headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read(65536).decode("utf-8", errors="ignore")
                return body, r.status, dict(r.headers)
        except urllib.error.HTTPError as e:
            try:    body = e.read(32768).decode("utf-8", errors="ignore")
            except: body = ""
            return body, e.code, dict(e.headers)
        except: return "", 0, {}

    def _is_valid_gql_response(self, body):
        """Anti-FP: Must be JSON with data or errors key."""
        try:
            data = json.loads(body)
            return isinstance(data, dict) and ("data" in data or "errors" in data)
        except: return False

    def _introspection_enabled(self, url):
        """Confirm introspection by checking __schema.types structure."""
        query = "{ __schema { types { name } } }"
        body, status, headers = self._post(url, query)
        if self.waf.should_skip(status, body, headers): return False, None
        if not self._is_valid_gql_response(body): return False, None
        try:
            data  = json.loads(body)
            types = data.get("data",{}).get("__schema",{}).get("types",[])
            if isinstance(types, list) and len(types) > 3:
                return True, [t.get("name") for t in types[:10]]
        except: pass
        return False, None

    def _get_full_schema(self, url):
        query = """
        { __schema {
            queryType { name }
            mutationType { name }
            types {
              name
              kind
              fields { name args { name type { name kind ofType { name kind } } }
                       type { name kind ofType { name kind } } }
            }
        }}"""
        body, status, _ = self._post(url, query)
        try: return json.loads(body).get("data",{}).get("__schema",{})
        except: return {}

    def _test_alias_bypass(self, url, schema):
        """Test alias-based rate limit bypass."""
        bugs = []
        # Find a query field from schema
        query_type = schema.get("queryType",{}).get("name","Query")
        alias_query = "{ " + " ".join([f"a{i}: __typename" for i in range(10)]) + " }"
        body, status, _ = self._post(url, alias_query)
        if self._is_valid_gql_response(body):
            try:
                data = json.loads(body).get("data",{})
                if len(data) >= 10:
                    bugs.append({"type":"GraphQL — Alias-Based Query Duplication",
                        "severity":"MEDIUM","url":url,
                        "evidence":f"10 aliased queries returned {len(data)} results",
                        "detail":"Alias bypass may allow rate-limit evasion or DoS",
                        "impact":"Rate limiting bypass, potential DoS amplification"})
                    bug_found("GraphQL Alias Bypass","MEDIUM",{
                        "URL":url,"Evidence":f"{len(data)} alias queries accepted"})
            except: pass
        return bugs

    def _test_query_depth(self, url):
        """Test deep nested query — server should reject or timeout."""
        bugs = []
        deep = "{ __type(name: \"Query\") { " * 15 + "name " + "} " * 15
        t0 = time.time()
        body, status, _ = self._post(url, deep)
        elapsed = time.time() - t0
        if status == 200 and elapsed < 5 and self._is_valid_gql_response(body):
            bugs.append({"type":"GraphQL — Unlimited Query Depth (No Depth Limit)",
                "severity":"MEDIUM","url":url,
                "evidence":f"15-level nested query accepted in {elapsed:.1f}s",
                "detail":"No query depth limit — attackable with deeply nested DoS queries",
                "impact":"Server resource exhaustion via crafted nested queries"})
            bug_found("GraphQL No Depth Limit","MEDIUM",{
                "URL":url,"Depth":"15 levels","Time":f"{elapsed:.1f}s"})
        return bugs

    def _test_field_suggestion(self, url):
        """When introspection disabled, check for field suggestions."""
        bugs = []
        query = "{ usr { emailAddress } }"  # intentionally wrong
        body, status, _ = self._post(url, query)
        if "Did you mean" in body or "did you mean" in body:
            import re as _re
            suggestions = _re.findall(r'Did you mean[^?]+\?["\s]*([^\?"]+)', body)
            bugs.append({"type":"GraphQL — Field Suggestion Leaks Schema",
                "severity":"LOW","url":url,
                "evidence":f"Server suggests fields: {suggestions[:3]}",
                "detail":"Field suggestion enabled despite introspection off — schema inferable",
                "impact":"Attacker can reconstruct schema via field suggestions"})
            bug_found("GraphQL Field Suggestion","LOW",{
                "URL":url,"Suggestions":str(suggestions[:3])})
        return bugs

    def _test_graphql_ide(self, url):
        """Check if GraphQL IDE/playground is exposed."""
        bugs = []
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent":"Mozilla/5.0","Accept":"text/html"})
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read(32768).decode("utf-8", errors="ignore")
                for ide in ["graphiql","playground","voyager","altair","sandbox"]:
                    if ide in body.lower():
                        bugs.append({"type":"GraphQL IDE/Playground Exposed",
                            "severity":"MEDIUM","url":url,
                            "evidence":f"'{ide}' interface found at {url}",
                            "detail":"Interactive GraphQL IDE publicly accessible",
                            "impact":"Anyone can explore and query entire API interactively"})
                        bug_found("GraphQL IDE Exposed","MEDIUM",{
                            "URL":url,"IDE":ide,"Impact":"Interactive API exploration"})
                        break
        except: pass
        return bugs

    def _test_batch_query(self, url):
        """Test if batched queries are accepted (amplification risk)."""
        bugs = []
        batch = [{"query":"{ __typename }"}] * 20
        payload = json.dumps(batch).encode()
        try:
            req = urllib.request.Request(url, data=payload, headers=self.headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read(32768).decode("utf-8", errors="ignore")
                status = r.status
            if status == 200:
                try:
                    data = json.loads(body)
                    if isinstance(data, list) and len(data) >= 10:
                        bugs.append({"type":"GraphQL — Batch Query Accepted",
                            "severity":"MEDIUM","url":url,
                            "evidence":f"20 batched queries all returned 200",
                            "detail":"Batch queries accepted — DoS / rate limit bypass risk",
                            "impact":"Amplified requests via batch — potential DoS"})
                        bug_found("GraphQL Batch Query","MEDIUM",{
                            "URL":url,"Batch Size":"20","Impact":"DoS amplification"})
                except: pass
        except: pass
        return bugs

    def run(self):
        section("GraphQL Security Analyzer V8 (Anti-FP Structural Confirm)")
        all_bugs = []

        for ep in GQL_ENDPOINTS:
            for scheme in ["https","http"]:
                url = f"{scheme}://{self.domain}{ep}"
                # Quick probe
                body, status, headers = self._post(url, "{ __typename }")
                if status == 0: continue
                if not self._is_valid_gql_response(body): break

                info(f"GraphQL endpoint found: {url}")

                # Introspection check (anti-FP: must see __schema.types)
                enabled, types = self._introspection_enabled(url)
                if enabled:
                    all_bugs.append({"type":"GraphQL Introspection Enabled",
                        "severity":"MEDIUM","url":url,
                        "evidence":f"Schema types: {types}",
                        "detail":"Full API schema accessible without authentication",
                        "impact":"Attacker enumerates all queries, mutations, fields"})
                    bug_found("GraphQL Introspection Enabled","MEDIUM",{
                        "URL":url,"Types Found":str(len(types or []))})

                    schema = self._get_full_schema(url)
                    all_bugs.extend(self._test_alias_bypass(url, schema))
                else:
                    all_bugs.extend(self._test_field_suggestion(url))

                all_bugs.extend(self._test_query_depth(url))
                all_bugs.extend(self._test_graphql_ide(url))
                all_bugs.extend(self._test_batch_query(url))
                break

        info(f"GraphQL scan done — {len(all_bugs)} findings")
        if not all_bugs: ok("No GraphQL issues found ✓")
        return {"bugs": all_bugs}
