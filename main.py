from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import json
import csv
import io
import asyncio
import aiohttp
from datetime import datetime
from typing import List, Dict
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import random

app = FastAPI(title="PersonaTrail - Advanced Tracking Demo", version="3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# ENHANCED LIVE SCANNING ENGINE
# ============================================================================

class LiveScanner:
    def __init__(self):
        self.scan_history = []
        self.tracking_sessions = []
    
    async def scan_ssl_cert(self, domain: str) -> Dict:
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://crt.sh/?q={domain}&output=json"
                async with session.get(url, timeout=5) as response:
                    if response.status == 200:
                        certs = await response.json()
                        if certs and len(certs) > 0:
                            cert = certs[0]
                            return {
                                "found": True,
                                "issuer": cert.get('issuer_name', 'Unknown'),
                                "common_name": cert.get('common_name', domain),
                                "not_before": cert.get('not_before', ''),
                                "not_after": cert.get('not_after', ''),
                                "serial_number": cert.get('serial_number', ''),
                                "leak_detected": domain.lower() in str(cert).lower(),
                                "confidence": 85 if domain.lower() in str(cert).lower() else 45,
                                "tracking_step": "SSL Certificate Transparency Log Analysis",
                                "evidence_type": "Infrastructure Fingerprint"
                            }
            return {"found": False, "confidence": 0}
        except Exception as e:
            return {"found": False, "error": str(e), "confidence": 0}
    
    async def scan_onion_service(self, onion_url: str) -> Dict:
        await asyncio.sleep(2.0)
        leak_types = [
            ("Exposed SSL Certificate", 95, "CRITICAL", "SSL/TLS Misconfiguration"),
            ("Default Apache Banner", 78, "MEDIUM", "Server Information Disclosure"),
            ("Status Page Exposed", 88, "HIGH", "Apache Mod_Status Enabled"),
            ("Server Info Disclosure", 72, "MEDIUM", "HTTP Headers Leak"),
            ("SSL Cert Reuse (Clearnet)", 92, "CRITICAL", "Certificate Reuse Across Networks"),
            ("Exposed Admin Panel", 96, "CRITICAL", "Administrative Interface Exposure"),
            ("No leak detected", 15, "LOW", "Secure Configuration")
        ]
        leak_type, confidence, severity, technical_detail = random.choice(leak_types)
        
        scan_result = {
            "onion_url": onion_url,
            "scan_time": datetime.now().isoformat(),
            "leak_type": leak_type,
            "confidence": confidence,
            "severity": severity,
            "technical_detail": technical_detail,
            "response_time_ms": random.randint(200, 1500),
            "server_banner": random.choice(["Apache/2.4.41 (Ubuntu)", "nginx/1.18.0", "CloudFlare-nginx"]),
            "tracking_methodology": "Passive Infrastructure Fingerprinting",
            "evidence_hash": f"SHA256:{random.randint(100000, 999999)}",
            "ssl_info": {
                "valid": random.choice([True, False]),
                "issuer": random.choice(["Let's Encrypt", "DigiCert", "Self-signed"]),
                "expires": "2026-12-31" if random.random() > 0.5 else "2024-01-15"
            }
        }
        self.scan_history.append(scan_result)
        return scan_result
    
    async def scan_wallet_activity(self, wallet_address: str) -> Dict:
        await asyncio.sleep(1.5)
        return {
            "wallet": wallet_address[:16] + "...",
            "total_transactions": random.randint(50, 5000),
            "total_volume_btc": round(random.uniform(0.5, 150.0), 4),
            "first_seen": f"202{random.randint(3,5)}-{random.randint(1,12):02d}-{random.randint(1,28):02d}",
            "last_seen": datetime.now().strftime("%Y-%m-%d"),
            "linked_addresses": random.randint(3, 25),
            "risk_score": random.randint(60, 98),
            "cluster_id": f"CLUSTER-{random.randint(1000, 9999)}",
            "tracking_method": "Blockchain Cluster Analysis",
            "correlation_confidence": random.randint(75, 98),
            "mixing_service_detected": random.choice([True, False])
        }
    
    async def search_threat_intel(self, query: str) -> List[Dict]:
        await asyncio.sleep(1.0)
        results = []
        for actor_id, actor in ACTORS_DB.items():
            if query.lower() in actor['handle'].lower() or any(query.lower() in alias.lower() for alias in actor['aliases']):
                results.append({
                    "type": "ACTOR", 
                    "handle": actor['handle'], 
                    "match_field": "handle/alias", 
                    "confidence": 95,
                    "tracking_evidence": "Handle/Alias Match",
                    "data": actor
                })
        for leak in LEAKS_DB:
            if query.lower() in leak['onion_url'].lower():
                results.append({
                    "type": "INFRASTRUCTURE", 
                    "onion": leak['onion_url'], 
                    "match_field": "onion_url", 
                    "confidence": leak['confidence'],
                    "tracking_evidence": "Infrastructure Leak Correlation",
                    "data": leak
                })
        if random.random() > 0.5:
            results.append({
                "type": "EXTERNAL_INTEL", 
                "source": random.choice(["VirusTotal", "AlienVault OTX", "MISP"]), 
                "match_field": "ioc_match", 
                "confidence": random.randint(70, 90),
                "tracking_evidence": "External Threat Intelligence Correlation"
            })
        return results

scanner = LiveScanner()

# ============================================================================
# ENHANCED DATABASES
# ============================================================================

ACTORS_DB = {
    "shadow_vendor": {
        "id": "ACT001", "handle": "ShadowVendor", "aliases": ["DarkKing", "PhantomX"],
        "marketplaces": ["AlphaMarket", "DarkEmporium", "SilkRoad2"], "status": "ACTIVE", "risk_level": "HIGH",
        "first_seen": "2024-01-15", "last_seen": "2026-09-16",
        "wallets": ["bc1q9x2k7m3n5p8q1r4t6y9u2i5o8p1a4s7d0f3g6h9j2l5z8x1c4v7b0n3m6"],
        "pgp_keys": ["0x8F3A2B1C4D5E6F7A"],
        "writing_samples": [
            "The product quality is guaranteed. Fast shipping via encrypted channels. Payment in BTC only.",
            "All items are tested and verified. Discreet packaging ensured. No refunds after delivery.",
            "Premium grade available. Bulk discounts for regular customers. Contact via PGP encrypted messages."
        ],
        "tracking_indicators": {
            "ssl_reuse": True,
            "wallet_cluster": "CLUSTER-4521",
            "stylometric_id": "STYLE-892",
            "behavioral_pattern": "Active 2-4 AM UTC, prefers Monero mixing"
        }
    },
    "crypto_master": {
        "id": "ACT002", "handle": "CryptoMaster", "aliases": ["BitLord", "CoinKing"],
        "marketplaces": ["AlphaMarket", "CryptoHaven", "DarkWallet"], "status": "ACTIVE", "risk_level": "HIGH",
        "first_seen": "2023-11-20", "last_seen": "2026-09-15",
        "wallets": ["bc1q7m3n5p8q1r4t6y9u2i5o8p1a4s7d0f3g6h9j2l5z8x1c4v7b0n3m6q9w2e5"],
        "pgp_keys": ["0x9A4B3C2D1E0F9A8B"],
        "writing_samples": [
            "Best crypto mixing service. Untraceable transactions guaranteed. 24/7 support available.",
            "Advanced tumbling technology. Multiple coin support. Instant confirmation.",
            "Privacy is our priority. No logs kept. Secure escrow system in place."
        ],
        "tracking_indicators": {
            "ssl_reuse": False,
            "wallet_cluster": "CLUSTER-7834",
            "stylometric_id": "STYLE-445",
            "behavioral_pattern": "Operates during European business hours"
        }
    }
}

LEAKS_DB = [
    {"id": "LEAK001", "onion_url": "shadowmarket7x.onion", "leak_type": "Exposed SSL Certificate", "severity": "CRITICAL", "confidence": 95, "detected_at": "2026-09-16T10:30:00Z", "actor_link": "shadow_vendor", "technical_detail": "Certificate CN matches clearnet domain", "tracking_method": "SSL Transparency Log Cross-Reference"},
    {"id": "LEAK002", "onion_url": "cryptoheist.onion", "leak_type": "SSL Cert Reuse (Clearnet)", "severity": "CRITICAL", "confidence": 92, "detected_at": "2026-09-16T05:15:00Z", "actor_link": "crypto_master", "technical_detail": "Same serial number on clearnet and onion", "tracking_method": "Certificate Serial Number Matching"},
    {"id": "LEAK003", "onion_url": "drugs4sale.onion", "leak_type": "Status Page Exposed", "severity": "HIGH", "confidence": 88, "detected_at": "2026-09-14T18:45:00Z", "actor_link": None, "technical_detail": "Apache mod_status enabled without auth", "tracking_method": "HTTP Endpoint Enumeration"},
    {"id": "LEAK004", "onion_url": "darkarms4u.onion", "leak_type": "Default Apache Banner", "severity": "MEDIUM", "confidence": 78, "detected_at": "2026-09-13T14:20:00Z", "actor_link": None, "technical_detail": "Server header reveals exact version", "tracking_method": "HTTP Header Analysis"}
]

AUDIT_LOG = []

# ============================================================================
# TRACKING METHODOLOGY EXPLANATIONS
# ============================================================================

TRACKING_STEPS = {
    "step1": {
        "title": "Infrastructure Fingerprinting",
        "description": "LeakRadar scans Tor hidden services for misconfigurations",
        "techniques": [
            "SSL Certificate Transparency Log Analysis",
            "HTTP Header Fingerprinting",
            "Server Banner Detection",
            "Status Page Enumeration"
        ],
        "output": "Identifies server-level leaks that can link .onion to clearnet"
    },
    "step2": {
        "title": "Blockchain Cluster Analysis",
        "description": "Wallet addresses are grouped into clusters using heuristics",
        "techniques": [
            "Common Input Ownership Heuristic",
            "Change Address Detection",
            "Peeling Chain Analysis",
            "Mixing Service Identification"
        ],
        "output": "Groups multiple addresses to single entity"
    },
    "step3": {
        "title": "Cross-Marketplace Correlation",
        "description": "TrustGraph links handles across different marketplaces",
        "techniques": [
            "PGP Key Matching",
            "Wallet Address Reuse Detection",
            "Vouching Relationship Mapping",
            "Username Pattern Analysis"
        ],
        "output": "Reveals actor's complete marketplace presence"
    },
    "step4": {
        "title": "Stylometric Analysis",
        "description": "AI analyzes writing style to detect rebrands",
        "techniques": [
            "TF-IDF Vectorization",
            "Cosine Similarity Matching",
            "N-gram Frequency Analysis",
            "Syntactic Pattern Recognition"
        ],
        "output": "Identifies same actor behind new handle (92% accuracy)"
    },
    "step5": {
        "title": "Behavioral Pattern Matching",
        "description": "Tracks operational habits and timing patterns",
        "techniques": [
            "Active Hours Analysis",
            "Transaction Timing Patterns",
            "Language Preference Tracking",
            "Pricing Strategy Consistency"
        ],
        "output": "Additional confidence layer for attribution"
    },
    "step6": {
        "title": "Confidence Score Calculation",
        "description": "Weighted evidence scoring for court-ready attribution",
        "formula": "SSL(40%) + Wallet(30%) + Style(20%) + Corroboration(10%)",
        "output": "Transparent, explainable confidence percentage"
    }
}

# ============================================================================
# CORE LOGIC
# ============================================================================

def calculate_confidence_score(actor_id: str) -> Dict:
    actor = ACTORS_DB.get(actor_id)
    if not actor:
        return {"score": 0, "breakdown": {}}
    cert_match = any(leak["actor_link"] == actor_id and "SSL" in leak["leak_type"] for leak in LEAKS_DB)
    cert_score = 40 if cert_match else 0
    wallet_score = 30 if len(actor["wallets"]) > 0 else 0
    style_score = 0
    if len(actor["writing_samples"]) >= 2:
        vectorizer = TfidfVectorizer()
        tfidf_matrix = vectorizer.fit_transform(actor["writing_samples"])
        similarity_matrix = cosine_similarity(tfidf_matrix)
        avg_similarity = np.mean(similarity_matrix[similarity_matrix < 1])
        style_score = int(avg_similarity * 20)
    else:
        style_score = 15
    corrob_score = 10 if len(actor["marketplaces"]) > 1 else 0
    return {
        "score": cert_score + wallet_score + style_score + corrob_score,
        "breakdown": {
            "ssl_certificate": cert_score, 
            "wallet_correlation": wallet_score, 
            "stylometric_match": style_score, 
            "corroboration": corrob_score
        },
        "evidence_count": len([l for l in LEAKS_DB if l["actor_link"] == actor_id])
    }

def log_audit_action(user: str, action: str, target: str):
    AUDIT_LOG.append({
        "timestamp": datetime.now().isoformat(), 
        "user": user, 
        "action": action, 
        "target": target,
        "ip_address": "192.168.1.100"
    })

# ============================================================================
# API ENDPOINTS
# ============================================================================

@app.get("/api/search/investigate")
async def investigate_target(query: str = Query(..., min_length=2)):
    """Advanced Deep-Dive Search for Demo"""
    await asyncio.sleep(2.5) # Fake processing time for dramatic effect
    
    # Mocking a deep investigation result
    target_id = "shadow_vendor" if "shadow" in query.lower() or "vendor" in query.lower() else "crypto_master"
    actor = ACTORS_DB.get(target_id)
    
    if not actor:
        return {"status": "not_found", "message": "No matching threat actor or infrastructure found."}

    confidence = calculate_confidence_score(target_id)
    
    # Generate a rich "Dossier"
    dossier = {
        "status": "success",
        "scan_logs": [
            f"[{datetime.now().strftime('%H:%M:%S')}] Initiating deep scan for: {query}",
            f"[{datetime.now().strftime('%H:%M:%S')}] Querying Certificate Transparency Logs (crt.sh)...",
            f"[{datetime.now().strftime('%H:%M:%S')}] Scanning Blockchain Cluster DB (Wallet: {actor['wallets'][0][:10]}...)",
            f"[{datetime.now().strftime('%H:%M:%S')}] Cross-referencing PGP Key {actor['pgp_keys'][0]} across 12 marketplaces...",
            f"[{datetime.now().strftime('%H:%M:%S')}] Running Stylometric AI analysis on 3 writing samples...",
            f"[{datetime.now().strftime('%H:%M:%S')}] Correlating behavioral patterns (Active hours: 02:00-04:00 UTC)",
            f"[{datetime.now().strftime('%H:%M:%S')}] ✅ MATCH CONFIRMED. Confidence: {confidence['score']}%"
        ],
        "dossier": {
            "handle": actor["handle"],
            "aliases": actor["aliases"],
            "risk_level": actor["risk_level"],
            "status": actor["status"],
            "first_seen": actor["first_seen"],
            "confidence_score": confidence["score"],
            "breakdown": confidence["breakdown"],
            "wallets": actor["wallets"],
            "pgp_keys": actor["pgp_keys"],
            "marketplaces": actor["marketplaces"]
        },
        "evidence": [
            {"type": "SSL Leak", "detail": "Certificate reused from clearnet domain shadowmarket.com", "severity": "CRITICAL"},
            {"type": "Wallet Cluster", "detail": f"Linked to cluster CLUSTER-4521 with 14 associated addresses", "severity": "HIGH"},
            {"type": "Stylometry", "detail": "Writing style matches 'DarkKing' with 92.4% similarity", "severity": "HIGH"}
        ]
    }
    
    log_audit_action("analyst", "DEEP_INVESTIGATE", query)
    return dossier



@app.get("/")
async def read_root():
    return FileResponse("index.html")

@app.get("/api/dashboard")
def get_dashboard():
    log_audit_action("analyst", "VIEW_DASHBOARD", "main")
    confidence = calculate_confidence_score("shadow_vendor")
    return {
        "stats": {
            "active_scans": 247 + len(scanner.scan_history),
            "actors_tracked": len(ACTORS_DB),
            "infrastructure_leaks": len(LEAKS_DB) + len([s for s in scanner.scan_history if s.get('leak_type') != 'No leak detected']),
            "avg_confidence": confidence["score"]
        },
        "confidence": confidence,
        "recent_leaks": LEAKS_DB[:5] + scanner.scan_history[-3:],
        "live_scans_today": len(scanner.scan_history),
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/actors")
def get_actors():
    log_audit_action("analyst", "VIEW_ACTORS", "all")
    actors_list = []
    for actor_id, actor in ACTORS_DB.items():
        confidence = calculate_confidence_score(actor_id)
        actors_list.append({
            **actor, 
            "confidence_score": confidence["score"], 
            "confidence_breakdown": confidence["breakdown"]
        })
    return {"actors": actors_list}

@app.get("/api/leaks")
def get_leaks():
    log_audit_action("analyst", "VIEW_LEAKS", "all")
    return {"leaks": LEAKS_DB}

@app.get("/api/graph")
def get_trust_graph():
    log_audit_action("analyst", "VIEW_GRAPH", "trust_network")
    return {
        "nodes": [
            {"id": "shadow_vendor", "label": "ShadowVendor\n(DarkKing)", "type": "actor", "size": 35, "color": "#3b82f6"},
            {"id": "crypto_master", "label": "CryptoMaster", "type": "actor", "size": 30, "color": "#3b82f6"},
            {"id": "wallet_1", "label": "bc1q...9x2", "type": "wallet", "size": 28, "color": "#f59e0b"},
            {"id": "pgp_1", "label": "0x8F3A...B2", "type": "pgp", "size": 28, "color": "#10b981"},
            {"id": "alpha_market", "label": "AlphaMarket", "type": "marketplace", "size": 22, "color": "#6b7280"}
        ],
        "edges": [
            {"from": "shadow_vendor", "to": "alpha_market", "label": "operates", "arrows": "to"},
            {"from": "shadow_vendor", "to": "wallet_1", "label": "owns", "arrows": "to"},
            {"from": "shadow_vendor", "to": "pgp_1", "label": "uses", "arrows": "to"},
            {"from": "crypto_master", "to": "alpha_market", "label": "operates", "arrows": "to"}
        ]
    }

@app.get("/api/timeline")
def get_timeline():
    log_audit_action("analyst", "VIEW_TIMELINE", "shadow_vendor")
    return {
        "timeline": [
            {"date": "Jan 2024", "event": "Handle 'ShadowVendor' created on AlphaMarket", "evidence": "Forum Registration", "icon": "fa-user-plus", "confidence": 100},
            {"date": "Mar 2024", "event": "First transaction recorded - 2.5 BTC", "evidence": "Blockchain Analysis", "icon": "fa-bitcoin", "confidence": 95},
            {"date": "Jun 2024", "event": "PGP Key 0x8F3A...B2 linked to handle", "evidence": "Marketplace Verification", "icon": "fa-key", "confidence": 98},
            {"date": "Sep 2024", "event": "SSL Certificate leak detected on hidden service", "evidence": "LeakRadar Scan", "icon": "fa-exclamation-triangle", "confidence": 95},
            {"date": "Dec 2024", "event": "Wallet bc1q...9x2 correlated with transactions", "evidence": "Blockchain Cluster Analysis", "icon": "fa-wallet", "confidence": 92},
            {"date": "Feb 2025", "event": "Rebrand to 'DarkKing' detected - Stylometry Match: 92%", "evidence": "AI PersonaTrail Analysis", "icon": "fa-robot", "confidence": 92},
            {"date": "Present", "event": "Active on 3 marketplaces - High confidence attribution", "evidence": "Multi-source Correlation", "icon": "fa-check-circle", "confidence": 88}
        ]
    }

@app.get("/api/tracking-methodology")
def get_tracking_methodology():
    return {"steps": TRACKING_STEPS}

@app.get("/api/live/search")
async def live_search(q: str = Query(..., min_length=2)):
    log_audit_action("analyst", "LIVE_SEARCH", q)
    results = await scanner.search_threat_intel(q)
    return {"query": q, "results_count": len(results), "results": results, "timestamp": datetime.now().isoformat()}

@app.get("/api/live/scan/onion/{onion_url}")
async def live_scan_onion(onion_url: str):
    log_audit_action("analyst", "LIVE_SCAN_ONION", onion_url)
    return await scanner.scan_onion_service(onion_url)

@app.get("/api/live/scan/wallet/{wallet_address}")
async def live_scan_wallet(wallet_address: str):
    log_audit_action("analyst", "LIVE_SCAN_WALLET", wallet_address[:16] + "...")
    return await scanner.scan_wallet_activity(wallet_address)

@app.get("/api/live/scan/ssl/{domain}")
async def live_scan_ssl(domain: str):
    log_audit_action("analyst", "LIVE_SCAN_SSL", domain)
    return await scanner.scan_ssl_cert(domain)

@app.get("/api/audit-log")
def get_audit_log():
    return {"audit_log": AUDIT_LOG[-50:]}

@app.get("/api/export/csv")
def export_csv():
    log_audit_action("analyst", "EXPORT_CSV", "all_data")
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ACTORS"])
    writer.writerow(["ID", "Handle", "Aliases", "Marketplaces", "Status", "Risk Level", "Confidence Score"])
    for actor_id, actor in ACTORS_DB.items():
        confidence = calculate_confidence_score(actor_id)
        writer.writerow([
            actor["id"], 
            actor["handle"], 
            ", ".join(actor["aliases"]), 
            ", ".join(actor["marketplaces"]), 
            actor["status"], 
            actor["risk_level"],
            confidence["score"]
        ])
    writer.writerow([])
    writer.writerow(["INFRASTRUCTURE LEAKS"])
    writer.writerow(["ID", "Onion URL", "Leak Type", "Severity", "Confidence", "Tracking Method"])
    for leak in LEAKS_DB:
        writer.writerow([
            leak["id"], 
            leak["onion_url"], 
            leak["leak_type"], 
            leak["severity"], 
            leak["confidence"],
            leak.get("tracking_method", "N/A")
        ])
    output.seek(0)
    return FileResponse(io.BytesIO(output.getvalue().encode()), media_type="text/csv", filename="personatrail_detailed_export.csv")

# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print("\n" + "="*80)
    print("🕵️  PersonaTrail - ADVANCED TRACKING DEMO")
    print("="*80)
    print("✅ 6-Step Tracking Methodology")
    print("✅ Infrastructure Fingerprinting (LeakRadar)")
    print("✅ Blockchain Cluster Analysis")
    print("✅ Cross-Marketplace Correlation (TrustGraph)")
    print("✅ AI Stylometric Matching (PersonaTrail)")
    print("✅ Behavioral Pattern Analysis")
    print("✅ Confidence Score Calculation")
    print("="*80)
    print("\n🌐 Open browser: http://localhost:8000")
    print("\n📊 Demo Features:")
    print("   - Step-by-step tracking explanation")
    print("   - Live scanning simulation")
    print("   - Interactive graph visualization")
    print("   - Detailed attribution timeline")
    print("="*80 + "\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)