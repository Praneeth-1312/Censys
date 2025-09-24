

from fastapi import FastAPI
from fastapi import UploadFile, File, HTTPException
import json
from pydantic import BaseModel
from typing import Any, Dict, List, Optional
from dotenv import load_dotenv
import os
from pathlib import Path
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # allow React frontend to call backend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=env_path, override=True)


app = FastAPI()

HOSTS = []

@app.get("/")
def read_root():
    return {"message": "Censys Summarization Agent Backend is running"}

@app.post("/upload_dataset/")
async def upload_dataset(file: UploadFile = File(...)):
    try:
        content = await file.read()
        data = json.loads(content)

        if isinstance(data, list):
            hosts = data
        elif isinstance(data, dict):
            if "hosts" in data and isinstance(data["hosts"], list):
                hosts = data["hosts"]
            elif all(isinstance(v, dict) for v in data.values()):
                hosts = list(data.values())
            else:
                raise ValueError("JSON structure not recognized. Provide a list of hosts or an object with 'hosts' list.")
        else:
            raise ValueError("JSON root must be a list or object.")

        global HOSTS
        HOSTS = hosts
        return {"status": "success", "hosts_loaded": len(HOSTS)}
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

class SummarizeRequest(BaseModel):
    ip: str

def _find_host_by_ip(ip: str) -> Optional[Dict[str, Any]]:
    for host in HOSTS:
        if not isinstance(host, dict):
            continue
        values = [
            host.get("ip"),
            host.get("ip_address"),
            host.get("ipv4"),
            host.get("ipv6"),
        ]
        if ip in [v for v in values if isinstance(v, str)]:
            return host
    return None

def _extract_services(host: Dict[str, Any]) -> List[Dict[str, Any]]:
    services = []
    candidates = host.get("services") or host.get("open_ports") or host.get("ports")
    if isinstance(candidates, list):
        for svc in candidates:
            if isinstance(svc, dict):
                port = svc.get("port") or svc.get("port_number") or svc.get("dst_port")
                name = svc.get("service") or svc.get("name") or svc.get("protocol")
                product = svc.get("product") or svc.get("software")
                services.append({"port": port, "service": name, "product": product})
            elif isinstance(svc, int):
                services.append({"port": svc, "service": None, "product": None})
    elif isinstance(candidates, dict):
        for k, v in candidates.items():
            try:
                port = int(k)
            except Exception:
                port = v.get("port") if isinstance(v, dict) else None
            name = v.get("service") if isinstance(v, dict) else None
            product = v.get("product") if isinstance(v, dict) else None
            services.append({"port": port, "service": name, "product": product})
    return services

def _extract_location(host: Dict[str, Any]) -> Dict[str, Any]:
    loc = host.get("location") or host.get("geo") or {}
    if not isinstance(loc, dict):
        return {}
    return {
        "country": loc.get("country") or loc.get("country_name"),
        "city": loc.get("city"),
        "region": loc.get("region") or loc.get("state"),
    }

def _extract_vulns(host: Dict[str, Any]) -> List[Dict[str, Any]]:
    vulns = host.get("vulnerabilities") or host.get("vulns") or []
    results: List[Dict[str, Any]] = []
    if isinstance(vulns, list):
        for v in vulns:
            if isinstance(v, dict):
                results.append({
                    "id": v.get("id") or v.get("cve"),
                    "severity": v.get("severity") or v.get("cvss_severity"),
                    "score": v.get("cvss") or v.get("cvss_score"),
                })
            elif isinstance(v, str):
                results.append({"id": v, "severity": None, "score": None})
    elif isinstance(vulns, dict):
        for k, v in vulns.items():
            if isinstance(v, dict):
                results.append({
                    "id": k,
                    "severity": v.get("severity") or v.get("cvss_severity"),
                    "score": v.get("cvss") or v.get("cvss_score"),
                })
            else:
                results.append({"id": k, "severity": None, "score": None})
    return results

def _compute_risk_level(services: List[Dict[str, Any]], vulns: List[Dict[str, Any]]) -> str:
    open_ports = len([s for s in services if s.get("port") is not None])
    high_vulns = len([v for v in vulns if str(v.get("severity")).lower() in {"high", "critical"} or (isinstance(v.get("score"), (int, float)) and v.get("score") and v.get("score") >= 7.0)])
    if high_vulns >= 2 or open_ports >= 10:
        return "High"
    if high_vulns == 1 or open_ports >= 5:
        return "Medium"
    return "Low"

async def _generate_summary_text(structured: Dict[str, Any]) -> str:
    # Try Gemini first if configured
    try:
        gemini_key = os.getenv("GEMINI_API_KEY")
        print("Gemini Key loaded:", gemini_key is not None)
        if gemini_key:
            try:
                import google.generativeai as genai
                genai.configure(api_key=gemini_key)
                model = genai.GenerativeModel("gemini-1.5-flash")
                prompt = (
                    "You are a cybersecurity analyst. Produce a concise 3-5 sentence summary "
                    "for a security report using the provided structured host data. Be factual, avoid speculation, "
                    "and mention location, prominent services/ports, notable vulnerabilities (CVE ids if present), and risk level.\n\n"
                    f"Structured data (JSON):\n{json.dumps(structured, ensure_ascii=False)}"
                )
                print("Calling Gemini API...")
                resp = model.generate_content(prompt)
                txt = (resp.text or "").strip()
                print("Gemini response:", txt)
                if txt:
                    return txt
            except Exception as e:
                print("Gemini error:", e)
                pass
    except Exception:
        pass

    # Then try OpenAI if configured
    try:
        api_key = os.getenv("OPENAI_API_KEY")
        if api_key:
            try:
                from openai import OpenAI
                client = OpenAI(api_key=api_key)
                messages = [
                    {"role": "system", "content": "You are a cybersecurity analyst. Write concise factual summaries."},
                    {"role": "user", "content": (
                        "Summarize this host for a security report in 3-5 sentences. "
                        f"Data: {json.dumps(structured, ensure_ascii=False)}"
                    )},
                ]
                resp = client.chat.completions.create(model="gpt-4o-mini", messages=messages, temperature=0.2)
                txt = resp.choices[0].message.content.strip()
                if txt:
                    return txt
            except Exception:
                pass
    except Exception:
        pass
    ip = structured.get("ip")
    loc = structured.get("location") or {}
    services = structured.get("services") or []
    vulns = structured.get("vulnerabilities") or []
    port_list = ", ".join([str(s.get("port")) for s in services if s.get("port") is not None][:10])
    vuln_ids = ", ".join([str(v.get("id")) for v in vulns if v.get("id")][:10])
    location_str = ", ".join([v for v in [loc.get("city"), loc.get("region"), loc.get("country")] if v]) or "Unknown"
    return (
        f"Host {ip} located in {location_str}. "
        f"Open services on ports: {port_list or 'none'}. "
        f"Known vulnerabilities: {vuln_ids or 'none'}. "
        f"Risk level assessed as {structured.get('risk_level','Low')}."
    )

@app.post("/summarize_host/")
async def summarize_host(payload: SummarizeRequest):
    host = _find_host_by_ip(payload.ip)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")

    services = _extract_services(host)
    location = _extract_location(host)
    vulnerabilities = _extract_vulns(host)
    risk_level = _compute_risk_level(services, vulnerabilities)

    structured = {
        "ip": payload.ip,
        "location": location,
        "services": services,
        "vulnerabilities": vulnerabilities,
        "risk_level": risk_level,
    }

    summary_text = await _generate_summary_text(structured)

    return {
        "ip": structured["ip"],
        "location": structured["location"],
        "services": structured["services"],
        "vulnerabilities": structured["vulnerabilities"],
        "risk_level": structured["risk_level"],
        "summary": summary_text,
    }
@app.get("/check_key/")
def check_key():
    gemini_key = os.getenv("GEMINI_API_KEY")
    return {"GEMINI_API_KEY": gemini_key}
