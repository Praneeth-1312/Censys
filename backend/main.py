

from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, status
from fastapi.responses import JSONResponse
import json
from pydantic import BaseModel, Field, field_validator
from typing import Any, Dict, List, Optional, Union
from dotenv import load_dotenv
import os
from pathlib import Path
from fastapi.middleware.cors import CORSMiddleware
import logging
from datetime import datetime
import traceback





# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

env_path = Path(__file__).parent / ".env"
load_dotenv(dotenv_path=env_path, override=True)

app = FastAPI(
    title="Censys Host Summarization API",
    description="API for analyzing and summarizing host data from Censys datasets",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # allow React frontend to call backend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state
HOSTS = []
UPLOAD_TIMESTAMP = None

# Pydantic Models
class SummarizeRequest(BaseModel):
    ip: str = Field(..., description="IP address to summarize", min_length=7, max_length=45)
    
    @field_validator('ip')
    @classmethod
    def validate_ip(cls, v):
        # Basic IP validation
        parts = v.split('.')
        if len(parts) == 4:
            try:
                for part in parts:
                    if not 0 <= int(part) <= 255:
                        raise ValueError("Invalid IP address")
                return v
            except ValueError:
                pass
        # For IPv6 or other formats, just check it's not empty
        if not v.strip():
            raise ValueError("IP address cannot be empty")
        return v.strip()

class HostSummary(BaseModel):
    ip: str
    location: Dict[str, Any]
    services: List[Dict[str, Any]]
    vulnerabilities: List[Dict[str, Any]]
    risk_level: str
    summary: str

class BatchSummaryResponse(BaseModel):
    summaries: List[Dict[str, str]]
    total_hosts: int
    processing_time: float

class UploadResponse(BaseModel):
    status: str
    hosts_loaded: int
    upload_timestamp: str
    file_name: str

class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
    timestamp: str

# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {str(exc)}")
    logger.error(traceback.format_exc())
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="Internal server error",
            detail=str(exc) if app.debug else "An unexpected error occurred",
            timestamp=datetime.now().isoformat()
        ).dict()
    )

@app.get("/")
def read_root():
    return {
        "message": "Censys Summarization Agent Backend is running",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "hosts_loaded": len(HOSTS),
        "last_upload": UPLOAD_TIMESTAMP
    }

@app.post("/upload_dataset/", response_model=UploadResponse)
async def upload_dataset(file: UploadFile = File(...)):
    global HOSTS, UPLOAD_TIMESTAMP
    
    try:
        # Validate file
        if not file.filename:
            raise HTTPException(status_code=400, detail="No file provided")
        
        if not file.filename.lower().endswith('.json'):
            raise HTTPException(status_code=400, detail="File must be a JSON file")
        
        # Check file size (10MB limit)
        content = await file.read()
        if len(content) > 10 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="File too large (max 10MB)")
        
        # Parse JSON
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise HTTPException(status_code=400, detail=f"Invalid JSON: {str(e)}")

        # Extract hosts from various JSON structures
        if isinstance(data, list):
            hosts = data
        elif isinstance(data, dict):
            if "hosts" in data and isinstance(data["hosts"], list):
                hosts = data["hosts"]
            elif all(isinstance(v, dict) for v in data.values()):
                hosts = list(data.values())
            else:
                raise HTTPException(
                    status_code=400, 
                    detail="JSON structure not recognized. Provide a list of hosts or an object with 'hosts' list."
                )
        else:
            raise HTTPException(status_code=400, detail="JSON root must be a list or object.")

        # Validate hosts structure
        if not hosts:
            raise HTTPException(status_code=400, detail="No hosts found in dataset")
        
        # Basic validation of host structure
        valid_hosts = []
        for i, host in enumerate(hosts):
            if not isinstance(host, dict):
                logger.warning(f"Skipping invalid host at index {i}: not a dictionary")
                continue
            # Check for at least one IP field
            ip_fields = ["ip", "ip_address", "ipv4", "ipv6"]
            if not any(host.get(field) for field in ip_fields):
                logger.warning(f"Skipping host at index {i}: no IP address found")
                continue
            valid_hosts.append(host)
        
        if not valid_hosts:
            raise HTTPException(status_code=400, detail="No valid hosts found in dataset")

        HOSTS = valid_hosts
        UPLOAD_TIMESTAMP = datetime.now().isoformat()
        
        logger.info(f"Successfully uploaded dataset: {len(HOSTS)} hosts from {file.filename}")
        
        return UploadResponse(
            status="success",
            hosts_loaded=len(HOSTS),
            upload_timestamp=UPLOAD_TIMESTAMP,
            file_name=file.filename
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

def _find_host_by_ip(ip: str) -> Optional[Dict[str, Any]]:
    # Trim the search IP to handle spaces
    search_ip = ip.strip()
    
    for host in HOSTS:
        if not isinstance(host, dict):
            continue
        values = [
            host.get("ip"),
            host.get("ip_address"),
            host.get("ipv4"),
            host.get("ipv6"),
        ]
        # Trim all values before comparison to handle spaces in dataset
        trimmed_values = [v.strip() if isinstance(v, str) else v for v in values]
        if search_ip in trimmed_values:
            return host
    return None

def _extract_services(host: Dict[str, Any]) -> List[Dict[str, Any]]:
    services: List[Dict[str, Any]] = []
    candidates = host.get("services") or host.get("open_ports") or host.get("ports")
    if isinstance(candidates, list):
        for svc in candidates:
            if isinstance(svc, dict):
                port = svc.get("port") or svc.get("port_number") or svc.get("dst_port")
                name = svc.get("service") or svc.get("name") or svc.get("protocol")
                product = svc.get("product")
                software = svc.get("software")
                software_str = None
                if isinstance(software, list) and software:
                    s0 = software[0]
                    if isinstance(s0, dict):
                        vendor = s0.get("vendor")
                        prod = s0.get("product")
                        version = s0.get("version")
                        parts = [p for p in [prod, version] if p]
                        software_str = " ".join(parts) if parts else None
                        if vendor and software_str:
                            software_str = f"{software_str} ({vendor})"
                elif isinstance(software, str):
                    software_str = software
                banner = svc.get("banner")
                svc_vulns: List[Dict[str, Any]] = []
                vuln_list = svc.get("vulnerabilities") or []
                if isinstance(vuln_list, list):
                    for v in vuln_list:
                        if isinstance(v, dict):
                            svc_vulns.append({
                                "id": v.get("cve_id") or v.get("id") or v.get("cve"),
                                "severity": v.get("severity"),
                                "score": v.get("cvss_score") or v.get("cvss"),
                                "description": v.get("description") or v.get("note"),
                            })
                services.append({
                    "port": port,
                    "service": name,
                    "product": product or software_str,
                    "banner": banner,
                    "vulnerabilities": svc_vulns,
                })
            elif isinstance(svc, int):
                services.append({"port": svc, "service": None, "product": None, "banner": None, "vulnerabilities": []})
    elif isinstance(candidates, dict):
        for k, v in candidates.items():
            try:
                port = int(k)
            except Exception:
                port = v.get("port") if isinstance(v, dict) else None
            name = v.get("service") if isinstance(v, dict) else None
            product = v.get("product") if isinstance(v, dict) else None
            services.append({"port": port, "service": name, "product": product, "banner": None, "vulnerabilities": []})
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
    # Append service-level vulnerabilities
    for svc in _extract_services(host):
        for v in svc.get("vulnerabilities") or []:
            results.append({
                "id": v.get("id"),
                "severity": v.get("severity"),
                "score": v.get("score"),
                "description": v.get("description"),
            })
    return results

def _extract_threat(host: Dict[str, Any]) -> Dict[str, Any]:
    ti = host.get("threat_intelligence") or {}
    labels = ti.get("security_labels") or ti.get("labels") or []
    risk_level = ti.get("risk_level") or ti.get("risk")
    malware = ti.get("malware_families") or []
    if not isinstance(labels, list):
        labels = []
    if not isinstance(malware, list):
        malware = []
    return {"labels": labels, "risk_level": risk_level, "malware_families": malware}

def _extract_org_asn(host: Dict[str, Any]) -> Dict[str, Any]:
    org = host.get("organization") or host.get("org") or host.get("owner")
    asn_block = host.get("autonomous_system") or host.get("asn") or {}
    if isinstance(asn_block, dict):
        asn = asn_block.get("asn") or asn_block.get("number") or asn_block.get("asn_number")
        asn_name = asn_block.get("name") or asn_block.get("asn_name")
    else:
        asn = asn_block if isinstance(asn_block, (str, int)) else None
        asn_name = None
    return {
        "organization": org,
        "asn": asn,
        "asn_name": asn_name,
    }

def _extract_os(host: Dict[str, Any]) -> Optional[str]:
    # Try common OS fields
    candidates = [
        host.get("os"),
        host.get("operating_system"),
        host.get("platform"),
    ]
    for c in candidates:
        if isinstance(c, str) and c.strip():
            return c
    # Sometimes OS might be present in banner fields per service; skip deep scan for speed
    return None

def _extract_cloud_provider(host: Dict[str, Any]) -> Optional[str]:
    # Common cloud hints
    provider = host.get("cloud_provider") or host.get("cloud") or host.get("provider")
    if isinstance(provider, str) and provider.strip():
        return provider
    cloud = host.get("cloud")
    if isinstance(cloud, dict):
        for key in ["provider", "name", "service"]:
            val = cloud.get(key)
            if isinstance(val, str) and val.strip():
                return val
    return None

def _compute_risk_with_reason(services: List[Dict[str, Any]], vulns: List[Dict[str, Any]], threat: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """Compute Risk Label and Risk Rationale per latest rules (CVSS tiers + service count + malware bump)."""
    num_services = len([s for s in services if s.get("port") is not None])
    highest_cvss: float = 0.0
    high_critical_scores: List[str] = []
    for v in vulns:
        score_val = v.get("score")
        score: Optional[float] = None
        try:
            if isinstance(score_val, str):
                score = float(score_val)
            elif isinstance(score_val, (int, float)):
                score = float(score_val)
        except Exception:
            score = None
        if isinstance(score, float):
            highest_cvss = max(highest_cvss, score)
            if score >= 7.0:
                high_critical_scores.append(f"{score:.1f}")

    malware_list: List[str] = []
    if isinstance(threat, dict):
        malware = threat.get("malware_families") or []
        if isinstance(malware, list):
            malware_list = [m for m in malware if isinstance(m, str)]

    # Base level from CVSS tiers
    if highest_cvss >= 9.0:
        level = "Critical"
        base_reason = "critical CVE (CVSS≥9)"
    elif highest_cvss >= 7.0:
        level = "High"
        base_reason = "high CVE (CVSS≥7)"
    elif highest_cvss >= 4.0:
        level = "Medium"
        base_reason = "medium CVE (CVSS≥4)"
    else:
        level = "Low"
        base_reason = "no significant CVEs"

    # Service count increases risk by one level if 3+ services
    def bump(lvl: str) -> str:
        order = ["Low", "Medium", "High", "Critical"]
        i = order.index(lvl) if lvl in order else 2
        return order[min(i + 1, len(order) - 1)]

    if num_services >= 3:
        level = bump(level)
        base_reason += f"; {num_services} exposed services"
    else:
        base_reason += f"; {num_services} exposed services"

    # Malware presence bumps risk by one level
    if malware_list:
        level = bump(level)
        base_reason += "; malware detected"

    scores_text = ", ".join(sorted(set(high_critical_scores), reverse=True)) or "none"
    malware_text = ", ".join(malware_list) if malware_list else "none"
    reason = f"CVSS scores: {scores_text}; Exposed services: {num_services}; Malware: {malware_text}; Reason: {base_reason}"

    return {"level": level, "reason": reason}

def _normalize_risk_label(value: Optional[str]) -> Optional[str]:
    if not isinstance(value, str):
        return None
    norm = value.strip().lower()
    mapping = {
        "critical": "Critical",
        "crit": "Critical",
        "high": "High",
        "med": "Medium",
        "medium": "Medium",
        "low": "Low",
    }
    return mapping.get(norm)

def _max_risk(level_a: Optional[str], level_b: Optional[str]) -> str:
    order = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
    a = _normalize_risk_label(level_a) or "Low"
    b = _normalize_risk_label(level_b) or "Low"
    return a if order[a] >= order[b] else b

def _format_summary_response(text: str) -> str:
    """
    Format the AI response into clean, readable paragraph format.
    """
    # First, handle the specific case where we have mixed format
    # Look for the pattern: "Host: IP\n⚠️ Critical-Risk Host: ..."
    if 'Host: ' in text and '⚠️' in text and ' - ' in text:
        # This is the mixed format we're seeing
        lines = text.split('\n')
        if len(lines) >= 2 and lines[0].startswith('Host: ') and '⚠️' in lines[1]:
            # Extract the main content from the second line
            main_content = lines[1].strip()
            # Process the main content as single-line
            return _format_single_line_content(main_content)
    
    # Also handle the case where it's all on one line but has the mixed pattern
    if 'Host: ' in text and '⚠️' in text and ' - ' in text and '\n' not in text:
        # Find where the main content starts (after "Host: IP")
        parts = text.split('⚠️', 1)
        if len(parts) == 2:
            main_content = '⚠️' + parts[1].strip()
            return _format_single_line_content(main_content)
    
    # Handle multi-line input
    if '\n' in text:
        lines = text.split('\n')
        paragraphs = []
        current_paragraph = []
        
        for line in lines:
            line = line.strip()
            if not line:
                if current_paragraph:
                    paragraphs.append(' '.join(current_paragraph))
                    current_paragraph = []
                continue
            
            # Check if this is a new section
            if line.startswith('- ') and any(line.startswith(f'- {header}') for header in ['Network:', 'Exposed Services:', 'Critical Vulnerabilities:', 'Threat Intel:', 'Risk Rationale:']):
                if current_paragraph:
                    paragraphs.append(' '.join(current_paragraph))
                    current_paragraph = []
                current_paragraph.append(line)
            elif line.startswith('Recommendations:'):
                if current_paragraph:
                    paragraphs.append(' '.join(current_paragraph))
                    current_paragraph = []
                # Handle recommendations specially
                rec_content = line.replace('Recommendations:', '').strip()
                if rec_content:
                    paragraphs.append(f"Recommendations: {rec_content}")
                else:
                    paragraphs.append("Recommendations: See detailed analysis above.")
            elif line.startswith('- '):
                # This is a recommendation item
                if current_paragraph and not any(p.startswith('Recommendations:') for p in paragraphs):
                    paragraphs.append(' '.join(current_paragraph))
                    current_paragraph = []
                rec_item = line[2:].strip()  # Remove "- " prefix
                if rec_item:
                    if paragraphs and paragraphs[-1].startswith('Recommendations:'):
                        paragraphs[-1] += f"; {rec_item}"
                    else:
                        paragraphs.append(f"Recommendations: {rec_item}")
            else:
                # Regular content
                current_paragraph.append(line)
        
        # Add final paragraph
        if current_paragraph:
            paragraphs.append(' '.join(current_paragraph))
        
        return "\n\n".join(paragraphs)
    else:
        # Single-line input
        return _format_single_line_content(text)

def format_host_summary(text: str) -> str:
    """
    Convert the messy single-line output into beautiful, structured format.
    Clean Python implementation.
    """
    # Handle the specific format we're getting
    if 'Recommendations:' in text:
        main_part, recommendations_part = text.split('Recommendations:', 1)
        main_part = main_part.strip()
        recommendations_part = recommendations_part.strip()
        
        # Parse the main part
        sections = main_part.split(' - ')
        
        if len(sections) > 1:
            # First section is the header
            header = sections[0].strip()
            
            # Parse each section
            network_info = []
            services_info = []
            vulnerabilities_info = []
            threat_info = []
            risk_info = []
            
            for section in sections[1:]:
                section = section.strip()
                if not section:
                    continue
                    
                if section.startswith('Network:'):
                    network_info.append(section.replace('Network:', '').strip())
                elif section.startswith('Exposed Services:'):
                    services_info.append(section.replace('Exposed Services:', '').strip())
                elif section.startswith('Critical Vulnerabilities:'):
                    vulnerabilities_info.append(section.replace('Critical Vulnerabilities:', '').strip())
                elif section.startswith('Threat Intel:'):
                    threat_info.append(section.replace('Threat Intel:', '').strip())
                elif section.startswith('Risk Rationale:'):
                    risk_info.append(section.replace('Risk Rationale:', '').strip())
            
            # Build the formatted output
            output_lines = [header, ""]  # Header with blank line
            
            # Network and Services section
            if network_info or services_info:
                output_lines.append("🌐")
                output_lines.append("NETWORK & SERVICES")
                if network_info:
                    output_lines.append(f"• Network: {', '.join(network_info)}")
                if services_info:
                    output_lines.append(f"• Exposed Services: {', '.join(services_info)}")
                output_lines.append("")
            
            # Security Assessment section
            if vulnerabilities_info or threat_info:
                output_lines.append("🔒")
                output_lines.append("SECURITY ASSESSMENT")
                if vulnerabilities_info:
                    output_lines.append(f"• Critical Vulnerabilities: {', '.join(vulnerabilities_info)}")
                if threat_info:
                    output_lines.append(f"• Threat Intelligence: {', '.join(threat_info)}")
                output_lines.append("")
            
            # Risk Analysis section
            if risk_info:
                output_lines.append("⚠️")
                output_lines.append("RISK ANALYSIS")
                output_lines.append(f"• {', '.join(risk_info)}")
                output_lines.append("")
            
            # Recommendations section
            if recommendations_part:
                output_lines.append("📋")
                output_lines.append("RECOMMENDATIONS")
                rec_items = [item.strip() for item in recommendations_part.split(';') if item.strip()]
                for i, rec in enumerate(rec_items, 1):
                    if rec and not rec.startswith('See detailed analysis'):
                        output_lines.append(f"{i}. {rec}")
                output_lines.append("")
            
            return "\n".join(output_lines).strip()
        else:
            return main_part
    else:
        # No recommendations, process normally
        sections = text.split(' - ')
        
        if len(sections) > 1:
            header = sections[0].strip()
            
            # Parse each section
            network_info = []
            services_info = []
            vulnerabilities_info = []
            threat_info = []
            risk_info = []
            
            for section in sections[1:]:
                section = section.strip()
                if not section:
                    continue
                    
                if section.startswith('Network:'):
                    network_info.append(section.replace('Network:', '').strip())
                elif section.startswith('Exposed Services:'):
                    services_info.append(section.replace('Exposed Services:', '').strip())
                elif section.startswith('Critical Vulnerabilities:'):
                    vulnerabilities_info.append(section.replace('Critical Vulnerabilities:', '').strip())
                elif section.startswith('Threat Intel:'):
                    threat_info.append(section.replace('Threat Intel:', '').strip())
                elif section.startswith('Risk Rationale:'):
                    risk_info.append(section.replace('Risk Rationale:', '').strip())
            
            # Build the formatted output
            output_lines = [header, ""]  # Header with blank line
            
            # Network and Services section
            if network_info or services_info:
                output_lines.append("🌐")
                output_lines.append("NETWORK & SERVICES")
                if network_info:
                    output_lines.append(f"• Network: {', '.join(network_info)}")
                if services_info:
                    output_lines.append(f"• Exposed Services: {', '.join(services_info)}")
                output_lines.append("")
            
            # Security Assessment section
            if vulnerabilities_info or threat_info:
                output_lines.append("🔒")
                output_lines.append("SECURITY ASSESSMENT")
                if vulnerabilities_info:
                    output_lines.append(f"• Critical Vulnerabilities: {', '.join(vulnerabilities_info)}")
                if threat_info:
                    output_lines.append(f"• Threat Intelligence: {', '.join(threat_info)}")
                output_lines.append("")
            
            # Risk Analysis section
            if risk_info:
                output_lines.append("⚠️")
                output_lines.append("RISK ANALYSIS")
                output_lines.append(f"• {', '.join(risk_info)}")
                output_lines.append("")
            
            return "\n".join(output_lines).strip()
        else:
            return text.strip()

def _convert_single_line_to_multiline(text: str) -> str:
    """
    Convert single-line text to multi-line by splitting on section markers.
    """
    # Try different splitting patterns
    patterns = [' - ', ' -', '- ']
    
    for pattern in patterns:
        if pattern in text:
            parts = text.split(pattern)
            if len(parts) > 1:
                formatted = parts[0] + '\n'
                
                # Process remaining parts
                for part in parts[1:]:
                    part = part.strip()
                    if not part:
                        continue
                        
                    # Check for section headers
                    if any(part.startswith(header) for header in ['Network:', 'Exposed Services:', 'Critical Vulnerabilities:', 'Threat Intel:', 'Risk Rationale:']):
                        formatted += '- ' + part + '\n'
                    elif part.startswith('- '):
                        formatted += part + '\n'
                    else:
                        # This might be a continuation
                        formatted += '- ' + part + '\n'
                
                return formatted.strip()
    
    # If no pattern found, try to split on common section markers
    section_markers = ['Network:', 'Exposed Services:', 'Critical Vulnerabilities:', 'Threat Intel:', 'Risk Rationale:']
    
    for marker in section_markers:
        if marker in text:
            # Split on the marker and format
            parts = text.split(marker)
            if len(parts) > 1:
                formatted = parts[0].strip() + '\n'
                
                for i, part in enumerate(parts[1:], 1):
                    part = part.strip()
                    if not part:
                        continue
                        
                    # Find the next section marker
                    next_marker = None
                    next_pos = len(part)
                    for next_m in section_markers:
                        pos = part.find(next_m)
                        if pos != -1 and pos < next_pos:
                            next_pos = pos
                            next_marker = next_m
                    
                    if next_marker:
                        current_section = part[:next_pos].strip()
                        remaining = part[next_pos:].strip()
                    else:
                        current_section = part
                        remaining = ""
                    
                    # Add the current section
                    if current_section:
                        if i == 1:  # First section after split
                            formatted += '- ' + marker + current_section + '\n'
                        else:
                            formatted += '- ' + current_section + '\n'
                    
                    # Add remaining content
                    if remaining:
                        formatted += remaining + '\n'
                
                return formatted.strip()
    
    # If no clear pattern, return as is
    return text


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
                    "You are a professional cybersecurity analyst. Using ONLY the provided host JSON, generate a concise, factual security report.\n\n"
                    "Output requirements:\n"
                    "- Format the summary as a single line.\n"
                    "- Use bullet points where appropriate.\n"
                    "- Follow this exact structure:\n\n"
                    "⚠️ [Risk Level]-Risk Host: [IP] ([City], [Country])\n"
                    "- Network: [Organization] (ASN [ASN], AS Country: [Country])\n"
                    "- Exposed Services:\n"
                    "  - [ServiceName (Port[, version/vendor/TLS])]\n"
                    "  - [Next Service]\n"
                    "- Critical Vulnerabilities:\n"
                    "  - [CVE (Severity, CVSS)]\n"
                    "  - [Next CVE]\n"
                    "- Threat Intel:\n"
                    "  - [Labels or Malware families]\n"
                    "- Risk Rationale:\n"
                    "  - [Short factual reason using CVSS, service count, or threats]\n"
                    "Recommendations:\n"
                    "  - [Recommendation 1]\n"
                    "  - [Recommendation 2 (optional)]\n"
                    "  - [Recommendation 3 (optional)]\n\n"
                    "- Infer protocols/encryption from standard ports if missing (e.g., 22→SSH encrypted, 80→HTTP unencrypted, 443→HTTPS TLS).\n"
                    "- If a field is missing, write 'Unknown'.\n"
                    "- Be strictly factual; avoid speculation or subjective language.\n"
                    "- Keep the report concise (4–8 lines plus recommendations).\n\n"
                    f"Host JSON:\n{json.dumps(structured, ensure_ascii=False)}"
                )



                print("Calling Gemini API...")
                resp = model.generate_content(prompt)
                txt = (resp.text or "").strip()
                print("Gemini response:", txt)
                if txt:
                    # Remove "Host: " prefix if it exists
                    if txt.startswith("Host: "):
                        txt = txt[6:]  # Remove "Host: " (6 characters)
                    # Ensure proper formatting with line breaks
                    txt = format_host_summary(txt)
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
                    {"role": "system", "content": "You are a cybersecurity analyst. Create single-line security summaries with specific format."},
                    {"role": "user", "content": (
                        "Using ONLY the provided host JSON, produce a concise security summary.\n\n"
                        "Output format: Create a single-line summary with this EXACT structure:\n"
                        "⚠️ [Risk Level]-Risk Host: [IP] ([City], [Country]) - Network: [Organization] (ASN [ASN], AS Country: [Country]) - Exposed Services: [Services] - Critical Vulnerabilities: [CVEs] - Threat Intel: [Threats] - Risk Rationale: [Rationale] Recommendations: [Recommendations]\n\n"
                        "IMPORTANT: Output must be a single line with all sections separated by ' - '. Include all information in this exact format.\n\n"
                        f"Host JSON:\n{json.dumps(structured, ensure_ascii=False)}"
                    )},
                ]
                resp = client.chat.completions.create(model="gpt-4o-mini", messages=messages, temperature=0.2)
                txt = resp.choices[0].message.content.strip()
                if txt:
                    # Remove "Host: " prefix if it exists
                    if txt.startswith("Host: "):
                        txt = txt[6:]  # Remove "Host: " (6 characters)
                    # Ensure proper formatting with line breaks
                    txt = format_host_summary(txt)
                    return txt
            except Exception:
                pass
    except Exception:
        pass
    ip = structured.get("ip")
    loc = structured.get("location") or {}
    asn_name_or_org = structured.get("asn_name") or structured.get("organization") or "Unknown"
    asn = structured.get("asn") or "Unknown"
    asn_country = structured.get("asn_country_code") or ""
    services = structured.get("services") or []
    vulns = structured.get("vulnerabilities") or []
    risk_level = structured.get("risk_level") or "Low"
    risk_reason = structured.get("risk_reason") or ""
    labels = []
    ti = structured.get("threat_intel")
    if isinstance(ti, dict):
        labels = [l for l in (ti.get("labels") or []) if isinstance(l, str)]

    # Exposed Services summary list like: SSH (OpenSSH 8.7), HTTP, HTTPS
    def compact_service(entry: Dict[str, Any]) -> Optional[str]:
        port = entry.get("port")
        name = entry.get("service") or entry.get("name") or entry.get("protocol")
        product = entry.get("product") or entry.get("software")
        if not name and isinstance(port, (int, str)):
            try:
                p = int(port)
            except Exception:
                p = None
            port_map = {22: "SSH", 80: "HTTP", 443: "HTTPS", 21: "FTP", 25: "SMTP", 3306: "MySQL", 3389: "RDP", 53: "DNS"}
            name = port_map.get(p)
        if not name and not product:
            return None
        if isinstance(product, str) and product.strip():
            return f"{name or 'Service'} ({product})" if name else product
        return f"{name}"

    exposed_list = [s for s in (compact_service(s) for s in services) if isinstance(s, str)]
    num_services = len([s for s in services if s.get("port") is not None])

    # Vulnerabilities line like: CVE-XXXX (Critical, CVSS 9.8)
    def cveline(v: Dict[str, Any]) -> Optional[str]:
        vid = v.get("id")
        if not vid:
            return None
        sev = v.get("severity")
        sev_cap = (str(sev).capitalize() if isinstance(sev, str) else sev) or "Unknown"
        score = v.get("score")
        score_txt = None
        try:
            if isinstance(score, str) and score.strip():
                float(score)  # validate
                score_txt = score
            elif isinstance(score, (int, float)):
                score_txt = f"{float(score):.1f}"
        except Exception:
            score_txt = None
        if score_txt:
            return f"{vid} ({sev_cap}, CVSS {score_txt})"
        return f"{vid} ({sev_cap})"

    cve_items = [c for c in (cveline(v) for v in vulns) if isinstance(c, str)]

    city = loc.get("city") or "Unknown"
    country = loc.get("country") or "Unknown"
    emoji = "⚠️"
    risk_header = f"{emoji} {str(risk_level).capitalize()}-Risk Host: {ip} ({city}, {country})"

    net_line = f"- Network: {asn_name_or_org} (ASN {asn}"
    if isinstance(asn_country, str) and asn_country:
        net_line += f", AS Country: {asn_country}"
    net_line += ")"

    exposed_line = "- Exposed Services: " + (", ".join(exposed_list[:10]) if exposed_list else "None")
    vuln_line = "- Critical Vulnerabilities: " + (", ".join(cve_items[:10]) if cve_items else "None")
    threat_line = "- Threat Intel: " + (", ".join(labels) if labels else "None")

    # Risk rationale: include exact number of services; reuse backend-computed reason if present
    reason_text = risk_reason or ""
    if f"Exposed services: {num_services}" not in reason_text:
        # Append explicit service count when not already present
        reason_text = (reason_text + ("; " if reason_text else "") + f"Exposed services: {num_services}").strip()
    rationale_line = f"- Risk Rationale: {reason_text}" if reason_text else f"- Risk Rationale: Exposed services: {num_services}"

    # Tailored recommendation set with prioritization
    # Detect services using both structured names and displayed exposed strings
    ports = [s.get("port") for s in services if isinstance(s.get("port"), (int, float))]
    names = [(s.get("service") or "").strip().lower() for s in services]
    exposed_lower = [e.lower() for e in exposed_list]
    def contains(term: str) -> bool:
        return any(term in n for n in names) or any(term in e for e in exposed_lower)

    has_ssh = contains("ssh") or 22 in ports
    has_https = contains("https") or 443 in ports
    has_http = (contains("http") and not has_https) or 80 in ports
    has_mysql = contains("mysql") or 3306 in ports
    has_ftp = contains("ftp") or 21 in ports

    # Non-standard externally exposed ports heuristic (exclude common web/ssh/dns/smtp)
    common_ports = {22, 53, 25, 80, 443}
    unusual_ports = [int(p) for p in ports if int(p) not in common_ports]

    # Buckets with priority: 1) Patch, 2) IR, 3) Critical service exposures (DB/FTP), 4) Web, 5) SSH, 6) Surface reduction, 7) Default
    patch: List[str] = []
    ir: List[str] = []
    svc_specific: List[str] = []
    web: List[str] = []
    ssh_hardening: List[str] = []
    surface: List[str] = []
    fallback: List[str] = []

    # CVE-specific guidance (OpenSSH)
    vuln_ids = {str(v.get("id")).upper() for v in vulns if v.get("id")}
    ssh_cves = {"CVE-2023-38408", "CVE-2024-6387", "CVE-2018-15473"}
    if vuln_ids & ssh_cves:
        patch.append("- Immediately patch OpenSSH to remediate listed CVEs (e.g., CVE-2023-38408, CVE-2024-6387).")
    elif cve_items:
        patch.append("- Immediately patch affected services to address listed CVEs.")

    # Threat intel / IR
    ti_labels = labels
    malware_families = []
    if isinstance(ti, dict):
        malware_families = [m for m in (ti.get("malware_families") or []) if isinstance(m, str)]
    label_set_lower = {str(l).strip().lower() for l in (ti_labels or [])}
    ir_label_triggers = {"c2", "command_and_control", "cobalt strike", "rat", "beacon", "loader", "backdoor"}
    if malware_families or (label_set_lower & ir_label_triggers):
        ir.append("- Investigate threat indicators and deploy enhanced monitoring/EDR.")

    # Service-specific exposures
    if has_mysql:
        svc_specific.append("- Restrict MySQL (3306) to internal networks; require strong auth and latest updates.")
    if has_ftp:
        svc_specific.append("- Disable FTP or enforce FTPS/SFTP; block external access to port 21.")

    # Web hardening
    if has_http and not has_https:
        web.append("- Enable HTTPS/TLS and redirect HTTP to HTTPS.")
        web.append("- Consider a WAF for public-facing endpoints.")

    # SSH hardening
    if has_ssh:
        ssh_hardening.append("- Enforce SSH key-based auth; disable password login.")
        # Add rate limiting only when we suspect auth abuse or broad exposure
        brute_force_indicators = {"brute_force", "ssh_bruteforce", "password_spray"}
        if (label_set_lower & brute_force_indicators) or num_services >= 5:
            ssh_hardening.append("- Restrict SSH to trusted IPs and enable rate limiting/fail2ban.")

    # Attack surface reduction
    if num_services >= 3 or unusual_ports:
        surface.append("- Minimize exposed services and close unnecessary ports with firewall rules.")

    if not any([patch, ir, svc_specific, web, ssh_hardening, surface]):
        fallback.append("- Apply latest security updates and validate configuration hardening.")

    # Merge by priority and deduplicate
    ordered = patch + ir + svc_specific + web + ssh_hardening + surface + fallback
    seen: set = set()
    recs: List[str] = []
    for r in ordered:
        if r not in seen:
            recs.append(r)
            seen.add(r)
    recs = recs[:4]

    # Create single-line format that our formatter expects
    recommendations_text = "; ".join(recs) if recs else "See detailed analysis above."
    
    # Ensure we have the ⚠️ symbol and proper format
    if not risk_header.startswith('⚠️'):
        risk_header = f"⚠️ {risk_header}"
    
    # Create the complete single-line format with all information
    fallback_text = f"{risk_header} - Network: {asn_name_or_org} (ASN {asn}" + (f", AS Country: {asn_country}" if isinstance(asn_country, str) and asn_country else "") + f") - Exposed Services: {', '.join(exposed_list[:10]) if exposed_list else 'None'} - Critical Vulnerabilities: {', '.join(cve_items[:10]) if cve_items else 'None'} - Threat Intel: {', '.join(labels) if labels else 'None'} - Risk Rationale: {reason_text if reason_text else f'Exposed services: {num_services}'} Recommendations: {recommendations_text}"
    
    print("DEBUG: Applying clean Python formatting to fallback response")
    formatted = format_host_summary(fallback_text)
    print(f"DEBUG: Formatted result: {formatted[:100]}...")
    return formatted

@app.post("/summarize_host/", response_model=HostSummary)
async def summarize_host(payload: SummarizeRequest):
    if not HOSTS:
        raise HTTPException(status_code=404, detail="No dataset uploaded")
    
    try:
        host = _find_host_by_ip(payload.ip)
        if not host:
            raise HTTPException(status_code=404, detail=f"Host {payload.ip} not found in dataset")

        logger.info(f"Summarizing host: {payload.ip}")
        
        services = _extract_services(host)
        location = _extract_location(host)
        vulnerabilities = _extract_vulns(host)
        org_asn = _extract_org_asn(host)
        os_name = _extract_os(host)
        cloud_provider = _extract_cloud_provider(host)
        threat = _extract_threat(host)
        computed = _compute_risk_with_reason(services, vulnerabilities, threat)
        risk_level = (threat.get("risk_level") if isinstance(threat, dict) else None) or computed.get("level")
        
        # Focused override: certain malware/C2 indicators should be Critical
        try:
            labels = (threat or {}).get("labels") or []
            malware = (threat or {}).get("malware_families") or []
            label_set = {str(l).strip().upper() for l in labels if isinstance(l, str)}
            malware_set = {str(m).strip().upper() for m in malware if isinstance(m, str)}
            c2_indicators = {"C2", "COMMAND_AND_CONTROL", "REMOTE_ACCESS", "RAT"}
            if ("COBALT STRIKE" in malware_set) or (label_set & c2_indicators):
                risk_level = "Critical"
        except Exception:
            pass

        structured = {
            "ip": payload.ip,
            "location": location,
            "services": services,
            "vulnerabilities": vulnerabilities,
            "risk_level": risk_level,
            "risk_reason": computed.get("reason"),
            "organization": org_asn.get("organization"),
            "asn": org_asn.get("asn"),
            "asn_name": org_asn.get("asn_name"),
            "asn_country_code": (host.get("autonomous_system") or {}).get("country_code") if isinstance(host.get("autonomous_system"), dict) else None,
            "os": os_name,
            "cloud_provider": cloud_provider,
            "threat_intel": {"labels": threat.get("labels"), "malware_families": threat.get("malware_families")},
        }

        summary_text = await _generate_summary_text(structured)

        return HostSummary(
            ip=structured["ip"],
            location=structured["location"],
            services=structured["services"],
            vulnerabilities=structured["vulnerabilities"],
            risk_level=structured["risk_level"],
            summary=summary_text,
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error summarizing host {payload.ip}: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Failed to summarize host: {str(e)}")

@app.get("/summarize_all/", response_model=BatchSummaryResponse)
async def summarize_all_hosts():
    if not HOSTS:
        raise HTTPException(status_code=404, detail="No dataset uploaded")
    
    start_time = datetime.now()
    summaries = []
    
    try:
        logger.info(f"Starting batch summarization for {len(HOSTS)} hosts")
        
        for i, host in enumerate(HOSTS):
            try:
                ip = host.get("ip") or host.get("ip_address") or host.get("ipv4") or host.get("ipv6")
                if not ip:
                    logger.warning(f"Skipping host at index {i}: no IP address found")
                    continue
                    
                services = _extract_services(host)
                location = _extract_location(host)
                vulnerabilities = _extract_vulns(host)
                org_asn = _extract_org_asn(host)
                os_name = _extract_os(host)
                cloud_provider = _extract_cloud_provider(host)
                threat = _extract_threat(host)
                computed = _compute_risk_with_reason(services, vulnerabilities, threat)
                risk_level = (threat.get("risk_level") if isinstance(threat, dict) else None) or computed.get("level")
                
                # Focused override: certain malware/C2 indicators should be Critical
                try:
                    labels = (threat or {}).get("labels") or []
                    malware = (threat or {}).get("malware_families") or []
                    label_set = {str(l).strip().upper() for l in labels if isinstance(l, str)}
                    malware_set = {str(m).strip().upper() for m in malware if isinstance(m, str)}
                    c2_indicators = {"C2", "COMMAND_AND_CONTROL", "REMOTE_ACCESS", "RAT"}
                    if ("COBALT STRIKE" in malware_set) or (label_set & c2_indicators):
                        risk_level = "Critical"
                except Exception:
                    pass

                structured = {
                    "ip": ip,
                    "location": location,
                    "services": services,
                    "vulnerabilities": vulnerabilities,
                    "risk_level": risk_level,
                    "risk_reason": computed.get("reason"),
                    "organization": org_asn.get("organization"),
                    "asn": org_asn.get("asn"),
                    "asn_name": org_asn.get("asn_name"),
                    "asn_country_code": (host.get("autonomous_system") or {}).get("country_code") if isinstance(host.get("autonomous_system"), dict) else None,
                    "os": os_name,
                    "cloud_provider": cloud_provider,
                    "threat_intel": {"labels": threat.get("labels"), "malware_families": threat.get("malware_families")},
                }

                summary_text = await _generate_summary_text(structured)
                summaries.append({
                    "ip": ip,
                    "summary": summary_text
                })
                
                # Log progress every 10 hosts
                if (i + 1) % 10 == 0:
                    logger.info(f"Processed {i + 1}/{len(HOSTS)} hosts")
                    
            except Exception as e:
                logger.error(f"Error processing host at index {i}: {str(e)}")
                # Continue with other hosts even if one fails
                continue
        
        end_time = datetime.now()
        processing_time = (end_time - start_time).total_seconds()
        
        logger.info(f"Batch summarization completed: {len(summaries)} summaries in {processing_time:.2f} seconds")
        
        return BatchSummaryResponse(
            summaries=summaries,
            total_hosts=len(summaries),
            processing_time=processing_time
        )
        
    except Exception as e:
        logger.error(f"Batch summarization error: {str(e)}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Batch summarization failed: {str(e)}")

@app.get("/get_uploaded_data/")
def get_uploaded_data():
    if not HOSTS:
        raise HTTPException(status_code=404, detail="No dataset uploaded")
    return {
        "hosts": HOSTS, 
        "count": len(HOSTS),
        "upload_timestamp": UPLOAD_TIMESTAMP
    }

@app.get("/check_key/")
def check_key():
    gemini_key = os.getenv("GEMINI_API_KEY")
    openai_key = os.getenv("OPENAI_API_KEY")
    return {
        "GEMINI_API_KEY": gemini_key is not None,
        "OPENAI_API_KEY": openai_key is not None,
        "has_any_key": (gemini_key is not None) or (openai_key is not None)
    }

@app.get("/stats/")
def get_stats():
    """Get statistics about the loaded dataset"""
    if not HOSTS:
        raise HTTPException(status_code=404, detail="No dataset uploaded")
    
    # Calculate basic statistics
    total_hosts = len(HOSTS)
    risk_levels = {}
    service_counts = []
    vulnerability_counts = []
    
    for host in HOSTS:
        # Count risk levels
        services = _extract_services(host)
        vulnerabilities = _extract_vulns(host)
        threat = _extract_threat(host)
        computed = _compute_risk_with_reason(services, vulnerabilities, threat)
        risk_level = (threat.get("risk_level") if isinstance(threat, dict) else None) or computed.get("level")
        
        risk_levels[risk_level] = risk_levels.get(risk_level, 0) + 1
        service_counts.append(len(services))
        vulnerability_counts.append(len(vulnerabilities))
    
    return {
        "total_hosts": total_hosts,
        "risk_distribution": risk_levels,
        "avg_services_per_host": sum(service_counts) / len(service_counts) if service_counts else 0,
        "avg_vulnerabilities_per_host": sum(vulnerability_counts) / len(vulnerability_counts) if vulnerability_counts else 0,
        "max_services": max(service_counts) if service_counts else 0,
        "max_vulnerabilities": max(vulnerability_counts) if vulnerability_counts else 0,
        "upload_timestamp": UPLOAD_TIMESTAMP
    }

@app.post("/reset/")
def reset_data():
    """Reset/clear all uploaded data"""
    global HOSTS, UPLOAD_TIMESTAMP
    HOSTS = []
    UPLOAD_TIMESTAMP = None
    return {
        "message": "Data reset successfully",
        "total_hosts": 0,
        "upload_timestamp": None
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

