"""
Cisco CUCM AXL (Administrative XML) API utility layer for RELAY.

Supports multiple CUCM clusters. Every public function accepts an optional
`cluster` parameter (a CUCMCluster instance). When omitted, the first
enabled cluster is used for single-cluster backwards compatibility.

AXL schema docs: https://developer.cisco.com/docs/axl/
"""
import re
import requests
from urllib3.exceptions import InsecureRequestWarning
from requests.auth import HTTPBasicAuth

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

AXL_NS      = "http://www.cisco.com/AXL/API/"
SOAP_ENV_NS = "http://schemas.xmlsoap.org/soap/envelope/"


def _get_cluster(cluster=None):
    """
    Return a CUCMCluster instance.
    If cluster is supplied directly, use it.
    Otherwise fall back to the first enabled cluster (legacy behaviour).
    """
    if cluster is not None:
        return cluster
    from app.models import CUCMCluster
    c = CUCMCluster.query.filter_by(is_enabled=True).first()
    if not c:
        raise RuntimeError(
            "No CUCM cluster is configured. Add one in Admin → CUCM Clusters."
        )
    return c


def _axl_url(cluster=None) -> str:
    c = _get_cluster(cluster)
    if not c.cucm_host:
        raise RuntimeError(f"CUCM host is not set for cluster '{getattr(c,'label','?')}'.")
    host = c.cucm_host.rstrip("/")
    if not host.startswith("http"):
        host = f"https://{host}"
    return f"{host}:8443/axl/"


def _soap_request(body_xml: str, cluster=None) -> str:
    """Send a SOAP/AXL request to a specific (or default) cluster."""
    c = _get_cluster(cluster)
    if not c.is_configured():
        label = getattr(c, "label", "?")
        raise RuntimeError(f"CUCM cluster '{label}' is not fully configured.")

    envelope = (
        f'<?xml version="1.0" encoding="UTF-8"?>'
        f'<soapenv:Envelope xmlns:soapenv="{SOAP_ENV_NS}"'
        f' xmlns:ns="{AXL_NS}{c.cucm_version}">'
        f"<soapenv:Header/>"
        f"<soapenv:Body>{body_xml}</soapenv:Body>"
        f"</soapenv:Envelope>"
    )
    headers = {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": '""'}
    r = requests.post(
        _axl_url(c),
        data=envelope.encode("utf-8"),
        headers=headers,
        auth=HTTPBasicAuth(c.cucm_username, c.cucm_password),
        verify=c.verify_ssl,
        timeout=20,
    )
    r.raise_for_status()
    return r.text


def _xml_val(text: str, tag: str, default: str = "") -> str:
    m = re.search(rf"<{re.escape(tag)}[^>]*>(.*?)</{re.escape(tag)}>",
                  text, re.DOTALL)
    return m.group(1).strip() if m else default


def _xml_all(text: str, tag: str) -> list[str]:
    return [m.group(1).strip()
            for m in re.finditer(rf"<{re.escape(tag)}[^>]*>(.*?)</{re.escape(tag)}>",
                                 text, re.DOTALL)]


# ── User search ───────────────────────────────────────────────
def search_cucm_users(query: str, max_results: int = 20, cluster=None) -> list:
    """
    Search CUCM end-users by userid, first/last name or phone number.
    cluster: CUCMCluster instance (optional — uses first enabled if omitted).
    """
    body = (
        f"<ns:listUser>"
        f"  <searchCriteria><userid>%{query}%</userid></searchCriteria>"
        f"  <returnedTags>"
        f"    <userid/><firstName/><lastName/><department/>"
        f"    <telephoneNumber/><primaryExtension><pattern/></primaryExtension>"
        f"  </returnedTags>"
        f"  <first>{max_results}</first>"
        f"</ns:listUser>"
    )
    xml = _soap_request(body, cluster)
    users = []
    for block in re.finditer(r"<user>(.*?)</user>", xml, re.DOTALL):
        b = block.group(1)
        users.append({
            "userid":    _xml_val(b, "userid"),
            "firstName": _xml_val(b, "firstName"),
            "lastName":  _xml_val(b, "lastName"),
            "fullName":  f"{_xml_val(b,'firstName')} {_xml_val(b,'lastName')}".strip(),
            "department":_xml_val(b, "department"),
            "phone":     _xml_val(b, "telephoneNumber"),
            "extension": _xml_val(b, "pattern"),
        })
    return users


# ── Single user detail ────────────────────────────────────────
def get_cucm_user_by_id(userid: str, cluster=None) -> dict:
    """Fetch full CUCM user record by userid."""
    body = f"<ns:getUser><userid>{userid}</userid></ns:getUser>"
    xml  = _soap_request(body, cluster)
    return {
        "userid":     _xml_val(xml, "userid"),
        "firstName":  _xml_val(xml, "firstName"),
        "lastName":   _xml_val(xml, "lastName"),
        "department": _xml_val(xml, "department"),
        "phone":      _xml_val(xml, "telephoneNumber"),
        "extension":  _xml_val(xml, "pattern"),
        "mailid":     _xml_val(xml, "mailid"),
        "userLocale": _xml_val(xml, "userLocale"),
        "status":     _xml_val(xml, "status"),
        "lines":      _xml_all(xml, "pattern"),
    }


# ── Line / DN inventory ───────────────────────────────────────
def list_all_cucm_lines(max_results: int = 5000, cluster=None) -> list:
    """
    Return all DN patterns from a cluster via listLine AXL.
    cluster: CUCMCluster instance (optional).
    """
    body = (
        f"<ns:listLine>"
        f"  <searchCriteria><pattern>%</pattern></searchCriteria>"
        f"  <returnedTags>"
        f"    <pattern/><description/><routePartitionName/><usage/>"
        f"  </returnedTags>"
        f"  <first>{max_results}</first>"
        f"</ns:listLine>"
    )
    xml = _soap_request(body, cluster)
    lines = []
    for block in re.finditer(r"<line>(.*?)</line>", xml, re.DOTALL):
        b = block.group(1)
        pattern = _xml_val(b, "pattern")
        if not pattern:
            continue
        lines.append({
            "pattern":     pattern,
            "description": _xml_val(b, "description"),
            "partition":   _xml_val(b, "routePartitionName"),
            "usage":       _xml_val(b, "usage"),
        })
    return lines


# ── Locations ─────────────────────────────────────────────────
def get_cucm_locations(cluster=None) -> list:
    """Return CUCM locations via listLocation AXL."""
    body = (
        "<ns:listLocation>"
        "  <searchCriteria><n>%</n></searchCriteria>"
        "  <returnedTags><name/><withinAudioBandwidth/></returnedTags>"
        "  <first>500</first>"
        "</ns:listLocation>"
    )
    xml = _soap_request(body, cluster)
    locations = []
    for block in re.finditer(r"<location>(.*?)</location>", xml, re.DOTALL):
        b = block.group(1)
        name = _xml_val(b, "name")
        if name:
            locations.append({"name": name})
    return locations


# ── Connection test ───────────────────────────────────────────
def test_cucm_connection(cluster=None) -> dict:
    """Verify AXL credentials and connectivity for a cluster."""
    try:
        body = "<ns:getCCMVersion></ns:getCCMVersion>"
        xml  = _soap_request(body, cluster)
        version = _xml_val(xml, "componentVersion") or _xml_val(xml, "version")
        return {"ok": True, "version": version or "connected"}
    except requests.exceptions.ConnectionError as e:
        return {"ok": False, "error": f"Connection refused: {e}"}
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else "?"
        if status == 401:
            return {"ok": False, "error": "Authentication failed (401) — check username/password"}
        return {"ok": False, "error": f"HTTP {status}: {e}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}
