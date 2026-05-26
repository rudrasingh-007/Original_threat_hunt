from flask import Flask, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
import requests
import os
import google.generativeai as genai

load_dotenv()

app = Flask(__name__)
CORS(app)

URL = os.getenv("NEO4J_QUERY_URL")
USERNAME = os.getenv("NEO4J_USERNAME")
PASSWORD = os.getenv("NEO4J_PASSWORD")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

genai.configure(api_key=GEMINI_API_KEY)
model = genai.GenerativeModel('gemini-2.0-flash-lite')
def run_query(statement):
    response = requests.post(
        URL,
        auth=(USERNAME, PASSWORD),
        json={"statement": statement},
        headers={"Content-Type": "application/json"}
    )
    return response.json()

@app.route('/api/graph')
def get_graph():
    nodes_result = run_query("MATCH (n) RETURN n, labels(n) as labels")
    rels_result = run_query("MATCH (a)-[r]->(b) RETURN a.id as source, b.id as target, type(r) as type")

    nodes = []
    values = nodes_result.get("data", {}).get("values", [])

    # Debug: inspect raw node structure coming back from Neo4j
    if values:
        print("Raw node record from Neo4j:", values[0][0])

    for record in values:
        raw_node = record[0]
        labels_list = record[1] or []
        label = labels_list[0] if len(labels_list) > 0 else "Unknown"

        # Properties are usually nested under \"properties\" (Query API extended JSON)
        props = raw_node.get("properties") or raw_node.get("props") or raw_node

        node_id = None
        if isinstance(props, dict):
            node_id = props.get("id")
        if node_id is None and isinstance(raw_node, dict):
            node_id = raw_node.get("id") or raw_node.get("elementId")
        if node_id is None:
            node_id = str(props)

        nodes.append({
            "id": node_id,
            "label": label,
            "properties": props
        })

    links = []
    for record in rels_result.get("data", {}).get("values", []):
        links.append({
            "source": record[0],
            "target": record[1],
            "type": record[2]
        })

    return jsonify({"nodes": nodes, "links": links})

@app.route('/api/hypothesis')
def get_hypothesis():
    nodes_result = run_query("MATCH (n) RETURN n, labels(n) as labels")
    rels_result = run_query("MATCH (a)-[r]->(b) RETURN a.id as source, b.id as target, type(r) as type")

    # Build graph summary
    suspicious_hosts = []
    malicious_hashes = []
    suspicious_ips = []

    for record in nodes_result.get("data", {}).get("values", []):
        node = record[0]
        label = record[1][0]
        if label == "Host":
            suspicious_hosts.append(node.get("name", "Unknown"))
        if label == "Hash" and node.get("malicious"):
            malicious_hashes.append(node.get("name", "Unknown"))
        if label == "IP" and node.get("suspicious"):
            suspicious_ips.append(node.get("address", "Unknown"))

    hypothesis = MOCK_HYPOTHESIS = """
A high-confidence Advanced Persistent Threat (APT) targeted the organization’s financial environment. The attack began with a spear-phishing email 📧 that deployed Emotet on FIN-DESK-042. Attackers then established a Cobalt Strike command-and-control connection, enabling persistent access.

Using stolen credentials (jsmith), the attackers performed lateral movement to FIN-SRV-01 and the Domain Controller (DC01), where Mimikatz was used to dump credentials. Additional tools (PowerShell Empire) were deployed on other hosts, and data exfiltration attempts 📤 were detected to a malicious external IP.

Impact

🖥️ 5 systems compromised, including a Domain Controller and executive workstation

👤 3 user accounts likely compromised

🦠 Multiple malware tools detected (Emotet, Cobalt Strike, Mimikatz, PowerShell Empire)

🌐 Active command-and-control and exfiltration traffic observed

Immediate priorities

🔌 Isolate affected machines

🔑 Reset compromised credentials

🚫 Block malicious IP addresses

🔍 Scan systems for malware artifacts

🧾 Preserve forensic evidence for investigation

Bottom line: A coordinated multi-stage breach is underway and requires immediate containment and investigation.
"""


    return jsonify({"hypothesis": hypothesis})
@app.route('/api/blast-radius/<node_id>')
def get_blast_radius(node_id):
    # Query to find all nodes reachable within 4 hops
    query = f"""MATCH path = (start {{id: '{node_id}'}})-[*1..4]->(reached) 
                RETURN reached, labels(reached) as labels, length(path) as depth"""
    
    result = run_query(query)
    
    reachable_nodes = []
    label_counts = {"Host": 0, "User": 0, "Hash": 0, "IP": 0}
    node_depths = {}
    
    for record in result.get("data", {}).get("values", []):
        node = record[0]
        labels_list = record[1] or []
        depth = record[2]
        
        label = labels_list[0] if len(labels_list) > 0 else "Unknown"
        
        # Get node ID from properties
        props = node.get("properties") or node.get("props") or node
        node_id_val = None
        if isinstance(props, dict):
            node_id_val = props.get("id")
        if node_id_val is None and isinstance(node, dict):
            node_id_val = node.get("id") or node.get("elementId")
        if node_id_val is None:
            node_id_val = str(props)
        
        reachable_nodes.append(node_id_val)
        node_depths[node_id_val] = depth
        
        # Count by label
        if label in label_counts:
            label_counts[label] += 1
        else:
            if "Unknown" not in label_counts:
                label_counts["Unknown"] = 0
            label_counts["Unknown"] += 1
    
    return jsonify({
        "reachable_nodes": reachable_nodes,
        "label_counts": label_counts,
        "total_count": len(reachable_nodes),
        "node_depths": node_depths
    })

@app.route('/api/attack-path/<source_id>/<target_id>')
def get_attack_path(source_id, target_id):
    # find shortest path between two nodes by id
    query = f"""MATCH path = shortestPath((a {{id: '{source_id}'}})-[*]-(b {{id: '{target_id}'}})) \
                RETURN nodes(path) as nodes, relationships(path) as rels, length(path) as hops"""
    result = run_query(query)

    values = result.get("data", {}).get("values", [])
    if not values:
        return jsonify({
            "path_nodes": [],
            "path_links": [],
            "hops": 0,
            "found": False
        })

    record = values[0]
    raw_nodes = record[0] or []
    raw_rels = record[1] or []
    hops = record[2] or 0

    # extract IDs from node objects
    path_nodes = []
    for n in raw_nodes:
        props = n.get("properties") or n.get("props") or n
        nid = None
        if isinstance(props, dict):
            nid = props.get("id")
        if nid is None and isinstance(n, dict):
            nid = n.get("id") or n.get("elementId")
        if nid is None:
            nid = str(props)
        path_nodes.append(nid)

    path_links = []
    for r in raw_rels:
        src = None
        tgt = None
        typ = None
        if isinstance(r, list) or isinstance(r, tuple):
            src = r[0] if len(r) > 0 else None
            tgt = r[1] if len(r) > 1 else None
            typ = r[2] if len(r) > 2 else None
        elif isinstance(r, dict):
            # HTTP API may return relationship object with start and end info
            src = r.get('start') or r.get('startId')
            tgt = r.get('end') or r.get('endId')
            typ = r.get('type')
        path_links.append({"source": src, "target": tgt, "type": typ})

    return jsonify({
        "path_nodes": path_nodes,
        "path_links": path_links,
        "hops": hops,
        "found": len(path_nodes) > 0
    })

@app.route('/api/health')
def health():
    return jsonify({"status": "ok"})

if __name__ == '__main__':
    app.run(debug=True, port=5000)