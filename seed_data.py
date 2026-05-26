import requests
from dotenv import load_dotenv
import os

load_dotenv()

URL = os.getenv("NEO4J_QUERY_URL")
USERNAME = os.getenv("NEO4J_USERNAME")
PASSWORD = os.getenv("NEO4J_PASSWORD")

def run_query(statement):
    response = requests.post(
        URL,
        auth=(USERNAME, PASSWORD),
        json={"statement": statement},
        headers={"Content-Type": "application/json"}
    )
    return response.status_code

def run_query_get_result(statement):
    """Run a query and return the parsed JSON response (for verification)."""
    response = requests.post(
        URL,
        auth=(USERNAME, PASSWORD),
        json={"statement": statement},
        headers={"Content-Type": "application/json"}
    )
    return response.json()

# ============ ID constants (single source of truth) ============
HOST_IDS = ['H1', 'H2', 'H3', 'H4', 'H5', 'H6', 'H7', 'H8', 'H9', 'H10']
USER_IDS = ['U1', 'U2', 'U3', 'U4', 'U5', 'U6', 'U7', 'U8']
HASH_IDS = ['FH1', 'FH2', 'FH3', 'FH4', 'FH5', 'FH6', 'FH7', 'FH8', 'FH9', 'FH10']
IP_IDS = ['IP1', 'IP2', 'IP3', 'IP4', 'IP5', 'IP6', 'IP7', 'IP8', 'IP9', 'IP10']

# Clear existing data
run_query("MATCH (n) DETACH DELETE n")

# ============ CREATE ALL NODES (using UNWIND for atomic batch creation) ============
run_query("""
UNWIND [
  {id: 'H1', name: 'FIN-DESK-042', os: 'Windows 10', timestamp: '2025-02-28T08:15:00'},
  {id: 'H2', name: 'FIN-SRV-01', os: 'Windows Server 2019', timestamp: '2025-02-28T09:22:00'},
  {id: 'H3', name: 'IT-DESK-118', os: 'Windows 11', timestamp: '2025-02-28T10:45:00'},
  {id: 'H4', name: 'DC01', os: 'Windows Server 2022', timestamp: '2025-02-28T11:03:00'},
  {id: 'H5', name: 'DC02', os: 'Windows Server 2022', timestamp: '2025-02-28T11:18:00'},
  {id: 'H6', name: 'EXCHANGE01', os: 'Windows Server 2019', timestamp: '2025-02-28T12:34:00'},
  {id: 'H7', name: 'HR-LAPTOP-07', os: 'Windows 10', timestamp: '2025-02-28T13:02:00'},
  {id: 'H8', name: 'SHAREPOINT-SRV', os: 'Windows Server 2019', timestamp: '2025-02-28T14:15:00'},
  {id: 'H9', name: 'LEGAL-DESK-23', os: 'Windows 10', timestamp: '2025-02-28T14:42:00'},
  {id: 'H10', name: 'EXEC-WS-01', os: 'Windows 11', timestamp: '2025-02-28T15:30:00'}
] AS row
CREATE (h:Host {id: row.id, name: row.name, os: row.os, timestamp: row.timestamp})
""")

run_query("""
UNWIND [
  {id: 'U1', name: 'jsmith', department: 'Finance', timestamp: '2025-02-28T08:00:00'},
  {id: 'U2', name: 'mjohnson', department: 'IT', timestamp: '2025-02-28T08:30:00'},
  {id: 'U3', name: 'akowalski', department: 'HR', timestamp: '2025-02-28T09:00:00'},
  {id: 'U4', name: 'rsanchez', department: 'Finance', timestamp: '2025-02-28T09:15:00'},
  {id: 'U5', name: 'tlarson', department: 'Executive', timestamp: '2025-02-28T10:00:00'},
  {id: 'U6', name: 'kchen', department: 'IT', timestamp: '2025-02-28T10:30:00'},
  {id: 'U7', name: 'dpatel', department: 'Legal', timestamp: '2025-02-28T11:00:00'},
  {id: 'U8', name: 'bwilliams', department: 'Finance', timestamp: '2025-02-28T11:30:00'}
] AS row
CREATE (u:User {id: row.id, name: row.name, department: row.department, timestamp: row.timestamp})
""")

run_query("""
UNWIND [
  {id: 'FH1', value: 'd4e6f8a2b1c3e5d7f9a1b3c5d7e9f1a', malicious: true, name: 'Emotet Loader', timestamp: '2025-02-28T08:20:00'},
  {id: 'FH2', value: 'a1b2c3d4e5f6789012345678abcdef01', malicious: true, name: 'Cobalt Strike Beacon', timestamp: '2025-02-28T10:50:00'},
  {id: 'FH3', value: '5d41402abc4b2a76b9719d911017c592', malicious: true, name: 'Mimikatz', timestamp: '2025-02-28T11:05:00'},
  {id: 'FH4', value: 'e3b0c44298fc1c149afbf4c8996fb924', malicious: true, name: 'Carbanak Banking Trojan', timestamp: '2025-02-28T09:25:00'},
  {id: 'FH5', value: '098f6bcd4621d373cade4e832627b4f6', malicious: true, name: 'PowerShell Empire Stager', timestamp: '2025-02-28T11:12:00'},
  {id: 'FH6', value: '5baa61e4c9b93f3f0682250b6cf8331b', malicious: false, name: 'WINWORD.EXE', timestamp: '2025-02-28T08:10:00'},
  {id: 'FH7', value: '2fd4e1c67a2d28fced849ee1bb76e73b', malicious: false, name: 'chrome.exe', timestamp: '2025-02-28T08:05:00'},
  {id: 'FH8', value: '7b8b965ad4bca0e41ab51de7b31363a1', malicious: false, name: 'svchost.exe', timestamp: '2025-02-28T08:00:00'},
  {id: 'FH9', value: 'd8578edf8458ce06fbc5bb76a58c5ca4', malicious: false, name: 'explorer.exe', timestamp: '2025-02-28T08:02:00'},
  {id: 'FH10', value: 'e10adc3949ba59abbe56e057f20f883e', malicious: true, name: 'Data Exfil Script', timestamp: '2025-02-28T14:25:00'}
] AS row
CREATE (f:Hash {id: row.id, value: row.value, malicious: row.malicious, name: row.name, timestamp: row.timestamp})
""")

run_query("""
UNWIND [
  {id: 'IP1', address: '45.33.32.156', suspicious: true, notes: 'Known C2 server', timestamp: '2025-02-28T08:25:00'},
  {id: 'IP2', address: '185.220.101.45', suspicious: true, notes: 'APT29 infrastructure', timestamp: '2025-02-28T10:48:00'},
  {id: 'IP3', address: '91.92.109.127', suspicious: true, notes: 'C2 callback', timestamp: '2025-02-28T11:15:00'},
  {id: 'IP4', address: '194.147.78.23', suspicious: true, notes: 'Exfil destination', timestamp: '2025-02-28T14:30:00'},
  {id: 'IP5', address: '103.224.182.88', suspicious: true, notes: 'Secondary C2', timestamp: '2025-02-28T12:35:00'},
  {id: 'IP6', address: '10.0.1.42', suspicious: false, notes: 'Internal Finance segment', timestamp: '2025-02-28T08:00:00'},
  {id: 'IP7', address: '10.0.1.10', suspicious: false, notes: 'Domain Controller', timestamp: '2025-02-28T11:00:00'},
  {id: 'IP8', address: '192.168.1.100', suspicious: false, notes: 'Internal IT', timestamp: '2025-02-28T10:30:00'},
  {id: 'IP9', address: '10.0.2.15', suspicious: false, notes: 'Exchange server', timestamp: '2025-02-28T12:30:00'},
  {id: 'IP10', address: '8.8.8.8', suspicious: false, notes: 'DNS - benign', timestamp: '2025-02-28T08:01:00'}
] AS row
CREATE (ip:IP {id: row.id, address: row.address, suspicious: row.suspicious, notes: row.notes, timestamp: row.timestamp})
""")

# ============ CREATE RELATIONSHIPS (using exact IDs from constants) ============

# LOGGED_INTO
run_query("MATCH (u:User {id: 'U1'}), (h:Host {id: 'H1'}) CREATE (u)-[:LOGGED_INTO {timestamp: '2025-02-28T08:15:00'}]->(h)")
run_query("MATCH (u:User {id: 'U1'}), (h:Host {id: 'H2'}) CREATE (u)-[:LOGGED_INTO {timestamp: '2025-02-28T09:22:00'}]->(h)")
run_query("MATCH (u:User {id: 'U2'}), (h:Host {id: 'H3'}) CREATE (u)-[:LOGGED_INTO {timestamp: '2025-02-28T10:45:00'}]->(h)")
run_query("MATCH (u:User {id: 'U2'}), (h:Host {id: 'H4'}) CREATE (u)-[:LOGGED_INTO {timestamp: '2025-02-28T11:03:00'}]->(h)")
run_query("MATCH (u:User {id: 'U3'}), (h:Host {id: 'H7'}) CREATE (u)-[:LOGGED_INTO {timestamp: '2025-02-28T13:02:00'}]->(h)")
run_query("MATCH (u:User {id: 'U5'}), (h:Host {id: 'H10'}) CREATE (u)-[:LOGGED_INTO {timestamp: '2025-02-28T15:30:00'}]->(h)")
run_query("MATCH (u:User {id: 'U7'}), (h:Host {id: 'H9'}) CREATE (u)-[:LOGGED_INTO {timestamp: '2025-02-28T14:42:00'}]->(h)")
run_query("MATCH (u:User {id: 'U4'}), (h:Host {id: 'H2'}) CREATE (u)-[:LOGGED_INTO {timestamp: '2025-02-28T09:30:00'}]->(h)")

# CONNECTED_TO
run_query("MATCH (h:Host {id: 'H1'}), (ip:IP {id: 'IP1'}) CREATE (h)-[:CONNECTED_TO {timestamp: '2025-02-28T08:25:00', port: 443}]->(ip)")
run_query("MATCH (h:Host {id: 'H1'}), (ip:IP {id: 'IP10'}) CREATE (h)-[:CONNECTED_TO {timestamp: '2025-02-28T08:01:00', port: 53}]->(ip)")
run_query("MATCH (h:Host {id: 'H2'}), (ip:IP {id: 'IP2'}) CREATE (h)-[:CONNECTED_TO {timestamp: '2025-02-28T09:45:00', port: 443}]->(ip)")
run_query("MATCH (h:Host {id: 'H3'}), (ip:IP {id: 'IP2'}) CREATE (h)-[:CONNECTED_TO {timestamp: '2025-02-28T10:48:00', port: 443}]->(ip)")
run_query("MATCH (h:Host {id: 'H3'}), (ip:IP {id: 'IP3'}) CREATE (h)-[:CONNECTED_TO {timestamp: '2025-02-28T11:15:00', port: 80}]->(ip)")
run_query("MATCH (h:Host {id: 'H4'}), (ip:IP {id: 'IP7'}) CREATE (h)-[:CONNECTED_TO {timestamp: '2025-02-28T11:00:00', port: 389}]->(ip)")
run_query("MATCH (h:Host {id: 'H6'}), (ip:IP {id: 'IP5'}) CREATE (h)-[:CONNECTED_TO {timestamp: '2025-02-28T12:35:00', port: 443}]->(ip)")
run_query("MATCH (h:Host {id: 'H8'}), (ip:IP {id: 'IP4'}) CREATE (h)-[:CONNECTED_TO {timestamp: '2025-02-28T14:30:00', port: 443}]->(ip)")
run_query("MATCH (h:Host {id: 'H2'}), (ip:IP {id: 'IP6'}) CREATE (h)-[:CONNECTED_TO {timestamp: '2025-02-28T09:20:00', port: 445}]->(ip)")

# RAN
run_query("MATCH (h:Host {id: 'H1'}), (f:Hash {id: 'FH1'}) CREATE (h)-[:RAN {timestamp: '2025-02-28T08:20:00'}]->(f)")
run_query("MATCH (h:Host {id: 'H1'}), (f:Hash {id: 'FH6'}) CREATE (h)-[:RAN {timestamp: '2025-02-28T08:10:00'}]->(f)")
run_query("MATCH (h:Host {id: 'H2'}), (f:Hash {id: 'FH4'}) CREATE (h)-[:RAN {timestamp: '2025-02-28T09:25:00'}]->(f)")
run_query("MATCH (h:Host {id: 'H3'}), (f:Hash {id: 'FH2'}) CREATE (h)-[:RAN {timestamp: '2025-02-28T10:50:00'}]->(f)")
run_query("MATCH (h:Host {id: 'H3'}), (f:Hash {id: 'FH3'}) CREATE (h)-[:RAN {timestamp: '2025-02-28T11:05:00'}]->(f)")
run_query("MATCH (h:Host {id: 'H4'}), (f:Hash {id: 'FH5'}) CREATE (h)-[:RAN {timestamp: '2025-02-28T11:12:00'}]->(f)")
run_query("MATCH (h:Host {id: 'H7'}), (f:Hash {id: 'FH7'}) CREATE (h)-[:RAN {timestamp: '2025-02-28T13:05:00'}]->(f)")
run_query("MATCH (h:Host {id: 'H8'}), (f:Hash {id: 'FH10'}) CREATE (h)-[:RAN {timestamp: '2025-02-28T14:25:00'}]->(f)")
run_query("MATCH (h:Host {id: 'H10'}), (f:Hash {id: 'FH6'}) CREATE (h)-[:RAN {timestamp: '2025-02-28T15:32:00'}]->(f)")

# LATERAL_MOVEMENT
run_query("MATCH (h1:Host {id: 'H1'}), (h2:Host {id: 'H2'}) CREATE (h1)-[:LATERAL_MOVEMENT {method: 'SMB', timestamp: '2025-02-28T09:20:00'}]->(h2)")
run_query("MATCH (h1:Host {id: 'H2'}), (h2:Host {id: 'H3'}) CREATE (h1)-[:LATERAL_MOVEMENT {method: 'WMI', timestamp: '2025-02-28T10:40:00'}]->(h2)")
run_query("MATCH (h1:Host {id: 'H3'}), (h2:Host {id: 'H4'}) CREATE (h1)-[:LATERAL_MOVEMENT {method: 'Pass-the-Hash', timestamp: '2025-02-28T11:00:00'}]->(h2)")
run_query("MATCH (h1:Host {id: 'H4'}), (h2:Host {id: 'H5'}) CREATE (h1)-[:LATERAL_MOVEMENT {method: 'DCSync', timestamp: '2025-02-28T11:18:00'}]->(h2)")
run_query("MATCH (h1:Host {id: 'H4'}), (h2:Host {id: 'H6'}) CREATE (h1)-[:LATERAL_MOVEMENT {method: 'RDP', timestamp: '2025-02-28T12:30:00'}]->(h2)")
run_query("MATCH (h1:Host {id: 'H6'}), (h2:Host {id: 'H8'}) CREATE (h1)-[:LATERAL_MOVEMENT {method: 'PsExec', timestamp: '2025-02-28T14:10:00'}]->(h2)")

# PRIVILEGE_ESCALATION
run_query("MATCH (u:User {id: 'U1'}), (h:Host {id: 'H1'}) CREATE (u)-[:PRIVILEGE_ESCALATION {from_level: 'Standard', to_level: 'Admin', method: 'Emotet dropper', timestamp: '2025-02-28T08:22:00'}]->(h)")
run_query("MATCH (u:User {id: 'U2'}), (h:Host {id: 'H4'}) CREATE (u)-[:PRIVILEGE_ESCALATION {from_level: 'Admin', to_level: 'Domain Admin', method: 'Mimikatz credentials', timestamp: '2025-02-28T11:08:00'}]->(h)")
run_query("MATCH (u:User {id: 'U4'}), (h:Host {id: 'H2'}) CREATE (u)-[:PRIVILEGE_ESCALATION {from_level: 'Standard', to_level: 'Admin', method: 'Stolen session', timestamp: '2025-02-28T09:35:00'}]->(h)")

# EXFILTRATED
run_query("MATCH (h:Host {id: 'H8'}), (ip:IP {id: 'IP4'}) CREATE (h)-[:EXFILTRATED {data_type: 'Financial records', size_mb: 450, timestamp: '2025-02-28T14:35:00'}]->(ip)")
run_query("MATCH (h:Host {id: 'H8'}), (ip:IP {id: 'IP4'}) CREATE (h)-[:EXFILTRATED {data_type: 'HR PII', size_mb: 120, timestamp: '2025-02-28T14:40:00'}]->(ip)")
run_query("MATCH (h:Host {id: 'H2'}), (ip:IP {id: 'IP2'}) CREATE (h)-[:EXFILTRATED {data_type: 'Credentials dump', size_mb: 2, timestamp: '2025-02-28T09:50:00'}]->(ip)")

# ============ VERIFICATION ============
node_result = run_query_get_result("MATCH (n) RETURN count(n) AS node_count")
rel_result = run_query_get_result("MATCH ()-[r]->() RETURN count(r) AS rel_count")

node_count = node_result.get("data", {}).get("values", [[0]])[0][0]
rel_count = rel_result.get("data", {}).get("values", [[0]])[0][0]

print("✅ Realistic APT threat data loaded into Neo4j successfully!")
print(f"   Nodes created: {node_count}")
print(f"   Relationships created: {rel_count}")
