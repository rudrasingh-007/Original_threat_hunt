import requests
from dotenv import load_dotenv
import os

load_dotenv()

url = os.getenv("NEO4J_QUERY_URL")
username = os.getenv("NEO4J_USERNAME")
password = os.getenv("NEO4J_PASSWORD")

response = requests.post(
    url,
    auth=(username, password),
    json={"statement": "RETURN 1"},
    headers={"Content-Type": "application/json"}
)

print(f"Status: {response.status_code}")
print(f"Response: {response.text}")
