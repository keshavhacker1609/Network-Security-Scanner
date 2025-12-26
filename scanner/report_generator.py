import json
import os
from datetime import datetime

def generate_reports(data, name):
    time = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Ensure directories exist
    os.makedirs("reports/json", exist_ok=True)
    os.makedirs("reports/html", exist_ok=True)

    json_path = f"reports/json/{name}_{time}.json"
    html_path = f"reports/html/{name}_{time}.html"

    with open(json_path, "w") as jf:
        json.dump(data, jf, indent=4)

    with open(html_path, "w") as hf:
        hf.write(f"<pre>{json.dumps(data, indent=4)}</pre>")

    return json_path, html_path
