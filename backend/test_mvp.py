import csv
import io
import os
import tempfile
import unittest
from pathlib import Path

# Keep tests isolated from the user's local demo database.
TEMP_DB = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
TEMP_DB.close()
os.environ["CYBERSHIELD_DB_PATH"] = TEMP_DB.name

from fastapi.testclient import TestClient
import backend.main as main

# Redirect the module to the isolated test database.
main.DB_PATH = Path(TEMP_DB.name)
main.init_db()
client = TestClient(main.app)


class CyberShieldMVPTests(unittest.TestCase):
    def setUp(self):
        main.init_db()
        with main.connect() as conn:
            conn.execute("DELETE FROM alerts")
            conn.execute("DELETE FROM events")

    def test_health(self):
        response = client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")

    def test_sample_generates_alerts(self):
        response = client.post("/api/demo/sample")
        self.assertEqual(response.status_code, 200)
        self.assertGreaterEqual(response.json()["total_alerts"], 2)
        alerts = client.get("/api/alerts").json()["alerts"]
        categories = {a["category"] for a in alerts}
        self.assertIn("Brute-force login attempts", categories)
        self.assertIn("Success after repeated failures", categories)

    def test_invalid_file_type(self):
        response = client.post("/api/logs/upload", files={"file": ("events.txt", b"hello", "text/plain")})
        self.assertEqual(response.status_code, 400)

    def test_stats_after_sample(self):
        client.post("/api/demo/sample")
        stats = client.get("/api/dashboard/stats").json()
        self.assertGreater(stats["processed_events"], 0)
        self.assertGreater(stats["total_alerts"], 0)

    def test_alert_status_update(self):
        client.post("/api/demo/sample")
        alert = client.get("/api/alerts").json()["alerts"][0]
        response = client.patch(f"/api/alerts/{alert['id']}", json={"status": "Resolved"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(client.get(f"/api/alerts/{alert['id']}").json()["status"], "Resolved")


if __name__ == "__main__":
    unittest.main()
