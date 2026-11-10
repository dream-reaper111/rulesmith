import asyncio
import os
import unittest
from unittest.mock import patch

import httpx

from rulesmith.api import app


class ApiTests(unittest.TestCase):
    def test_auth_and_precheck(self):
        async def check():
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                payload = {"kind": "yara", "content": "rule Test { condition: true }"}
                with patch.dict(os.environ, {"RULESMITH_API_TOKEN": "a" * 32}):
                    response = await client.post("/v1/lint", json=payload)
                    self.assertEqual(response.status_code, 401)
                    response = await client.post("/v1/lint", json=payload,
                                                 headers={"Authorization": "Bearer " + "a" * 32})
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.json()["status"], "precheck_only")

        asyncio.run(check())


if __name__ == "__main__":
    unittest.main()
