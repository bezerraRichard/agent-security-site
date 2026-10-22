import unittest
from email.message import Message

from agent_security.fingerprint import AEM_CLOUD, detect_platform


def page(facts=None, **headers):
    message = Message()
    for key, value in headers.items():
        message[key.replace("_", "-")] = value
    return {"headers": message, "facts": facts}


class DetectPlatformTests(unittest.TestCase):
    def test_aem_cloud_service_behind_fastly(self):
        platform = detect_platform(
            [
                {"headers": None},
                page(X_Served_By="cache-lis1490056-LIS", X_Vhost="publish", facts={"technologies": ["OneTrust"]}),
            ]
        )
        self.assertEqual((platform["cdn"], platform["cms"]), ("Fastly", AEM_CLOUD))
        self.assertEqual(platform["technologies"], ["OneTrust"])
        self.assertIn("CDN Fastly: X-Served-By: cache-lis1490056-LIS", platform["evidence"])

    def test_other_cdns_and_aem_from_page_resources(self):
        self.assertEqual(detect_platform([page(CF_RAY="abc")])["cdn"], "Cloudflare")
        self.assertEqual(detect_platform([page(X_Amz_Cf_Id="x")])["cdn"], "Amazon CloudFront")
        aem = detect_platform([page(facts={"technologies": ["Adobe Experience Manager"]})])
        self.assertEqual((aem["cdn"], aem["cms"]), (None, "Adobe Experience Manager"))

    def test_nothing_recognised(self):
        self.assertEqual(
            detect_platform([page(Server="nginx")]), {"cdn": None, "cms": None, "technologies": [], "evidence": []}
        )


if __name__ == "__main__":
    unittest.main()
