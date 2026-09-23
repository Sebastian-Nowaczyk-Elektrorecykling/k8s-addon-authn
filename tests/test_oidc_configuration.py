"""Check the contract between the authentik provider and oauth2-proxy."""
from pathlib import Path
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]


class OIDCConfigurationTests(unittest.TestCase):
    def test_provider_explicitly_permits_the_browser_authorization_code_flow(self):
        # BaseLoader inspects blueprint values without resolving !Env/!Find tags.
        blueprint = yaml.load((ROOT / "apps/authentik/cluster-sites.yaml").read_text(),
                              Loader=yaml.BaseLoader)
        provider = next(entry["attrs"] for entry in blueprint["entries"]
                        if entry["model"] == "authentik_providers_oauth2.oauth2provider")
        # New authentik providers default to no grants. A syntactically valid
        # blueprint without this field returns invalid_request at /authorize/.
        self.assertIn("authorization_code", provider.get("grant_types", []),
                      "authentik must explicitly allow oauth2-proxy's code flow")


if __name__ == "__main__":
    unittest.main()
