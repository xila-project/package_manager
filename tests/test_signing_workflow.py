"""Exercise the reusable workflow's fail-closed signing event guard."""
import os
from pathlib import Path
import subprocess
import textwrap
import unittest

WORKFLOW = Path(__file__).resolve().parents[1] / '.github/workflows/package-wasm.yml'

class SigningRequestContextTests(unittest.TestCase):
    def check_context(self, *, event, ref, sign, publish):
        workflow = WORKFLOW.read_text()
        step = workflow.split('- name: "Validate | Signing request context"', 1)[1]
        block = step.split('        run: |\n', 1)[1].split('      - name:', 1)[0]
        env = dict(os.environ, GITHUB_EVENT_NAME=event, GITHUB_REF=ref,
                   SIGN_ARTIFACT=str(sign).lower(), PUBLISH_RELEASE=str(publish).lower())
        return subprocess.run(['bash', '-c', textwrap.dedent(block)], env=env, capture_output=True).returncode

    def test_main_and_tag_pushes_are_allowed(self):
        self.assertEqual(self.check_context(event='push', ref='refs/heads/main', sign=True, publish=False), 0)
        self.assertEqual(self.check_context(event='push', ref='refs/tags/v1.0.0', sign=False, publish=True), 0)

    def test_release_publication_from_release_plz_main_push(self):
        # release-plz tags from the main push itself; GITHUB_TOKEN tags start no workflow.
        self.assertEqual(self.check_context(event='push', ref='refs/heads/main', sign=False, publish=True), 0)
        self.assertEqual(self.check_context(event='push', ref='refs/heads/main', sign=True, publish=True), 0)

    def test_single_secret_signer_without_external_vault(self):
        workflow = WORKFLOW.read_text()
        self.assertIn('XILA_DEV_SIGNING_SEED_B64: ${{ secrets.XILA_DEV_SIGNING_SEED_B64 }}', workflow)
        self.assertIn('package-manager/tools/sign_with_seed.py', workflow)
        self.assertIn('"$PACKAGE_FILENAME.pub"', workflow)
        self.assertIn('"$builder" verify', workflow)
        for removed in ('OpenBao', 'NetBird', 'id-token'):
            self.assertNotIn(removed, workflow)

    def test_pr_manual_and_wrong_ref_cannot_request_signing(self):
        for event, ref, sign, publish in [
            ('pull_request', 'refs/pull/1/merge', True, False),
            ('workflow_dispatch', 'refs/heads/main', True, False),
            ('push', 'refs/heads/other', True, False),
            ('push', 'refs/heads/other', False, True),
            ('workflow_dispatch', 'refs/tags/v1.0.0', False, True),
        ]:
            with self.subTest(event=event, ref=ref):
                self.assertNotEqual(self.check_context(event=event, ref=ref, sign=sign, publish=publish), 0)
