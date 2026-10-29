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

    def test_development_signing_stays_separate_from_release_signing(self):
        workflow = WORKFLOW.read_text()
        self.assertIn('if: inputs.sign-artifact && !inputs.publish-release', workflow)
        for step in ('Validate | Signing builder revision',
                     'Setup | Connect ephemeral NetBird peer',
                     'Diagnose | OpenBao connectivity',
                     'Sign | Authenticate with OpenBao'):
            section = workflow.split('- name: "' + step + '"', 1)[1].split('\n      - name:', 1)[0]
            self.assertIn('if: inputs.publish-release', section)
        self.assertIn('"$PACKAGE_FILENAME.pub"', workflow)
        self.assertIn('"$RUNNER_TEMP/signing-work/public.key"', workflow)
        self.assertIn('"$builder" verify', workflow)
        self.assertIn('ephemeral CI signing and release signing must not be combined', workflow)

    def test_pr_manual_and_wrong_ref_cannot_request_signing(self):
        for event, ref, sign, publish in [
            ('pull_request', 'refs/pull/1/merge', True, False),
            ('workflow_dispatch', 'refs/heads/main', True, False),
            ('push', 'refs/heads/other', True, False),
            ('push', 'refs/heads/main', False, True),
            ('workflow_dispatch', 'refs/tags/v1.0.0', False, True),
        ]:
            with self.subTest(event=event, ref=ref):
                self.assertNotEqual(self.check_context(event=event, ref=ref, sign=sign, publish=publish), 0)
