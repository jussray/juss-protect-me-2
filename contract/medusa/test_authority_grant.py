#!/usr/bin/env python3
"""Local synthetic acceptance tests for Medusa Layer 1; never contact networks."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from datetime import timedelta

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import authority_grant as g


class AuthorityGrantTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.grants = self.root / 'grants'
        self.grants.mkdir(mode=0o700)
        self.trust = self.root / 'trusted.json'
        self.old_env = dict(os.environ)
        self.addCleanup(lambda: (os.environ.clear(), os.environ.update(self.old_env)))
        os.environ['MEDUSA_GRANTS_DIR'] = str(self.grants)
        os.environ['MEDUSA_TRUSTED_SIGNERS'] = str(self.trust)
        self.keys = {}
        self.entries = []
        for who in ('alice', 'bob', 'eve'):
            key = Ed25519PrivateKey.generate()
            path = self.root / (who + '.pem')
            path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            path.chmod(0o600)
            self.keys[who] = str(path)
            pub = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
            entry = {'decider': who, 'public_key_b64': pub}
            if who == 'alice':
                entry['authority'] = {'action_classes': ['quarantine_file', 'block_deploy', 'log_only'],
                                      'target_scopes': ['/srv/apps'],
                                      'excluded_paths': ['/srv/apps/secrets'],
                                      'max_blast_radius': 5,
                                      'min_evidence_tag': 'VERIFIED',
                                      'min_detection_severity': 'High',
                                      'expires_at': g.iso(g.utc_now() + timedelta(days=6)),
                                      'can_delegate': True,
                                      'max_delegation_depth': 2}
            self.entries.append(entry)
        self.trust.write_text(json.dumps({'signers': self.entries}))
        self.trust.chmod(0o600)

    def cli(self, *a):
        with contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()) as err:
            code = g.main(list(a))
        return code, output.getvalue(), err.getvalue()

    def issue(self, who='alice', name='parent', extra=()):
        return self.cli('issue', '--decider', who, '--key', self.keys[who], '--grant-id', name,
                        '--action-class', 'quarantine_file', '--target-scope', '/srv/apps/payments',
                        '--hours', '24', *extra)

    def assert_blocked(self, result, text=None):
        self.assertEqual(result[0], 2, result)
        if text:
            self.assertIn(text, result[2])

    def test_root_valid_and_signed_audit(self):
        self.assertEqual(self.issue()[0], 0)
        self.assertEqual(self.cli('verify', 'parent')[0], 0)
        self.assertIn('1 events', self.cli('audit')[1])

    def test_world_writable_trust_file_is_refused(self):
        self.trust.chmod(0o666)
        self.assert_blocked(self.issue(), 'trust file permissions')

    def test_unsafe_trust_directory_is_refused(self):
        self.root.chmod(0o777)
        self.addCleanup(lambda: self.root.chmod(0o700))
        self.assert_blocked(self.issue(), 'trust directory permissions')

    def test_duplicate_public_key_cannot_name_two_deciders(self):
        self.entries[1]['public_key_b64'] = self.entries[0]['public_key_b64']
        self.trust.write_text(json.dumps({'signers': self.entries}))
        self.assert_blocked(self.issue(), 'duplicate public signing key')

    def test_identity_cannot_be_confused(self):
        result = self.cli('issue', '--decider', 'alice', '--key', self.keys['eve'],
                          '--action-class', 'quarantine_file', '--target-scope', '/srv/apps/payments')
        self.assert_blocked(result, 'signing key does not belong')
        self.assertFalse(list(self.grants.glob('*.grant.json')))

    def test_no_automatic_revocation_or_irreversible_actions(self):
        for action in ('revoke_token', 'isolate_host', 'delete_file', 'transfer_ownership'):
            self.assert_blocked(self.issue(extra=('--action-class', action)), 'manual-only')

    def test_unsafe_id_and_overwrite_blocked(self):
        self.assert_blocked(self.issue(name='../escape'), 'unsafe grant_id')
        self.assertEqual(self.issue()[0], 0)
        self.assert_blocked(self.issue(), 'grant ID already exists')

    def test_symlink_grant_filename_refused(self):
        outside = self.root / 'outside'
        outside.write_text('sentinel')
        (self.grants / 'parent.grant.json').symlink_to(outside)
        self.assert_blocked(self.issue())
        self.assertEqual(outside.read_text(), 'sentinel')

    def test_bad_duration_blocks(self):
        for val in ('0', '-1', 'nan', 'inf', '800'):
            self.assert_blocked(self.issue(extra=('--hours', val)), 'hours')

    def test_scope_caps_and_exclusion(self):
        self.assert_blocked(self.issue(extra=('--blast-radius', '6')), 'root blast radius')
        self.assert_blocked(self.issue(extra=('--target-scope', '/etc')), 'root target scope')
        self.assert_blocked(self.issue(extra=('--target-scope', '/srv/apps/secrets')), 'excluded root path')
        self.assert_blocked(self.issue(extra=('--severity', 'Low')), 'root severity threshold')
        self.assert_blocked(self.issue(extra=('--target-scope', '/srv/apps/../etc')), 'traversal')

    def test_delegation_valid_and_restrictions_at_issue(self):
        self.assertEqual(self.issue(extra=('--delegate-to', 'bob', '--delegation-depth', '2', '--blast-radius', '5'))[0], 0)
        child_args = ('--delegates-from', 'parent', '--blast-radius', '3', '--severity', 'Critical', '--delegation-depth', '1')
        self.assertEqual(self.issue('bob', 'child', extra=child_args)[0], 0)
        self.assertEqual(self.cli('verify', 'child')[0], 0)
        self.assert_blocked(self.issue('bob', 'too_wide', extra=('--delegates-from', 'parent', '--blast-radius', '10')), 'widens blast radius')
        self.assert_blocked(self.issue('bob', 'too_low', extra=('--delegates-from', 'parent', '--severity', 'Medium')), 'lowers severity')
        self.assert_blocked(self.issue('bob', 'too_broad', extra=('--delegates-from', 'parent', '--target-scope', '/srv/apps')), 'widens target scope')
        self.assert_blocked(self.issue('bob', 'too_long', extra=('--delegates-from', 'parent', '--hours', '48')), 'outlives parent')
        self.assert_blocked(self.issue('eve', 'unauth', extra=('--delegates-from', 'parent',)), 'did not authorize this delegate')

    def test_parent_revocation_invalidates_child(self):
        self.assertEqual(self.issue(extra=('--delegate-to', 'bob', '--delegation-depth', '2', '--blast-radius', '5'))[0], 0)
        self.assertEqual(self.issue('bob', 'child', extra=('--delegates-from', 'parent'))[0], 0)
        self.assert_blocked(self.cli('revoke', 'parent', '--decider', 'bob', '--key', self.keys['bob']), 'only granting decider')
        self.assertEqual(self.cli('revoke', 'parent', '--decider', 'alice', '--key', self.keys['alice'])[0], 0)
        self.assert_blocked(self.cli('verify', 'parent'), 'revoked')
        self.assert_blocked(self.cli('verify', 'child'), 'revoked')

    def test_revocation_cannot_overwrite_original_grant(self):
        self.assertEqual(self.issue()[0], 0)
        original = (self.grants / 'parent.grant.json').read_bytes()
        self.assertEqual(self.cli('revoke', 'parent', '--decider', 'alice', '--key', self.keys['alice'])[0], 0)
        self.assertEqual((self.grants / 'parent.grant.json').read_bytes(), original)
        self.assert_blocked(self.cli('revoke', 'parent', '--decider', 'alice', '--key', self.keys['alice']), 'revoked')

    def test_unsigned_changes_block(self):
        self.assertEqual(self.issue()[0], 0)
        path = self.grants / 'parent.grant.json'
        doc = json.loads(path.read_text())
        doc['max_blast_radius'] = 999
        path.write_text(json.dumps(doc))
        self.assert_blocked(self.cli('verify', 'parent'), 'invalid grant signature')

    def test_audit_chain_tampering_blocks(self):
        self.assertEqual(self.issue()[0], 0)
        path = self.grants / '_audit.jsonl'
        blob = path.read_bytes()
        path.write_bytes(blob[:-3])
        self.assert_blocked(self.cli('verify', 'parent'))
        self.assert_blocked(self.issue('alice', 'next'))

    def test_deleted_audit_blocks_existing_grants(self):
        self.assertEqual(self.issue()[0], 0)
        (self.grants / '_audit.jsonl').unlink()
        self.assert_blocked(self.cli('verify', 'parent'), 'audit log missing')

    def test_signed_revocation_tampering_fails_closed(self):
        self.assertEqual(self.issue()[0], 0)
        self.assertEqual(self.cli('revoke', 'parent', '--decider', 'alice', '--key', self.keys['alice'])[0], 0)
        path = self.grants / 'parent.revocation.json'
        rev = json.loads(path.read_text())
        rev['decider'] = 'bob'
        path.write_text(json.dumps(rev))
        self.assert_blocked(self.cli('verify', 'parent'), 'invalid signed revocation')

    def test_root_authority_required(self):
        self.assert_blocked(self.issue('bob', 'unauth'), 'root decider has no explicit authority')

    def test_parent_exclusion_inherited_only_when_scope_overlaps(self):
        self.assertEqual(self.issue(extra=('--target-scope', '/srv/apps',
                                           '--exclude', '/srv/apps/secrets',
                                           '--delegate-to', 'bob', '--delegation-depth', '1'))[0], 0)
        # Child narrows to payments, so a sibling exclusion is no longer needed.
        self.assertEqual(self.issue('bob', 'child', extra=('--delegates-from', 'parent'))[0], 0)
        self.assert_blocked(self.issue('bob', 'no_exclusion', extra=('--delegates-from', 'parent',
                                  '--target-scope', '/srv/apps')), 'removes excluded paths')
        self.assert_blocked(self.issue('bob', 'secret_scope', extra=('--delegates-from', 'parent',
                                  '--target-scope', '/srv/apps/secrets')), 'excluded path')

    def test_expiry_checked_at_verification_including_parent(self):
        self.assertEqual(self.issue()[0], 0)
        grant = g.load_grant('parent')
        at = g.when(grant['expires_at']) + timedelta(seconds=1)
        with self.assertRaisesRegex(g.GrantError, 'not active'):
            g.check_grant(grant, g.signer_db(), at=at)

    def test_two_concurrent_writers_preserve_hash_chain(self):
        script = str(Path(g.__file__))
        env = dict(os.environ)
        cmds = [[sys.executable, script, 'issue', '--decider', 'alice', '--key', self.keys['alice'],
                 '--grant-id', gid, '--action-class', 'quarantine_file', '--target-scope', '/srv/apps/payments']
                for gid in ('parallel_1', 'parallel_2')]
        p1 = subprocess.Popen(cmds[0], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
        p2 = subprocess.Popen(cmds[1], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
        _o1, e1 = p1.communicate(timeout=10)
        _o2, e2 = p2.communicate(timeout=10)
        self.assertEqual((p1.returncode, p2.returncode), (0, 0), (e1, e2))
        self.assertEqual(self.cli('verify', 'parallel_1')[0], 0)
        self.assertEqual(self.cli('verify', 'parallel_2')[0], 0)
        self.assertEqual(len(g.verify_ledger(g.signer_db())), 2)

    def test_no_auto_actuator_in_module(self):
        self.assertFalse(hasattr(g, 'execute_action'))
        self.assertFalse(hasattr(g, 'actuate'))


if __name__ == '__main__':
    unittest.main()
