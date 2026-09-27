import ast
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('policy', ROOT/'native/action_policy.py')
policy = importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name] = policy
spec.loader.exec_module(policy)


class PolicyTests(unittest.TestCase):
    def test_all_actual_deployed_dispatches_accounted(self):
        source = ast.parse((ROOT/'data/Dockerfiles/dockerapi/modules/DockerApi.py').read_text())
        existing = {item.name.removeprefix('container_post__') for cls in source.body if isinstance(cls, ast.ClassDef) for item in cls.body if isinstance(item, ast.FunctionDef) and item.name.startswith('container_post__')}
        self.assertEqual(existing, policy.OPERATIONS)
        self.assertEqual(len(existing), 29)  # Plus host stats observation outside container_post.

    def test_control_and_no_arbitrary_units(self):
        plan = policy.compile_action('dovecot-mailcow', 'restart', {})
        self.assertEqual(plan.argv, ('/usr/bin/systemctl', 'restart', '--', 'mailcow-dovecot.service'))
        for service in ('sshd', 'nginx.service', '../../sshd', 'postfix-mailcow;shutdown'):
            with self.assertRaises(policy.PolicyError): policy.compile_action(service, 'stop', {})
        with self.assertRaises(policy.PolicyError): policy.compile_action('postfix-mailcow', 'exec', {'cmd':'system','task':'fts_rescan','all':True})

    def test_queue_ids_and_shell_injection(self):
        plan = policy.compile_action('postfix-mailcow','exec', {'cmd':'mailq','task':'delete','items':['A1','b2']})
        self.assertEqual(plan.argv, ('/usr/sbin/postsuper','-d','A1','-d','b2'))
        for items in ([], ['ALL'], ['x;whoami'], ['AB\n'], ['-d'], 'AB', ['1'*65]):
            with self.assertRaises(policy.PolicyError): policy.compile_action('postfix-mailcow','exec', {'cmd':'mailq','task':'delete','items':items})
        plan = policy.compile_action('dovecot-mailcow','exec', {'cmd':'sieve','task':'list','username':"fixture';$(id)@example.test"})
        self.assertEqual(plan.argv[-1], "fixture';$(id)@example.test")
        self.assertNotIn('/bin/bash', plan.argv)

    def test_maildir_and_disk_scope(self):
        for value in ('../secret','domain/../../secret','/absolute','domain/.hidden','domain/user/extra','domain\\user','domain/..'):
            with self.assertRaises(policy.PolicyError): policy.compile_action('dovecot-mailcow','exec', {'cmd':'maildir','task':'cleanup','maildir':value})
        plan = policy.compile_action('dovecot-mailcow','exec', {'cmd':'maildir','task':'move','old_maildir':'example.test/fixture','new_maildir':'example.test/renamed'})
        self.assertEqual(plan.primitive, 'maildir-transaction')
        with self.assertRaises(policy.PolicyError): policy.compile_action('dovecot-mailcow','exec', {'cmd':'system','task':'df','dir':'/etc'})

    def test_pubsub_same_policy_and_secret_not_in_plan(self):
        request = {'cmd':'rspamd','task':'worker_password','raw':'synthetic-secret'}
        plan = policy.compile_pubsub({'api_call':'container_post','container_name':'rspamd-mailcow','post_action':'exec','request':request})
        self.assertNotIn('synthetic-secret', repr(plan))
        self.assertEqual(plan, policy.compile_action('rspamd-mailcow','exec', request))
        with self.assertRaises(policy.PolicyError): policy.compile_pubsub({'api_call':'exec','container_name':'rspamd-mailcow','request':request})

    def test_option_values_and_service_user_context(self):
        sieve = policy.compile_action('dovecot-mailcow','exec', {'cmd':'sieve','task':'print','username':'-fixture@example.test','script_name':'-A'})
        self.assertEqual(sieve.argv[-2:], ('--', '-A'))
        acl = policy.compile_action('dovecot-mailcow','exec', {'cmd':'doveadm','task':'set_acl','user':'-fixture@example.test','mailbox':'-A','id':'-peer@example.test','rights':['read']})
        self.assertEqual(acl.argv[5:7], ('--', '-A'))
        rename = policy.compile_action('sogo-mailcow','exec', {'cmd':'sogo','task':'rename_user','old_username':'-old@example.test','new_username':'-new@example.test'})
        self.assertEqual(rename.argv[-2:], ('-old@example.test','-new@example.test'))
        self.assertEqual(rename.user,'sogo')
        for task in ('cat','list','flush','deliver'):
            plan = policy.compile_action('postfix-mailcow','exec', {'cmd':'mailq','task':task,'items':['AB']})
            self.assertEqual(plan.user,'postfix')
        self.assertEqual(policy.compile_action('postfix-mailcow','exec', {'cmd':'mailq','task':'delete','items':['AB']}).user,'root')

    def test_complete_operation_examples_compile(self):
        examples = {
            'mailq': ('postfix', {'items':['AB']}), 'system': ('dovecot', {'username':'fixture@example.test','dir':'/var/vmail'}),
            'sieve': ('dovecot', {'username':'fixture@example.test','script_name':'vacation'}),
            'maildir': ('dovecot', {'maildir':'example.test/fixture','old_maildir':'example.test/fixture','new_maildir':'example.test/new'}),
            'rspamd': ('rspamd', {'raw':'synthetic'}), 'sogo': ('sogo', {'old_username':'old@example.test','new_username':'new@example.test'}),
            'doveadm': ('dovecot', {'user':'fixture@example.test','mailbox':'Inbox','id':'peer@example.test','rights':['read']})}
        seen = set()
        for cmd,tasks in policy.EXEC_ACTIONS.items():
            for task in tasks:
                component,fields = examples.get(cmd,('postfix',{}))
                if cmd == 'reload': component = task
                if cmd == 'system' and task.startswith('mysql'): component='mysql'
                plan = policy.compile_action(component+'-mailcow','exec', {'cmd':cmd,'task':task,**fields})
                seen.add(plan.operation)
        self.assertEqual(len(seen),24)


if __name__ == '__main__': unittest.main(verbosity=2)
