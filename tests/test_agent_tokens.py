import os
os.environ["AICHAT_TESTING"] = "1"
import asyncio
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from aichat.hub import ChatHub
from aichat.storage import ChatStorage
from aichat.mcp_server import (
    hub,
    register_agent,
    get_my_identity,
    create_room,
    list_rooms,
    join_room,
    send_message,
    read_messages,
    check_new_messages,
    who_is_listening,
)


class TestAgentTokensAndClosedRegistry(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / 'test_agents.db'
        self.logs_dir = Path(self.temp_dir) / 'logs'
        self.storage = ChatStorage(db_path=self.db_path, logs_dir=self.logs_dir)
        self.orig_storage = hub.storage
        hub.storage = self.storage
        self.hub = hub

    def tearDown(self):
        self.storage.close()
        hub.storage = self.orig_storage
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_closed_registry_and_duplicate_rejection(self):
        with self.assertRaises(PermissionError):
            self.hub.register_agent_admin(callsign='Claude-1.5', supervisor_token='wrong_token')

        res = self.hub.register_agent_admin(callsign='Claude-1.5', supervisor_token=self.hub.human_token)
        self.assertEqual(res['callsign'], 'Claude-1.5')
        token_1 = res['token']
        self.assertTrue(len(token_1) > 10)

        with self.assertRaises(ValueError) as ctx:
            self.hub.register_agent_admin(callsign='Claude-1.5', supervisor_token=self.hub.human_token)
        self.assertIn('já está em uso', str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            self.hub.register_agent_admin(callsign='claude-1.5', supervisor_token=self.hub.human_token)
        self.assertIn('já está em uso', str(ctx.exception))

        with self.assertRaises(ValueError) as ctx:
            self.hub.register_agent_admin(callsign='Rui', supervisor_token=self.hub.human_token)
        self.assertIn('reservado', str(ctx.exception))

    async def test_mcp_requires_token_on_all_tools(self):
        c_res = json.loads(create_room('pub-room'))
        self.assertEqual(c_res['status'], 'error')
        self.assertIn('Missing agent_token', c_res['error'])

        reg = self.hub.register_agent_admin(callsign='Claude-1.5', supervisor_token=self.hub.human_token)
        claude_token = reg['token']

        c_res_ok = json.loads(create_room('pub-room', agent_token=claude_token))
        self.assertEqual(c_res_ok['status'], 'success')

        l_res = json.loads(list_rooms())
        self.assertEqual(l_res['status'], 'error')
        self.assertIn('Missing agent_token', l_res['error'])

        l_res_ok = json.loads(list_rooms(agent_token=claude_token))
        self.assertEqual(l_res_ok['status'], 'success')

        chk_res = json.loads(check_new_messages('pub-room'))
        self.assertEqual(chk_res['status'], 'error')
        self.assertIn('Missing agent_token', chk_res['error'])

        chk_res_ok = json.loads(check_new_messages('pub-room', agent_token=claude_token))
        self.assertEqual(chk_res_ok['status'], 'success')

    async def test_auto_binding_and_anti_impersonation(self):
        reg1 = self.hub.register_agent_admin(callsign='Claude-1.5', supervisor_token=self.hub.human_token)
        reg2 = self.hub.register_agent_admin(callsign='CL-Neural-Dev2', supervisor_token=self.hub.human_token)
        create_room('work-room', agent_token=reg1['token'])

        msg_res = json.loads(await send_message('work-room', 'Hello from official Claude', agent_token=reg1['token']))
        self.assertEqual(msg_res['status'], 'success')
        self.assertEqual(msg_res['sender'], 'Claude-1.5')
        self.assertTrue(msg_res['is_verified'])

        fake_res = json.loads(await send_message('work-room', 'I am dev', sender_name='CL-Neural-Dev2', agent_token=reg1['token']))
        self.assertEqual(fake_res['status'], 'error')
        self.assertIn('Impersonation blocked', fake_res['error'])

        fake_rui = json.loads(await send_message('work-room', 'I am Rui', sender_name='Rui', agent_token=reg1['token']))
        self.assertEqual(fake_rui['status'], 'error')
        self.assertIn('Impersonation blocked', fake_rui['error'])

    async def test_dlp_token_masking(self):
        reg = self.hub.register_agent_admin(callsign='Claude-1.5', supervisor_token=self.hub.human_token)
        claude_tok = reg['token']
        create_room('chat-room', agent_token=claude_tok)

        leaked_content = f'Olha aqui o meu token secreto: {claude_tok} e o do admin {self.hub.human_token}!'
        msg_res = json.loads(await send_message('chat-room', leaked_content, agent_token=claude_tok))
        self.assertEqual(msg_res['status'], 'success')

        read_res = json.loads(read_messages('chat-room', agent_token=claude_tok))
        stored_content = read_res['messages'][0]['content']
        self.assertNotIn(claude_tok, stored_content)
        self.assertNotIn(self.hub.human_token, stored_content)
        self.assertIn('[REDACTED_TOKEN]', stored_content)

    def test_get_my_identity_tool(self):
        reg = self.hub.register_agent_admin(callsign='Claude-1.5', supervisor_token=self.hub.human_token)
        claude_tok = reg['token']

        ident_res = json.loads(get_my_identity(agent_token=claude_tok))
        self.assertEqual(ident_res['status'], 'success')
        self.assertEqual(ident_res['callsign'], 'Claude-1.5')
        self.assertEqual(ident_res['role'], 'agent')
        self.assertFalse(ident_res['is_human'])

    def test_env_var_agent_token(self):
        import os
        reg = self.hub.register_agent_admin(callsign='Claude-1.5', supervisor_token=self.hub.human_token)
        claude_tok = reg['token']

        # Without token or env var -> error
        err_res = json.loads(list_rooms())
        self.assertEqual(err_res['status'], 'error')

        # With env var set -> success
        os.environ['AI_CHAT_AGENT_TOKEN'] = claude_tok
        try:
            ok_res = json.loads(list_rooms())
            self.assertEqual(ok_res['status'], 'success')
            ident_res = json.loads(get_my_identity())
            self.assertEqual(ident_res['status'], 'success')
            self.assertEqual(ident_res['callsign'], 'Claude-1.5')
        finally:
            os.environ.pop('AI_CHAT_AGENT_TOKEN', None)

    async def test_human_supervisor_master_room_access(self):
        # Create a protected room with a strict room password
        self.hub.create_room('vault-room', password='SuperSecretPassword!')

        # Unauthenticated / empty token cannot verify access
        self.assertFalse(self.hub.verify_room_access('vault-room', password='wrong'))
        self.assertFalse(self.hub.verify_room_access('vault-room', password=''))

        # Human supervisor token grants master access without room password
        self.assertTrue(self.hub.verify_room_access('vault-room', requester_token=self.hub.human_token))

        # Supervisor can read messages without room password
        msgs = self.hub.read_messages('vault-room', requester_token=self.hub.human_token)
        self.assertEqual(msgs, [])

        # Supervisor can list tasks and check presence without room password
        tasks = self.hub.list_tasks('vault-room', requester_token=self.hub.human_token)
        self.assertEqual(tasks, [])
        presence = self.hub.who_is_listening('vault-room', requester_token=self.hub.human_token)
        self.assertIn('total_listening', presence)

    def test_self_register_agent(self):
        # 1. Reject reserved human names
        raw_res = register_agent(callsign='Rui')
        data = json.loads(raw_res)
        self.assertEqual(data['status'], 'error')
        self.assertIn('reservado', data['error'])

        # 2. Self register successfully (token withheld from response, delivered by supervisor)
        raw_res = register_agent(callsign='NewDev-1')
        data = json.loads(raw_res)
        self.assertEqual(data['status'], 'registered_pending_token')
        self.assertEqual(data['callsign'], 'NewDev-1')
        self.assertNotIn('agent_token', data)
        self.assertIn('supervisor Rui', data['message'])

        # Supervisor Rui inspects registry and retrieves token
        agents = hub.list_registered_agents(requester_token=hub.human_token)
        agent_entry = next(a for a in agents if a['callsign'].lower() == 'newdev-1')
        token = agent_entry['token']
        self.assertTrue(len(token) > 10)

        # 3. Duplicate rejection
        dup_res = json.loads(register_agent(callsign='newdev-1'))
        self.assertEqual(dup_res['status'], 'error')
        self.assertIn('já está em uso', dup_res['error'])

        # 4. Use token received from supervisor to call get_my_identity
        ident = json.loads(get_my_identity(agent_token=token))
        self.assertEqual(ident['status'], 'success')
        self.assertEqual(ident['callsign'], 'NewDev-1')


if __name__ == '__main__':
    unittest.main()

