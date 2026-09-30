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
    current_auth_token,
    reset_register_rate_limits,
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
        reset_register_rate_limits()
        current_auth_token.set(None)
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / 'test_agents.db'
        self.logs_dir = Path(self.temp_dir) / 'logs'
        self.storage = ChatStorage(db_path=self.db_path, logs_dir=self.logs_dir)
        self.orig_storage = hub.storage
        hub.storage = self.storage
        self.hub = hub

    def tearDown(self):
        current_auth_token.set(None)
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
        current_auth_token.set(None)
        c_res = json.loads(create_room('pub-room'))
        self.assertEqual(c_res['status'], 'error')
        self.assertTrue('Access denied' in c_res['error'] or 'Missing' in c_res['error'])

        reg = self.hub.register_agent_admin(callsign='Claude-1.5', supervisor_token=self.hub.human_token)
        claude_token = reg['token']

        current_auth_token.set(claude_token)
        c_res_ok = json.loads(create_room('pub-room'))
        self.assertEqual(c_res_ok['status'], 'success')

        current_auth_token.set(None)
        l_res = json.loads(list_rooms())
        self.assertEqual(l_res['status'], 'error')
        self.assertTrue('Access denied' in l_res['error'] or 'Missing' in l_res['error'])

        current_auth_token.set(claude_token)
        l_res_ok = json.loads(list_rooms())
        self.assertEqual(l_res_ok['status'], 'success')

        current_auth_token.set(None)
        chk_res = json.loads(check_new_messages('pub-room'))
        self.assertEqual(chk_res['status'], 'error')
        self.assertTrue('Access denied' in chk_res['error'] or 'Missing' in chk_res['error'])

        current_auth_token.set(claude_token)
        chk_res_ok = json.loads(check_new_messages('pub-room'))
        self.assertEqual(chk_res_ok['status'], 'success')
        current_auth_token.set(None)

    async def test_auto_binding_and_anti_impersonation(self):
        reg1 = self.hub.register_agent_admin(callsign='Claude-1.5', supervisor_token=self.hub.human_token)
        reg2 = self.hub.register_agent_admin(callsign='CL-Neural-Dev2', supervisor_token=self.hub.human_token)

        current_auth_token.set(reg1['token'])
        create_room('work-room')

        msg_res = json.loads(await send_message('work-room', 'Hello from official Claude'))
        self.assertEqual(msg_res['status'], 'success')
        self.assertEqual(msg_res['sender'], 'Claude-1.5')
        self.assertTrue(msg_res['is_verified'])

        # Sending with another agent's token binds that other agent
        current_auth_token.set(reg2['token'])
        msg_res2 = json.loads(await send_message('work-room', 'Hello from Dev2'))
        self.assertEqual(msg_res2['status'], 'success')
        self.assertEqual(msg_res2['sender'], 'CL-Neural-Dev2')
        self.assertTrue(msg_res2['is_verified'])

        # Direct hub send_message with mismatched token is blocked
        with self.assertRaises(PermissionError):
            await self.hub.send_message('work-room', sender='CL-Neural-Dev2', content='Fake dev', member_token=reg1['token'])

        with self.assertRaises(PermissionError):
            await self.hub.send_message('work-room', sender='Rui', content='Fake rui', member_token=reg1['token'])
        current_auth_token.set(None)

    async def test_dlp_token_masking(self):
        reg = self.hub.register_agent_admin(callsign='Claude-1.5', supervisor_token=self.hub.human_token)
        claude_tok = reg['token']

        current_auth_token.set(claude_tok)
        create_room('chat-room')

        leaked_content = f'Olha aqui o meu token secreto: {claude_tok} e o do admin {self.hub.human_token}!'
        msg_res = json.loads(await send_message('chat-room', leaked_content))
        self.assertEqual(msg_res['status'], 'success')

        read_res = json.loads(read_messages('chat-room'))
        stored_content = read_res['messages'][0]['content']
        self.assertNotIn(claude_tok, stored_content)
        self.assertNotIn(self.hub.human_token, stored_content)
        self.assertIn('[REDACTED_TOKEN]', stored_content)
        current_auth_token.set(None)

    def test_get_my_identity_tool(self):
        reg = self.hub.register_agent_admin(callsign='Claude-1.5', supervisor_token=self.hub.human_token)
        claude_tok = reg['token']

        current_auth_token.set(claude_tok)
        ident_res = json.loads(get_my_identity())
        self.assertEqual(ident_res['status'], 'success')
        self.assertEqual(ident_res['callsign'], 'Claude-1.5')
        self.assertEqual(ident_res['role'], 'agent')
        self.assertFalse(ident_res['is_human'])
        current_auth_token.set(None)

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

        # 2. Self register successfully (token withheld from response, delivered by administrator)
        raw_res = register_agent(callsign='NewDev-1')
        data = json.loads(raw_res)
        self.assertIn(data['status'], ('registered_pending_token', 'pending'))
        self.assertEqual(data['callsign'], 'NewDev-1')
        self.assertNotIn('agent_token', data)
        self.assertTrue('administrador' in data['message'].lower() or 'supervisor' in data['message'].lower())

        # Retrieve token
        agents = hub.list_registered_agents(requester_token=hub.human_token)
        agent_entry = next(a for a in agents if a['callsign'].lower() == 'newdev-1')
        token = agent_entry.get('token')
        if not token:
            token = self.storage.get_agent_identity_by_name('NewDev-1')['token']
        self.assertTrue(len(token) > 10)

        # 3. Duplicate rejection
        dup_res = json.loads(register_agent(callsign='newdev-1'))
        self.assertEqual(dup_res['status'], 'error')
        self.assertIn('já está em uso', dup_res['error'])

        # 4. Use token to call get_my_identity
        current_auth_token.set(token)
        ident = json.loads(get_my_identity())
        self.assertEqual(ident['status'], 'success')
        self.assertEqual(ident['callsign'], 'NewDev-1')
        current_auth_token.set(None)

    def test_deactivated_agent_cannot_self_reactivate_and_old_token_revoked(self):
        # 1. Register agent
        reg = self.hub.register_agent_admin(callsign="DeactAgent", supervisor_token=self.hub.human_token)
        orig_token = reg["token"]
        self.hub.create_room("room-deact-test")
        self.hub.join_room("room-deact-test", "DeactAgent", role="agent", member_token=orig_token)

        # 2. Rotate token
        new_token = self.hub.rotate_agent_token_admin("DeactAgent", supervisor_token=self.hub.human_token)
        self.assertNotEqual(orig_token, new_token)

        # Original token must be rejected immediately (not active anywhere)
        current_auth_token.set(orig_token)
        raw_ident_orig = get_my_identity()
        data_orig = json.loads(raw_ident_orig)
        self.assertEqual(data_orig["status"], "error")
        self.assertIn("Token de agente inválido", data_orig["error"])
        current_auth_token.set(None)

        # 3. Deactivate agent
        self.hub.update_agent_status_admin("DeactAgent", "inactive", supervisor_token=self.hub.human_token)

        # New token is now also rejected because agent is inactive
        current_auth_token.set(new_token)
        raw_ident_new = get_my_identity()
        data_new = json.loads(raw_ident_new)
        self.assertEqual(data_new["status"], "error")
        self.assertIn("desativado", data_new["error"].lower())
        current_auth_token.set(None)

        # 4. Deactivated agent attempts self-registration to reactivate itself -> MUST FAIL
        current_auth_token.set(None)
        raw_self_reg = register_agent(callsign="DeactAgent")
        data_self_reg = json.loads(raw_self_reg)
        self.assertEqual(data_self_reg["status"], "error")
        self.assertTrue("desativado" in data_self_reg["error"].lower() or "já está em uso" in data_self_reg["error"].lower() or "já existe" in data_self_reg["error"].lower())

        # Verify agent is still inactive
        agent_info = self.hub.storage.get_agent_identity_by_name("DeactAgent")
        self.assertEqual(agent_info["status"], "inactive")

        # 5. Only supervisor can reactivate
        self.hub.update_agent_status_admin("DeactAgent", "active", supervisor_token=self.hub.human_token)
        agent_info_after = self.hub.storage.get_agent_identity_by_name("DeactAgent")
        self.assertEqual(agent_info_after["status"], "active")

        # Now active agent can authenticate with current token
        current_auth_token.set(new_token)
        ident_ok = json.loads(get_my_identity())
        self.assertEqual(ident_ok["status"], "success")
        self.assertEqual(ident_ok["agent_status"], "active")
        current_auth_token.set(None)


if __name__ == '__main__':
    unittest.main()

