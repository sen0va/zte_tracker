"""ZTE H3600P - Turk Telekom firmware: HTTP, single-shot LAN/WLAN endpoints,
session preempt (loginErrType e_exceed_max_user_preempt) and a required root
reload after any successful login. Uses reserved-for-documentation addresses
(RFC 5737, 192.0.2.0/24) only - never a real router address."""

import sys
from pathlib import Path
from unittest import TestCase
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_router_details_parsing import _load_client  # noqa: E402

HOST = "192.0.2.1"

LAN_XML = """<ajax_response_xml_root><IF_ERRORSTR>SUCC</IF_ERRORSTR>
  <OBJ_ACCESSDEV_ID>
    <Instance>
      <ParaName>HostName</ParaName><ParaValue>laptop</ParaValue>
      <ParaName>IPAddress</ParaName><ParaValue>192.0.2.10</ParaValue>
      <ParaName>Active</ParaName><ParaValue>1</ParaValue>
      <ParaName>MACAddress</ParaName><ParaValue>aa:bb:cc:dd:ee:01</ParaValue>
      <ParaName>AliasName</ParaName><ParaValue>LAN1</ParaValue>
    </Instance>
  </OBJ_ACCESSDEV_ID></ajax_response_xml_root>"""

WLAN_XML = """<ajax_response_xml_root><IF_ERRORSTR>SUCC</IF_ERRORSTR>
  <OBJ_ACCESSDEV_ID>
    <Instance>
      <ParaName>HostName</ParaName><ParaValue>phone</ParaValue>
      <ParaName>IPAddress</ParaName><ParaValue>192.0.2.11</ParaValue>
      <ParaName>Active</ParaName><ParaValue>1</ParaValue>
      <ParaName>MACAddress</ParaName><ParaValue>aa:bb:cc:dd:ee:02</ParaValue>
      <ParaName>AliasName</ParaName><ParaValue>home</ParaValue>
    </Instance>
  </OBJ_ACCESSDEV_ID></ajax_response_xml_root>"""

PREEMPT_PAGE_HTML = (
    '<form><input value=sess-42 type="radio" name="preempt_sessid">'
    "</form>"
)


def _resp(text="", content=None, json_data=None):
    r = MagicMock()
    r.raise_for_status = MagicMock()
    r.text = text
    r.content = content if content is not None else text.encode()
    if json_data is not None:
        r.json = MagicMock(return_value=json_data)
    return r


class TestH3600PTTProfile(TestCase):
    def setUp(self):
        self.cls = _load_client()

    def test_model_is_listed_and_distinct_from_retail_h3600p(self):
        self.assertIn("H3600P-TT", self.cls.get_models())
        tt = self.cls(HOST, "admin", "pw", "H3600P-TT")
        retail = self.cls(HOST, "admin", "pw", "H3600P")
        self.assertEqual(tt.scheme, "http")
        self.assertEqual(tt.base_url, f"http://{HOST}")
        self.assertEqual(retail.scheme, "https")
        self.assertIsNot(tt.paths, retail.paths)
        self.assertTrue(tt.paths.get("tt_session_quirks"))
        self.assertFalse(retail.paths.get("tt_session_quirks", False))

    def test_lan_and_wifi_use_single_homepage_request(self):
        client = self.cls(HOST, "admin", "pw", "H3600P-TT")
        client.session = MagicMock()

        client.session.get.side_effect = [_resp(LAN_XML)]
        devices = client.get_lan_devices()
        self.assertEqual(client.session.get.call_count, 1)
        url = client.session.get.call_args[0][0]
        self.assertIn("accessdev_homepage_lua.lua", url)
        self.assertIn("InstNum=1000", url)
        self.assertEqual(devices[0]["MACAddress"], "AA:BB:CC:DD:EE:01")

        client.session.get.side_effect = [_resp(WLAN_XML)]
        devices = client.get_wifi_devices()
        url = client.session.get.call_args[0][0]
        self.assertIn("wlan_homepage_lua.lua", url)
        self.assertIn("InstNum=1000", url)
        self.assertEqual(devices[0]["MACAddress"], "AA:BB:CC:DD:EE:02")


class TestH3600PTTLogin(TestCase):
    def setUp(self):
        self.client = _load_client()(HOST, "admin", "secret", "H3600P-TT")
        self.client._setup_session = MagicMock()
        self.client.session = MagicMock()

    def _token_responses(self):
        return [
            _resp(json_data={"lockingTime": 0, "sess_token": "stok"}),
            _resp(content=b"<ajax_response_xml_root>tok123</ajax_response_xml_root>"),
        ]

    def test_normal_login_reloads_root(self):
        self.client.session.get.side_effect = self._token_responses() + [
            _resp()  # root reload
        ]
        self.client.session.post.return_value = _resp(
            json_data={"login_need_refresh": 0, "lockingTime": 0}
        )

        self.assertTrue(self.client.login())
        self.assertEqual(self.client.session.get.call_count, 3)
        self.assertEqual(self.client.session.post.call_count, 1)
        self.assertEqual(self.client.session.get.call_args[0][0], "http://192.0.2.1/")

    def test_preempt_takes_over_stuck_session_then_reloads_root(self):
        self.client.session.get.side_effect = self._token_responses() + [
            _resp(text=PREEMPT_PAGE_HTML),  # preempt page lookup
            _resp(),  # final root reload
        ]
        self.client.session.post.side_effect = [
            _resp(json_data={"loginErrType": "e_exceed_max_user_preempt"}),
            _resp(json_data={"login_need_refresh": 1}),  # login_preempt result
        ]

        self.assertTrue(self.client.login())
        self.assertEqual(self.client.session.get.call_count, 4)
        self.assertEqual(self.client.session.post.call_count, 2)
        preempt_call = self.client.session.post.call_args_list[1]
        self.assertIn("_tag=login_preempt", preempt_call.args[0])
        self.assertEqual(preempt_call.kwargs["data"]["preempt_sessid"], "sess-42")
        self.assertEqual(preempt_call.kwargs["data"]["action"], "preempt")
        self.assertEqual(self.client.login_data, {"login_need_refresh": 1})

    def test_preempt_without_a_takeover_target_fails_outright(self):
        self.client.session.get.side_effect = self._token_responses() + [
            _resp(text="<html>no preempt form here</html>"),
        ]
        self.client.session.post.return_value = _resp(
            json_data={"loginErrType": "e_exceed_max_user_preempt"}
        )

        self.assertFalse(self.client.login())
        self.assertIn("could not be taken over", self.client.statusmsg)
        # No retry: exactly one login_entry POST, nothing else attempted.
        self.assertEqual(self.client.session.post.call_count, 1)

    def test_bad_credentials_fail_without_fallback_retry(self):
        self.client.session.get.side_effect = self._token_responses()
        self.client.session.post.return_value = _resp(
            json_data={"loginErrType": "e_passwd_error", "loginErrMsg": "bad"}
        )

        self.assertFalse(self.client.login())
        self.assertEqual(self.client.statusmsg, "Login denied: bad")
        self.assertEqual(self.client.session.post.call_count, 1)

    def test_empty_login_json_fails_without_fallback_retry(self):
        self.client.session.get.side_effect = self._token_responses()
        self.client.session.post.return_value = _resp(json_data={})

        self.assertFalse(self.client.login())
        self.assertEqual(self.client.statusmsg, "Router did not confirm login.")
        self.assertEqual(self.client.session.post.call_count, 1)

    def test_logout_sends_a_fresh_session_token(self):
        self.client.login_data = {"login_need_refresh": 0}
        session = self.client.session
        session.get.return_value = _resp(
            json_data={"lockingTime": 0, "sess_token": "fresh-tok"}
        )
        session.post.return_value = _resp(json_data={})

        self.client.logout()

        post_kwargs = session.post.call_args.kwargs
        self.assertEqual(post_kwargs["data"]["_sessionTOKEN"], "fresh-tok")
        self.assertEqual(post_kwargs["data"]["IF_LogOff"], "1")

    def test_retail_h3600p_login_is_unaffected(self):
        """The existing H3600P alias must keep its plain success path."""
        retail = _load_client()(HOST, "admin", "secret", "H3600P")
        retail._setup_session = MagicMock()
        retail.session = MagicMock()
        retail.session.get.side_effect = [
            _resp(json_data={"lockingTime": 0, "sess_token": "stok"}),
            _resp(content=b"<ajax_response_xml_root>tok123</ajax_response_xml_root>"),
        ]
        retail.session.post.return_value = _resp(
            json_data={"login_need_refresh": 0, "lockingTime": 0}
        )

        self.assertTrue(retail.login())
        # No extra root reload for the retail profile.
        self.assertEqual(retail.session.get.call_count, 2)
