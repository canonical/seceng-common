#!/usr/bin/env python3

import sys
import os
import unittest
import subprocess
import platform
import logging
import tempfile
from pathlib import Path
from unittest.mock import patch, Mock

_TEST_DIRECTORY = Path(__file__).resolve().parent
sys.path.append(str(_TEST_DIRECTORY.parent))
from send_notification import SendNotification, CONFIG_PATH

TEST_JSON = str(_TEST_DIRECTORY / 'test.json')
EMPTY_JSON = str(_TEST_DIRECTORY / 'empty.json')
TEST_SH = str(_TEST_DIRECTORY / 'test.sh')

class TestSendNotification(unittest.TestCase):

    def setUp(self):
        self.os_name = platform.system()

    def run_test(self, filename, output):
        test_full_path = _TEST_DIRECTORY / Path(filename)
        if 'REFRESH_FILES' in os.environ:
            print("REFRESHING TEST FILES, NOT TESTING!")
            with open(test_full_path, 'w') as f:
                f.write(output)
        return test_full_path.read_text(), output

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_use_json(self):
        """Test use json input."""
        sn = SendNotification(json=TEST_JSON)
        expected, result = self.run_test('test_use_json', str(sn))
        self.assertEqual(expected, result)

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_use_exec(self):
        """Test use exec input."""
        sn = SendNotification(command=TEST_SH,
                                                sender='security+test@ubuntu.com',
                                                to=['destination@email.net'],
                                                subject='Notification Test')
        expected, result = self.run_test('test_use_exec', str(sn))
        self.assertEqual(expected, result)

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_use_exec_local_dir(self):
        """Test use exec input with script in local directory."""
        sn = SendNotification(command=TEST_SH,
                                                sender='security+test@ubuntu.com',
                                                to=['destination@email.net'],
                                                subject='Notification Test')
        expected, result = self.run_test('test_use_exec_local_dir', str(sn))
        self.assertEqual(expected, result)

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_use_exec_json_output(self):
        """Test use exec input that export json as output."""
        sn = SendNotification(command=f'{TEST_SH} json')
        expected, result = self.run_test('test_use_exec_json_output', str(sn))
        self.assertEqual(expected, result)

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_use_exec_with_arguments(self):
        """Test use exec with arguments."""
        sn = SendNotification(command=f'{TEST_SH} one two three "four four" five',
                                                sender='security+test@ubuntu.com',
                                                to=['destination1@email.net', 'destination2@email.net'],
                                                cc=['in_cc1@email.net', 'in_cc2@email.net'],
                                                bcc=['in_bcc1@email.net', 'in_bcc2@email.net'],
                                                subject='Notification Test')
        expected, result = self.run_test('test_use_exec_with_arguments', str(sn))
        self.assertEqual(expected, result)

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_use_exec_and_json(self):
        """Test use exec and json input."""
        tempjson = tempfile.NamedTemporaryFile(delete=False)
        sn = SendNotification(command=f'{TEST_SH} json {tempjson.name}', json=tempjson.name)
        expected, result = self.run_test('test_use_exec_and_json', str(sn))
        self.assertEqual(expected, result)

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_use_include_bcc(self):
        """Test use include-bcc argument."""
        sn = SendNotification(command=f'{TEST_SH} json', include_bcc=['debug@email.net', 'debug2@email.net'])
        expected, result = self.run_test('test_use_include_bcc', str(sn))
        self.assertEqual(expected, result)

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_use_add_prefix(self):
        """Test use add-prefix argument."""
        sn = SendNotification(command=f'{TEST_SH} json', add_prefix='new notification')
        expected, result = self.run_test('test_use_add_prefix', str(sn))
        self.assertEqual(expected, result)

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_use_replace_to(self):
        """Test use replace-to argument."""
        sn = SendNotification(command=f'{TEST_SH} json', replace_to=['debug@email.net', 'debug2@email.net'])
        expected, result = self.run_test('test_use_replace_to', str(sn))
        self.assertEqual(expected, result)

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_use_summary(self):
        """Test use summary."""
        sn = SendNotification(json=TEST_JSON, send_summary=['notification_owner@email.net'])
        expected, result = self.run_test('test_use_summary', str(sn))
        self.assertEqual(expected, result)

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_use_summary_no_emails_sent(self):
        """Test use summary and no emails sent."""
        sn = SendNotification(json=EMPTY_JSON, send_summary=['notification_owner@email.net'])
        expected, result = self.run_test('test_use_summary_no_emails_sent', str(sn))
        self.assertEqual(expected, result)

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_config_default(self):
        """Test default configuration."""
        expected = {
                'include_bcc': [],
                'add_prefix': None,
                'send_summary': [],
                'replace_to': [],
                'smtp_config': {
                    'default': {
                        'server': 'mx.canonical.com',
                        'port': 25
                        }
                    },
                'sender': None,
                'to': [],
                'subject': None,
                'cc': [],
                'bcc': []
                }
        sn = SendNotification(json=TEST_JSON)
        self.assertEqual(expected, vars(sn.config))
        expected, result = self.run_test('test_config_default', str(sn))
        self.assertEqual(expected, result)

    @patch('send_notification.CONFIG_PATH', _TEST_DIRECTORY / 'config_dir')
    def test_config_custom(self):
        """Test custom configuration."""
        expected = {
                'include_bcc': ['noreply+test1@canonical.com', 'noreply+test2@canonical.com'],
                'add_prefix': 'my_notification',
                'send_summary': ['summary@email.net'],
                'replace_to': ['another@email.net'],
                'smtp_config': {
                    'default': {
                        'server': 'localhost',
                        'port': 25
                        },
                    'onecase@email.net': {
                        'server': 'one_smtp_server',
                        'port': 1111,
                        'login': 'one_login',
                        'password': 'one_password'
                        },
                    'anothercase@email.net': {
                        'server': 'another_smtp_server',
                        'port': 2222,
                        'login': 'another_login',
                        'password': 'another_password'
                        }
                    },
                'sender': 'config+from@email.net',
                'to': ['config+to@email.net'],
                'subject': 'config_subject',
                'cc': ['config+cc@email.net'],
                'bcc': ['config+bcc@email.net']
                }
        sn = SendNotification(json=TEST_JSON)
        self.assertEqual(expected, vars(sn.config))
        expected, result = self.run_test('test_config_custom_json', str(sn))
        self.assertEqual(expected, result)

        #TODO Fix: 'to' field not tested because it's replaced by 'replace_to'
        sn = SendNotification(command=TEST_SH)
        expected, result = self.run_test('test_config_custom_exec', str(sn))
        self.assertEqual(expected, result)

if __name__ == '__main__':
    logging.basicConfig(level=logging.CRITICAL)
    unittest.main()
