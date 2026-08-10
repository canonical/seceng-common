#!/usr/bin/env python3

import sys
import os
import unittest
import subprocess
import platform
import logging
import tempfile
from pathlib import Path
from unittest.mock import patch

_TEST_DIRECTORY = Path(__file__).resolve().parent
sys.path.append(str(_TEST_DIRECTORY.parent))
from send_notification import SendNotification, EmailParams, ConfigOverrides, Notification, Configuration

TEST_JSON = str(_TEST_DIRECTORY / 'test.json')
EMPTY_JSON = str(_TEST_DIRECTORY / 'empty.json')
TEST_SH = str(_TEST_DIRECTORY / 'test.sh')

class TestSendNotification(unittest.TestCase):

    def setUp(self):
        self.os_name = platform.system()
        self.mock_home = patch('pathlib.Path.home', return_value=Path('/home/example'))
        self.mock_home.start()
        self.addCleanup(self.mock_home.stop)

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
        self.assertEqual(len(sn.notifications), 3)
        self.assertEqual(sn.notifications[0].subject, 'Notification Example')
        self.assertEqual(sn.notifications[0].sender, 'My Notification <security+my_notification@ubuntu.com>')
        expected, result = self.run_test('test_use_json', str(sn))
        self.assertEqual(expected, result)

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_use_exec(self):
        """Test use exec input."""
        sn = SendNotification(command=TEST_SH,
                              email_params=EmailParams(sender='security+test@ubuntu.com',
                                                       to=['destination@email.net'],
                                                       subject='Notification Test'))
        self.assertEqual(len(sn.notifications), 1)
        self.assertIn('ERRORS:', str(sn.notifications[0]))
        expected, result = self.run_test('test_use_exec', str(sn))
        self.assertEqual(expected, result)

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_use_exec_local_dir(self):
        """Test use exec input with script referenced by filename in the local directory."""
        original_dir = os.getcwd()
        try:
            os.chdir(_TEST_DIRECTORY)
            sn = SendNotification(command='test.sh',
                                  email_params=EmailParams(sender='security+test@ubuntu.com',
                                                           to=['destination@email.net'],
                                                           subject='Notification Test'))
            self.assertEqual(len(sn.notifications), 1)
            expected, result = self.run_test('test_use_exec_local_dir', str(sn))
            self.assertEqual(expected, result)
        finally:
            os.chdir(original_dir)

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_use_exec_json_output(self):
        """Test use exec input that exports json as output."""
        sn = SendNotification(command=f'{TEST_SH} json')
        self.assertEqual(len(sn.notifications), 3)
        expected, result = self.run_test('test_use_exec_json_output', str(sn))
        self.assertEqual(expected, result)

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_use_exec_with_arguments(self):
        """Test use exec with arguments."""
        sn = SendNotification(command=f'{TEST_SH} one two three "four four" five',
                              email_params=EmailParams(sender='security+test@ubuntu.com',
                                                       to=['destination1@email.net', 'destination2@email.net'],
                                                       subject='Notification Test',
                                                       cc=['in_cc1@email.net', 'in_cc2@email.net'],
                                                       bcc=['in_bcc1@email.net', 'in_bcc2@email.net']))
        self.assertEqual(len(sn.notifications), 1)
        notification_str = str(sn.notifications[0])
        self.assertIn('1: one', notification_str)
        self.assertIn('4: four four', notification_str)
        expected, result = self.run_test('test_use_exec_with_arguments', str(sn))
        self.assertEqual(expected, result)

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_use_exec_and_json(self):
        """Test use exec and json input."""
        with tempfile.NamedTemporaryFile(delete=False) as tempjson:
            tmp_path = tempjson.name
        self.addCleanup(os.unlink, tmp_path)
        sn = SendNotification(command=f'{TEST_SH} json {tmp_path}', json=tmp_path)
        expected, result = self.run_test('test_use_exec_and_json', str(sn))
        self.assertEqual(expected, result)

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_use_include_bcc(self):
        """Test use include-bcc argument."""
        sn = SendNotification(command=f'{TEST_SH} json',
                              config_overrides=ConfigOverrides(include_bcc=['debug@email.net', 'debug2@email.net']))
        for notification in sn.notifications:
            self.assertIn('debug@email.net', notification.all_receivers)
            self.assertIn('debug2@email.net', notification.all_receivers)
        expected, result = self.run_test('test_use_include_bcc', str(sn))
        self.assertEqual(expected, result)

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_use_add_prefix(self):
        """Test use add-prefix argument."""
        sn = SendNotification(command=f'{TEST_SH} json',
                              config_overrides=ConfigOverrides(add_prefix='new notification'))
        for notification in sn.notifications:
            self.assertTrue(notification.subject.startswith('[new notification]'))
        expected, result = self.run_test('test_use_add_prefix', str(sn))
        self.assertEqual(expected, result)

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_use_replace_to(self):
        """Test use replace-to argument."""
        sn = SendNotification(command=f'{TEST_SH} json',
                              config_overrides=ConfigOverrides(replace_to=['debug@email.net', 'debug2@email.net']))
        for notification in sn.notifications:
            self.assertCountEqual(notification.to, ['debug@email.net', 'debug2@email.net'])
            self.assertEqual(notification.cc, [])
            self.assertEqual(notification.bcc, [])
        expected, result = self.run_test('test_use_replace_to', str(sn))
        self.assertEqual(expected, result)

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_use_summary(self):
        """Test use summary."""
        sn = SendNotification(json=TEST_JSON,
                              config_overrides=ConfigOverrides(send_summary=['notification_owner@email.net']))
        self.assertEqual(len(sn.notifications), 4)  # 3 from JSON + 1 summary
        summary = sn.notifications[-1]
        self.assertEqual(summary.subject, 'Summary')
        self.assertEqual(summary.to, ['notification_owner@email.net'])
        self.assertIn('3 emails sent', summary.content)
        expected, result = self.run_test('test_use_summary', str(sn))
        self.assertEqual(expected, result)

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_use_summary_no_emails_sent(self):
        """Test use summary when no emails are sent."""
        sn = SendNotification(json=EMPTY_JSON,
                              config_overrides=ConfigOverrides(send_summary=['notification_owner@email.net']))
        self.assertEqual(len(sn.notifications), 1)  # summary only
        summary = sn.notifications[0]
        self.assertEqual(summary.subject, 'Summary')
        self.assertIn('no emails were sent', summary.content)
        expected, result = self.run_test('test_use_summary_no_emails_sent', str(sn))
        self.assertEqual(expected, result)

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_use_only_on_stderr_with_error(self):
        """Test that a notification is sent when the command produces stderr output."""
        sn = SendNotification(command=TEST_SH,
                              email_params=EmailParams(sender='security+test@ubuntu.com',
                                                       to=['destination@email.net'],
                                                       subject='Notification Test'),
                              config_overrides=ConfigOverrides(only_on_stderr=True))
        self.assertEqual(len(sn.notifications), 1)
        self.assertIn('ERRORS:', str(sn.notifications[0]))
        expected, result = self.run_test('test_use_only_on_stderr_with_error', str(sn))
        self.assertEqual(expected, result)

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_use_only_on_stderr_without_error(self):
        """Test that no notification is sent when the command produces no stderr output."""
        sn = SendNotification(command=f'{TEST_SH} noerror',
                              email_params=EmailParams(sender='security+test@ubuntu.com',
                                                       to=['destination@email.net'],
                                                       subject='Notification Test'),
                              config_overrides=ConfigOverrides(only_on_stderr=True))
        self.assertEqual(len(sn.notifications), 0)
        expected, result = self.run_test('test_use_only_on_stderr_without_error', str(sn))
        self.assertEqual(expected, result)

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_config_default(self):
        """Test default configuration."""
        expected = {
                'include_bcc': [],
                'add_prefix': None,
                'send_summary': [],
                'replace_to': [],
                'only_on_stderr': False,
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
    def test_config_custom_json(self):
        """Test custom configuration with json input."""
        expected_config = {
                'include_bcc': ['noreply+test1@canonical.com', 'noreply+test2@canonical.com'],
                'add_prefix': 'my_notification',
                'send_summary': ['summary@email.net'],
                'replace_to': ['another@email.net'],
                'only_on_stderr': False,
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
        self.assertEqual(expected_config, vars(sn.config))
        expected, result = self.run_test('test_config_custom_json', str(sn))
        self.assertEqual(expected, result)

    @patch('send_notification.CONFIG_PATH', _TEST_DIRECTORY / 'config_dir')
    def test_config_custom_exec(self):
        """Test custom configuration with exec input."""
        sn = SendNotification(command=TEST_SH)
        expected, result = self.run_test('test_config_custom_exec', str(sn))
        self.assertEqual(expected, result)

    @patch('send_notification.CONFIG_PATH', _TEST_DIRECTORY / 'config_dir')
    def test_config_only_on_stderr_true(self):
        """Test only_on_stderr set to True in config file."""
        config_content = "[default]\nonly_on_stderr = True\n"
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_config = Path(tmp_dir) / 'config.ini'
            tmp_config.write_text(config_content)
            with patch('send_notification.CONFIG_PATH', Path(tmp_dir)):
                sn = SendNotification(command=f'{TEST_SH} noerror',
                                      email_params=EmailParams(sender='security+test@ubuntu.com',
                                                               to=['destination@email.net'],
                                                               subject='Notification Test'))
                # Since it's noerror and only_on_stderr=True from config, no notification should be sent.
                self.assertEqual(len(sn.notifications), 0)
                self.assertTrue(sn.config.only_on_stderr)

    # --- Unit tests for helper classes and methods ---

    def test_normalize_emails_list(self):
        """Test normalize_emails with a list of emails."""
        sn = SendNotification.__new__(SendNotification)
        self.assertEqual(sn.normalize_emails(['a@b.com', 'c@d.com']), ['a@b.com', 'c@d.com'])

    def test_normalize_emails_comma_separated_string(self):
        """Test normalize_emails with a comma-separated string."""
        sn = SendNotification.__new__(SendNotification)
        self.assertEqual(sn.normalize_emails('a@b.com,c@d.com'), ['a@b.com', 'c@d.com'])

    def test_normalize_emails_space_separated_string(self):
        """Test normalize_emails with a space-separated string."""
        sn = SendNotification.__new__(SendNotification)
        self.assertEqual(sn.normalize_emails('a@b.com c@d.com'), ['a@b.com', 'c@d.com'])

    def test_normalize_emails_none(self):
        """Test normalize_emails with None returns empty list."""
        sn = SendNotification.__new__(SendNotification)
        self.assertEqual(sn.normalize_emails(None), [])

    def test_normalize_emails_empty_list(self):
        """Test normalize_emails with an empty list."""
        sn = SendNotification.__new__(SendNotification)
        self.assertEqual(sn.normalize_emails([]), [])

    def test_normalize_emails_filters_empty_strings(self):
        """Test normalize_emails filters out empty string entries."""
        sn = SendNotification.__new__(SendNotification)
        self.assertEqual(sn.normalize_emails(['a@b.com', '', 'c@d.com']), ['a@b.com', 'c@d.com'])

    def test_notification_all_receivers(self):
        """Test Notification.all_receivers combines to, cc, bcc and deduplicates."""
        n = Notification(
            sender='from@example.com',
            to=['a@example.com', 'b@example.com'],
            subject='Test',
            content='Body',
            cc=['b@example.com', 'c@example.com'],
            bcc=['d@example.com'],
        )
        self.assertEqual(n.all_receivers, ['a@example.com', 'b@example.com', 'c@example.com', 'd@example.com'])

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_configuration_get_smtp_config_default(self):
        """Test get_smtp_config returns the default config when no sender-specific entry exists."""
        config = Configuration()
        smtp = config.get_smtp_config('unknown@example.com')
        self.assertEqual(smtp['server'], 'mx.canonical.com')
        self.assertEqual(smtp['port'], 25)

    @patch('send_notification.CONFIG_PATH', _TEST_DIRECTORY / 'config_dir')
    def test_configuration_get_smtp_config_match(self):
        """Test get_smtp_config returns the sender-specific config when available."""
        config = Configuration()
        smtp = config.get_smtp_config('onecase@email.net')
        self.assertEqual(smtp['server'], 'one_smtp_server')
        self.assertEqual(smtp['port'], 1111)
        self.assertEqual(smtp['login'], 'one_login')

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_command_not_found(self):
        """Test that a missing command triggers sys.exit."""
        with self.assertRaises(SystemExit):
            SendNotification(command='nonexistent_command_xyz',
                             email_params=EmailParams(sender='from@example.com',
                                                      to=['to@example.com'],
                                                      subject='Test'))

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_send_calls_smtp(self):
        """Test that send() establishes an SMTP connection and calls sendmail for each notification."""
        sn = SendNotification(json=TEST_JSON)
        with patch('send_notification.SMTP') as mock_smtp_class:
            mock_instance = mock_smtp_class.return_value.__enter__.return_value
            sn.send()
        self.assertEqual(mock_instance.sendmail.call_count, len(sn.notifications))

    @patch('send_notification.CONFIG_PATH', Path('/dev/null'))
    def test_send_uses_smtp_credentials(self):
        """Test that send() calls login when smtp config includes credentials."""
        sn = SendNotification(json=TEST_JSON)
        sn.config.smtp_config['default']['login'] = 'user'
        sn.config.smtp_config['default']['password'] = 'pass'
        with patch('send_notification.SMTP') as mock_smtp_class:
            mock_instance = mock_smtp_class.return_value.__enter__.return_value
            sn.send()
        mock_instance.login.assert_called_with('user', 'pass')

if __name__ == '__main__':
    # Parse -v/-vv/-vvv before handing off to unittest so we can control
    # buffering independently of unittest's own verbosity flag.
    #   (no flags) : dots only, subprocess output suppressed
    #   -v         : test names, subprocess output suppressed
    #   -vv        : test names, subprocess output shown
    #   -vvv       : test names, subprocess output shown, debug logging
    v_count = 0
    new_argv = [sys.argv[0]]
    for arg in sys.argv[1:]:
        if arg.startswith('-') and arg[1:] and all(c == 'v' for c in arg[1:]):
            v_count = max(v_count, len(arg) - 1)
        else:
            new_argv.append(arg)
    sys.argv = new_argv

    log_level = logging.DEBUG if v_count >= 3 else logging.CRITICAL
    logging.basicConfig(level=log_level)

    unittest.main(
        verbosity=2 if v_count >= 1 else 1,
        buffer=v_count < 2,
    )
