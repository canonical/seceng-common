#!/usr/bin/env python3

# Copyright (C) 2025 Canonical, Ltd.
# Author: Paulo Flabiano Smorigo <pfsmorigo@canonical.com>

# This script is distributed under the terms and conditions of the GNU General
# Public License, Version 3 or later. See http://www.gnu.org/copyleft/gpl.html
# for details.

import sys
import json
import argparse
import logging
import subprocess
import shlex
import re
import os
from pathlib import Path
from smtplib import SMTP
from email.utils import parseaddr
from email.mime.text import MIMEText
from configparser import ConfigParser
from pprint import pformat

TITLE = 'Notification Sender Script'
SMTP_SERVER = 'mx.canonical.com'
SMTP_PORT = 25
CONFIG_PATH = f'/etc/seceng/{os.environ.get("USER")}'

class SendNotification:
    def __init__(self, json=None, command=None, sender=None, to=None, subject=None, content=None, cc=None, bcc=None, include_bcc=None, add_prefix=None, send_summary=None, replace_to=None):

        to = self.normalize_emails(to)
        cc = self.normalize_emails(cc)
        bcc = self.normalize_emails(bcc)
        include_bcc = self.normalize_emails(include_bcc)
        send_summary = self.normalize_emails(send_summary)
        replace_to = self.normalize_emails(replace_to)

        self.notifications = []

        self.config = Configuration(include_bcc, add_prefix, send_summary, replace_to)

        if not sender and self.config.sender:
            sender = self.config.sender
        if not subject and self.config.subject:
            subject = self.config.subject
        if not to and self.config.to:
            to = self.normalize_emails(self.config.to)
        if not cc and self.config.cc:
            cc = self.normalize_emails(self.config.cc)
        if not bcc and self.config.bcc:
            bcc = self.normalize_emails(self.config.bcc)

        content = None

        # Check first it there is a command to run since it can be used to generate a json
        # file that can be used next.
        if command:
            content = self.process_command(command)

        # If a json file is set, all the email fields should be set in there
        if json:
            self.load_json_file(json)

        # If there still no content set and no json available, check the stdin for
        # content.
        if content is None and not json and not self.notifications:
           content = sys.stdin.read()

        if content:
            if not subject:
                self.error_log(f'Missing argument: "subject"')
            if not sender:
                self.error_log(f'Missing argument: "from"')
            if not to:
                self.error_log(f'Missing argument: "to"')
            self.add_notification(sender, to, subject, content, cc, bcc)

        if self.config.send_summary:
            if not sender:
                sender = 'security+send_notification@ubuntu.com'
            to = self.normalize_emails(self.config.send_summary)
            if len(self.notifications) > 0:
                content = f'Notification trigged and {len(self.notifications)} emails sent:\n\n'
                for notification in self.notifications:
                    content += f' - "{notification.subject}" to {", ".join(notification.to)}\n'
            else:
                content = f'Notification trigged and no emails were sent.'
            self.add_notification(sender, to, 'Summary', content)

    def normalize_emails(self, emails):
        if emails is None:
            return []
        elif type(emails) is list:
            return list(filter(None, emails))
        else:
            return list(filter(None, re.split(r'[\s,]+', emails.strip())))

    def add_notification(self, sender, to, subject, content, cc=[], bcc=[]):
        if self.config.add_prefix:
            subject = f'[{self.config.add_prefix}] {subject}'
        if self.config.replace_to:
            to = self.config.replace_to
            cc = bcc = []
        self.notifications.append(Notification(sender, to, subject, content, cc, bcc + self.config.include_bcc))

    def error_log(self, message):
        logging.error(message)
        sys.exit(1)

    def load_json_file(self, filename):
        logging.info(f'Processing {filename}...')
        with open(filename) as json_data:
            self.process_json(json.load(json_data))

    def process_json(self, data):
        for email in data:
            sender = email['from']
            cc = []
            bcc = []

            to = self.normalize_emails(email['to'])
            if 'cc' in email:
                cc = self.normalize_emails(email['cc'])
            if 'bcc' in email:
                bcc = self.normalize_emails(email['bcc'])
            subject = email['subject']
            body = email['body']

            self.add_notification(sender, to, subject, body, cc, bcc)

    def process_command(self, command):
        try:
            command_parts = shlex.split(command)
        except ValueError as e:
            logging.error(f"Error parsing command: {e}")
            sys.exit(1)

        p = Path(command_parts[0])
        # First check if the command is in the current directory
        if (p.parent / p.name).exists():
            command_parts[0] = str((p.parent / p.name).resolve())
        else:
            # Otherwise, check if the command is in the script directory
            script_directory = Path(__file__).parent
            if (script_directory / p.name).exists():
                command_parts[0] = str((script_directory / p.name).resolve())
            # No script found, print error
            else:
                logging.error(f'Command not found: {command_parts[0]}')
                sys.exit(1)

        logging.info(f'Running command: {command_parts}')
        output = ''
        result = None
        try:
            result = subprocess.run(command_parts, capture_output=True, text=True)
            output = result.stdout
            if result.stderr:
                logging.warning(result.stderr)
                output += f'\nERRORS:\n\n{result.stderr}'
        except Exception as e:
            output = f"An unexpected error occurred: {e}"
            if result.stdout:
                output += f'\nSTDOUT:\n\n{result.stdout}'
            if result.stderr:
                output += f'\nSTDERR:\n\n{result.stderr}'

        # Try validate the output as a JSON file
        try:
            valid_json = json.loads(output)
            self.process_json(valid_json)
        # Otherwise return the string to be used and the email content
        except ValueError:
            return output

    def send(self, debuglevel=0):
        for notification in self.notifications:
            try:
                smtp_config = self.config.get_smtp_config(notification.sender)
                logging.debug(f'SMTP: Connecting to {smtp_config["server"]}:{smtp_config["port"]}')
                with SMTP(smtp_config['server'], smtp_config['port']) as smtp:
                    smtp.set_debuglevel(debuglevel)
                    smtp.ehlo()
                    smtp.starttls()
                    if 'login' in smtp_config and 'password' in smtp_config:
                        logging.debug(f'SMTP: Using {smtp_config["login"]} credentials')
                        smtp.login(smtp_config['login'], smtp_config['password'])
                    receivers = notification.all_receivers
                    logging.debug(f"Sending email:\n{notification} to {', '.join(receivers)}")
                    smtp.sendmail(notification.sender, receivers, str(notification))
                    smtp.quit()
                    logging.info('Email sent successfully!')
            except Exception as e:
                logging.error(f'Error sending notification: {e}')

    def __str__(self):
        return '\n\n\n\n'.join([str(f"HEADER TO: {n.all_receivers}\n{n}") for n in self.notifications])


class Configuration:
    def __init__(self, include_bcc=[], add_prefix=None, send_summary=[], replace_to=[], section_name='default'):
        self.include_bcc = include_bcc
        self.add_prefix = add_prefix
        self.send_summary = send_summary
        self.replace_to = replace_to
        self.smtp_config = {'default': {'server': SMTP_SERVER, 'port': SMTP_PORT }}

        self.sender = None
        self.to = []
        self.subject = None
        self.cc = []
        self.bcc = []

        self.load_smtp_config()
        self.load_config(section_name)

    def get_smtp_config(self, sender):
        name, email_address = parseaddr(sender)
        return self.smtp_config[email_address] \
                if email_address in self.smtp_config \
                else self.smtp_config['default']

    def load_smtp_config(self):
        config_file = Path(CONFIG_PATH) / 'smtp.ini'
        if config_file.is_file():
            config = ConfigParser()
            config.read(config_file)

            for section in config.sections():
                if section not in self.smtp_config:
                    self.smtp_config[section] = {}
                for field, value in config[section].items():
                    value = int(value) if field == 'port' else value
                    self.smtp_config[section][field] = value

    def load_config(self, section_name):
        config_file = Path(CONFIG_PATH) / 'config.ini'
        if config_file.is_file():
            config = ConfigParser()
            config.read(config_file)

            if section_name in config.sections():
                for field in config[section_name]:
                    if field in ['to', 'cc', 'bcc', 'include_bcc', 'send_summary', 'replace_to']:
                        value = config[section_name][field].split(',')
                    else:
                        value = config[section_name][field]
                    setattr(self, field, value)

    def __str__(self):
        return pformat(self.__dict__)


class Notification:
    def __init__(self, sender, to, subject, content, cc=[], bcc=[]):
        self.sender = sender
        self.to = to
        self.subject = subject
        self.content = content
        self.cc = cc
        self.bcc = bcc

        # Bcc field is only in the header, please do not include it here!
        self.email = MIMEText(self.content, "plain")
        self.email["Subject"] = self.subject
        self.email["From"] = self.sender
        self.email["To"] = ', '.join(self.to)
        if self.cc:
            self.email["Cc"] = ', '.join(self.cc)

    @property
    def all_receivers(self):
        return sorted(set(self.to+self.cc+self.bcc))

    def __str__(self):
        return self.email.as_string()

def main():
    parser = argparse.ArgumentParser(description=TITLE)
    parser.add_argument('--json', type=str,
                        help='use a JSON file as input')
    parser.add_argument('--exec', type=str,
                        help='execute a file and use its output')
    parser.add_argument('--cc', dest='email_cc', type=str, default='', metavar='EMAIL',
                        help='include cc recipients. Comma-separated list (e.g., email1,email2,email3)')
    parser.add_argument('--bcc', dest='email_bcc', type=str, default='', metavar='EMAIL',
                        help='include bcc recipients. Comma-separated list (e.g., email1,email2,email3)')
    parser.add_argument('--include-bcc', type=str, default='', metavar='EMAIL',
                        help='include bcc recipients to all emails. Comma-separated list (e.g., email1,email2,email3)')
    parser.add_argument('--add-prefix', type=str, default='', metavar='PREFIX',
                        help='add a prefix between brackets to the email\'s subject')
    parser.add_argument('--send-summary', type=str, default='', metavar='EMAIL',
                        help='send a summary of all notifications sent. Comma-separated list (e.g., email1,email2,email3)')
    parser.add_argument('--replace-to', type=str, default='', metavar='EMAIL',
                        help='replace destination email and skip cc/bcc recipients. This should be used just for testing.')
    parser.add_argument('--log', type=str,
                        help='log to a file')
    parser.add_argument('--print-config', action='store_true',
                        help='print configuration')
    parser.add_argument('-v', '--verbose', action='count', default=1,
                        help='verbosity')
    parser.add_argument('-d', '--dry-run', action='store_true',
                        help='only print, don\'t send notifications')
    parser.add_argument('email_subject', metavar='subject', nargs='?',
                        help='notification subject')
    parser.add_argument('email_from', nargs='?', metavar='from',
                        help='motification sender')
    parser.add_argument('email_to', metavar='to', nargs='*',
                        help='notification recipients')
    args = parser.parse_args()

    if args.print_config:
        print(Configuration())
        return

    verbose = 40 - (10 * args.verbose) if args.verbose > 0 else 0
    if args.log:
        logging.basicConfig(filename=args.log, format='%(asctime)s - %(levelname)s: %(message)s', level=verbose)
    else:
        logging.basicConfig(format='%(levelname)s: %(message)s', level=verbose)

    logging.info(f'{TITLE} started')

    sn = SendNotification(json=args.json, command=args.exec, sender=args.email_from,
                          to=args.email_to, subject=args.email_subject, cc=args.email_cc, bcc=args.email_bcc,
                          include_bcc=args.include_bcc, add_prefix=args.add_prefix,
                          send_summary=args.send_summary, replace_to=args.replace_to)

    if args.dry_run:
        logging.info(sn)
    else:
        # Rebalance the verbose number to level with the debuglevel from SMTP
        sn.send(debuglevel=args.verbose-3)

    logging.info(f'{TITLE} ended')

if __name__ == '__main__':
    main()
