from __future__ import print_function
import argparse
import json
import getpass
import sys
import logging
import base64
import xml.dom.minidom

import botocore.session

from .saml import SAMLCredentialFetcher
from .cache import JSONFileCache


def saml(argv=None, prompter=getpass.getpass, client_creator=None,
         cache_dir=None):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-e', '--endpoint', required=True, help=(
            'The SAML idp endpoint.'
        )
    )
    parser.add_argument(
        '-u', '--username', required=True,
        help='Your SAML username.'
    )
    parser.add_argument(
        '-p', '--provider', required=True, choices=['okta', 'adfs', 'shib',],
        help=(
            'The name of your SAML provider. Currently okta, adfs, and Shibboleth '
            'form-based auth is supported.'
        )
    )
    parser.add_argument(
        '-a', '--role-arn', required=True, help=(
            'The role arn you wish to assume. Your SAML provider must be '
            'configured to give you access to this arn.'
        )
    )
    parser.add_argument(
        '--no-cache', action='store_false', default=True, dest='cache',
        help=(
            'Disables the storing and retrieving of credentials from the '
            'local file cache.'
        )
    )
    parser.add_argument(
        '-D', '--duo', action='store_true', help=('Duo Security MFA prompt will be included in login flow.')
    )
    parser.add_argument(
        '--duo-device', action='store', default='phone1', help=('Specify the Duo MFA device to use.  Default `phone1`.')
    )
    parser.add_argument(
        '--duo-factor',
        action='store',
        choices=['Duo Push', 'Phone Call', 'Passcode', 'webauthn'],
        default='Duo Push',
        help=('Specify the Duo MFA factor to use.  Default `Duo Push`.')
    )
    parser.add_argument(
        '--logfile', type=argparse.FileType('a+'), default=None, action='store', help=('Log to file LOGFILE.')
    )
    parser.add_argument(
        '--loglevel',
        choices=['debug', 'info', 'warn', 'error', 'critical',],
        default='error',
        action='store', 
        help=('Log events with severity LOGLEVEL or greater.')
    )
    args = parser.parse_args(argv)

    if args.logfile is not None:
        logger = logging.getLogger('awsprocesscreds')
        level = getattr(logging, args.loglevel.upper())
        logger.setLevel(level)
        handler = PrettyPrinterLogHandler(args.logfile)
        handler.setLevel(level)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    if client_creator is None:
        client_creator = botocore.session.Session().create_client

    cache = {}
    if args.cache:
        cache = JSONFileCache(cache_dir)

    fetcher = SAMLCredentialFetcher(
        client_creator=client_creator,
        provider_name=args.provider,
        saml_config={
            'saml_endpoint': args.endpoint,
            'saml_authentication_type': 'form',
            'saml_username': args.username,
            'role_arn': args.role_arn
        },
        password_prompter=prompter,
        cache=cache,
        duo_mfa_flow=args.duo,
        duo_config=dict(duo_device=args.duo_device, duo_factor=args.duo_factor),
    )
    creds = fetcher.fetch_credentials()
    creds['Version'] = 1
    print(json.dumps(creds) + '\n')


class PrettyPrinterLogHandler(logging.StreamHandler):
    def emit(self, record):
        self._pformat_record_args(record)
        super(PrettyPrinterLogHandler, self).emit(record)

    def _pformat_record_args(self, record):
        if isinstance(record.args, dict):
            record.args = self._pformat_dict(record.args)
        elif getattr(record, 'is_saml_assertion', False):
            formatted = self._pformat_saml_assertion(record.args[0])
            record.args = tuple([formatted])

    def _pformat_dict(self, args):
        return json.dumps(args, indent=4, sort_keys=True)

    def _pformat_saml_assertion(self, assertion):
        xml_string = base64.b64decode(assertion).decode('utf-8')
        return xml.dom.minidom.parseString(xml_string).toprettyxml()
