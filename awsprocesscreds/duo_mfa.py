
import base64
import getpass
import json
import logging
import struct
import time
from urllib.parse import (
    quote_plus,
    urlencode,
    urljoin,
)
import xml.etree.cElementTree as ET
from .html_parsers import FormParser, FrameParser
from .fido2 import present_challenge_to_authenticator

logger = logging.getLogger(__name__)

def duo_mfa_flow_entry_point(parent, response, duo_device, duo_factor):
    """
    Process Duo MFA flow.
    """
    logger.info("Starting DUO MFA flow ...")
    login_url = response.url
    logger.debug("DUO login_url: {}".format(login_url))
    parser = FormParser()
    parser.feed(response.text)
    form = parser.extract_form_by_id('duo_form')
    form_node = ET.fromstring(form)
    signed_duo_response, app = _perform_duo_mfa_flow(parent, login_url, response, duo_device, duo_factor)
    payload = dict(
        (tag.attrib['name'], tag.attrib.get('value', ''))
            for tag in form_node.findall(".//input")
    )
    payload['signedDuoResponse'] = ':'.join([signed_duo_response, app])
    keys = list(payload.keys())
    valid_keys = set(['signedDuoResponse', 'execution', '_eventId', 'geolocation'])
    for key in keys:
        if key not in valid_keys:
            del payload[key]
    response = parent._send_form_post(login_url, payload)
    logger.info("DUO MFA flow complete.")
    return response

def _perform_duo_mfa_flow(parent, login_url, response, duo_device, duo_factor):
    """
    Perform Duo MFA web flow.
    """
    parser = FrameParser()
    parser.process_frames(response.text)
    frame = parser.get_frame_by_id('duo_iframe')
    host = frame['data-host']
    logger.debug("DUO host: {}".format(host))
    duo_poll_seconds = parent.DUO_POLL_SECONDS
    status_endpoint = urljoin("https://{}".format(host), "/frame/status")
    logger.debug("DUO status endpoint: {}".format(status_endpoint))
    duo_auth_version = parent.DUO_AUTH_VERSION
    duo_sig, app = tuple(frame['data-sig-request'].split(':'))
    auth_endpoint = "https://{}/frame/web/v1/auth?tx={}&parent={}&v={}".format(host, duo_sig, quote_plus(login_url), duo_auth_version)
    logger.debug("DUO auth_endpoint: {}".format(auth_endpoint))
    logger.debug("DUO HTTP GET auth_endpoint ...")
    raw_response = parent._requests_session.get(auth_endpoint, verify=True)
    logger.debug("DUO parsing auth_endpoint response ...")
    duo_form_html_node = parent._parse_form_from_html(raw_response.text, form_index=parent.DUO_FORM_INDEX)
    payload = dict((tag.attrib['name'], tag.attrib.get('value', ''))
                   for tag in duo_form_html_node.findall(".//input"))
    logger.debug("DUO HTTP POST to auth_endpoint.  payload: {}".format(payload))
    raw_response = parent._send_form_post(auth_endpoint, payload)
    logger.debug("DUO Got response from auth_endpoint.")
    duo_form_html_node = parent._parse_form_from_html(raw_response.text, form_index=parent.DUO_FORM_INDEX)
    payload = dict((tag.attrib['name'], tag.attrib.get('value', ''))
                   for tag in duo_form_html_node.findall(".//input"))
    sid = payload['sid']
    logger.debug("DUO sid: {}".format(sid))

    # Get prompt endpoint; get txid
    payload['device'] = duo_device
    if duo_factor == "webauthn":
        payload['factor'] = "WebAuthn Credential"
    else:
        payload['factor'] = duo_factor
    if duo_factor == 'Passcode':
        payload['passcode'] = getpass.getpass("Passcode: ")
    action = duo_form_html_node.attrib.get('action', '')
    prompt_endpoint = urljoin("https://{}".format(host), action)
    logger.debug("DUO prompt endpoint: {}".format(prompt_endpoint))
    logger.debug("DUO prompt endpoint payload: {}".format(payload))
    response = parent._send_form_post(prompt_endpoint, payload)
    logger.debug("Duo prompt endpoint response: {}".format(response.text))
    response = json.loads(response.text)
    if response.get('stat') != 'OK':
        raise Exception("DUO POST to prompt endpoint resulted in error: {}".format(response))
    txid = response.get("response", {}).get("txid")
    logger.debug("DUO txid: {}".format(txid))

    if duo_factor == 'webauthn':
        logger.debug("DUO Getting challenge from status endpoint ...")
        logger.debug("DUO device: {}".format(duo_device))
        payload['device'] = duo_device
        payload['factor'] = "WebAuthn Credential"
        payload['txid'] = txid
        logger.debug("DUO status endpoint: {}".format(status_endpoint))
        logger.debug("DUO payload: {}".format(payload))
        raw_response = parent._send_form_post(status_endpoint, payload)
        logger.debug("DUO got response from status endpoint.")
        try:
            response = json.loads(raw_response.text)
        except Exception as ex:
            logger.error("DUO Error decoding JSON response from prompt endpoint: {}".format(ex))
            raise
        if response.get('stat') != 'OK':
            logger.error("DUO POST for credential challenge resulted in error: {}".format(response))
            raise Exception("DUO POST for credential challenge resulted in error: {}".format(response))
        webauthn_opts = response.get('response', {}).get('webauthn_credential_request_options') 
        origin = 'https://api-6bfb7da1.duosecurity.com'
        logger.info("Getting assertion from authenticator ...")
        assertion = present_challenge_to_authenticator(webauthn_opts, origin)
        logger.debug("DUO authenticator assertion: {}".format(assertion))
        payload['device'] = "webauthn_credential"
        payload['factor'] = "webauthn_finish"
        auth_data = assertion.auth_data
        b64_cred_id = base64.urlsafe_b64encode(assertion.credential['id']).decode('ascii')
        response_data = json.dumps(dict(
            sessionId=webauthn_opts['sessionId'],
            id=b64_cred_id,
            rawId=b64_cred_id,
            type=assertion.credential['type'],
            authenticatorData=base64.b64encode(auth_data.rp_id_hash + struct.pack(">BI", auth_data.flags, auth_data.counter)).decode('ascii'),
            clientDataJSON=base64.b64encode(json.dumps(dict(
                challenge=webauthn_opts['challenge'],
                clientExtensions={},
                hashAlgorithm="SHA-256",
                origin=origin,
                type="webauthn.get"
            )).encode('ascii')).decode('ascii'),
            signature=assertion.signature.hex(),
        ))
        logger.debug("DUO webauthn response_data: {}".format(response_data))
        payload['response_data'] = response_data
        logger.debug("DUO prompt URL: {}".format(prompt_endpoint))
        logger.debug("DUO payload : {}".format(payload))
        raw_response = parent._send_form_post(prompt_endpoint, payload)
        logger.debug("DUO response received from webauthn_finish endpoint: {}".format(raw_response.text))
        try:
            response = json.loads(raw_response.text)
        except Exception as ex:
            logger.error("DUO Could not decode webauthn response.")
            raise ex
        stat = response.get('stat', '')
        if stat!= 'OK':
            logger.error("DUO webauthn stat: {}".format(stat))
            raise Exception("DUO webauthn stat: {}".format(stat))
        txid = response.get('response', {}).get('txid')

    payload = dict(sid=sid, txid=txid)
    logger.debug("DUO poll yield time: {}".format(duo_poll_seconds))
    while True:
        logger.debug("DUO polling for status ...")
        logger.debug("DUO status_endpoint: {}".format(status_endpoint))
        logger.debug("DUO status payload: {}".format(payload))
        raw_response = parent._send_form_post(status_endpoint, payload)
        logger.debug("DUO Got response from status endpoint.")
        response = json.loads(raw_response.text)
        if response.get('stat') != 'OK':
            logger.error("DUO stat code: {}".format(response.get('stat')))
            raise Exception("POST to Duo status endpoint resulted in error: {}".format(raw_response.text))
        status_code = response.get('response', {}).get('status_code') 
        if status_code == 'pushed':
            logger.debug("DUO status code == 'pushed'")
            time.sleep(duo_poll_seconds)
            continue
        elif status_code == 'allow':
            logger.debug("DUO status code == 'allow'")
            result_url = response.get('response', {}).get('result_url')
            break
        else:
            logger.error("DUO status code: {}".format(response.get('stat')))
            logger.error("DUO raw response: {}".format(raw_response.text))
            raise Exception("Duo returned status code: `{}`".format(status_code))
    payload = dict(sid=sid)
    status_result_endpoint = urljoin("https://{}".format(host), result_url)
    logger.debug("DUO status result endpoint: {}".format(status_result_endpoint))
    raw_response = parent._send_form_post(status_result_endpoint, payload)
    logger.debug("DUO status result endpoint response: {}".format(raw_response.text))
    response = json.loads(raw_response.text)
    cookie = response['response']['cookie']
    logger.debug("DUO cookie: {}".format(cookie))
    logger.debug("DUO app: {}".format(app))
    return cookie, app
