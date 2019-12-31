
import getpass
import json
import logging
import time
from urllib.parse import (
    quote_plus,
    urlencode,
    urljoin,
)
import xml.etree.cElementTree as ET
from .html_parsers import FormParser, FrameParser

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
    duo_auth_version = parent.DUO_AUTH_VERSION
    duo_sig, app = tuple(frame['data-sig-request'].split(':'))
    frame_url = "https://{}/frame/web/v1/auth?tx={}&parent={}&v={}".format(host, duo_sig, quote_plus(login_url), duo_auth_version)
    logger.debug("DUO frame auth URL: {}".format(frame_url))
    response = parent._requests_session.get(frame_url, verify=True)
    duo_form_html_node = parent._parse_form_from_html(response.text, form_index=parent.DUO_FORM_INDEX)
    payload = dict((tag.attrib['name'], tag.attrib.get('value', ''))
                   for tag in duo_form_html_node.findall(".//input"))
    response = parent._send_form_post(frame_url, payload)
    duo_form_html_node = parent._parse_form_from_html(response.text, form_index=parent.DUO_FORM_INDEX)
    payload = dict((tag.attrib['name'], tag.attrib.get('value', ''))
                   for tag in duo_form_html_node.findall(".//input"))
    action = duo_form_html_node.attrib.get('action', '')
    frame_url = urljoin("https://{}".format(host), action)
    logger.debug("DUO prompt endpoint: {}".format(frame_url))
    payload['device'] = duo_device
    if duo_factor == "webauthn":
        payload['factor'] = "WebAuthn Credential"
    else:
        payload['factor'] = duo_factor
    if duo_factor == 'Passcode':
        payload['passcode'] = getpass.getpass("Passcode: ")
    logger.debug("DUO prompt endpoint payload: {}".format(payload))
    response = parent._send_form_post(frame_url, payload)
    logger.debug("Duo prompt endpoint response: {}".format(response.text))
    response = json.loads(response.text)
    if response.get('stat') != 'OK':
        raise Exception("POST to Duo prompt resulted in error: {}".format(response))
    txid = response.get('response', {}).get('txid')
    sid = payload['sid']
    payload = dict(sid=sid, txid=txid)
    duo_status_url = urljoin("https://{}".format(host), "/frame/status")
    duo_poll_seconds = parent.DUO_POLL_SECONDS
    logger.debug("DUO status endpoint: {}".format(duo_status_url))
    if duo_factor == 'webauthn':
        logger.debug("Getting challenge from Duo prompt endpoint ...")
        logger.debug("DUO device: {}".format(duo_device))
        #payload['device'] = duo_device
        payload['factor'] = "WebAuthn Credential"
        payload['device'] = "WA5NXAL405S765X5WJFA"
        logger.debug("DUO status URL: {}".format(duo_status_url))
        logger.debug("DUO payload: {}".format(payload))
        raw_response = parent._send_form_post(duo_status_url, payload)
        try:
            response = json.loads(raw_response.text)
        except Exception as ex:
            logger.error("DUO Error decoding JSON response from prompt endpoint: {}".format(ex))
            raise
        # Example response
        # {"stat": "OK", "response": {"webauthn_credential_request_options": {"allowCredentials": [{"transports": ["usb", "nfc", "ble"], "id": "_HbP_XU2bqAFEi6spjC6RT00JysSJZPYg-U32zK_7i4mnzrd-SPQRhJh12Olk0xHXQL720PTvLEBfvhhla3-8A", "type": "public-key"}], "rpId": "duosecurity.com", "timeout": 60000, "challenge": "YagLoMMgBn8UlOsm3do5yVE55erM1XxJ", "sessionId": "BY_Y_j5zNHM4aPlu25JCqGXJqI8YgYuaYYloB2hR2jc"}, "status": "Use your Security Key to log in...", "status_code": "webauthn_sent"}} 
        if response.get('stat') != 'OK':
            raise Exception("DUO POST for credential challenge resulted in error: {}".format(response))
        webauthn_opts = response.get('response', {}).get('webauthn_credential_request_options') 
        # TODO: submit options to authenticator, pass results to Duo endpoint. 
        raise Exception("webauthn_opts: {}".format(webauthn_opts))
    while True:
        raw_response = parent._send_form_post(duo_status_url, payload)
        response = json.loads(raw_response.text)
        if response.get('stat') != 'OK':
            logger.error("DUO stat code: {}".format(response.get('stat')))
            raise Exception("POST to Duo status URL resulted in error: {}".format(raw_response.text))
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
    duo_result_url = urljoin("https://{}".format(host), result_url)
    logger.debug("DUO status result endpoint: {}".format(duo_result_url))
    raw_response = parent._send_form_post(duo_result_url, payload)
    logger.debug("DUO status result endpoint response: {}".format(raw_response.text))
    response = json.loads(raw_response.text)
    cookie = response['response']['cookie']
    logger.debug("DUO cookie: {}".format(cookie))
    logger.debug("DUO app: {}".format(app))
    return cookie, app
