
import json
import time
from urllib.parse import (
    quote_plus,
    urlencode,
    urljoin,
)
import xml.etree.cElementTree as ET
from .html_parsers import FormParser, FrameParser

def duo_mfa_flow_entry_point(parent, response):
    """
    Process Duo MFA flow.
    """
    login_url = response.url
    parser = FormParser()
    parser.feed(response.text)
    form = parser.extract_form_by_id('duo_form')
    form_node = ET.fromstring(form)
    signed_duo_response, app = _perform_duo_mfa_flow(parent, login_url, response)
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
    return response

def _perform_duo_mfa_flow(parent, login_url, response):
    """
    Perform Duo MFA web flow.
    """
    parser = FrameParser()
    parser.process_frames(response.text)
    frame = parser.get_frame_by_id('duo_iframe')
    host = frame['data-host']
    duo_auth_version = parent.DUO_AUTH_VERSION
    duo_sig, app = tuple(frame['data-sig-request'].split(':'))
    frame_url = "https://{}/frame/web/v1/auth?tx={}&parent={}&v={}".format(host, duo_sig, quote_plus(login_url), duo_auth_version)
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
    payload['device'] = parent.duo_device
    payload['factor'] = parent.duo_factor
    response = parent._send_form_post(frame_url, payload)
    response = json.loads(response.text)
    if response.get('stat') != 'OK':
        raise Exception("POST to Duo prompt resulted in error: {}".format(response))
    txid = response.get('response', {}).get('txid')
    sid = payload['sid']
    payload = dict(sid=sid, txid=txid)
    duo_status_url = urljoin("https://{}".format(host), "/frame/status")
    duo_poll_seconds = parent.DUO_POLL_SECONDS
    while True:
        raw_response = parent._send_form_post(duo_status_url, payload)
        response = json.loads(raw_response.text)
        if response.get('stat') != 'OK':
            raise Exception("POST to Duo status URL resulted in error: {}".format(raw_response.text))
        status_code = response.get('response', {}).get('status_code') 
        if status_code == 'pushed':
            time.sleep(duo_poll_seconds)
            continue
        elif status_code == 'allow':
            result_url = response.get('response', {}).get('result_url')
            break
        else:
            raise Exception("Duo returned status code: `{}`".format(status_code))
    payload = dict(sid=sid)
    duo_result_url = urljoin("https://{}".format(host), result_url)
    raw_response = parent._send_form_post(duo_result_url, payload)
    response = json.loads(raw_response.text)
    cookie = response['response']['cookie']
    return cookie, app
