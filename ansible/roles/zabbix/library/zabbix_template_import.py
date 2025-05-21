#!/usr/bin/python
# -*- coding: utf-8 -*-
import json
import yaml
import http.client
import ssl
from ansible.module_utils.basic import AnsibleModule

def zabbix_api_call(url, method, params, auth=None):
    """
    Handles communication with the Zabbix API using http.client with SSL verification disabled.
    """
    url = url.rstrip("/")
    protocol, rest = url.split("://")
    host, path = rest.split("/", 1) if "/" in rest else (rest, "")
    path = f"/{path}/api_jsonrpc.php"

    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
        "auth": auth
    }
    headers = {"Content-Type": "application/json"}

    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    conn = http.client.HTTPSConnection(host, context=ssl_context) if protocol == "https" else http.client.HTTPConnection(host)

    try:
        conn.request("POST", path, body=json.dumps(payload), headers=headers)
        response = conn.getresponse()

        if response.status != 200:
            return {'error': 'HTTP request failed', 'details': response.read().decode('utf-8')}

        try:
            return json.loads(response.read().decode('utf-8'))
        except json.JSONDecodeError:
            return {'error': 'Invalid JSON response', 'details': response.read().decode('utf-8')}
    finally:
        conn.close()

def authenticate(url, username, password):
    """
    Authenticate with Zabbix API and return the token.
    """
    auth_response = zabbix_api_call(
        url,
        "user.login",
        {
            "username": username,
            "password": password
        }
    )
    if "result" not in auth_response:
        return None, auth_response
    return auth_response["result"], None

def import_template(url, auth_token, template_yaml):
    """
    Import a template into Zabbix from YAML format.
    """
    payload = {
        "format": "yaml",
        "rules": {
            "discoveryRules": {"createMissing": True, "updateExisting": True, "deleteMissing": True},
            "graphs": {"createMissing": True, "updateExisting": True, "deleteMissing": True},
            "groups": {"createMissing": True, "updateExisting": True},
            "hosts": {"createMissing": True, "updateExisting": True},
            "httptests": {"createMissing": True, "updateExisting": True, "deleteMissing": True},
            "images": {"createMissing": True, "updateExisting": True},
            "items": {"createMissing": True, "updateExisting": True, "deleteMissing": True},
            "maps": {"createMissing": True, "updateExisting": True},
            "mediaTypes": {"createMissing": True, "updateExisting": True},
            "templateLinkage": {"createMissing": True, "deleteMissing": True},
            "templates": {"createMissing": True, "updateExisting": True},
            "templateDashboards": {"createMissing": True, "updateExisting": True, "deleteMissing": True},
            "triggers": {"createMissing": True, "updateExisting": True, "deleteMissing": True},
            "valueMaps": {"createMissing": True, "updateExisting": True, "deleteMissing": True}
        },
        "source": template_yaml
    }

    response = zabbix_api_call(url, "configuration.import", payload, auth_token)

    if "error" in response:
        return {"msg": response["error"]["message"], "failed": True}

    return {"msg": "Template imported successfully.", "failed": False}

def run_module():
    """
    Entry point for the Ansible module execution.
    """
    module_args = dict(
        server_url=dict(type='str', required=True),
        username=dict(type='str', required=False),
        password=dict(type='str', required=False, no_log=True),
        token=dict(type='str', required=False),
        template_yaml=dict(type='str', required=True),
    )

    module = AnsibleModule(argument_spec=module_args)

    url = module.params['server_url'].rstrip('/') + "/api_jsonrpc.php"
    auth_token = module.params['token']

    if not auth_token:
        if not module.params['username'] or not module.params['password']:
            module.fail_json(msg="Either token or username/password must be provided.")

        auth_token, error = authenticate(url, module.params["username"], module.params["password"])
        if error:
            module.fail_json(msg="Authentication failed", details=error)

    result = import_template(url, auth_token, module.params["template_yaml"])
    if result["failed"]:
        module.fail_json(msg="Template import failed.", details=result["msg"])

    module.exit_json(changed=True, response=result["msg"])

def main():
    run_module()

if __name__ == '__main__':
    main() 