#!/usr/bin/python
# -*- coding: utf-8 -*-
from ansible.module_utils.basic import AnsibleModule
import http.client
import ssl
import json

def zabbix_api_call(url, method, params, auth=None):
    """
    Handles communication with the Zabbix API using http.client.
    """
    protocol, rest = url.split("://")
    host, path = rest.split("/", 1)
    path = f"/{path}/api_jsonrpc.php"

    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "id": 1,
        "auth": auth
    }
    headers = {"Content-Type": "application/json"}

    # Create SSL context that disables verification
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    # Create HTTP/HTTPS connection based on protocol
    conn = http.client.HTTPSConnection(host, context=ssl_context) if protocol == "https" else http.client.HTTPConnection(host)

    try:
        conn.request("POST", path, body=json.dumps(payload), headers=headers)
        response = conn.getresponse()

        # Check HTTP response status
        if response.status != 200:
            return {'error': 'HTTP request failed', 'details': response.read().decode('utf-8')}

        # Parse JSON response
        try:
            return json.loads(response.read().decode('utf-8'))
        except json.JSONDecodeError:
            return {'error': 'Invalid JSON response', 'details': response.read().decode('utf-8')}
    finally:
        conn.close()

def run_module():
    """
    Main function to handle module parameters and execute the operations.
    """
    module_args = dict(
        server_url=dict(type='str', required=True),
        user=dict(type='str', required=False),
        password=dict(type='str', required=False, no_log=True),
        token=dict(type='str', required=False),
        group_name=dict(type='str', required=True)
    )

    module = AnsibleModule(argument_spec=module_args)

    # Extract parameters
    url = module.params['server_url'].rstrip('/') + "/api_jsonrpc.php"
    auth_token = module.params['token']

    # Authenticate if no token is provided
    if not auth_token:
        if not module.params['user'] or not module.params['password']:
            module.fail_json(msg="Either token or user/password must be provided.")

        login_resp = zabbix_api_call(
            url,
            "user.login",
            {
                "username": module.params['user'],
                "password": module.params['password']
            }
        )

        if "result" not in login_resp:
            module.fail_json(msg="Login failed", details=login_resp)

        auth_token = login_resp["result"]

    # Check if group already exists
    group_check = zabbix_api_call(url, "hostgroup.get", {
        "filter": {"name": module.params["group_name"]}
    }, auth=auth_token)

    if group_check["result"]:
        group_id = group_check["result"][0]["groupid"]
        module.exit_json(changed=False, msg="Group already exists", groupid=group_id)

    # Create the group
    group_create = zabbix_api_call(url, "hostgroup.create", {
        "name": module.params["group_name"]
    }, auth=auth_token)

    if "result" in group_create:
        group_id = group_create["result"]["groupids"][0]
        module.exit_json(changed=True, msg="Group created", groupid=group_id)
    else:
        module.fail_json(msg="Group creation failed", details=group_create)

def main():
    run_module()

if __name__ == '__main__':
    main() 