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

def get_template_id(url, auth_token, template_name):
    """
    Fetch template ID using template name from Zabbix API.
    """
    response = zabbix_api_call(url, "template.get", {
        "output": ["templateid", "name"],
        "filter": {"name": template_name}
    }, auth=auth_token)

    if response.get("result"):
        return response["result"][0]["templateid"]
    
    return None

def run_module():
    """
    Main function to handle module parameters and execute the operations.
    """
    module_args = dict(
        server_url=dict(type='str', required=True),
        user=dict(type='str', required=False),
        password=dict(type='str', required=False, no_log=True),
        token=dict(type='str', required=False),
        host_name=dict(type='str', required=True),
        ip=dict(type='str', required=False),
        dns=dict(type='str', required=False),
        use_dns=dict(type='bool', default=False),
        group_id=dict(type='str', required=False),
        group_name=dict(type='str', required=False),
        template_name=dict(type='str', required=False),
        interface_type=dict(type='str', required=False, default='agent'),
        port=dict(type='str', required=False, default='10050'),
        snmp_community=dict(type='str', required=False)
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

    # Fetch group_id based on group_name if group_id is not provided
    if not module.params['group_id'] and module.params['group_name']:
        group_resp = zabbix_api_call(url, "hostgroup.get", {
            "filter": {"name": module.params["group_name"]}
        }, auth=auth_token)

        if not group_resp["result"]:
            module.fail_json(msg="Group name not found in Zabbix")

        group_id = group_resp["result"][0]["groupid"]
    else:
        group_id = module.params["group_id"]

    if not group_id:
        module.fail_json(msg="Group ID or name must be provided.")

    # Check if host already exists
    existing = zabbix_api_call(url, "host.get", {
        "filter": {"host": module.params["host_name"]}
    }, auth=auth_token)

    if existing["result"]:
        module.exit_json(changed=False, msg="Host already exists", hostid=existing["result"][0]["hostid"])

    # Validate IP/DNS requirements
    if module.params['use_dns']:
        if not module.params['dns']:
            module.fail_json(msg="use_dns is true but no DNS name provided")
        interface_ip = ""
        interface_dns = module.params['dns']
        useip = 0
    else:
        if not module.params['ip']:
            module.fail_json(msg="use_dns is false but no IP address provided")
        interface_ip = module.params['ip']
        interface_dns = ""
        useip = 1

    # Fetch template ID based on template name
    template_id = None
    if module.params['template_name']:
        template_id = get_template_id(url, auth_token, module.params["template_name"])
        if not template_id:
            module.fail_json(msg=f"Template '{module.params['template_name']}' not found.")

    # Determine interface type based on the interface_type parameter
    interface_type_id = 1  # Default to agent
    if module.params['interface_type'] == 'snmp':
        interface_type_id = 2
    elif module.params['interface_type'] == 'ipmi':
        interface_type_id = 3
    elif module.params['interface_type'] == 'jmx':
        interface_type_id = 4

    # Create the host
    create_payload = {
        "host": module.params["host_name"],
        "interfaces": [{
            "type": interface_type_id,
            "main": 1,
            "useip": useip,
            "ip": interface_ip,
            "dns": interface_dns,
            "port": module.params['port'],
            "details": {
                "version": 2,
                "community": module.params.get('snmp_community', 'public')
            }
        }],
        "groups": [{"groupid": group_id}],
        "templates": [{"templateid": template_id}] if template_id else []
    }

    create = zabbix_api_call(url, "host.create", create_payload, auth_token)

    if "result" in create:
        host_id = create["result"]["hostids"][0]
        module.exit_json(changed=True, msg="Host created and template applied", hostid=host_id, template=module.params["template_name"])
    else:
        module.fail_json(msg="Host creation failed", details=create)

def main():
    run_module()

if __name__ == '__main__':
    main() 