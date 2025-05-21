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

def get_host_interface_id(url, auth_token, host_id, interface_type):
    """
    Get interface ID for a specific host and interface type.
    """
    response = zabbix_api_call(url, "hostinterface.get", {
        "output": ["interfaceid"],
        "hostids": host_id,
        "filter": {"type": interface_type}
    }, auth=auth_token)

    if response.get("result"):
        return response["result"][0]["interfaceid"]
    
    return None

def run_module():
    """
    Main function to handle module parameters and execute the operations.
    """
    module_args = dict(
        server_url=dict(type='str', required=True),
        token=dict(type='str', required=True),
        host_id=dict(type='str', required=True),
        name=dict(type='str', required=True),
        key=dict(type='str', required=True),
        type=dict(type='int', required=True),
        value_type=dict(type='int', required=True),
        interface_type=dict(type='int', required=True),
        delay=dict(type='str', required=False, default='1m'),
        snmp_oid=dict(type='str', required=False),
        snmp_community=dict(type='str', required=False, default='public'),
        description=dict(type='str', required=False),
        units=dict(type='str', required=False),
        history=dict(type='str', required=False, default='90d'),
        trends=dict(type='str', required=False, default='365d')
    )

    module = AnsibleModule(argument_spec=module_args)

    # Extract parameters
    url = module.params['server_url'].rstrip('/') + "/api_jsonrpc.php"
    auth_token = module.params['token']

    # Get interface ID
    interface_id = get_host_interface_id(url, auth_token, module.params['host_id'], module.params['interface_type'])
    if not interface_id:
        module.fail_json(msg=f"Could not find interface of type {module.params['interface_type']} for host {module.params['host_id']}")

    # Prepare item creation payload
    create_payload = {
        "hostid": module.params['host_id'],
        "name": module.params['name'],
        "key_": module.params['key'],
        "type": module.params['type'],
        "value_type": module.params['value_type'],
        "interfaceid": interface_id,
        "delay": module.params['delay'],
        "history": module.params['history'],
        "trends": module.params['trends']
    }

    # Add optional parameters if provided
    if module.params['description']:
        create_payload["description"] = module.params['description']
    if module.params['units']:
        create_payload["units"] = module.params['units']

    # Add SNMP specific parameters if type is SNMP agent
    if module.params['type'] == 20:  # SNMP agent
        if not module.params['snmp_oid']:
            module.fail_json(msg="snmp_oid is required for SNMP agent items")
        create_payload["snmp_oid"] = module.params['snmp_oid']
        create_payload["snmp_community"] = module.params['snmp_community']

    # Create the item
    create = zabbix_api_call(url, "item.create", create_payload, auth_token)

    if "result" in create:
        item_id = create["result"]["itemids"][0]
        module.exit_json(changed=True, msg="Item created successfully", itemid=item_id)
    else:
        module.fail_json(msg="Item creation failed", details=create)

def main():
    run_module()

if __name__ == '__main__':
    main() 