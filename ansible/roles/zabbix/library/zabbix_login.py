#!/usr/bin/python
# -*- coding: utf-8 -*-
from ansible.module_utils.basic import AnsibleModule
import http.client
import json
import ssl

def run_module():
    module_args = dict(
        server_url=dict(type='str', required=True),
        user=dict(type='str', required=True),
        password=dict(type='str', required=True, no_log=True)
    )

    module = AnsibleModule(argument_spec=module_args)

    url = module.params['server_url'].rstrip('/') + "/api_jsonrpc.php"  # Ensure proper URL format

    payload = {
        "jsonrpc": "2.0",
        "method": "user.login",
        "params": {
            "username": module.params['user'],  # Use username correctly
            "password": module.params['password']
        },
        "id": 1
    }

    try:
        # Parse the URL and decide connection protocol
        protocol, rest = url.split("://")
        host = rest.split('/')[0]
        path = '/' + '/'.join(rest.split('/')[1:])  # Ensure proper API path

        # Set up SSL context (only for HTTPS)
        if protocol == "https":
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, context=ssl_context)
        elif protocol == "http":
            conn = http.client.HTTPConnection(host)
        else:
            module.fail_json(msg=f"Unsupported protocol '{protocol}' in server_url.")

        # Send the POST request
        conn.request("POST", path, body=json.dumps(payload), headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        data = response.read()

        # Parse the response
        result = json.loads(data.decode('utf-8'))
        if "result" in result:
            module.exit_json(changed=False, token=result["result"])
        else:
            module.fail_json(msg="Login failed", details=result.get("error"))
    except Exception as e:
        module.fail_json(msg="Exception occurred", details=str(e))
    finally:
        conn.close()

def main():
    run_module()

if __name__ == '__main__':
    main() 