#!/usr/bin/python
# -*- coding: utf-8 -*-
from ansible.module_utils.basic import AnsibleModule
import http.client
import json
import time

def zabbix_api_call(server_url, token, method, params, max_retries=3, retry_delay=2):
    # Remove protocol from server_url if present
    if server_url.startswith('http://'):
        server_url = server_url[7:]
    elif server_url.startswith('https://'):
        server_url = server_url[8:]

    # Remove trailing slash if present
    server_url = server_url.rstrip('/')

    # Split server_url into host and port if port is specified
    if ':' in server_url:
        host, port = server_url.split(':')
        port = int(port)
    else:
        host = server_url
        port = 80  # Default to HTTP port

    for attempt in range(max_retries):
        try:
            # Create HTTP connection
            conn = http.client.HTTPConnection(
                host=host,
                port=port,
                timeout=30
            )

            # Prepare the request
            headers = {
                'Content-Type': 'application/json-rpc',
                'User-Agent': 'Ansible Zabbix Module'
            }
            
            payload = {
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
                "auth": token,
                "id": 1
            }

            # Send the request
            conn.request("POST", "/api_jsonrpc.php", json.dumps(payload), headers)
            response = conn.getresponse()
            
            if response.status != 200:
                raise Exception(f"HTTP Error: {response.status} {response.reason}")
                
            data = json.loads(response.read().decode())

            # Check for API errors
            if "error" in data:
                error_msg = data["error"].get("data", "Unknown error")
                if "already exists" in error_msg:
                    # If item exists, try to update it
                    return update_existing_item(server_url, token, params)
                raise Exception(f"API Error: {error_msg}")

            return data["result"]

        except (http.client.HTTPException, ConnectionError) as e:
            if attempt < max_retries - 1:
                time.sleep(retry_delay * (attempt + 1))  # Exponential backoff
                continue
            raise Exception(f"Connection failed after {max_retries} attempts: {str(e)}")
        except Exception as e:
            raise Exception(f"API call failed: {str(e)}")
        finally:
            try:
                conn.close()
            except:
                pass

def update_existing_item(server_url, token, params):
    # First, get the existing item
    get_params = {
        "output": ["itemid", "name", "key_"],
        "filter": {
            "hostid": params["hostid"],
            "key_": params["key_"]
        }
    }
    
    existing_items = zabbix_api_call(server_url, token, "item.get", get_params)
    
    if not existing_items:
        raise Exception("Item not found for update")
    
    item_id = existing_items[0]["itemid"]
    
    # Update the existing item
    update_params = {
        "itemid": item_id,
        "name": params["name"],
        "key_": params["key_"],
        "hostid": params["hostid"],
        "type": params["type"],
        "value_type": params["value_type"],
        "delay": params["delay"],
        "description": params.get("description", ""),
        "params": params["params"]
    }

    # Add tags if present in original params
    if "tags" in params:
        update_params["tags"] = params["tags"]
    
    return zabbix_api_call(server_url, token, "item.update", update_params)

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
        script=dict(type='str', required=True),
        value_type=dict(type='int', required=True),
        delay=dict(type='str', required=True),
        description=dict(type='str', required=False, default=''),
        tags=dict(type='list', required=False, default=[])
    )

    result = dict(
        changed=False,
        itemid='',
        message=''
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    # Extract parameters
    server_url = module.params['server_url']
    token = module.params['token']
    host_id = module.params['host_id']
    name = module.params['name']
    key = module.params['key']
    script = module.params['script']
    value_type = module.params['value_type']
    delay = module.params['delay']
    description = module.params['description']
    tags = module.params['tags']

    try:
        # Prepare the payload for item creation
        params = {
            "hostid": host_id,
            "name": name,
            "key_": key,
            "type": 21,  # Script type
            "value_type": value_type,
            "delay": delay,
            "description": description,
            "params": script
        }

        # Add tags if provided
        if tags:
            params["tags"] = tags

        # Create the item
        item_result = zabbix_api_call(server_url, token, "item.create", params)
        
        if isinstance(item_result, list) and len(item_result) > 0:
            result['itemid'] = item_result[0]
            result['changed'] = True
            result['message'] = f"Script item created successfully with ID: {item_result[0]}"
        else:
            result['message'] = "Script item created or updated successfully"
            result['changed'] = True

    except Exception as e:
        module.fail_json(msg=f"Script item creation failed: {str(e)}", **result)

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main() 