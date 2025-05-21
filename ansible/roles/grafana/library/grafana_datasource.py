#!/usr/bin/python
# -*- coding: utf-8 -*-
from ansible.module_utils.basic import AnsibleModule
import http.client
import ssl
import json

def create_ssl_context():
    """
    Create an SSL context with TLS verification disabled.
    """
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE  # Skip TLS Verification
    return ssl_context

def authenticate_grafana(grafana_url, username, password):
    """
    Authenticate with Grafana API using username and password.
    Returns session cookies if authentication is successful.
    """
    # Validate URL format
    if "://" not in grafana_url:
        raise ValueError(f"Invalid URL format: {grafana_url}. Ensure it starts with 'http://' or 'https://'.")

    # Parse URL into protocol, host, and path
    protocol, rest = grafana_url.split("://")
    host, path = rest.split("/", 1) if "/" in rest else (rest, "")
    login_path = f"/{path}/login" if path else "/login"

    payload = json.dumps({"user": username, "password": password})
    headers = {"Content-Type": "application/json"}

    conn = http.client.HTTPSConnection(host, context=create_ssl_context()) if protocol == "https" else http.client.HTTPConnection(host)
    try:
        conn.request("POST", login_path, body=payload, headers=headers)
        response = conn.getresponse()
        if response.status != 200:
            return None, response.read().decode("utf-8")

        cookies = response.headers.get("Set-Cookie", None)
        if not cookies:
            return None, "Authentication succeeded but no cookie received."

        return cookies, None
    finally:
        conn.close()

def check_datasource_exists(grafana_url, cookies, datasource_name):
    """
    Check if a data source with the given name already exists in Grafana.
    Returns a tuple of (exists, uid) if found.
    """
    protocol, rest = grafana_url.split("://")
    host, path = rest.split("/", 1) if "/" in rest else (rest, "")
    datasource_path = f"/{path}/api/datasources" if path else "/api/datasources"

    headers = {
        "Content-Type": "application/json",
        "Cookie": cookies
    }

    conn = http.client.HTTPSConnection(host, context=create_ssl_context()) if protocol == "https" else http.client.HTTPConnection(host)
    try:
        conn.request("GET", datasource_path, headers=headers)
        response = conn.getresponse()
        if response.status != 200:
            return False, None, response.read().decode("utf-8")

        datasources = json.loads(response.read().decode("utf-8"))
        for ds in datasources:
            if ds.get("name") == datasource_name:
                return True, ds.get("uid"), None  # Found, return True and uid

        return False, None, None  # Not found
    finally:
        conn.close()

def add_zabbix_datasource(grafana_url, cookies, datasource_config):
    """
    Add a Zabbix data source to Grafana using API.
    Returns the response from Grafana API or error details.
    """
    # Validate URL format
    if "://" not in grafana_url:
        raise ValueError(f"Invalid URL format: {grafana_url}. Ensure it starts with 'http://' or 'https://'.")

    protocol, rest = grafana_url.split("://")
    host, path = rest.split("/", 1) if "/" in rest else (rest, "")
    datasource_path = f"/{path}/api/datasources" if path else "/api/datasources"

    headers = {
        "Content-Type": "application/json",
        "Cookie": cookies
    }

    # Append `/api_jsonrpc.php` if missing in the Zabbix URL
    if not datasource_config["url"].endswith("/api_jsonrpc.php"):
        datasource_config["url"] += "/api_jsonrpc.php"

    payload = json.dumps(datasource_config)

    conn = http.client.HTTPSConnection(host, context=create_ssl_context()) if protocol == "https" else http.client.HTTPConnection(host)
    try:
        conn.request("POST", datasource_path, body=payload, headers=headers)
        response = conn.getresponse()
        if response.status != 200:
            return {"msg": response.read().decode("utf-8")}, True

        return json.loads(response.read().decode("utf-8")), False
    finally:
        conn.close()

def run_module():
    """
    Entry point for the grafana_add_zabbix_datasource module execution.
    Validates inputs, authenticates Grafana, and adds the Zabbix data source.
    """
    module_args = dict(
        grafana_url=dict(type="str", required=True),
        username=dict(type="str", required=True),
        password=dict(type="str", required=True, no_log=True),
        datasource=dict(type="dict", required=True),
    )

    module = AnsibleModule(argument_spec=module_args)

    grafana_url = module.params["grafana_url"]
    username = module.params["username"]
    password = module.params["password"]
    datasource = module.params["datasource"]

    try:
        # Authenticate with Grafana
        cookies, error = authenticate_grafana(grafana_url, username, password)
        if error:
            module.fail_json(msg="Authentication to Grafana failed", details=error)

        # Check if the data source already exists
        exists, uid, error = check_datasource_exists(grafana_url, cookies, datasource["name"])
        if exists:
            module.exit_json(
                changed=False,
                msg=f"Data source '{datasource['name']}' already exists with UUID: {uid}."
            )
        elif error:
            module.fail_json(msg="Failed to check existing data sources", details=error)

        # Add Zabbix data source
        result, failed = add_zabbix_datasource(grafana_url, cookies, datasource)
        if failed:
            module.fail_json(msg="Failed to add Zabbix datasource", details=result)
        else:
            # At this point, we can read the new datasource's uid from the result
            uid = result["datasource"].get("uid", "unknown")
            debug_info = {
                "grafana_url": grafana_url,
                "datasource_name": datasource.get("name"),
                "datasource_url": datasource.get("url"),
                "result_data": result,
                "uid": uid
            }
            module.exit_json(changed=True, data=result, uid=uid, debug=debug_info)

    except ValueError as ve:
        module.fail_json(msg="ValueError encountered", details=str(ve))
    except Exception as e:
        module.fail_json(msg=f"An unexpected error occurred: {str(e)}")

def main():
    run_module()

if __name__ == "__main__":
    main() 