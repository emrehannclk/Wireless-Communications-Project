#!/usr/bin/python
# -*- coding: utf-8 -*-
import json
import http.client
import ssl
import logging
import traceback
from ansible.module_utils.basic import AnsibleModule

# Logging configuration
logging.basicConfig(
    level=logging.INFO,  # Adjusted to show only INFO and above levels
    format="%(asctime)s - %(levelname)s - %(message)s",
)

def create_ssl_context():
    """ Create a secure SSL context that bypasses certificate verification. """
    try:
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        return ssl_context
    except Exception as e:
        logging.error("Failed to create SSL context.")
        raise RuntimeError(f"Failed to create SSL context: {str(e)}")

def authenticate_grafana(grafana_url, username, password):
    """ Authenticate with Grafana using session-based login. """
    try:
        if "://" not in grafana_url:
            raise ValueError(f"Invalid URL format: {grafana_url}. Ensure it starts with 'http://' or 'https://'.")

        protocol, rest = grafana_url.split("://")
        host, path = rest.split("/", 1) if "/" in rest else (rest, "")
        login_path = f"/{path}/login" if path else "/login"

        payload = json.dumps({"user": username, "password": password})
        headers = {"Content-Type": "application/json"}

        conn = http.client.HTTPSConnection(host, context=create_ssl_context()) if protocol == "https" else http.client.HTTPConnection(host)
        conn.request("POST", login_path, body=payload, headers=headers)
        response = conn.getresponse()
        response_data = response.read().decode('utf-8')

        if response.status != 200:
            logging.error(f"Authentication failed with status: {response.status}")
            return None, response_data

        cookies = response.headers.get("Set-Cookie", None)
        if not cookies:
            return None, "Authentication succeeded but no cookie received."

        return cookies, None
    except Exception as e:
        logging.error("An error occurred during authentication.")
        return None, str(e)
    finally:
        if 'conn' in locals():
            conn.close()

def update_panels(dashboard_model, new_uid, new_group, new_host):
    """ Update panels with UID, group filter, and host filter. """
    try:
        for panel in dashboard_model.get("panels", []):
            if "datasource" in panel:
                panel["datasource"]["uid"] = new_uid

            for target in panel.get("targets", []):
                if "datasource" in target:
                    target["datasource"]["uid"] = new_uid
                if "group" in target and "filter" in target["group"]:
                    target["group"]["filter"] = new_group
                if "host" in target and "filter" in target["host"]:
                    target["host"]["filter"] = new_host
        return dashboard_model
    except Exception as e:
        logging.error("Failed to update panels.")
        raise RuntimeError(f"Failed to update panels: {str(e)}")

def update_json_model(json_model, new_uid, new_group, new_host, web_service_group=None):
    """ Create proper payload structure for dashboard updates. """
    try:
        # Wrap the JSON model with a "dashboard" key if it's not already a dictionary
        if not isinstance(json_model.get("dashboard"), dict):
            json_model = {"dashboard": json_model}

        # Access the "dashboard" model
        dashboard_model = json_model["dashboard"]

        # Assign or update the "uid" key
        if not dashboard_model.get("uid"):
            dashboard_model["uid"] = "testtest"
        else:
            if new_uid:
                if web_service_group:
                    dashboard_model["uid"] = f"{new_host.replace('.', '')}_{web_service_group}"
                else:
                    dashboard_model["uid"] = new_host.replace(".", "")

        # Update title and ID
        if web_service_group:
            dashboard_model["title"] = f"{new_host} {web_service_group} Servives Dashboard"
        else:
            dashboard_model["title"] = f"{new_host} Dashboard"
        dashboard_model["id"] = None

        # Call an external function to update panels
        dashboard_model = update_panels(dashboard_model, new_uid, new_group, new_host)

        # Return the updated JSON structure
        return {"dashboard": dashboard_model, "overwrite": True}
    except Exception as e:
        # Log the error and raise a RuntimeError
        logging.error("Failed to update JSON model.")
        raise RuntimeError(f"Failed to update JSON model: {str(e)}")

def send_dashboard(grafana_url, cookies, payload):
    """ Send the updated JSON model to Grafana API and return response. """
    try:
        if "://" not in grafana_url:
            raise ValueError(f"Invalid URL format: {grafana_url}. Ensure it starts with 'http://' or 'https://'.")
        protocol, rest = grafana_url.split("://")
        host, path = rest.split("/", 1) if "/" in rest else (rest, "")
        dashboard_path = f"/{path}/api/dashboards/db" if path else "/api/dashboards/db"

        headers = {"Content-Type": "application/json", "Cookie": cookies}

        conn = http.client.HTTPSConnection(host, context=create_ssl_context()) if protocol == "https" else http.client.HTTPConnection(host)
        conn.request("POST", dashboard_path, json.dumps(payload), headers)
        response = conn.getresponse()
        response_data = response.read().decode("utf-8")

        if response.status != 200:
            logging.error("Failed to send dashboard.")
            return {"msg": response_data}, True

        return json.loads(response_data), False
    except Exception as e:
        logging.error("An error occurred while sending the dashboard.")
        return {"msg": str(e)}, True
    finally:
        if 'conn' in locals():
            conn.close()

def run_module():
    """ Execute Ansible module with structured error handling. """
    module_args = {
        "grafana_url": {"type": "str", "required": True},
        "username": {"type": "str", "required": True},
        "password": {"type": "str", "required": True, "no_log": True},
        "json_model": {"type": "dict", "required": True},
        "new_uid": {"type": "str", "required": True},
        "new_group": {"type": "str", "required": True},
        "new_host": {"type": "str", "required": True},
        "web_service_group": {"type": "str", "required": False},
    }

    global module
    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    try:
        cookies, error = authenticate_grafana(
            module.params["grafana_url"], 
            module.params["username"], 
            module.params["password"]
        )
        if error:
            module.fail_json(msg="Authentication to Grafana failed.", details=error)

        updated_payload = update_json_model(
            module.params["json_model"],
            module.params["new_uid"],
            module.params["new_group"],
            module.params["new_host"],
            module.params.get("web_service_group")
        )

        result, failed = send_dashboard(module.params["grafana_url"], cookies, updated_payload)
        if failed:
            module.fail_json(msg="Failed to send dashboard.", details=result)

        module.exit_json(changed=True, response=result)
    except Exception as e:
        logging.error("An unexpected error occurred during module execution.")
        module.fail_json(msg="An unexpected error occurred.", details=str(e))

if __name__ == '__main__':
    run_module() 