import logging

from mantis.modules.secretscanner.submodules.gitleaks_runner import GitleaksRunner
from mantis.modules.secretscanner.submodules.secret_finder import SecretFinder
from mantis.utils.crud_utils import CrudUtils
from mantis.models.args_model import ArgsModel
from mantis.tool_base_classes.toolScanner import ToolScanner
from mantis.utils.tool_utils import get_org_assets
from mantis.utils.base_request import BaseRequestExecutor
import os
import re


'''
Jshastra module is used to scrape metadata around the JS files 
'''

class JShashtra(ToolScanner):
    def __init__(self) -> None:
        super().__init__()
        self.js_assets = None

    async def get_commands(self, args: ArgsModel):
        # Store args in the instance
        self.args = args
        self.org = args.org


       # Fetch subdomains
        try:
            # Fetch JS assets for the organization
            logging.info(f"Fetching JS assets for org: {self.org}")
            self.assets = await get_org_assets(self.org)
            if not self.assets:
                logging.error(f"No subdomain found for org: {self.org}")
                return []

            for asset in self.assets:
                logging.info(f"Processing asset: {asset.get('_id', None)}")
                current_asset = asset.get('_id', None)
                js_assets = asset.get('js_assets', [])
                if not js_assets:
                    continue

                js_assets = [js for js in js_assets if js.strip()]
                all_js_api_paths = {}

                # python
                for js_asset in js_assets:
                    request_tuple = (js_asset, None, None, asset)
                    try:
                        _, response = BaseRequestExecutor.sendRequest("GET", request_tuple, download_large_file=True)
                        if response.status_code not in range(200, 299):
                            logging.error(f"Failed to fetch {js_asset}: {response.status_code}")
                            continue
                    except Exception as e:
                        logging.error(f"Failed to fetch {js_asset}: {e}")
                        continue

                    # Save the response content to a file
                    output_dir = f"logs/js/{args.org}/"
                    os.makedirs(output_dir, exist_ok=True)  # Ensure the directory exists
                    safe_file_name = js_asset.replace('/', '_').replace(':', '_')  # Handle invalid characters
                    file_path = os.path.join(output_dir, f"{safe_file_name}")

                    with open(file_path, 'wb') as file:
                        file.write(response.content)

                   # Secret Extraction using JS files
                    GitleaksRunner.process_js(output_dir)
                    secret_finder = SecretFinder(output_dir, args, '')
                    await secret_finder.find_secrets_in_js(asset)

                    # extract API endpoints from the JS file
                    with open(file_path, "r", encoding="utf-8") as f:
                        js_content = f.read()

                    # Regex patterns
                    full_url_pattern = r'https?://[^\s"\'<>]*?(?:/api|/v\d+|/auth|/login|/register|/data|/user|/admin|/token|/search|/update|/get|/post|/put|/delete)[^\s"\'<>]*'
                    relative_path_pattern = r'(?<![a-zA-Z0-9])/(?:api|v\d+|rest)(?:/[^\s"\'<>]*)?'
                    rootless_path_pattern = r'(?<![a-zA-Z0-9/])(?:api|v\d+|rest)/(?:[^\s"\'<>]*)'

                    full_urls = re.findall(full_url_pattern, js_content)    # Apply regex
                    relative_paths = re.findall(relative_path_pattern, js_content)
                    rootless_paths = re.findall(rootless_path_pattern, js_content)

                    api_paths = list(set(full_urls + relative_paths + rootless_paths))

                    if api_paths:
                        # Get js_assets - convert list to dict if needed
                        existing_js_assets = asset.get("js_assets", {})

                        # If it's a list (original format), convert it to dict
                        if isinstance(existing_js_assets, list):
                            existing_js_assets = {js: [] for js in existing_js_assets}

                        # Update the API paths for the current JS file
                        existing_js_assets[js_asset] = api_paths

                        # Update the asset in DB
                        await CrudUtils.update_asset(
                            asset=current_asset,
                            org=self.org,
                            tool_output_dict={"js_assets": existing_js_assets}
                        )
                        logging.info("API paths extracted and updated successfully.")
                    else:
                        logging.warning(f"No API paths found in {js_asset}")

                    # delete the file once processed
                    os.remove(file_path)
                    logging.info(f"Deleted file: {file_path}")

            return []

        except Exception as e:
            logging.error(f"Something went wrong in JShashtra: {e}")
            return []

        # Return the base commands with the fetched assets
        return super().base_get_commands(self.js_assets)
