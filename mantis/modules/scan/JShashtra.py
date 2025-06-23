import logging
import os
import re

from mantis.modules.secretscanner.submodules.gitleaks_runner import GitleaksRunner
from mantis.modules.secretscanner.submodules.secret_finder import SecretFinder
from mantis.utils.crud_utils import CrudUtils
from mantis.models.args_model import ArgsModel
from mantis.tool_base_classes.toolScanner import ToolScanner
from mantis.utils.tool_utils import get_org_assets
from mantis.utils.base_request import BaseRequestExecutor


'''
JShashtra module is used to scrape metadata around the JS files
'''

class JShashtra(ToolScanner):
    def __init__(self) -> None:
        super().__init__()
        self.js_assets = None

    async def get_commands(self, args: ArgsModel):
        self.args = args
        self.org = args.org

        try:
            logging.info(f"Fetching JS assets for org: {self.org}")
            self.assets = await get_org_assets(self.org)
            if not self.assets:
                logging.error(f"No subdomain found for org: {self.org}")
                return []

            for asset in self.assets:
                logging.info(f"Processing asset: {asset.get('_id', None)}")
                current_asset = asset.get('_id', None)
                js_assets = asset.get('js_assets', [])

                # Skip if empty or all strings are blank
                js_assets = [js for js in js_assets if isinstance(js, str) and js.strip()]
                if not js_assets:
                    continue

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

                    # Save JS content to file
                    output_dir = f"logs/js/{args.org}/"
                    os.makedirs(output_dir, exist_ok=True)
                    safe_file_name = js_asset.replace('/', '_').replace(':', '_')
                    file_path = os.path.join(output_dir, f"{safe_file_name}")

                    with open(file_path, 'wb') as file:
                        file.write(response.content)

                    GitleaksRunner.process_js(output_dir)
                    secret_finder = SecretFinder(output_dir,args,'')
                    await secret_finder.find_secrets_in_js(asset)

                    # Read JS content as text
                    try:
                        with open(file_path, "r", encoding="utf-8") as f:
                            js_content = f.read()
                    except Exception as e:
                        logging.error(f"Error reading JS file {file_path}: {e}")
                        continue

                    # Extract information
                    async def extract_ip_addresses(js_content):
                        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                        return list(set(re.findall(ip_pattern, js_content)))

                    async def extract_emails(js_content):
                        email_pattern = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
                        return list(set(re.findall(email_pattern, js_content)))

                    async def extract_api_paths(js_content):
                        full_url_pattern = r'https?://[^\s"\'<>]*?(?:/api|/v\d+|/auth|/login|/register|/data|/user|/admin|/token|/search|/update|/get|/post|/put|/delete)[^\s"\'<>]*'
                        relative_path_pattern = r'(?<![a-zA-Z0-9])/(?:api|v\d+|rest)(?:/[^\s"\'<>]*)?'
                        rootless_path_pattern = r'(?<![a-zA-Z0-9/])(?:api|v\d+|rest)/(?:[^\s"\'<>]*)'

                        full_urls = re.findall(full_url_pattern, js_content)
                        relative_paths = re.findall(relative_path_pattern, js_content)
                        rootless_paths = re.findall(rootless_path_pattern, js_content)

                        return list(set(full_urls + relative_paths + rootless_paths))

                    async def process_js_file(js_asset, js_content, current_asset, asset):
                        ips = await extract_ip_addresses(js_content)
                        emails = await extract_emails(js_content)
                        apis = await extract_api_paths(js_content)

                        structured_entry = {
                            "js_link": js_asset,
                            "ips": ips,
                            "emails": emails,
                            "apis": apis
                        }

                        js_assets_list = asset.get("js_assets", [])
                        if not isinstance(js_assets_list, list):
                            js_assets_list = []

                        # Remove old entry if exists
                        js_assets_list = [entry for entry in js_assets_list if not (isinstance(entry, dict) and entry.get("js_link") == js_asset)]

                        # Add new structured info
                        js_assets_list.append(structured_entry)

                        await CrudUtils.update_asset(
                            asset=current_asset,
                            org=self.org,
                            tool_output_dict={"js_assets": js_assets_list}
                        )

                        logging.info(f"[JS_ASSET] Processed: {js_asset}")
                        logging.info(f"  ↳ IPs: {ips}")
                        logging.info(f"  ↳ Emails: {emails}")
                        logging.info(f"  ↳ APIs: {apis}")

                    await process_js_file(js_asset, js_content, current_asset, asset)

                    try:
                        os.remove(file_path)
                        logging.info(f"Deleted file: {file_path}")
                    except Exception as e:
                        logging.warning(f"Could not delete file {file_path}: {e}")

            return []

        except Exception as e:
            logging.error(f"Something went wrong in JShashtra: {e}")
            return []

        return super().base_get_commands(self.js_assets)
