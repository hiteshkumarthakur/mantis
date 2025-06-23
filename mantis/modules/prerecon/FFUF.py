from mantis.constants import ASSET_TYPE_SUBDOMAIN
from mantis.utils.common_utils import CommonUtils
from mantis.utils.crud_utils import CrudUtils
from mantis.tool_base_classes.toolScanner import ToolScanner
from mantis.models.args_model import ArgsModel
from mantis import constants
from mantis.utils.tool_utils import get_assets_grouped_by_type, get_assets_with_non_empty_fields, \
    get_assets_with_empty_fields
import json
import os
import logging

class FFUF(ToolScanner):

    def __init__(self) -> None:
        super().__init__()

    def ensure_http_prefix(self, domain):
        if not domain.startswith("http://") and not domain.startswith("https://"):
            return "http://" + domain
        return domain

    async def get_commands(self, args: ArgsModel):
        self.org = args.org
        self.base_command = "ffuf -u http://{input_domain}/FUZZ -w /var/tmp/raft-large-directories-lowercase.txt -of json -o {output_file_path} t 50 -mc 200,204,403"
        self.outfile_extension = ".json"
        self.assets = await get_assets_grouped_by_type(self, args, ASSET_TYPE_SUBDOMAIN)
        # Ensure all input domains have http:// prefix
        # for i, asset in enumerate(self.assets):
        #     if isinstance(asset, dict):
        #         asset['input_domain'] = self.ensure_http_prefix(asset['input_domain'])
        #     elif isinstance(asset, str):
        #         self.assets[i] = self.ensure_http_prefix(asset)
        return super().base_get_commands(self.assets)

    def parse_report(self, outfile):
        tool_output_dict = {}
        content_discovery = {}

        if not os.path.exists(outfile):
            logging.warning(f"FFUF output file not found: {outfile}")
            return tool_output_dict

        try:
            with open(outfile, "r") as f:
                data = json.load(f)
                for result in data.get("results", []):
                    url = result.get("url")
                    status = result.get("status")
                    if url and status:
                        content_discovery[url] = status
        except json.JSONDecodeError:
            logging.error(f"Could not parse FFUF output: {outfile}")
            return tool_output_dict

        tool_output_dict["content_discovery"] = content_discovery
        return tool_output_dict

    async def db_operations(self, tool_output_dict, asset):
        await CrudUtils.update_asset(asset=asset, org=self.org, tool_output_dict=tool_output_dict)