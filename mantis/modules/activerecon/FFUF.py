from mantis.constants import ASSET_TYPE_SUBDOMAIN
from mantis.utils.common_utils import CommonUtils
from mantis.utils.crud_utils import CrudUtils
from mantis.tool_base_classes.toolScanner import ToolScanner
from mantis.models.args_model import ArgsModel
from mantis.utils.tool_utils import get_assets_grouped_by_type, get_assets_with_non_empty_fields, \
    get_assets_with_empty_fields
import json
import os
import logging

class FFUF(ToolScanner):

    def __init__(self) -> None:
        super().__init__()
        super().download_required_file()
        self.wordlist = "configs/resources/raft-medium-directories.txt"


    async def get_commands(self, args: ArgsModel):
        self.org = args.org
        self.base_command = "ffuf -u https://{input_domain}/FUZZ -w configs/resources/raft-medium-directories.txt -of json -o {output_file_path} -recursion -ac"
        # self.base_command = "ffuf -u https://{input_domain}/FUZZ -w {wordlist} -of json -o {output_file_path} -ac"
        self.outfile_extension = ".json"
        self.assets = await get_assets_with_non_empty_fields(self, args, "active_hosts")
        # self.assets = await get_assets_grouped_by_type(self, args, ASSET_TYPE_SUBDOMAIN)

        for every_asset in self.assets:
            if "_id" in every_asset:
                domain = every_asset["_id"]
                # Filter out hosts
                filtered_hosts = [
                    host for host in every_asset["active_hosts"][0]
                    if not host.endswith(":80")
                ]
                for active_host in filtered_hosts:
                    outfile = CommonUtils.generate_unique_output_file_name(domain, self.outfile_extension)
                    command = self.base_command.format(input_domain=active_host, output_file_path=outfile)
                    self.commands_list.append((self, command, outfile, domain))
            else:
                outfile = CommonUtils.generate_unique_output_file_name(every_asset, self.outfile_extension)
                command = self.base_command.format(input_domain=every_asset, output_file_path=outfile)
                self.commands_list.append((self, command, outfile, every_asset))

        return self.commands_list
        # return super().base_get_commands(self.assets)

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