from mantis.constants import ASSET_TYPE_SUBDOMAIN
from mantis.utils.common_utils import CommonUtils
from mantis.utils.crud_utils import CrudUtils
from mantis.tool_base_classes.toolScanner import ToolScanner
from mantis.models.args_model import ArgsModel
from mantis import constants
from mantis.utils.tool_utils import get_assets_grouped_by_type, get_assets_with_non_empty_fields, \
    get_assets_with_empty_fields
import json
import logging

class Katana(ToolScanner):

    def __init__(self) -> None:
        super().__init__()

    async def get_commands(self, args: ArgsModel):
        self.org = args.org
        self.base_command = "katana -u {input_domain} -kf robotstxt,sitemapxml | grep '.js$' > {output_file_path}"
        # self.base_command = 'katana -u {input_domain} -d 5 -jc -jsl -kf robotstxt,sitemapxml -hl -o {output_file_path}'
        self.outfile_extension = ".txt"
        self.assets = await get_assets_with_non_empty_fields(self, args, "active_hosts")
        for every_asset in self.assets:
            if "_id" in every_asset:
                domain = every_asset["_id"]
                # Filter out hosts ending with :443, keep all others
                filtered_hosts = [
                    host for host in every_asset["active_hosts"][0]
                    if not host.endswith(":443")
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

    def parse_report(self, outfile):
        tool_output_dict = {}

        js = []
        with open(outfile) as f:
            for line in f:
                filename = line.strip()
                if filename:
                    js.append(filename)

        tool_output_dict['js_assets'] = js
        return tool_output_dict

    async def db_operations(self, tool_output_dict, asset):
        await CrudUtils.update_asset(asset=asset, org=self.org, tool_output_dict=tool_output_dict)