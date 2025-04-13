from mantis.constants import ASSET_TYPE_SUBDOMAIN
from mantis.utils.common_utils import CommonUtils
from mantis.utils.crud_utils import CrudUtils
from mantis.tool_base_classes.toolScanner import ToolScanner
from mantis.models.args_model import ArgsModel
from mantis.utils.tool_utils import get_assets_grouped_by_type, get_assets_with_non_empty_fields, \
    get_assets_with_empty_fields
import json
import logging

class Gau_JS(ToolScanner):

    def __init__(self) -> None:
        super().__init__()

    async def get_commands(self, args: ArgsModel):
        self.org = args.org
        self.base_command = "gau {input_domain} --fc 404 --threads 5 | grep '.js$' > {output_file_path}"
        self.outfile_extension = ".txt"
        self.assets = await get_assets_grouped_by_type(self, args, ASSET_TYPE_SUBDOMAIN)
        return super().base_get_commands(self.assets)

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