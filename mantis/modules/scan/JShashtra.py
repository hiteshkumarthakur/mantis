import json
import logging
import subprocess
from mantis import constants
from mantis.utils.crud_utils import CrudUtils
from mantis.models.args_model import ArgsModel
from mantis.utils.common_utils import CommonUtils
from mantis.tool_base_classes.toolScanner import ToolScanner
from mantis.utils.tool_utils import get_assets_with_non_empty_fields
from mantis.config_parsers.config_client import ConfigProvider
from mantis.utils.base_request import BaseRequestExecutor
import os


'''
Jshastra module is used to scrape metadata around the JS files 
'''

class JShashtra(ToolScanner):
    def __init__(self) -> None:
        super().__init__()

    async def get_commands(self, args: ArgsModel):
        # Store args in the instance
        self.args = args
        self.org = args.org


       # Fetch JS assets
        try:
            logging.info(f"Fetching JS assets for org: {self.org}")
            self.js_assets = await get_assets_with_non_empty_fields(self, args, "js_assets")
            # logging.info(f"Fetched JS assets: {self.js_assets}")

            if not self.js_assets:
                logging.error(f"No JS assets found for org: {self.org}")
                return []

            # Flatten all js_assets into a single list
            all_js_assets = [url for item in self.js_assets for sublist in item['js_assets'] for url in sublist]



        except Exception as e:
            logging.error(f"Something went wrong in JShashtra: {e}")
            return []

        # Return the base commands with the fetched assets
        return super().base_get_commands(self.js_assets)

