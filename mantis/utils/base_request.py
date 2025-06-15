import os
import requests
import logging
from requests import Timeout
from retry import retry


class BaseRequestExecutor:

    TIMEOUT = 5

    @staticmethod
    @retry((ConnectionError, Timeout), delay=5, tries=5)
    def sendRequest(method, api_tuple, download_large_file=False, download_path=None):
        url, headers, body, asset = api_tuple
        session = requests.session()
        try:
            if method == "POST":
                if headers is not None:
                    response = session.post(url, data=body, headers=headers, timeout=BaseRequestExecutor.TIMEOUT, verify=True)
                else:
                    response = session.post(url, data=body, timeout=BaseRequestExecutor.TIMEOUT, verify=True)

                logging.debug(f"Response code for {url} : {response.status_code}, {response.request}")

                if response.status_code not in range(200, 299):
                    logging.warning(requests.exceptions.HTTPError(f"Request failed with status code {response.status_code}"))

                return (asset, response)

            elif method == "GET":
                if download_large_file and download_path:
                    # Handle large file download
                    with session.get(url, headers=headers, stream=True, timeout=BaseRequestExecutor.TIMEOUT) as response:
                        response.raise_for_status()
                        os.makedirs(os.path.dirname(download_path), exist_ok=True)
                        with open(download_path, "wb") as file:
                            for chunk in response.iter_content(chunk_size=1024 * 1024):  # 1 MB chunks
                                if chunk:
                                    file.write(chunk)
                        logging.info(f"File downloaded successfully to {download_path}")
                        return (asset, response)
                else:
                    if headers is not None:
                        response = session.get(url, headers=headers, verify=True, timeout=BaseRequestExecutor.TIMEOUT)
                    else:
                        response = session.get(url, verify=True, timeout=BaseRequestExecutor.TIMEOUT)

                    logging.debug(f"Response code for {url} : {response.status_code}, {response.request}")

                    if response.status_code not in range(200, 299):
                        logging.warning(requests.exceptions.HTTPError(f"Request failed with status code {response.status_code}"))

                    return (asset, response)
        except requests.exceptions.Timeout as e:
            logging.error(f"Error: HTTP Request Exception in {url} - {e}")
            raise
        except requests.exceptions.RequestException as e:
            logging.error(f"Error: HTTP Request Exception in {url} - {e}")
            raise