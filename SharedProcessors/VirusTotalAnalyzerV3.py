#!/usr/local/autopkg/python
#
# Copyright 2022 Ian Cohn 
# https://www.github.com/iancohn
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#Factored for Python 3
from __future__ import absolute_import

import hashlib
import time

from autopkglib import Processor, ProcessorError, URLGetter
from os import path

__all__ = ["VirusTotalAnalyzerV3"]

VT_API_V3_BASE_URL = 'https://www.virustotal.com/api/v3'
DEFAULT_PAUSE_INTERVAL = 15 #Virus Total default rate limits at 4 requests per minute.

class VirusTotalAnalyzerV3(Processor):
	description = "Returns the size and shas of the indicated file"

	input_variables = {
        "file_path": {
            "required": False,
            "description": "The path to the file you wish to submit.",
			"default": "%pathname%"
        },
		"max_report_age_days": {
			"required": False,
			"description": (
				"Int representing the maximum age in days of the available report in VirusTotal. "
				"If the existing report is older than this value, the file/url will be rescanned. "
				"A value of 0 will effectively force a rescan."
			)
		},
		"pause_interval": {
			"required": False,
			"description": "Number of seconds to wait between requests to the Virus Total api to avoid rate limiting.",
			"default": DEFAULT_PAUSE_INTERVAL
		}
    }
	output_variables = {}

	__doc__ = description
	
	# Set Variables
	apiKey = self.env.get("VIRUSTOTAL_API_KEY")
	downloadDictPath = self.env.get("pathname") + ".info.json"
	filePath = self.env.get("file_path", self.env.get("pathname"))
	if apiKey > '':
		self.output('API Key retrieved.', verbose_level=3)
	else:
		raise ProcessorError("API Key not found. Cannot continue.")
	if path.exists(downloadDictPath) == False:
		self.output("Download Dictionary does not exist. Hashes will be computed.")

	try:
		# Check file size, get submission url
		fileSize = int(path.getsize(filePath))
		if fileSize < 33554432:
			self.output("File size is less than 32MB, using default file submission endpoint", verbose_level=2)
			submissionUrl = VT_API_V3_BASE_URL + "/files"
		elif fileSize < 524288000:
			self.output("File size is greater than ")
			submissionUrl = self.download()
		else:
			raise ProcessorError(
				"File size is too large for Virus Total. If this is a compressed archive, "
				"consider submitting enclosed files individually."
			)

		# 
		self.download(driverSearchUrl, text=True, headers=headers)


	except Exception as e:
		raise e

	


if __name__ == "__main__":
    PROCESSOR = VirusTotalAnalyzerV3()
    PROCESSOR.execute_shell()
