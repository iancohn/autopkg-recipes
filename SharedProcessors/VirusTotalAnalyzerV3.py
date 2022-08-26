#!/usr/bin/python
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
from bdb import Breakpoint
from sys import int_info
from autopkglib import Processor, ProcessorError,URLDownloader #, URLGetter
from os import path
from urllib.parse import urlparse

import hashlib
import time
import json

__all__ = ["VirusTotalAnalyzerV3"]

VT_API_V3_BASE_URL = 'https://www.virustotal.com/api/v3'
DEFAULT_PAUSE_INTERVAL = 15 #Virus Total default rate limits at 4 requests per minute.
DEFAULT_MAX_ATTEMPTS = 5
class VirusTotalAnalyzerV3(URLDownloader):
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
		},
		"max_retry_attempts": {
			"required": False,
			"description": "Number of times to attempt to retrieve Virus Total analysis results. Enter 0 to retry indefinitely.",
			"default": DEFAULT_MAX_ATTEMPTS
		}
    }
	output_variables = {
		"json": {
			"description": "json data"
		},
		"myVar": {"description": "myVar"}
	}

	__doc__ = description

	def get_pause_interval(self) -> int:
		try:
			s = self.env.get["pause_interval", self["input_variables"]["pause_interval"]["default"]]
			interval = int(s)
		except:
			interval = DEFAULT_PAUSE_INTERVAL
		finally:
			return interval

	def calculate_md5(self, filePath:str) -> str:
		if (path.exists(filePath) and path.isfile(filePath)) == False:
			raise ProcessorError("File ({}) does not exist".format(filePath))
	
		self.output("Calculating the md5 sum.", verbose_level=3)
		blockSize = int(65536)
		hasher = hashlib.md5()
		with open(filePath, 'rb') as fileBlob:
			buffer = fileBlob.read(blockSize)
			while len(buffer) > 0:
				hasher.update(buffer)
				buffer = fileBlob.read(blockSize)

		md5 = hasher.hexdigest()
		self.output("Calculated MD5: {}".format(md5),verbose_level=3)
		return md5

	def main(self):
		# Set Variables
		apiKey = self.env.get("VIRUSTOTAL_API_KEY")
		pauseInterval = self.get_pause_interval()
		filePath = "/Users/icc/Library/AutoPkg/Cache/com.github.iancohn.download.DellSupportAssist-Win64/downloads/Dell-SupportAssist-OS-Recovery-Plugin-for-Dell-Update_RH18Y_WIN_5.5.1.16143_A00.EXE"#self.env.get("file_path", self.env.get("pathname"))
		md5 = self.calculate_md5(filePath)
		self.env["myVar"] = md5
		return

		if apiKey > '':
			self.output('API Key retrieved.', verbose_level=3)
		else:
			raise ProcessorError("API Key not found. Cannot continue.")

		try:
			# Search for md5

			# If not exists or last scan is too old, submit file

				# Wait on file up to the max number of retries, return report.
				
				# Return results

			# Else return results

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
			curl_cmd = (
				self.curl_binary(),
				"--url",
				submissionUrl,
				"-H",
				"X-apikey: {}".format(apiKey),
				"-H",
				"Accept: application/json",
				"-H",
				"Content-Type: multipart/form-data",
				"--form",
				"file=@{}".format(filePath)
			)
			analysis = self.download_with_curl(curl_cmd)
			time.sleep(pauseInterval)
			
			self.env["json"] = response


		except Exception as e:
			raise e

if __name__ == "__main__":
    PROCESSOR = VirusTotalAnalyzerV3()
    PROCESSOR.execute_shell()
