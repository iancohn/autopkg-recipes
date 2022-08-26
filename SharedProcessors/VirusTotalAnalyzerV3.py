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
		"vt_type_description": {"description": "Returned from Virus Total"},
		"vt_creation_date": {"description": "Returned from Virus Total"},
		"vt_signature_product": {"description": "Returned from Virus Total"},
		"vt_signature_verified": {"description": "Returned from Virus Total"},
		"vt_signature_description": {"description": "Returned from Virus Total"},
		"vt_signature_date": {"description": "Returned from Virus Total"},
		"vt_signature_status": {"description": "Returned from Virus Total"},
		"vt_signature_valid_usage": {"description": "Returned from Virus Total"},
		"vt_signature_name": {"description": "Returned from Virus Total"},
		"vt_signature_algorithm": {"description": "Returned from Virus Total"},
		"vt_signature_valid_from": {"description": "Returned from Virus Total"},
		"vt_signature_valid_to": {"description": "Returned from Virus Total"},
		"vt_signature_serial_number": {"description": "Returned from Virus Total"},
		"vt_signature_cert_issuer": {"description": "Returned from Virus Total"},
		"vt_signature_thumbprint": {"description": "Returned from Virus Total"}
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

	def calculate_sha256(self, filePath:str) -> str:
		if (path.exists(filePath) and path.isfile(filePath)) == False:
			raise ProcessorError("File ({}) does not exist".format(filePath))
	
		self.output("Calculating the sha256.", verbose_level=3)
		blockSize = int(65536)
		hasher = hashlib.sha256()
		with open(filePath, 'rb') as fileBlob:
			buffer = fileBlob.read(blockSize)
			while len(buffer) > 0:
				hasher.update(buffer)
				buffer = fileBlob.read(blockSize)

		sha256 = hasher.hexdigest()
		self.output("Calculated SHA256: {}".format(sha256),verbose_level=3)
		return sha256

	def get_min_scan_date(self,maxReportAge:int) -> int:
		sMaxAge = maxReportAge*24*60*60
		nowEpoch = int(time.mktime(time.gmtime()))
		maxAgeEpoch = nowEpoch - sMaxAge

		return maxAgeEpoch

	def main(self):
		# Set Variables
		apiKey = self.env.get("VIRUSTOTAL_API_KEY")
		pauseInterval = self.get_pause_interval()
		maxRetry = 3 #int(self.env.get("max_retry_attempts"), self["input_variables"]["max_retry_attempts"]["default"])
		maxAgeDays = 1 #int(self.env.get("max_report_age_days"), self["input_variables"]["max_report_age_days"]["default"])
		filePath = "/Users/icc/Library/AutoPkg/Cache/com.github.iancohn.download.DellSupportAssist-Win64/downloads/Dell-SupportAssist-OS-Recovery-Plugin-for-Dell-Update_RH18Y_WIN_5.5.1.16143_A00.EXE"#self.env.get("file_path", self.env.get("pathname"))

		sha = self.calculate_sha256(filePath)
		minTimeEpoch = self.get_min_scan_date(maxAgeDays)

		if apiKey > '':
			self.output('API Key retrieved.', verbose_level=3)
		else:
			raise ProcessorError("API Key not found. Cannot continue.")

		try:
		# Search for sha
			searchUrl = VT_API_V3_BASE_URL + "/search?query={}".format(sha)
			curl_cmd = (
				self.curl_binary(),
				"--url",
				searchUrl,
				"-H",
				"X-apikey: {}".format(apiKey),
				"-H",
				"Accept: application/json"#,
				#"-H",
				#"Content-Type: multipart/form-data",
				#"--form",
				#"file=@{}".format(filePath)
			)
			queryResponse = self.download_with_curl(curl_cmd)
			jsonResponse = json.loads(queryResponse)

		# If not exists or last scan is too old
			if len(jsonResponse["data"]) != 1 or \
			((queryResponse["data"]["attributes"]["date"] < minTimeEpoch) == False):
			# Submit File
				self.output("File does not exist in Virus Total, or there are ambiguous results. Beginning upload process now.", verbose_level=1)
				fileSize = int(path.getsize(filePath))

				if fileSize < 33554432:
					self.output("File size is less than 32MB, using default file submission endpoint", verbose_level=2)
					submissionUrl = VT_API_V3_BASE_URL + "/files"
				elif fileSize < 419430400:
					self.output("Getting file submission url.", verbose_level=3)
				elif fileSize < 524288000:
					self.output(
						"Warning: File size is > 400 MB. If this is a compressed "
						"archive, consider extracting and submitting files individually. ",
						verbose_level=1
					)
					self.output("Getting file submission url.", verbose_level=3)
				else:
					raise ProcessorError(
						"File size is too large for Virus Total. If this is a compressed archive, "
						"consider submitting enclosed files individually."
					)
				if submissionUrl == None:
					curlSubmissionUrl = (
						self.curl_binary(),
						"--url",
						VT_API_V3_BASE_URL + '/files/upload_url',
						"-H",
						"X-apikey: {}".format(apiKey),
						"-H",
						"Accept: application/json"
				)
					time.sleep(pauseInterval)
					submissionUrlResponse = self.download_with_curl(curlSubmissionUrl)
					jsUrl = json.loads(submissionUrlResponse)
					submissionUrl = jsUrl["data"]

				curlSubmitFile = (
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
				analysisResponse = self.download_with_curl(curlSubmitFile)
				jsAnalysis = json.loads(analysisResponse)
				analysisId = jsAnalysis["data"]["id"]
			# Wait on file up to the max number of retries, return report.
				attempts = maxRetry
				curlCheckAnalysis = (
					self.curl_binary(),
					"--url",
					(VT_API_V3_BASE_URL + "/analyses/" + analysisId),
					"-H",
					"X-apikey: {}".format(apiKey),
					"-H",
					"Accept: application/json"
				)

				while ((maxRetry == 0) or (attempts > 0)) and \
				(status != 'completed'):
					self.output("Pausing to avoid rate limiting.", verbose_level=3)
					time.sleep(pauseInterval)
					self.output("Checking Virus Total analysis status. Attemp {}.".format(attempts), verbose_level=3)
					analysis = self.download_with_curl(curlCheckAnalysis)
					jsStatus = json.loads(analysis)
					del analysis
					status = jsStatus["data"]["attributes"]["status"]
					attempts -= 1

				self.output("Analysis status: {}".format(status))
			# Return results
				detailsUrl = jsStatus["data"]["links"]["item"]
			
				curlDetails = (
					self.curl_binary(),
					"--url",
					detailsUrl,
					"-H",
					"X-apikey: {}".format(apiKey),
					"-H",
					"Accept: application/json"
				)
				detailsResponse = self.download_with_curl(curlDetails)
				jsDetails = json.loads(detailsResponse)
				data = jsDetails["data"]

		# Else return results
			else:
				data = jsonResponse["data"]


			signInfo = data["attributes"]["signature_info"]
			signersDetails = signInfo["signers details"][0]
			self.env["vt_type_description"] = jsDetails["data"]["attributes"]["type_description"]
			self.env["vt_creation_date"] = jsDetails["data"]["attributes"]["creation_date"]
			self.env["vt_signature_product"] = signInfo["product"]
			self.env["vt_signature_verified"] = signInfo["verified"]
			self.env["vt_signature_description"] = signInfo["description"]
			self.env["vt_signature_date"] = signInfo["signing date"]
			self.env["vt_signature_status"] = signersDetails["status"]
			self.env["vt_signature_valid_usage"] = signersDetails["valid usage"]
			self.env["vt_signature_name"] = signersDetails["name"]
			self.env["vt_signature_algorithm"] = signersDetails["algorithm"]
			self.env["vt_signature_valid_from"] = signersDetails["valid from"]
			self.env["vt_signature_valid_to"] = signersDetails["valid to"]
			self.env["vt_signature_serial_number"] = signersDetails["serial number"]
			self.env["vt_signature_cert_issuer"] = signersDetails["cert issuer"]
			self.env["vt_signature_thumbprint"] = signersDetails["thumbprint"]

		except Exception as e:
			raise e
		

if __name__ == "__main__":
    PROCESSOR = VirusTotalAnalyzerV3()
    PROCESSOR.execute_shell()
