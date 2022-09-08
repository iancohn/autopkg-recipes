#!/usr/bin/python3
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

from inspect import _void
from autopkglib import ProcessorError,Processor,URLTextSearcher
import re,json

__all__ = ["CVEScoreGetter"]

NVD_SEARCH_URL_BASE = "https://nvd.nist.gov/vuln/detail/"
NVD_SEARCH_PATTERN = ''
CVSS_VERSION_OPTS = ["v3,v2"]
CVSS_VERSION_DEFAULT = "v3"

class CVEScoreGetter(URLTextSearcher):
	"""Search the National Vulnerability Database for provided CVEs, return the maximum score and corresponding rating category."""

	description = __doc__

	input_variables = {
		"cves": {
			"required": True,
			"description": (
				"A list of CVEs (delimit with commas) to search nvd.nist.gov for."
			)
		},
		"cvss_version": {
			"required": False,
			"description": "CVSS version to use in risk calculation. Options: {}".format(CVSS_VERSION_OPTS),
			"default": CVSS_VERSION_DEFAULT
		}
	}
	output_variables = {
        "maximum_cve_score": {"description": "The maximum score returned for the list of CVEs."},
		"maximum_cve_rating": {"description": "The rating (critical/medium/etc.) corresponding to the returned maximum_cve_score"}
    }
	
	def split_cves(self,cves:str) ->list:
		trimmed = []
		for s in cves.split(','):
			trimmed.append(s.strip())

		return trimmed

	def get_cve_score(self,cve:str) ->dict:
		score = {}
		cvssVersion = self.env.get("cvss_version", self.env["input_variables"]["cvss_version"]["default"])
		url = NVD_SEARCH_URL_BASE + cve

		html = self.download(url, Text=True)
		pattern = "\\\"severityDetail\\\"[\s\S]*?{}\-calculator[\s\S]*?((?P<risk_score>[\d\.]*)\s+(?P<risk_rating>\w*))\<\/a\>".format(cvssVersion)
		rePattern = re.compile('', re.I)
		myMatch = rePattern.search(html)
		score = myMatch.groupdict()

		return score

	def main(self):
				
		cveString = self.env.get("cves")
		cves = self.split_cves(cves)

		scores = []
		try:
			for cve in cves:
				score = self.get_cve_score(cve)
				scores.append(score)

			scores.sort(key="risk_score", reverse=True)
			topCveScore = scores[0]

			self.env["maximum_cve_score"] = topCveScore["risk_score"]
			self.env["maximum_cve_rating"] = topCveScore["risk_rating"]

			self.output("{}: {}".format(outputVarName,self.env[outputVarName]),verbose_level=3)

		except Exception as e:
			raise ProcessorError(e)
		
		self.output("Completed string manipulations.",verbose_level=2)

		
if __name__ == "__main__":
	PROCESSOR = CVEScoreGetter()
	PROCESSOR.execute_shell()
