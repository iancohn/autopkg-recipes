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

from autopkglib import Processor, ProcessorError
from signify import authenticode,exceptions,fingerprinter,x509,pkcs7
import re,json


#> sudo /Library/AutoPkg/Python3/Python.framework/Versions/Current/bin/python3 -m pip install --target=/Library/AutoPkg/Python3/Python.framework/Versions/Current/lib/python3.7/site-packages/ --ignore-installed signify


__all__ = ["CodeSignatureVerifierPython"]

#Define Options
FORM_FACTOR_OPT = [
    "Desktop",
    "Laptop",
    "Tower",
    "AIO",
    "Small",
    "Mini",
    ""
]

#Define Defaults
DEFAULT_FF = "Desktop"

class WindowsCodeSignatureVerifier(Processor):
	description = "Provides code signature verification for (primarily) windows binary files (.cat, .exe, .msi, .ps1, .dll)"
	input_variables = {
		"DISABLE_CODE_SIGNATURE_VERIFICATION": {
			"required": False,
			"description": (
				"Skip this Processor step altogether. Typically this "
				"would be invoked using AutoPkg's defaults or via '--key' "
				"CLI options at the time of the run, rather than being "
				"defined explicitly within a recipe."
			),
		},
		"input_path": {
			"required": True,
			"description": (
				"The path to the file to examine for code signature verification."
			),
		},
		"expected_authority_names": {
			"required": False,
			"description": (
				"An array of strings defining a list of expected certificate "
				"authority names. Complete list of the certificate name chain "
				"is required and it needs to be in the correct order. These "
				"can be determined by using a utility like Virus Total: "
			),
		},
		"deep_verification": {
			"required": False,
			"description": (
				"Boolean value to specify that any nested code content will be "
				"recursively verified as to its full content. Note that this option "
				"is ignored if the current system version is less than 10.9."
			),
		},
		"strict_verification": {
			"required": False,
			"description": (
				"Boolean value to control the strictness of signature validation. "
				"If not defined, codesign defaults are used. Note that this option "
				"is ignored if the current system version is less than 10.11."
			),
		}
	}

	output_variables = {
	}

	__doc__ = description

	def main(self):
		self.output("")

if __name__ == "__main__":
	PROCESSOR = CodeSignatureVerifierPython()
	PROCESSOR.execute_shell()
