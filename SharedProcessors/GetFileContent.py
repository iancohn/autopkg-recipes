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

from autopkglib import ProcessorError,Processor,URLTextSearcher
from os import path
from inspect import _void
import json

__all__ = ["GetFileContent"]

CONTENT_TYPE_OPTIONS = [
	#"json",
	#"xml",
	#"binary_plist",
	"lines",
	"raw"
]
CONTENT_TYPE_DEFAULT = "raw"
OUTPUT_VAR_NAME_DEFAULT = "output"

class GetFileContent(Processor):
	"""Get the contents of a file."""

	description = __doc__

	input_variables = {
		"content_type": {
			"required": False,
			"description": ("The type of to use for the output variable type. Defaults to {}".format(CONTENT_TYPE_DEFAULT)),
			"default": CONTENT_TYPE_DEFAULT
		},
		"output_var_name": {
			"required": False,
			"description": ("The variable name to output the text as. Defaults to {}".format(OUTPUT_VAR_NAME_DEFAULT)),
			"default": OUTPUT_VAR_NAME_DEFAULT
		},
		"file_path":{
			"required": False,
			"description": ("The pathname of the file whose content this processor will get. Defaults to '%pathname%'")
		}
}
	output_variables = {
        
    }
	
	def replace_text(self,input_variable_name:str = 'output',output_variable_name:str = 'output', options:dict = {"replacements":[]})->_void:
		self.output("Getting input variable with name: {}".format(input_variable_name), verbose_level=3)
		myString = self.env.get(input_variable_name)
		replacements = options["replacements"]
		if len(replacements) == 0:
			raise(ProcessorError('No replacements indicated.'))
		else:
			self.output("{} replacements indicated".format(len(replacements)), verbose_level=3)
		
		for replacement in replacements:
			nStrings = replacement["replace_n"] or -1
			searchString = replacement["find_text"]
			replaceString = replacement["replace_text"]
			self.output("FINDING: {}\tREPLACE WITH: {}".format(searchString,replaceString), verbose_level=3)
			self.output("IN String: {}".format(myString),verbose_level=3)
			myString = myString.replace(searchString,replaceString,nStrings)
			self.output("OUT String: {}".format(myString),verbose_level=3)
			del nStrings,searchString,replaceString
		
		self.env[output_variable_name] = myString

	def get_lines(self,file_content:str) ->list:
		return file_content.splitlines()
	
	def get_raw(self,file_content:str) ->str:
		return file_content
	
	def main(self):
		contentType = self.env.get("content_type", self.input_variables["content_type"]["default"])
		outputVarName = self.env.get("output_var_name", self.input_variables["output_var_name"]["default"])
		filePath = self.env.get("file_path", self.env["pathname"]) or ""
		
		getContentFunctions = {
			"json": json.loads,
			#"xml": self.output_xml,
			#"binary_plist": self.output_plist,
			"lines": self.get_lines,
			"raw": self.get_raw
		}
		
		try:
			if path.isfile(filePath) == False:
				raise ProcessorError("file_path must be set to the full pathname for the file which whose contents you wish to get.")
			
			with open(filePath) as f:
				file = f.read()
			
			self.env[outputVarName] = getContentFunctions[contentType](file)

		except Exception as e:
			raise ProcessorError(e)
		
		self.output("Completed string manipulations.",verbose_level=2)

		
if __name__ == "__main__":
	PROCESSOR = GetFileContent()
	PROCESSOR.execute_shell()
