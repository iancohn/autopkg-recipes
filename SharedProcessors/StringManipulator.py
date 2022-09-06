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

from distutils.filelist import findall
from autopkglib import Processor, ProcessorError, UrlGetter
import re,json

ACTION_TYPE_OPTIONS = [
	"replace",
	"split",
	"loop",
	"concatenate",
	"match",
	"retrieve_url",
	"format"
]

MASTER_SCHEMA = {
	""
}


OBJECT_SCHEMAS = {
	"action": {
		"action_type": "replace",#enum
		"action_input_var": "var",#string
		"action_output_var": "var",#string
		"arguments": {
			#arguments object schema depends on action_type enum value
		}
	},
	"replace_arguments": {
		"replacements": [
			{
				"find_text": "a string to find",
				"replace_text": "replace it with this.",
				"replace_all": True
			},
			{
				"find_text": "a string to find",
				"replace_text": "replace it with this.",
				"replace_all": True
			}
		]
	}

}



REPLACE_ACTION_SAMPLE = {
	"action_input_var": "input",
	"action_type": "replace",
	"action_output_var": "output",
	"arguments": {
		"replacements": [
			{
				"find_text": "a string to find",
				"replace_text": "replace it with this.",
				"replace_all": True
			}
		]
	}
}
SPLIT_ACTION_SAMPLE = {
	"action_input_var": "input",
	"action_type": "split",
	"action_output_var": "output",
	"arguments": {
		"split_on_text": ","
	}
}
LOOP_ACTION_SAMPLE = {
	"action_input_var": "input",
	"action_type": "loop",
	"action_output_var": "output",
	"arguments": {
		
	}
}
CONCATENATE_ACTION_SAMPLE = {
	"action_input_var": "input",
	"action_type": "concatenate",
	"action_output_var": "output",
	"arguments": {
		"concatenate_with_text": ""
	}
}
MATCH_ACTION_SAMPLE = {
	"action_input_var": "input/item",
	"action_type": "match",
	"action_output_var": "output",
	"arguments": {
		"re_pattern": "",
		"re_flags": [],
		"find_all": True
	}
}

#> sudo /Library/AutoPkg/Python3/Python.framework/Versions/Current/bin/python3 -m pip install --target=/Library/AutoPkg/Python3/Python.framework/Versions/Current/lib/python3.7/site-packages/ --ignore-installed signify
__all__ = ["StringManipulator"]

class StringManipulator(UrlGetter):
	description = "Parse, manipulate, and return a string"
	input_variables = {
		"manipulation_actions": {
			"required": True,
			"default": [],
			"description": (
				"An array of dictionaries representing the actions to take on a string"
			)
		}
}
	output_variables = {
        'file_size': {"description": "The size of the file."}
    }

	__doc__ = description

	def main(self):
		print('something')


if __name__ == "__main__":
	PROCESSOR = StringManipulator()
	PROCESSOR.execute_shell()
