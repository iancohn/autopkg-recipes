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
from autopkglib import Processor, ProcessorError, URLGetter
from os import getsize
import hashlib


__all__ = ["GetFileStatistics"]

SHA_ALGORITM_OPT = [
	'shake_256',
    'sha3_384',
    'sha512',
    'blake2s',
    'sha1',
    'sha3_512',
    'shake_128',
    'sha3_224',
    'sha256',
    'sha3_256',
    'sha384',
    'blake2b',
    'md5',
    'sha224'
]

class GetFileStatistics(Processor):
    description = "Returns the size and shas of the indicated file"
    input_variables = {
        "file_path": {
            "required": True,
            "description": "Defaults to %pathname%."
        },
        "sha_algorithms": {
            "required": False,
            "default": ["sha1", "sha256", "md5"],
            "description": (
                "An array of strings representing hashing algorithms to return"
                "Options: {}".format(SHA_ALGORITM_OPT)
            )
        }
    }
    output_variables = {
        "DriverId": {"description": "The unique identifier assigned to the product by Dell."}
    }

    __doc__ = description

    def main(self):
        chunkSize = int(65536)
        shaAlgorithms = self.env.get("sha_algorithms", self.input_variables["sha_algorithms"]["default"])
        filePath = self.env.get("file_path", self.env.get("pathname"))

        try:
            self.env['file_size'] = getsize(filePath)
            fileBlob = open(filePath, 'rb').read(chunkSize)
            algorithmOptions = {
                'shake_256': hashlib.shake_256,
                'sha3_384': hashlib.sha3_384,
                'sha512': hashlib.sha512,
                'blake2s': hashlib.blake2s,
                'sha1': hashlib.sha1,
                'sha3_512': hashlib.sha3_512,
                'shake_128': hashlib.shake_128,
                'sha3_224': hashlib.sha3_224,
                'sha256': hashlib.sha256,
                'sha3_256': hashlib.sha3_256,
                'sha384': hashlib.sha384,
                'blake2b': hashlib.blake2b,
                'md5': hashlib.md5,
                'sha224': hashlib.sha224
            }
            for alg in shaAlgorithms:
                if alg in SHA_ALGORITM_OPT:
                    hash = algorithmOptions[alg]()
                    hash.update(fileBlob)
                    self.env[alg + '_result'] = hash.hexdigest()
                    del hash
                else:
                    self.output("Algorithm ({}) is not supported. Skipping.".format(alg), verbose_level=2)

        except Exception as e:
            self.output("Failed to retrieve hashing algorithm results.")
            raise e

if __name__ == "__main__":
    PROCESSOR = GetFileStatistics()
    PROCESSOR.execute_shell()
