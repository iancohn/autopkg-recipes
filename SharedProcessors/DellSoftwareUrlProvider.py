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

from autopkglib import Processor, ProcessorError, URLGetter
import json
import re

DELL_BASE_URL = "https://www.dell.com/support/driver/en-us/ips/api/driverlist/fetchdriversbyproduct?"
# productcode=precision-17-7760-laptop
# &oscode=WT64A
# X-Requested-With : XMLHttpRequest
__all__ = ["DellSoftwareUrlProvider"]

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
PRODUCT_FAMILY_OPT = [
    "Precision",
    "Optiplex",
    "Latitude",
    "XPS"
]
CATEGORY_OPT = [
    "AP", #Application
    "AU", #Audio
    "BI", #BIOS
    "CM", #Modem/Communications
    "CS", #Chipset
    "DK", #Docks/Stands
    "DP", #Dell Data Security
    "IN", #Mouse, Keyboard & Input Devices
    "NI", #Network, Ethernet & Wireless
    "SM", #Systems Management
    "ST", #Storage
    "SY", #Security
    "TDS", #Trusted Device Security
    "VI" #Video,
    ""
]
FILE_TYPE_OPT = [
    "BEW",  #CPG BIOS Executable for Windows/DOS
    "CUG",  #A zip file or cab file containing the users guide in HTML
    "LW64", #Update Package for MS Windows 64-Bit.
    "LWXP", #Update Package for MS Windows 32-Bit
    "SAE",  #An application
    "SEZ"   #Extracts files directly to local disk
]

#Define Defaults
DEFAULT_FF = "Desktop"
DEFAULT_FAM = "Optiplex"
DEFAULT_CAT = "BI"
DEFAULT_MODEL = "5000"
DEFAULT_FILE_TYPE = "BEW"
DEFAULT_RE = ".*"

class DellSoftwareUrlProvider(URLGetter):
    """Use Dell Driver Fetch API to retrieve software product download url"""
    description = "Provides a download url and file metadata for Dell software packages."
    input_variables = {
        "OS_CODE": {
            "required": False,
            "default": "WT64A",
            "description": "The OS Code to download the package for."
        },
        "PRODUCT_CODE_OVERRIDE": {
            "required": False,
            "description": (
                "The product code to use, if the product code does not "
                "conform to the standard of [family]-[model]-[form factor]"
            )
        },
        "FAMILY": {
            "required": True,
            "default": "Optiplex",
            "description": (
                "The product family to use when searching Dell's downloads."
                "Options: {}".format(PRODUCT_FAMILY_OPT)
            )
        },
        "MODEL": {
            "required": True,
            "default": "5000",
            "description": "The Model number (or name) to used for searching packages."
        },
        "FORM_FACTOR": {
            "required": False,
            "default": DEFAULT_FF,
            "description": (
                "The Form Factor of the system used for searching packages. "
                "Options: {}".format(FORM_FACTOR_OPT)
            )
        },        
        "CATEGORY": {
            "required": True,
            "default": DEFAULT_CAT,
            "description": (
                "The category code of the software."
                "Options: {}".format(CATEGORY_OPT)
            )
        },
        "FILE_TYPE": {
            "required": True,
            "default": DEFAULT_FILE_TYPE,
            "description": (
                "The code for the file type to download."
                "Options: {}".format(FILE_TYPE_OPT)
            )
        },
        "DRIVER_NAME_RE_PATTERN": {
            "required": False,
            "default": DEFAULT_RE,
            "description": "A RegEx pattern to use to match the Driver Name against."
        }
    }
    output_variables = {
        "DriverId": {"description": "The unique identifier assigned to the product by Dell."},
        "DriverName": {"description": "The friendly name of the driver."},
        "Type": {"description": "The driver type."},
        "TypeName": {"description": "The driver type name"},
        "Importance": {"description": "The importance/severity of the release."},
        "ImportanceId": {"description": "The importance/severity of the release expressed as an int."},
        "ReleaseDate": {"description": "The release date of the product."},
        "RequiresRestart": {"description": "Whether the software requires a restart to complete successfully."},
        "DellVersion": {"description": "The version of the product according to Dell."},
        "Version": {"description": "A more standard version of the version."},
        "VersionFriendly": {"description": "The version of the product as its friendly version (ex. A10)."},
        "DellDescription": {"description": "Dell's description of the product."},
        "url": {"description": "The download url for the product."},
        "CatName": {"description": "The category name of the product."},
        "FileId": {"description": "The numerical id of the download file."},
        "FileName": {"description": "The name of the file."},
        "FileFormatName": {"description": "The format of the file."},
        "FileSize": {"description": "The size of the file in bytes."},
        "ConvertedFileSize": {"description": "The size of the file as the largest, easily readable size."}
    }

    __doc__ = description

    def main(self):
        headers = {
            "X-Requested-With": "XMLHttpRequest", 
            "Accept": "application/json"
        }
        osCode = self.env.get("OS_CODE", self.input_variables["OS_CODE"]["default"])
        family = self.env.get("FAMILY", self.input_variables["FAMILY"]["default"])
        model = self.env.get("MODEL", self.input_variables["MODEL"]["default"])
        formFactor = self.env.get("FORM_FACTOR", self.input_variables["FORM_FACTOR"]["default"])
        if self.env.get("PRODUCT_CODE_OVERRIDE") == None:
            PRODUCT_CODE_OVERRIDE = ""
        
        productCode = self.env.get(
            "PRODUCT_CODE_OVERRIDE",
            "{}-{}-{}".format(family,model,formFactor)
        )
        category = self.env.get("CATEGORY", self.input_variables["CATEGORY"]["default"])
        fileType = self.env.get("FILE_TYPE", self.input_variables["FILE_TYPE"]["default"])
        rePattern = self.env.get("DRIVER_NAME_RE_PATTERN", self.input_variables["DRIVER_NAME_RE_PATTERN"]["default"])
        baseUrl = self.env.get("DELL_BASE_URL",DELL_BASE_URL)
        if self.env.get("FORM_FACTOR") >= "":
            formFactor = self.env.get("FORM_FACTOR")
        else:
            self.output("Form Factor not set. Skipping.")

        self.output("Constructing URL", verbose_level=3)
        driverSearchUrl = (
            baseUrl + 
            "productCode={}".format(str(productCode)) +
            "&oscode={}".format(str(osCode))
        )

        self.output("Retrieving software products from Dell URL ({})".format(driverSearchUrl), verbose_level=3)

        try:
            blob = self.download(driverSearchUrl, text=True, headers=headers)
            softwares = json.loads(blob)
            self.output("Retrieved {} packages for Dell product with code: {}".format(len(softwares["DriverListData"]),softwares["ProductCode"]),verbose_level=3)
        # Select array item by product name
            selected_products = []
            for product in softwares["DriverListData"]:
                self.output("Desired Type: {}\t\tFound Type:{}".format(fileType,product["Type"]),verbose_level=4)
                if (
                    product["FileFrmtInfo"]["FileType"] == fileType and
                    2 == 2
                ):
                    selected_product += product
                    continue
                else:
                    self.output("File Type does not match",verbose_level=4)
            
            self.output("Selected product {}".format(selected_product["DriverName"]))
            asdfasdf
        # Select Architecture and and Platform
            releases = []
            for release in selected_product:
                if ((release["Platform"] == platform ) and (release["Architecture"] == architecture)):
                    releases.append(release)
        # Sort releases, and select latest released
            latest_release = sorted(releases, key=lambda x: x["PublishedTime"], reverse=True )[0]
            url = latest_release["Artifacts"][0]["Location"]
            version = latest_release["ProductVersion"]
            installer_version = platform + "-" + architecture + "-v" + latest_release["ProductVersion"] + "-"+ product
            installer_type = latest_release["Artifacts"][0]["ArtifactName"]
            Hash = latest_release["Artifacts"][0]["Hash"]
            HashAlgorithm = latest_release["Artifacts"][0]["HashAlgorithm"]
            SizeInBytes = latest_release["Artifacts"][0]["SizeInBytes"]
            PublishedTime = latest_release["PublishedTime"]
        except Exception as e:
            self.output("Unexpected JSON encountered.")
            raise e

        # Return Values
        self.env["url"] = url
        self.env["version"] = version
        self.env["installer_version"] = installer_version
        self.env["Hash"] = Hash
        self.env["HashAlgorithm"] = HashAlgorithm
        self.env["SizeInBytes"] = SizeInBytes
        self.env["installer_type"] = installer_type
        self.env["PublishedTime"] = PublishedTime

if __name__ == "__main__":
    PROCESSOR = DellSoftwareUrlProvider()
    PROCESSOR.execute_shell()
