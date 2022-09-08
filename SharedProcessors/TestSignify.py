from signify import authenticode,exceptions,fingerprinter,x509,pkcs7
from os import path
import re,json
import time


print(time.ctime())

test_msi_path = "/Users/icc/Downloads/Teams_windows_x64.msi"
test_exe_path = "/Users/icc/Downloads/horizonagents.exe"
test_dll_path = "/Users/icc/Library/AutoPkg/Cache/com.github.iancohn.download.DellCommandPSProvider-Win64/PSProvider/DellBIOSProvider/DellBIOSProvider.dll"
test_ps1_path = "/Users/icc/Library/AutoPkg/Cache/com.github.iancohn.download.DellCommandPSProvider-Win64/PSProvider/DellBIOSProvider/Clear-DellAdminPassword.ps1"

paths = [
#	test_msi_path,
	#test_dll_path, #works
	test_ps1_path,
	#test_exe_path #works
]

for p in paths:
	print("Working on {}".format(p))
	with open(p, "rb") as f:
		pefile = authenticode.SignedPEFile(f)
		for signed_data in pefile.signed_datas:
			print("Certificates:::")
			for cert in signed_data.certificates:
				print("      - Subject: {}".format(cert.subject.dn))
				print("        Issuer: {}".format(cert.issuer.dn))
				print("        Serial: {}".format(cert.serial_number))
				print("        Valid from: {}".format(cert.valid_from))
				print("        Valid to: {}".format(cert.valid_to))
				print("    Signer:")
				print("        Issuer: {}".format(signed_data.signer_info.issuer.dn))
				print("        Serial: {}".format(signed_data.signer_info.serial_number))
				print("        Program name: {}".format(signed_data.signer_info.program_name))
				print("        More info: {}".format(signed_data.signer_info.more_info))

				if signed_data.signer_info.countersigner:
					print()
					if hasattr(signed_data.signer_info.countersigner, 'issuer'):
						print("    Countersigner:")
						print("        Issuer: {}".format(signed_data.signer_info.countersigner.issuer.dn))
						print("        Serial: {}".format(signed_data.signer_info.countersigner.serial_number))
					if hasattr(signed_data.signer_info.countersigner, 'signer_info'):
						print("    Countersigner (nested RFC3161):")
						print("        Issuer: {}".format(
							signed_data.signer_info.countersigner.signer_info.issuer.dn
						))
						print("        Serial: {}".format(
							signed_data.signer_info.countersigner.signer_info.serial_number
						))
					print("        Signing time: {}".format(signed_data.signer_info.countersigner.signing_time))

					if hasattr(signed_data.signer_info.countersigner, 'certificates'):
						print("        Included certificates:")
						for cert in signed_data.signer_info.countersigner.certificates:
							print("          - Subject: {}".format(cert.subject.dn))
							print("            Issuer: {}".format(cert.issuer.dn))
							print("            Serial: {}".format(cert.serial_number))
							print("            Valid from: {}".format(cert.valid_from))
							print("            Valid to: {}".format(cert.valid_to))

				print()
				print("    Digest algorithm: {}".format(signed_data.digest_algorithm.__name__))
				print("    Digest: {}".format(signed_data.spc_info.digest.hex()))

				print()

				result, e = signed_data.explain_verify()
				print("    {}".format(result))
				if e:
					print("    {}".format(e))
				print("--------")
	



