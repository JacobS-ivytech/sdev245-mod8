import re
import logging
import os
from pathlib import Path
import argparse

#patterns to check against
regex = {
    "Cloudflare API": re.compile("[A-Za-z0-9_\-]{40}"),
    "X Access Token": re.compile("[1-9][0-9]+-[0-9a-zA-Z]{40}"),
    "Instagram OAuth": re.compile("[0-9a-fA-F]{7}.[0-9a-fA-F]{32}"),
    "Google API Key": re.compile("AIza[0-9A-Za-z-_]{35}"),
    "Github Personal Access Token": re.compile("^ghp_[a-zA-Z0-9]{36}$"),
    "Shopify Admin API Token": re.compile("shpat_[a-fA-F0-9]{32}"),
    "Shopify Public Access Token": re.compile("shpca_[a-fA-F0-9]{32}"),
    "Shopify Private Access Token": re.compile("shppa_[a-fA-F0-9]{32}"),
    "Shopify App Secret Key": re.compile("shpss_[a-fA-F0-9]{32}"),
    "Square Access Token": re.compile("sqOatp-[0-9A-Za-z-_]{22}"),
    "AWS IAM Access Key ID": re.compile("AKIA[0-9A-Z]{16}"),
    "Additional AWS Access Key": re.compile("(AKIA|ASIA|AROA|AIDA|ANPA|ANVA|APKA)[0-9A-Z]{16}"),
    "AWS Secret Access Key": re.compile("(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
    "Google Cloud OAuth": re.compile("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"),
    "Google Cloud API KEY": re.compile("[A-Za-z0-9_]{21}--[A-Za-z0-9_]{8}"),
    "Open AI Project API Key": re.compile("sk-proj-[A-Za-z0-9_\-]{48,}")
}

#initiate logger
logger = logging.getLogger(__name__)

def FileScan(filePath):
    #method to search a specific file path
    secrets = []
    try:

        #safely open file
        with open(filePath, "r") as file:

            #search line by line of file
            for lineNum, line in enumerate(file, start=1):

                #search for each pattern in each line
                for regexType, pattern in regex.items():
                    matches = re.finditer(pattern, line)

                    #save matches
                    for match in matches:
                        secrets.append({"file": str(filePath), "type": regexType, "line": lineNum, "match": match.group()})

    except Exception as e:
        #log error with opening file
        logger.error(f"File {filePath} not loaded successfully. {e}")

    return secrets

def PathScan(dirPath):
    #method to search a directory
    secrets = ["Directory being searched: " + str(dirPath)]

    #walk through directory to files
    for root, dirs, files in os.walk(dirPath):

        #loop through list to touch each file
        for file in files:
            #build path to file
            filePath = Path(root) / file

            #Scan built path and then add findings to list
            fileSecrets = FileScan(filePath)
            secrets.extend(fileSecrets)

def ReportFindings(secrets):
    print("\n" + "#" * 20, end="" )
    print("   SECRET REPORT   ", end="")
    print("#" * 20 + "\n")
    print("-" * 60 + "\n")

    #check if any secrets were found
    if not secrets:
        print("No secrets detected")
        return
    
    #stylized report of findings
    for secret in secrets:
        print(f"Secret found in: {secret['file']}")
        print(f"On line {secret['line']} a {secret['type']}")
        print(f"Match: {secret['match']}")
        print("\n" + "-" * 60)
    
def Scanner():
    #create instance of parser
    parser = argparse.ArgumentParser(
        prog='SecretScanner',
        description="Scans files and/or directories for hidden plain text secrets")

    parser.add_argument("path", help="File path or Directory to be scanned")

    #parse args
    args = parser.parse_args()

    #find path to desired scan
    target = Path(args.path)

    if target.is_file():
        print(f"Scanning File {target}")
        secrets = FileScan(target)
    elif target.is_dir():
        print(f"Scanning Directory {target}")
        secrets = PathScan(target)
    else:
        logger.error(f"{target} is improper path")
        return
    
    ReportFindings(secrets)

if __name__ == "__main__":
    Scanner()
