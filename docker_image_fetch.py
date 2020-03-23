import os
import json5
import argparse
import requests
import base64

# pulls Docker Images from docker registry api. 
# and checks for docker misconfigurations. 

apiversion = "v2"
final_list_of_blobs = []

	
# Disable insecure request warning 
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

parser = argparse.ArgumentParser(description="Download all the things from a docker registry")
parser.add_argument('-u', '--url', dest="url", help="URL Endpoint for Docker Registry API v2. Eg https://IP:Port", default="spam")
parser.add_argument('-n', '--user', dest="user", help="Username for basic authentication")
parser.add_argument('-p', '--password', dest="password", help="Password for basic authentication")
options = parser.parse_args()
url = options.url

headers = {}
if (options.user is not None):
	auth = base64.b64encode(options.user + ":" + options.password)
	headers = { 'Authorization': 'Basic ' + auth}

def list_repos():
	req = requests.get(url+ "/" + apiversion + "/_catalog", verify=False, headers=headers)
	print(req.text)
	return json5.loads(req.text)["repositories"]

def find_tags(reponame):
	req = requests.get(url+ "/" + apiversion + "/" + reponame+"/tags/list", verify=False, headers=headers)
	print "\n"
	data =  json5.loads(req.content)
	if "tags" in data:
		return data["tags"]


def list_blobs(reponame,tag):
	req = requests.get(url+ "/" + apiversion + "/" + reponame+"/manifests/" + tag, verify=False, headers=headers)
	data = json5.loads(req.content)
	if "fsLayers" in data:
		for x in data["fsLayers"]:
			curr_blob = x['blobSum'].split(":")[1]
			if curr_blob not in final_list_of_blobs:
				final_list_of_blobs.append(curr_blob)

def download_blobs(reponame, blobdigest,dirname):
	req = requests.get(url+ "/" + apiversion + "/" + reponame +"/blobs/sha256:" + blobdigest, verify=False, headers=headers)
	filename = "%s.tar.gz" % blobdigest
	with open(dirname + "/" + filename, 'wb') as test:
		test.write(req.content)

def main(): 
	if url is not "spam":
		list_of_repos = list_repos()
		print "\n[+] List of Repositories:\n"
		for x in list_of_repos:
			print x
		target_repo = raw_input("\nWhich repo would you like to download?:  ")
		if target_repo in list_of_repos:
			tags = find_tags(target_repo)
			if tags is not None:
				print "\n[+] Available Tags:\n"
				for x in tags:
					print x

				target_tag = raw_input("\nWhich tag would you like to download?:  ")
				if target_tag in tags:
					list_blobs(target_repo,target_tag)

					dirname = raw_input("\nGive a directory name:  ")
					os.makedirs(dirname)
					print "Now sit back and relax. I will download all the blobs for you in %s directory. \nOpen the directory, unzip all the files and explore like a Boss. " % dirname
					for x in final_list_of_blobs:
						print "\n[+] Downloading Blob: %s" % x
						download_blobs(target_repo,x,dirname)
				else:
					print "No such Tag Available. Qutting...."
			else:
				print "[+] No Tags Available. Quitting...."
		else:
			print "No such repo found. Quitting...."
	else:
		print "\n[-] Please use -u option to define API Endpoint, e.g. https://IP:Port\n"


if __name__ == "__main__":
	main()
