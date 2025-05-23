#!/usr/bin/env python3

import requests
import json
import os
import time
import datetime
import random
import re
from urllib.parse import quote_plus
import html2text


# infosec.exchange
IFSX_AUTH_TOKEN = os.getenv("IFSX_AUTH_TOKEN")
#ioc.exchange
IOCX_AUTH_TOKEN = os.getenv("IOCX_AUTH_TOKEN")

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

TESTMODE = os.getenv("TESTMODE") # for dev only

if TESTMODE:
	print("TESTMODE enabled")

CVE_PATTERN = r'(?i)\bcve\-\d{4}-\d{4,7}'
EUVD_PATTERN = r'(?i)\beuvd\-\d{4}-\d{4,7}'

# blocked accounts for excessive noise / automation / spam or other reasons.
# we want real posts by real people; not automated bots that spam every CVE
BLOCKED_ACCTS = ['RedPacketSecurity@mastodon.social']

start = time.time()

def has_digits(s):
	return any(char.isdigit() for char in s)

def normalize_cve(cvestr):
	'''
	normalize a cve string to CVE-YYYY-ZZZZZ
	'''
	if not (cvestr.upper().startswith("CVE") and has_digits(cvestr) and len(cvestr) > 10): # validate it
		print(f"INFO: invalid cve str {cvestr}")
		return None
	cve = ''
	cve += cvestr[:3].upper() # first 3 chars
	if cvestr[3].isdigit(): #if the fourth char is a number e.g. cve202312345
		cve += f"-{cvestr[3:7]}-{cvestr[7:].replace('-','').replace('_','')}"
	elif cvestr[3] in ["_", "-"]:
		# a proper CVE string should also work, not just with underscore 
		cve += f"-{cvestr[4:8]}-{cvestr[9:]}"
	else:
		print(f"WARNING: weird cve str {cvestr}")
		return None
	return cve

def normalize_euvd(euvdstr):
	'''
	normalize a cve string to CVE-YYYY-ZZZZZ
	'''
	if not (euvdstr.upper().startswith("EUVD") and has_digits(euvdstr) and len(euvdstr) > 10): # validate it
		print(f"INFO: invalid euvd str {euvdstr}")
		return None
	euvd = ''
	euvd += euvdstr[:4].upper() # first 3 chars
	if euvdstr[4].isdigit(): #if the fourth char is a number e.g. cve202312345
		euvd += f"-{euvdstr[4:8]}-{euvdstr[8:].replace('-','').replace('_','')}"
	elif euvdstr[4] in ["_", "-"]:
		# a proper CVE string should also work, not just with underscore 
		euvd += f"-{euvdstr[5:9]}-{euvdstr[10:]}"
	else:
		print(f"WARNING: weird euvd str {euvdstr}")
		return None
	return euvd

def redhat_cve_detail(cve):
	'''
	get cve detail from redhats portal
	'''
	url = f'https://access.redhat.com/labs/securitydataapi/cve/{cve}.json'
	r = requests.get(url)
	if r.status_code != 200:
		print(f"WARN: bad redhat api status for {cve}", r.status_code, r.text)
	return r.json()

def ghsa_cve_detail(cve):
	'''
	get cve data from the github security advisory api
	https://docs.github.com/en/rest/security-advisories/global-advisories?apiVersion=2022-11-28
	'''

	time.sleep(2) # rate limit, just to be safe 

	headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {GITHUB_TOKEN}", "X-GitHub-Api-Version": "2022-11-28"}

	url = f'https://api.github.com/advisories?cve_id={cve}'

	r = requests.get(url, headers=headers)

	if r.status_code != 200:
		print("ERROR bad status code:", r.status_code, r.text)
		if 'API rate limit' in r.text :
			print("Exceeded API limit, sleeping..")
			time.sleep(10)

	return r.json()




def nvd_cve_detail(cve):
	'''
	get cve detail (like cvss score) from the nvd api 
	https://nvd.nist.gov/developers/vulnerabilities

	it's unreliable AF
	'''
	url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}'
	r = requests.get(url)
	if r.status_code == 403:
		print("rate limited by assholes at NVD, sleeping.. error message:", r.text)
		time.sleep(6.1)
		r = requests.get(url)
		if r.status_code == 403:
			return None
	if r.status_code not in [200, 403]:
		print(f"WARN: bad nvd api status for {cve}", r.status_code, r.text[:100])
		return None
	else:
		return r.json()

def get_nuclei_template(cve):
	'''
	use github's API to search and return nuclei template
	'''
	headers = {"Accept": "application/vnd.github+json", "Authorization": f"Bearer {GITHUB_TOKEN}", "X-GitHub-Api-Version": "2022-11-28"}
	q = f'repo:projectdiscovery/nuclei-templates {cve}'
	url = f'https://api.github.com/search/code?q={quote_plus(q)}'

	time.sleep(2)
	r = requests.get(url, headers=headers)

	if r.status_code != 200:
		print("ERROR bad status code:", r.status_code, r.text)
		if 'API rate limit' in r.text :
			print("Exceeded API limit, sleeping..")
			time.sleep(10)
			return get_nuclei_template(cve)

	d = r.json()
	if 'total_count' not in d:
		return None
	if d['total_count'] > 0:
		for item in d['items']:
			if item['path'].endswith(f"{cve}.yaml"):
				return item['html_url']

	return None

def first_epss_for_cves_list(cves):
	'''
	get EPSS (Exploit Prediction Scoring System) detail for the list of cves
	'''
	print(f'getting epss data for {len(cves)} cves')
	data = []
	for i in range(0, len(cves), 30):
		cves_csv = ','.join(cves[i:i+30])
		r = requests.get(f'https://api.first.org/data/v1/epss?cve={cves_csv}')
		data.extend(r.json()['data'])
	return data

def get_hashtag_timeline(instance_url, hashtag, auth_token=None, limit=10):
	'''
	get posts (timeline) of a particular hashtag
	'''
	r = requests.get(f"{instance_url}/api/v1/timelines/tag/{hashtag}?limit={limit}", headers={"Authorization":f"Bearer {auth_token}"})
	if r.status_code != 200:
		print(f"WARN: {instance_url} get_hashtag_timeline api status", r.status_code, r.text)
	return r.json()

def get_github_repos(cve):

	github_repos = set() # use set to dedup; cast this back to a list later

	# bloody rate limit
	time.sleep(2)

	# search generically, without "in:.."
	# > When you omit this qualifier, only the repository name, description, and topics are searched.
	# in:readme sucks and returns false positives instead of actual PoCs
	url = f'https://api.github.com/search/repositories?q={cve}&per_page=100'
	headers = {'Accept':'application/vnd.github+json', 'Authorization': f'Bearer {GITHUB_TOKEN}', 'X-GitHub-Api-Version': '2022-11-28'}
	r = requests.get(url, headers=headers)

	if r.status_code != 200:
		print("ERROR bad status code:", r.status_code, r.text)
		if 'API rate limit' in r.text :
			print("Exceeded API limit, sleeping..")
			time.sleep(10)
		return ['#search_error']

	for d in r.json()['items']:
		github_repos.add(d['html_url'])

	return list(github_repos)



def search_poll(instance_url, q, search_type='hashtags', auth_token=None, last_days=14):
	'''
	search_type: Specify whether to search for only accounts, hashtags, statuses
	'''
	lstart = time.time()
	results = []

	limit = 40
	offset = 0
	total_pages_to_fetch = 5
	curr_page = 0
	while True:
		r = requests.get(f"{instance_url}/api/v2/search?q={q}&type={search_type}&limit={limit}&offset={offset}", headers={"Authorization":f"Bearer {auth_token}"})
		# print("Status:", r.status_code)
		d = r.json()
		# print('keys:', d.keys())
		# print(d)
		results.extend(d[search_type])
		offset += len(d[search_type])
		curr_page += 1

		if len(d[search_type]) < limit or curr_page > total_pages_to_fetch: # done
			break
	print(f'done polling {instance_url}, found {len(results)} {search_type} secs:', time.time() - lstart)
	return results

def filter_posts(posts):
	filtered_posts = []
	filtered_count = 0
	for p in posts:
		if p['account']['acct'] in BLOCKED_ACCTS:
			filtered_count += 1
			continue
		filtered_posts.append(p)
	print(f"filtered out {filtered_count} posts")
	return filtered_posts


def get_enisa_euvd_details(euvd):
	'''
	fetch EUVD details from EUVD API
	e.g. https://euvdservices.enisa.europa.eu/api/enisaid?id=EUVD-2024-45012
	'''
	# python requests is blocked not sure why, maybe LLM scraping crap
	headers = {"User-Agent":"curl"}
	r = requests.get(f'https://euvdservices.enisa.europa.eu/api/enisaid?id={euvd}', headers={"User-Agent":"curl"})
	if r.status_code == 200:
		d = r.json()
		return d
	else:
		print(f"bad status getting EUVD details from ENISA API for {euvd}:",r.status_code, r.text)
		return None

def main():


	# hashtags = []
	# hashtags.extend(search_poll("https://infosec.exchange","CVE", auth_token=IFSX_AUTH_TOKEN))
	# hashtags.extend(search_poll("https://ioc.exchange","CVE", auth_token=IOCX_AUTH_TOKEN))


	# get most used, trending past N days
	last_days = 14

	cve_counts = {}
	euvd_posts = {}


	# get posts by statuses (toots) search
	post_search_results = []
	post_search_results.extend(filter_posts(search_poll("https://infosec.exchange", "EUVD-", search_type="statuses", auth_token=IFSX_AUTH_TOKEN, last_days=last_days)))
	post_search_results.extend(filter_posts(search_poll("https://ioc.exchange", "EUVD-", search_type="statuses", auth_token=IOCX_AUTH_TOKEN, last_days=last_days)))
	for result in post_search_results:
		euvds = re.findall(EUVD_PATTERN, result["content"])
		euvds = list(set(euvds)) #dedup
		# print('extracted:', cves)
		for euvd in euvds:
			euvd = normalize_euvd(euvd)
			if euvd not in euvd_posts:
				euvd_posts[euvd] = []
			if result not in euvd_posts[euvd]: # no dup
				euvd_posts[euvd].append(result)
				if euvd not in cve_counts:
					cve_counts[euvd] = 0
				cve_counts[euvd] += 1

	print(f"total {len(euvd_posts)} EUVDs")
	if TESTMODE:
		print("TESTMODE, limiting number of results..")
		euvd_posts = dict([(key, euvd_posts[key]) for key in list(euvd_posts.keys())[:3]+list(euvd_posts.keys())[-2:]])

	print("getting EUVD details...")
	lstart = time.time()
	euvd_details = {}
	for euvd in euvd_posts:
		try:
			euvd_details[euvd] =  get_enisa_euvd_details(euvd)
		except Exception as e:
			print("Exception trying to get euvd details:", e)



	# one big JSON blob for the page to render
	euvd_feed = {} #euvd:...

	print("done getting EUVD details:", time.time()-lstart)

	euvd_cves = {} # euvd:cve
	euvd_aliases = {}
	for euvd in euvd_details:
		# print('aliases:',euvd_details[euvd]["aliases"])
		# aliases = [ x for x in euvd_details[euvd]["aliases"].split("\n") if "CVE" in x]
		aliases = []
		if euvd_details.get(euvd) != None:
			euvd_aliases[euvd] =  euvd_details[euvd]["aliases"].split('\n')
			if '' in euvd_aliases[euvd]:
				euvd_aliases[euvd].remove('')
			for a in euvd_details[euvd]["aliases"].split('\n'):
				if "CVE" in a:
					aliases.append(a)

		if len(aliases) > 0:
			euvd_cves[euvd] = aliases[0]
			print(f'found CVE {aliases[0]} for {euvd}')


	print("getting github repos..")

	euvd_repos = {} # euvd:[repo_urls]

	lstart = time.time()
	for euvd in euvd_posts:
		github_repos = get_github_repos(euvd_cves[euvd])
		euvd_repos[euvd] = github_repos
	print("done getting github repos:", time.time()-lstart)
	print(euvd_repos)


	for euvd in euvd_posts:
		# Final stage - euvd_feed is the dictionary that will be pumped to the front end

		cve = euvd_cves.get(euvd)

		euvd_feed[euvd] = {}
		euvd_feed[euvd]['basescore'] = 0
		euvd_feed[euvd]['cve'] = cve
		euvd_feed[euvd]['severity'] = None
		euvd_feed[euvd]['epss'] = 0
		euvd_feed[euvd]['epss_severity'] = None
		euvd_feed[euvd]['nuclei'] = get_nuclei_template(cve)
		euvd_feed[euvd]['posts'] = []
		euvd_feed[euvd]['description'] = "N/A"
		euvd_feed[euvd]['repos'] = euvd_repos[euvd]
		euvd_feed[euvd]['updated'] = None
		euvd_feed[euvd]['aliases'] = ','.join(euvd_aliases[euvd])

		for post in euvd_posts[euvd]:
			# filter using created_at for recent days only
			dt = datetime.datetime.fromisoformat(post['created_at'].split('.')[0])
			if (datetime.datetime.utcnow() - dt) > datetime.timedelta(days=last_days): # more than N last days, skip
				continue

			# # convert content to markdown to make XSS-ing this website slightly harder 
			# content = "ERROR with html2text parsing"
			# try:
			# 	content = h2t.handle(post['content']).replace("- ", "-") # fix link separation issue with dashes
			# except Exception as e:
			# 	print("ERROR with html2text parsing:", e)

			euvd_feed[euvd]['posts'].append({'account':post['account'],'url':post['url'], 'content':post['content'], 'created_at':post['created_at']})
			

			if euvd in euvd_details:
				try:
					if "description" in euvd_details[euvd]:
						euvd_feed[euvd]['description'] =  euvd_details[euvd]['description']
					euvd_feed[euvd]['basescore'] = euvd_details[euvd]['baseScore']
					euvd_feed[euvd]['updated'] = euvd_details[euvd]['dateUpdated']
					euvd_feed[euvd]['epss'] = euvd_details[euvd]['epss'] * 100
					# epss severity is just done here for coloring; it's not part of any spec that defines levels
					if euvd_feed[euvd]['epss'] >= 50:
						euvd_feed[euvd]['epss_severity'] = "CRITICAL"
					elif euvd_feed[euvd]['epss'] >= 20:
						euvd_feed[euvd]['epss_severity'] = "HIGH"
					elif euvd_feed[euvd]['epss'] >= 10:
						euvd_feed[euvd]['epss_severity'] = "MEDIUM"
					else:
						euvd_feed[euvd]['epss_severity'] = "LOW"

					if euvd_feed[euvd]['basescore'] > 0 and euvd_feed[euvd]['basescore'] < 4:
						euvd_feed[euvd]['severity'] = 'LOW'
					elif euvd_feed[euvd]['basescore'] > 4 and euvd_feed[euvd]['basescore'] < 7:
						euvd_feed[euvd]['severity'] = 'MEDIUM'
					elif euvd_feed[euvd]['basescore'] > 7 and euvd_feed[euvd]['basescore'] < 9:
						euvd_feed[euvd]['severity'] = 'HIGH'
					elif euvd_feed[euvd]['basescore'] > 9:
						euvd_feed[euvd]['severity'] = 'CRITICAL'

				except Exception as e:
					print(f"Error parsing euvd detail on {euvd}:", e, euvd_details[euvd])

			# print(f"{cve} {author_acct} {content}")
		if len(euvd_feed[euvd]['posts']) == 0:
			# remove cve if there are no posts
			del euvd_feed[euvd]



	outfile = 'euvd_feed.json'
	with open(outfile, 'w+') as f:
		json.dump(euvd_feed, f, indent=2)

	from renderer import render
	render(outfile)

	print(f'done, written output to {outfile}. total elapsed:', time.time() - start)

if __name__ == "__main__":
	main()
