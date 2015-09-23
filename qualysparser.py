#['IP', 'DNS', 'NetBIOS', 'OS', 'IP Status', 'QID', 'Title', 'Type', 'Severity', 'Port', 'Protocol', 'FQDN', 'SSL', 'CVE ID', 'Vendor Reference', 'Bugtraq ID', 'CVSS Base', 'CVSS Temporal', 'Threat', 'Impact', 'Solution', 'Exploitability', 'Associated Malware', 'Results', 'PCI Vuln', 'Instance']

#Row 8
#sample usage 1: python qualysparse.py -f qualysreport.csv -t "Feature Denial of Service"
#sample usage 2: python qualysparse.py -f qualysreport.csv -s 5
#python qualysparse.py -f qualysreport.csv -c CVE-2014-0224
# Prajwal Panchmahalkar's script to parse Qualys Reports 


import optparse
import csv
import sys,os
def parse_by_severity(qualysreportfile, severity):
	x =[]
	with open(qualysreportfile) as f:
		for i, line in enumerate(csv.reader(f,delimiter=','),1):
			if i > 9:
				try:
					if((int(line[8])==int(severity)) &(str(line[7])!='Practice')):
						y = str(line[6])
						x.append(line[6])
				except:
					pass
				continue
	for i in set(x):
		print "\n\n"+i+"\n\n"
		listvul = raw_input("do you want to list the vulnerable hosts? [Y/N]")
		if (listvul == 'Y' or listvul == 'y'):
			parse_by_title(qualysreportfile,str(i))
		else:
			continue

def parse_by_cve(qualysreportfile, cveid):
	with open(qualysreportfile) as f:
		for i, line in enumerate(csv.reader(f,delimiter=','),1):
			if i>9:
				try:
					if(str(cveid) in str(line[13])):
						if((line[9]!=None) and (line[1]!=None)):
							print line[0]+" | "+line[1]+" | "+line[9]+" | "+line[6]
						else:
							print line[0]+" | "+line[1]+" | "+line[6]
				except:
					pass
				continue
def parse_by_title(qualysreportfile, title):
	print "Printing for Title: "+title+"\n"
	print "Affected hosts: \n \n"
	with open(qualysreportfile) as f:
		for i, line in enumerate(csv.reader(f,delimiter=','),1):
			
			if i>9:
				try:
					if(str(title) in str(line[6])):
						if((line[9]!=None) and (line[1]!=None)):
							print line[0]+" : "+line[1]+" : "+str(line[9])
							threat = str(line[18])+ "\n\n\n"+str(line[19])+ "\n\n\n"+str(line[20])
						else:
							print line[0]+" : "+line[1]
							threat = str(line[18])+ "\n\n\n"+str(line[19])+ "\n\n\n"+str(line[20])
				except:
					pass
				continue
	print threat

def main():
	parser = optparse.OptionParser('python %prog -f qualys.csv  -s <severity> or -cve <CVEID> or -t <title>')
	parser.add_option('-f', dest = 'tgtfile', metavar = 'FILE', help ='specify the qualys report in csv')
	parser.add_option('-s', dest = 'severity', help ='specify the severity 1-5 report in csv')
	parser.add_option('-c', dest = 'CVEID', help ='eg.,CVE-2014-0224')
	parser.add_option('-t', dest = 'title', help ='NTP monlist feature denial of service')
	(options,args) = parser.parse_args()
	reportfile = options.tgtfile
	severity = options.severity
	cve = options.CVEID
	vulntitle = options.title
	if((reportfile==None) & ((severity==None)|(cve==None)|(vulntitle==None))):
		print parser.usage
		sys.exit(0)
	if(severity!=None):
		if int(severity) in range(1,6):
			parse_by_severity(reportfile,severity)
		else:
			print "[!]Severity must be in range 1 to 5."
			print "[!]Exiting...."
			sys.exit(0)
	if(cve!=None):
		parse_by_cve(reportfile,cve)
	if(vulntitle!=None):
		parse_by_title(reportfile,vulntitle)

if __name__ =="__main__":
    main()
