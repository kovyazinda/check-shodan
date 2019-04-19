import requests
import json
import csv
import sys
import time

keyparam = '?key=YourShodanAPIKey'
url = 'https://api.shodan.io/shodan/host/'

headers = requests.utils.default_headers()
headers.update({
        'User-Agent': 'Shodan-checker-python-v.0.1',
    })

inputfile = sys.argv[1]
outputfile = sys.argv[2]

if sys.argv[1] and sys.argv[2]:
 infile=open(inputfile,"r")
 outfile=open(outputfile,"w+")
 csvrecord = csv.writer(outfile, delimiter=';',quotechar='"', quoting=csv.QUOTE_MINIMAL)
 headerarray=["IP","Country","Hostnames","Organization","ISP","Tags","Ports"]
 csvrecord.writerow(headerarray)

 for string in infile:


  target=url+string.rstrip()+keyparam
  try:
   response = requests.get(target,headers=headers)
   print (target)
   print (response)

   data_json = json.loads(response.text)

   resultcountry=data_json['country_name']
   resulthostnames=','.join(data_json['hostnames']).encode('ascii', 'ignore')
   resultorg=data_json['org']
   resultisp=data_json['isp']
   resulttags=','.join(data_json['tags']).encode('ascii', 'ignore')
   resultports=data_json['ports']

   valuearr=[string.rstrip(),resultcountry,resulthostnames,resultorg,resultisp,resulttags,resultports]
   print(valuearr)
   csvrecord.writerow(valuearr)

# slowdown queries
   time.sleep(2)




  except:
   print ("Query Error")



 infile.close
 outfile.close

else:
 print ("Syntax: check-shodan.py <inputfile-iplist.txt> <outputfile.csv>")
 
