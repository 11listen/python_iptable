#coding: utf-8

import json
import MySQLdb

#conn_db
db = MySQLdb.connect("192.168.0.107", "admin_zone", "1q2w3e4R", "detection")

#get_db_cursor
cursor = db.cursor()

#create_db
db_sql = """
CREATE TABLE iptable(
user char(20) not null,
job char(20) not null,
mac char(48) not null,
ip int(64) not null,
description char(128)
)
"""

cursor.execute(db_sql)

#test_date
test_date = {
   'test1': {
        'user': 'listen',
        'job': 'te',
        'mac':'aa:bb:cc:dd:ee:ff',
        'ip': '192.168.1.1',
        'description': '',
        },
    'test2': {
        'user': 'test',
        'job': 'cn',
        'mac': '11:aa:22:bb:33:cc',
        'ip': '192.168.100.100',
        'description': '',
        }
    }

a = []
json_str = json.dumps(test_date)
date = json_str.encode('utf-8')
eval_dict = eval(date)

#traverse_eval_dict
for y in eval_dict.items():
    user = y[1]['user']
    job = y[1]['job']
    mac = y[1]['mac']
    ip = y[1]['ip']
    description = y[1]['description']
    a.append((user, job, mac, ip, description))
#convert_to_tuple
b = tuple(a)

#insert_to_db
insert_sql = """INSERT INTO `iptable` (`user`, `job`, `mac`, `ip`, `description`) VALUES ('%s', '%s', '%s', '%s', '%s')""" % (b[0][0], b[0][1], b[0][2], b[0][3], b[0][4])

insert_sql_test = """INSERT INTO `iptable` (`user`, `job`, `mac`, `ip`, `description`) VALUES ('%s', '%s', '%s', '%s', '%s')""" % (b[1][0], b[1][1], b[1][2], b[1][3], b[1][4])

try:
    cursor.execute(insert_sql)
    cursor.execute(insert_sql_test)
    db.commit()
    print 'success insert to db'
except:
    db.rollback()
    print 'error, please check you code'

db.close()














