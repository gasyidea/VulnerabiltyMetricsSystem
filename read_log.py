# -*- coding: utf-8 -*-

import os, sys
import subprocess
import datetime, re

# Apache log file
# log_file = "/var/log/apache2/access.log"
# diff_log = "/home/men5gasy/Public/appli/diff.log"
# scalp_folder = "/home/men5gasy/Public/appli/scalp"

# report_folder = "/home/men5gasy/Public/appli/apache_report"

t2 = "access2.log"
t1 = "access1.log"


def main():
    # Generate diffrence between 2 logs
    fileComparateur(t2, t1)

    # Audit diffrence to find attacks
    cmd = ['python', 'scalp-0.4.py', '-l', 'diff.log', '-f', 'default_filter.xml', '-a',
           'xss,sqli,csrf,dos,dt,spam,id,ref,lfi', '-o', 'report', '--text', '-u']
    subprocess.call(cmd, shell=True)
    # scalp-0.4.py -l /var/log/apache2/access.log -f default_filter.xml -u -p 29/Oct/2016:22:28:16;*/Nov/2016 -a xss,sqli,csrf,dos,dt,spam,id,ref,lfi -o report --xml


    # Read result txt
    now = datetime.date.today()
    result_name = 'report/diff.log_scalp_' + now.strftime('%a-%d-%b-%Y') + '.txt'

    attack_type = []
    ip_adress = []
    date_attack = []

    try:
        with open(result_name) as f:
            lines = f.readlines()

            for i in range(0, len(lines) - 1):
                if lines[i].startswith('Attack') and not lines[i + 1].startswith('Attack'):
                    attack_type.append([lines[i].rstrip('\n'), getLineNumber(result_name, lines[i].rstrip('\n')), 0])

                    temp = lines[i + 3].split(' ')
                    ip_adress.append(temp[0])
                    date_attack.append(temp[3].strip('[]').split('+')[0].strip(' '))

        # Remove report from report direcotry
        #os.remove(result_name)

        # Success Request
        success = GetSuccessfullRequest(result_name)

        # Get successed attack
        nb_attack = len(attack_type)

        for index in success:
            for i in range(0, nb_attack - 1):
                if index in range(attack_type[i][1], attack_type[i + 1][1]):
                    attack_type[i][2] = 1
                    break

        if success[len(success) - 1] > attack_type[nb_attack - 1][1]:
            attack_type[nb_attack - 1][2] = 1


        # Write result
        result = open('result.txt', 'w')

        for i in range(0, nb_attack):
            text = str(ip_adress[i]).lstrip('\t') + '_' + str(date_attack[i]) + '_' + str(attack_type[i][0]) + '_' + str(attack_type[i][2]) + '_ND@\n'
            result.write(text)

        result.close()

    except IOError:
        print "Pas d'alerte à signaler"""

    """# Read result xml
    now = datetime.date.today()
    result_name = 'report/diff.log_scalp_' + now.strftime('%a-%d-%b-%Y') + '.xml'
    #print result_name

    # Read Xml, delete header and send infos
    newXml = open('diff.log_scalp_' + now.strftime('%a-%d-%b-%Y') + '.xml', 'w')

    try:
        with open(result_name) as f:
            for i in xrange(4):
                f.next()
            for line in f:
                newXml.write(str(line))

        newXml.close()

        # Remove report from report direcotry
        os.remove(result_name)

        # Read new xml without header




        #tree = etree.parse()
        #rootXml = tree.getroot()


    except IOError:
        print "Pas d'alerte à signaler"""


# Get line number
def getLineNumber(file, lookup):
    with open(file) as myFile:
        for num, line in enumerate(myFile, 1):
            if lookup in line:
                return num


# Get Success Request
def GetSuccessfullRequest(file):
    SuccessStatut = []
    with open(file) as myFile:
        for num, line in enumerate(myFile, 1):
            temp = line.split(' ')

            if len(temp[0].strip('\t').split('.')) == 4:
                index = line.index('HTTP/1.1')
                if line[index + 10:index + 14].startswith('2'):
                    SuccessStatut.append(num)

    return SuccessStatut


# Function for getting diffrence between 2 logs files
def fileComparateur(t2, t1):
    file = open('diff.log', 'w')

    # Nb ligne t1
    with open(t1, 'r') as f:
        lines = f.readlines()
        num_lines = len([l for l in lines if l.strip(' \n') != ''])

    with open(t2) as f:
        for i in xrange(num_lines):
            f.next()
        for line in f:
            file.write(str(line))

    file.close()


if __name__ == '__main__':
    main()

"""if temps in open('access2.log').read():
    f = open('access2.log', 'r+b')
    mf = mmap.mmap(f.fileno(), 0)
    mf.seek(0) # reset file cursor
    m = re.search('pattern', mf)
    print m.start(), m.end()
    mf.close()
    f.close()"""

"""with open('access2.log', 'r') as f1, open('access1.log', 'r') as f2:
    diff = difflib.ndiff(f1.readlines(), f2.readlines())

    for line in diff:
        if line.startswith('-'):
            line_str = str(line)
            debut = line_str.index('1')
            print line_str[debut:]"""
