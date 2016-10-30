# -*- coding: utf-8 -*-

import os
import subprocess
import datetime

# Copy apache log to space work
cmd = "copy C:\\ms4w\\Apache\\logs\\access.log C:\\readLog\\current_access.log"
subprocess.call(cmd, shell=True)

t2 = "current_access.log"
t1 = "last_access.log"


def main():

    # Classif des vulnerabilites
    classif = ['sqli', 'id', 'xss', 'dom', 'ref', 'lfi', 'dt', 'csrf']

    # Generate diffrence between 2 logs
    fileComparateur(t2, t1)

    # Audit diffrence to find attacks
    cmd = ['python', 'scalp-0.4.py', '-l', 'diff.log', '-f', 'default_filter.xml', '-a',
           'xss,sqli,csrf,dos,dt,spam,id,ref,lfi', '-o', 'report', '--text', '-u']
    subprocess.call(cmd, shell=True)

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

            id_attack = str(attack_type[i][0])[attack_type[i][0].index('(')+1:attack_type[i][0].index(')')]

            if id_attack in classif:
                index = 'A' + str(classif.index(id_attack) + 1)
            else:
                index = 'ND'

            # Format date
            d = datetime.datetime.strptime(date_attack[i], '%d/%b/%Y:%H:%M:%S')

            text = str(ip_adress[i]).lstrip('\t') + '_' + str(d.strftime('%d/%m/%Y:%H:%M:%S')) + '_' + id_attack + '_' + str(attack_type[i][2]) + '_' + index + '\n'
            result.write(text)

        result.close()

        # Copy to send directory
        #cmd = "copy result.txt C:\\readLog\\current_access.log"
        #subprocess.call(cmd, shell=True)

        # Replace last_access by current_access
        cmd = "copy C:\\readLog\\current_access.log C:\\readLog\\last_access.log"
        subprocess.call(cmd, shell=True)

        # Remove report from report direcotry
        os.remove(result_name)
        os.remove('current_access.log')
        #os.remove('result.txt')

    except IOError:
        pass

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