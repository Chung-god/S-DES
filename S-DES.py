'''
사용 전 터미널에서
pip install termcolor 을 하셔야 실행이 됩니다.

''.join() 는 리스트를 하나의 문자로 합치기 위해 사용됩니다. 문자열 리스트에만 쓰이기 때문에 보시면 int를 문자열로 mapping 하고 있습니다.
'''

import os
import sys
import time
import msvcrt as m  # c언어 getch() 사용
from termcolor import colored  # pip install termcolor 필요

printList = ['' for i in range(22)]  # 출력이 나오는, 즉 계속해서 변하는 22개의 문자열을 담는 리스트
K1 = []
K2 = []
plaintext = []
ciphertext = []
speedNum = 5  # 처리 속도


def P10(mylist):
    P10num = [2, 4, 1, 6, 3, 9, 0, 8, 7, 5]
    P10key = [0 for i in range(10)]
    for i in range(0, 10):
        P10key[i] = mylist[P10num[i]]
    return P10key


def shift(mylist):
    left5 = mylist[0:5]
    right5 = mylist[5: 10]

    # left shift
    temp = left5[0]
    left5[0:4] = left5[1:5]
    left5[4] = temp
    # right shift
    temp = right5[0]
    right5[0:4] = right5[1:5]
    right5[4] = temp

    mylist = left5 + right5
    return mylist


def P8(mylist):
    P8num = [5, 2, 6, 3, 7, 4, 9, 8]
    p8list = [0 for i in range(8)]
    for i in range(8):
        p8list[i] = mylist[P8num[i]]
    return p8list


# 초기순열함수
def IP(mylist):
    IPnum = [1, 5, 2, 0, 3, 7, 4, 6]
    iplist = [0 for i in range(8)]
    for i in range(8):
        iplist[i] = mylist[IPnum[i]]
    return iplist


# 최종순열함수
def IPinverse(mylist):
    IPinversenum = [3, 0, 2, 4, 6, 1, 7, 5]
    ipinverselist = [0 for i in range(8)]
    for i in range(8):
        ipinverselist[i] = mylist[IPinversenum[i]]
    return ipinverselist


# 이에 대한 내장 함수가 존재하지만 직관적으로 하기위해 함수작성
def changeChartoBinary(s):
    if s == '00':
        return 0
    elif s == '01':
        return 1
    elif s == '10':
        return 2
    elif s == '11':
        return 3


def changeBinarytoChar(s):
    if s == 0:
        return '00'
    elif s == 1:
        return '01'
    elif s == 2:
        return '10'
    elif s == 3:
        return '11'


def FK(mylist, key):
    # S-box 선언
    S0 = [[1, 0, 3, 2], [3, 2, 1, 0], [0, 2, 1, 3], [3, 1, 3, 2]]
    S1 = [[0, 1, 2, 3], [2, 0, 1, 3], [3, 0, 1, 0], [2, 1, 0, 3]]

    # 강의의 FK부분을 보시면 이해가 가실 겁니다.
    left = mylist[0:4]
    right = mylist[4:8]
    # EP 확장
    EPnum = [3, 0, 1, 2, 1, 2, 3, 0]
    EPlist = [0 for i in range(8)]
    for i in range(8):
        EPlist[i] = right[EPnum[i]] ^ key[i]

    # Sbox에서 위치 구하기
    row1 = str(EPlist[0]) + str(EPlist[3])
    col1 = str(EPlist[1]) + str(EPlist[2])
    S0out1 = S0[changeChartoBinary(row1)][changeChartoBinary(col1)]

    row2 = str(EPlist[4]) + str(EPlist[7])
    col2 = str(EPlist[5]) + str(EPlist[6])
    S0out2 = S1[changeChartoBinary(row2)][changeChartoBinary(col2)]

    Sout = list(changeBinarytoChar(S0out1) + changeBinarytoChar(S0out2))
    result = []
    for i in range(4):
        result.append(int(P4(Sout)[i]) ^ int(left[i]))
    return result + right


def P4(mylist):
    P4num = [1, 3, 2, 0]
    p4list = [0 for i in range(4)]
    for i in range(4):
        p4list[i] = mylist[P4num[i]]
    return p4list


def SW(mylist):
    left = mylist[0:4]
    right = mylist[4:8]
    return right + left


# 키 생성 함수
def makeArrkey(key):
    global printList
    global K1
    global K2
    global speedNum
    printList[0] = key
    keylist = list(map(int, list(str("{0:b}".format(key).zfill(10)))))
    # 이진수를 Key 리스트에 하나씩 쪼개서 넣음

    # key P10 연산
    P10key = P10(keylist)
    printList[1] = ''.join(list(map(str, P10key)))
    printProcess()
    time.sleep(speedNum / 10)

    # key에 shift 연산
    shiftkey = shift(P10key)
    printList[2] = ''.join(list(map(str, shiftkey)))
    printProcess()
    time.sleep(speedNum / 10)

    # key에 P8 연산
    P8K1 = P8(shiftkey)
    printList[3] = ''.join(list(map(str, P8K1)))
    printProcess()
    time.sleep(speedNum / 10)

    # K1 정의
    K1 = P8K1
    shiftkeyK2 = shift(shift(shiftkey))
    printList[4] = ''.join(list(map(str, shiftkeyK2)))
    printProcess()
    time.sleep(speedNum / 10)

    # k2 를 위해 P8 연산
    P8K2 = P8(shiftkeyK2)
    printList[5] = ''.join(list(map(str, P8K2)))
    printProcess()
    time.sleep(speedNum / 10)

    K2 = P8K2


# 암호화 함수
def Encrypt():
    # 평문
    global plaintext
    global ciphertext
    global printList
    global K1
    global K2
    global speedNum
    printList[6] = plaintext
    printProcess()
    time.sleep(speedNum / 10)

    plaintext = list(plaintext)

    # 암호화
    for i in plaintext:
        for j in range(7, 13):
            printList[j] = ""
        printList[7] = i
        printProcess()
        time.sleep(speedNum / 10)
        chartoBin = list(map(int, list(str("{0:b}".format(ord(i)).zfill(8)))))

        # IP
        IPlist = IP(chartoBin)
        printList[8] = ''.join(list(map(str, IPlist)))
        printProcess()
        time.sleep(speedNum / 10)

        # FK 함수 실행
        FK1 = FK(IPlist, K1)
        printList[9] = ''.join(list(map(str, FK1)))
        printProcess()
        time.sleep(speedNum / 10)

        # SW 실행
        SWlist = SW(FK1)
        printList[10] = ''.join(list(map(str, SWlist)))
        printProcess()
        time.sleep(speedNum / 10)

        # FK2 함수 실행
        FK2 = FK(SWlist, K2)
        printList[11] = ''.join(list(map(str, FK2)))
        printProcess()
        time.sleep(speedNum / 10)

        # IPinverse
        IPinverselist = IPinverse(FK2)
        printList[12] = ''.join(list(map(str, IPinverselist)))
        printProcess()
        time.sleep(speedNum / 10)

        binary = ""
        for j in IPinverselist:
            binary = binary + str(j)

        ciphertext.append(chr(int(binary, 2)))
        printList[13] = ''.join(ciphertext)
        printProcess()
        time.sleep(speedNum / 10)

    printList[14] = ''.join(ciphertext)
    printProcess()
    time.sleep(speedNum / 10)


# 복호화 함수
def Decrypt():
    global plaintext
    global ciphertext
    global printList
    global K1
    global K2
    global speedNum

    plaintext = []
    for i in ciphertext:
        for j in range(15, 21):
            printList[j] = ""
        chartoBin = list(map(int, list(str("{0:b}".format(ord(i)).zfill(8)))))
        printList[15] = i
        printProcess()
        time.sleep(speedNum / 10)

        # IP
        IPlist = IP(chartoBin)
        printList[16] = ''.join(list(map(str, IPlist)))
        printProcess()
        time.sleep(speedNum / 10)

        FK2 = FK(IPlist, K2)
        printList[17] = ''.join(list(map(str, FK2)))
        printProcess()
        time.sleep(speedNum / 10)

        SWlist = SW(FK2)
        printList[18] = ''.join(list(map(str, SWlist)))
        printProcess()
        time.sleep(speedNum / 10)

        FK1 = FK(SWlist, K1)
        printList[19] = ''.join(list(map(str, FK1)))
        printProcess()
        time.sleep(speedNum / 10)

        IPinverselist = IPinverse(FK1)
        printList[20] = ''.join(list(map(str, IPinverselist)))
        printProcess()
        time.sleep(speedNum / 10)

        binary = ""
        for j in IPinverselist:
            binary = binary + str(j)

        plaintext.append(chr(int(binary, 2)))
        printList[21] = ''.join(plaintext)
        printProcess()
        time.sleep(speedNum / 10)


# 여기서 부터 출력과 관계있는 함수들입니다.

def move(y, x):  # 커서 y,x로 이동
    print("\033[%d;%dH" % (y, x))


def format(s: str):  # 보기좋게 문자열 양끝에 공백 채우기
    i = (14 - len(s)) // 2
    result = ' ' * i + s + ' ' * (14 - len(s) - i)
    return result


def main():
    os.system("mode con cols=80 lines=25")
    os.system("cls")
    print()
    print('--------- 정보보안 ---------')
    print('----- S-DES 시뮬레이터 ----- ')
    print('메뉴')
    print('1. S-DES 암호화 / 복호화')
    print('2. 속도조절')
    print('3. README')
    print('4. EXIT')
    move(10, 0)
    print(' ' * 20 + '동명대학교')
    print(' ' * 18 + '컴퓨터공학과')
    print(' ' * 15 + '06120023 김태욱')
    move(8, 0)
    try:
        select = int(input(' > '))
        if select < 1 or select > 4:
            raise TypeError
    except:
        os.system("cls")
        print('잘못 입력하셨습니다.')
        print('메뉴중 수를 입력해 주세요!')
        time.sleep(1)
        return 0
    return select


def sdes():
    global printList
    global plaintext
    os.system("mode con cols=120 lines=50")  # 가로 120, 세로 50으로 콘솔창 사이즈 조절
    key = 0
    message = ''

    while True:
        os.system("cls")  # 화면 clear
        try:
            key = int(input('10비트의 키(Key) 값을 입력하세요 (0~1023) : '))
            if 0 <= key <= 1023:
                break
            else:
                raise TypeError
        except:
            os.system("cls")
            print('잘못 입력하셨습니다.!!')
            print('정확한 수치를 입력해 주세요! ^^')
            time.sleep(1)  # 1초대기
    while True:
        os.system("cls")
        plaintext = input('메시지를 입력해주세요! (10 자리까지 입력): ')
        if len(message) <= 10:
            break
        os.system("cls")
        print('잘못 입력하셨습니다.!!')
        print('정확한 수치를 입력해 주세요! ^^')
        time.sleep(1)
    # len(data) == 22

    makeArrkey(key)
    Encrypt()
    Decrypt()
    print('암호문 : ', printList[14])
    print('복호문 : ', printList[21])
    print('계속하려면 아무 키나 누르십시오 . . . ')
    m.getch()  # 아무 키 입력 대기
    printList = ['' for i in range(22)]


def printProcess():
    global printList
    os.system("cls")
    print('\n')
    print('                                                  KEY :  ', printList[0])
    print('                                                          │')
    print('                                                  P10     ↓')
    print('                                                  ┌--------------┐')
    # 컬러로 print 하실경우 아래처럼 변경 하시면 됩니다.
    # print('           MESSAGE :'+colored(format(printList[6]),'blue')+'                │'+colored(format(printList[1]),'yellow')+'│                       MESSAGE')
    print('           MESSAGE :' + format(printList[6]) + '                │' + format(
        printList[1]) + '│                       MESSAGE')
    print('           ┌--------------┐                       └--------------┘                       ┌--------------┐')
    print('           │' + format(
        printList[7]) + '|                               │                              │' + format(
        printList[21]) + '│')
    print('           └--------------┘                       Shift   ↓                             └--------------┘')
    print('                   │                              ┌--------------┐                               ↑')
    print(
        '           IP      ↓                             │' + format(printList[2]) + '│                       IP￣¹  │')
    print('           ┌--------------┐                       └--------------┘                       ┌--------------┐')
    print('           │' + format(
        printList[8]) + '│                               ├━━━━━━━━━┐                    │' + format(
        printList[20]) + '│')
    print('           └--------------┘                       P8      ↓        │                    └--------------┘')
    print('                   │                              ┌--------------┐  │                            ↑')
    print('           FK 1    ↓                             │' + format(
        printList[3]) + '│  │                    FK 1    │')
    print('           ┌--------------┐                       └--------------┘  │                    ┌--------------┐')
    print('           │' + format(
        printList[9]) + '│   ←───────────────────────────→                            │' + format(printList[19]) + '│')
    print('           └--------------┘                               ┌━━━━━━━━━┘                    └--------------┘')
    print('                   │                              Shift   ↓                                     ↑')
    print('           SW      ↓                             ┌--------------┐                       SW      │')
    print('           ┌--------------┐                       │' + format(
        printList[4]) + '│                       ┌--------------┐')
    print('           │' + format(
        printList[10]) + '│                       └--------------┘                       │' + format(
        printList[18]) + '│')
    print('           └--------------┘                       P8      ↓                             └--------------┘')
    print('                   │                              ┌--------------┐                               ↑')
    print('           FK 2    ↓                             │' + format(
        printList[5]) + '│                       FK 2    │')
    print('           ┌--------------┐                       └--------------┘                       ┌--------------┐')
    print('           │' + format(
        printList[11]) + '│   ←───────────────────────────→                            │' + format(printList[17]) + '│')
    print('           └--------------┘                                                              └--------------┘')
    print('                   │                                                                             ↑')
    print('           IP￣¹  ↓                                                                    IP      │')
    print('           ┌--------------┐                                                              ┌--------------┐')
    print('           │' + format(
        printList[12]) + '│                                                              │' + format(
        printList[16]) + '│')
    print('           └--------------┘                                                              └--------------┘')
    print('                   │                                                                             ↑')
    print('                   ↓                                                                            │')
    print('            CipherText                                                                   ┌--------------┐')
    print('           ┌--------------┐                                                              │' + format(
        printList[15]) + '│')
    print('           │' + format(
        printList[13]) + '│                                                              └--------------┘')
    print('           └--------------┘                                                               CipherText : ' +
          printList[14])


def speed(speedNum: int):
    os.system("cls")
    print('암호화 / 복호화 과정의 속도를 조절 할 수 있습니다.')
    print('1~10 사이의 수를 입력해 주세요!(기본속도 5 : 0.5초를 의미함)')
    print('참고.세팅한 속도는 프로그램이 켜져 있는 동안 기억함.')
    print('현재 속도 :', speedNum)

    try:
        speedNum = int(input('> '))
        if speedNum < 0 or speedNum > 10:
            raise TypeError
    except:
        os.system("cls")
        print('잘못 입력하셨습니다.!!')
        print('정확한 수치를 입력해 주세요! ^^')
        time.sleep(1)
        return speed(speedNum)
    return speedNum


def readme():
    os.system("cls")
    print('\n S-DES : 8Bit 의 메세지를 10Bit 의 키 값을 이용하여')
    print(' 암호화 / 복호화 과정을 보여주는 툴 입니다.')

    print(
        '\n    1 번 메뉴를 통해서 암호화 및 복호화 과정을 볼 수 있으며\n    입력해야 할 값은 KEY 값 (0 ~ 1023 사이의 수) 과 암호화\n    할 메세지(10자리까지 입력 가능) 를 입력하면 암호화 과정과\n    복호화 과정을 순차적으로 보여줍니다.')

    print(
        '\n    2 번 메뉴는 1번 메뉴에서 암/복호화 과정의 속도를 조절 할 수\n        있도록 조절 할 수 있는 메뉴 입니다. 1 ~ 10 까지의 수를 입력\n        할 수 있고, 기본값으로 5가 설정 되어 있습니다.')

    print('\n    3 번 메뉴는 도움말 메뉴 입니다.')
    print('\n    4 번 메뉴는 프로그램을 종료 하는 메뉴입니다.')
    print('                                                        감사합니다.\n\n')
    print('계속하려면 아무 키나 누르십시오 . . . ')
    m.getch()  # 아무 키 입력 대기


if __name__ == "__main__":
    status = 0
    while True:
        if status == 1:
            sdes()
            status = 0
        elif status == 2:
            speedNum = speed(speedNum)
            status = 0
        elif status == 3:
            readme()
            status = 0
        elif status == 4:
            break
        else:
            status = main()