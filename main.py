#!/usr/bin/env python3
# coding: utf-8
import os
import re
import time
import json
import base64
import hashlib
import requests
from PIL import Image
from io import BytesIO
from Crypto.Cipher import AES


viewerName = input("请输入手机号：")


def toBytes(target: str) -> bytes:
    """将字符串转16进制Bytes
    :param: target: 待转换的字符串
    :return: 转换结果
    """
    result = []
    for i in range(0, len(target), 2):
        result.append(int(target[i:i+2], 16))
    return "".join(map(chr, result)).encode('latin1')


def decodeKey(originKey: bytes, vid: str) -> bytes:
    """解密原始Key，获取真实Key
    :param: originKey: 原始被加密的Key
    :param: vid: 视频id
    :return: 真实Key，可用于视频解密
    """
    temp = hashlib.md5(vid.encode()).hexdigest()
    key = temp[:16].encode()
    iv = temp[-16:].encode()
    jsonUrl = f"https://player.polyv.net/secure/{vid}.json"
    headers = {
        'user-agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
    }
    response = requests.get(jsonUrl, headers=headers).json()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = cipher.decrypt(toBytes(response["body"]))
    jsonData = base64.b64decode(data).decode()
    seedConst = re.findall(r'"seed_const":(.*?),', jsonData)[0]
    temp = hashlib.md5(seedConst.encode()).hexdigest()
    key = temp[:16].encode('latin1')
    iv = base64.b64decode("AQIDBQcLDRETFx0HBQMCAQ==")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(originKey)[:16]


def checkName(target:str) -> str:
    """过滤非法文件名字符
    :param: target: 待过滤字符串
    :return: 合法字符串
    """
    return re.sub('[\/:*?"<>|]','',target)


if not os.path.exists("./videoInfo"):
    os.mkdir("./videoInfo")


url = "https://ke.gupaoedu.cn/wx-api/wx/focuslogin/authQrcode"
response = requests.get(url).json()
codeUrl = response["data"]['codeUrl']
ticket = response["data"]['ticket']
codeImage = requests.get(codeUrl)
Image.open(BytesIO(codeImage.content)).show()
while True:
    response = requests.get(f"https://ke.gupaoedu.cn/wx-api/wx/focuslogin/checkLogin?ticket={ticket}").json()
    if response["data"]["code"] == 0:
        openId = response["data"]["data"]["openId"]
        unionId = response["data"]["data"]["unionId"]
        print("#"*46)
        print(f"{'>'*5}登录成功，现在你可以关闭二维码窗口了{'<'*5}")
        print("#"*46)
        break
    time.sleep(1)
viewerId = unionId
data = {
    "loginType":2,
    "terminalType":31,
    "unionId":unionId,
    "openId":openId,
    "platformId":100
}
headers = {
    'Content-Type': "application/json;charset=UTF-8",
    'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
}
response = requests.post("https://passport.gupaoedu.cn/api/passport/login/wx", headers=headers, json=data).json()
headers['token'] = response["data"]["token"]["code"]


data = {
    'pageIndex': 1,
    'pageSize': 12,
    'filter': 0
}
response = requests.post("https://ke.gupaoedu.cn/api/v2/study/myList", headers=headers, json=data)
classList = response.json()["data"]["data"]
print()
print("课程列表如下：")
for index, each in enumerate(classList, start=1):
    print(index, each["title"])
print()

print("开始收集信息...")
for eachClass in classList:
    videoCount = 1
    classTitle = checkName(eachClass['title'])
    os.mkdir(f"./videoInfo/{classTitle}")
    videoInfo = []
    url = f"https://ke.gupaoedu.cn/api/v2/curriculum/outline?curriculumId={eachClass['id']}&onlyOwner=1&classId={eachClass['currentClassId']}"
    response = requests.get(url, headers=headers)
    for each in response.json().get("data").get("outlineVOList"):
        for video in each["sectionDetailList"]:
            videoInfo.append((video['content'], video['title']))
    for vid, name in videoInfo:
        data = {
            'cuId': eachClass['id'],
            'phaseId': eachClass['currentClassId'],
            'videoId': vid,
            'viewerId': viewerId,
            'viewerName': viewerName,
        }
        print(data)
        response = requests.post("https://ke.gupaoedu.cn/nodeapi/v1/admin/videoes/play/auth", headers=headers, json=data)
        print(response.json())
        keyTokne = response.json()["data"]["token"]
        m3u8ListUrl = f"https://hls.videocc.net/{vid[:10]}/{vid.split('_')[0][-1]}/{vid.split('_')[0]}.m3u8?device=desktop"
        response = requests.get(m3u8ListUrl, headers=headers)
        m3u8List = [each for each in response.text.split(
            '\n')[:-1] if not each.startswith("#")]
        m3u8Url = f"https://hls.videocc.net/{vid[:10]}/{vid.split('_')[0][-1]}/{m3u8List[0]}"
        response = requests.get(m3u8Url, headers=headers)
        keyUrl = re.findall(r'URI="(.*?)"', response.text)[
            0] + f"?token={keyTokne}"
        iv = bytes.fromhex(re.findall(r'IV=0x(.*?)\n', response.text)[0])
        tsUrlList = [each for each in response.text.split(
            '\n')[:-1] if not each.startswith("#")]
        originKey = requests.get(keyUrl, headers=headers).content
        assert len(originKey) != 0, ValueError("没拿到Key")
        relKey = decodeKey(originKey, vid)
        with open(f"./videoInfo/{classTitle}/{videoCount}-"+checkName(name)+".json", "w", encoding="utf-8") as f:
            f.write(json.dumps({
                'iv': base64.b64encode(iv).decode(),
                'key': base64.b64encode(relKey).decode(),
                'tsUrls': tsUrlList
            }))
        videoCount += 1