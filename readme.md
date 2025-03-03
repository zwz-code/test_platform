<h1 align="center" > 安全测试平台</h1>
<p align="center"><span></span></p>
<h5 align="center"> 功能：漏洞检测扫描、端口扫描、目录扫描、流量回放</a></h5>
<h4 align="center" >
	<a >项目介绍 -</a>
	<a >功能说明 -</a>





## 项目介绍

### 系统简介

本项目是一款基于 **Python-Django** 开发的**多功能 Web安全测试平台**，其核心功能包含**漏洞检测扫描、端口扫描、目录扫描、流量回放**等功能。


### 项目功能

本系统包含了常用的web安全测试功能，如端口扫描、目录识别、信息泄露检测、漏洞检测扫描等，并揭示测试URI地址存在的漏洞以及危害等级并给出修复建议。通过这一系列的步骤，可以对Web应用进行全面安全测试，从而发现存在的安全隐患。Web安全测试集成了常用的安全测试工具，包含了公司内部产品工具和一些开源工具，通过API接口进行开发，并对测试完成的结果进行可视化展示和统计。该平台简化了测试流程，通过平台配置即可完成一系列的复杂测试，并且对接Devops平台打通了CI/CD流程。此外该平台包含了流量回放功能，该功能基于tcpreplay进行二次开发，来处理pcap文件的上传和回放，该功能可以准确回放真实流量，通过回放Pcap包进行攻防验证。

###  相关技术


| 名称     | Python    | Django    | MySql | ECharts   | Redis | Celery | Boostrap Table |
| -------- | --------- | --------- | ---------- | --------- | --------- | -------------- | ---------- |
| **版本** | **3.10.5** | **5.1.2** | **8.0.29** | **5.6.0** | **7.05** |  **5.3.0**   | **1.19.1** |



## 功能说明

### 流量回放

#### 功能描述

该功能主要是针对上传的pcap包进行预处理和回放流量，该功能可以准确执行回放真实流量和协议仿真，通过回放Pcap包进行攻防验证。此外，通过Celery异步任务队列管理多任务并发执行。通过以上功能搭建一套靶场回放系统。

#### 实现效果
流量模板新建：
![image](https://github.com/zwz-code/test_platform/blob/master/picture/upload.png)


任务队列编辑下发
![image](https://github.com/zwz-code/test_platform/blob/master/picture/huifang.png)


查看已经下发的任务状态
![image](https://github.com/zwz-code/test_platform/blob/master/picture/task.png)
#### 详细实现

Pcap包回放功能需要集成tcpreplay工具，并使用预处理工具（如 `tcprewrite` 或 `Scapy`）修改 `.pcap` 文件后再进行回放。此外使用Celery和redis实现异步任务队列进行多任务下发管理，

单个回放任务的下发参数配置由Django Model进行建立：

```python
from django.db import models
from django.contrib.auth.models import User

class PcapFile(models.Model):
    name = models.CharField("场景名称", max_length=100)
    description = models.TextField("场景描述")
    SIM_TYPE_CHOICES = [
        ('IP', 'IP仿真'),
        ('PROTOCOL', '协议仿真')
    ]
    sim_type = models.CharField("仿真类型", max_length=20, choices=SIM_TYPE_CHOICES)
    MODE_CHOICES = [
        ('SERIAL', '单向'),
        ('BIDIRECTIONAL', '双向')
    ]
    target_mode = models.CharField("目标模式", max_length=20, choices=MODE_CHOICES)
    target_port = models.IntegerField("目标端口", default=8080)
    protocol = models.CharField("协议类型", max_length=20)
    
    # 高级配置
    pcap_file = models.FileField(upload_to='pcaps/')
    created_by = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

class ReplayTask(models.Model):
    TASK_STATUS_CHOICES = (
        ('queued', '队列中'),
        ('running', '运行中'),
        ('completed', '已完成'),
        ('failed', '失败'),
    )
    pcap_file = models.ForeignKey(PcapFile, on_delete=models.CASCADE)
    task_id = models.CharField(max_length=255, unique=True)
    status = models.CharField(max_length=20, choices=TASK_STATUS_CHOICES, default='queued')
    speed_factor = models.FloatField(default=1.0)  # 回放速度倍数
    started_at = models.DateTimeField(null=True)
    finished_at = models.DateTimeField(null=True)
```

进行网络流量回放时，需要修改原始数据包的数据，如源目的地址。或者对原数据包进行筛选或按不同的协议类型进行分类。因此可能需要结合其他工具，如tcprewrite（属于tcpreplay套件的一部分）来预处理pcap文件。此外对原包进行筛选分类需要Python的第三方库Scapy来进行自动化处理。

```bash
#!/bin/bash

 output_file="./modified/$(basename $file)"
 tcprewrite \
        --enet-smac=00:11:22:33:44:55 \
        --enet-dmac=66:77:88:99:AA:BB \
        --srcipmap=0.0.0.0/0:192.168.1.100 \
        --dstipmap=0.0.0.0/0:10.0.0.200 \
        --fixcsum \
        --infile="$file" \
        --outfile="$output_file"

```

```python
from scapy.all import rdpcap

def analyze_protocols(pcap_file):
   
    packets = rdpcap(pcap_file)
    protocol_counts = {}
    
    for pkt in packets:
        layer = pkt
        # 遍历数据包的每一层协议
        while isinstance(layer, (Packet,)):
            proto_name = layer.__class__.__name__
            protocol_counts[proto_name] = protocol_counts.get(proto_name, 0) + 1
            layer = layer.payload
    
    return protocol_counts
```

此外，当Pcap文件过大时，需要考虑进行大文件的特殊处理，为了解决这个问题，可以使用分块上传和断点续传技术。本系统将采用第一种方案将大文件分成多个小块进行传输。此外考虑部分文件丢失的问题，假如一个8MB的文件上传，其中第2块和第6块失败了，那么重新上传的时候应该可以只上传第2第6，这样能减少再次上传的大小。代码实现如下：

```python
@csrf_exempt
def check_file(request):
	"""
	:info 判断文件是否存在
	:param equest:
	:return:
	"""
	try:
		if request.method == 'POST':
            body = request.PosT.dict()
            hava_file = File.objects.filter(md5=body['md5'])
            if hava file :
				# 判断文件是否上传完毕
				file = hava _file.first()
				file chunk list = [chunk.chunk number for chunk in file.chunks.all()]
                if 	len(file_chunk_list)== int(file.total_chunks):
					return JsonResponse({'status': 'error','err_msg': 'File is exists'})
            	else:
					un_upload_chunk_list = {i for i in range(int(file.total_chunks))}
                    for i in file_chunk_list:
						un_upload_chunk_list.remove(i)
					return JsonResponse({'status': 'ok', 'msg': 'File is exists bug not enough',
                                         'data': list(un_upload_chunk_list)})
			file = File(**body)
			file.save()
            retunn JsonResponse(f'status':'ok','msg': 'File is upload'})
        else:
			return JsonResponse({'status': 'error', 'err_msg': 'Method Not Allowed'})
   except Exception as e:
    return JsonResponse({'status': 'error','err_msg': str(e)})

@csrf_exempt
def upload_chunk(request):
"""
:info 上传文件分片
:param request:
:return
"""
try:
	if request.method =='POST':
		file_id = request.PosT.get('file_id')
		chunk_number =int(request.PosT.get('chunk_number'))
		file_chunk = request.FILES['file']
		chunk = Filechunk(file_id=file_id,chunk_number=chunk_number, file_chunk=file_chunk
		chunk.save()
		return JsonResponse({'status': 'ok'})
	else:
        return JsonResponse({'status': 'error', 'err_msg': "Method Not Allowed'})
except Exception as e:
    return JsonResponse({'status':'error', 'err_msg':str(e)})
                             
def fileUpload(request):
	file_chunks = File.objects.values()
	paginator=Paginator(file_chunks，10)#每页显示10个文件
    page_number = request.GET.get('page')
    page _obj= paginator.get_page(page number)
    for i in page_obj:
        file = File.objects.get(file id=i.get('file_id'))
        i["chunk"], i["total_chunks"], i["upload_percent"],i['chunk_number_list'] = get_file_chunk
    return render(request,'fileUpload/fileUpload.html',f'page_obj': page_obj})
```

回放通过对tcpreplay的二次开发来实现，tcpreplay是专门用于流量回放的工具。此外tcpreplay包含多种配置参数，可实现定制化回放。

WebSocket可以实现实时日志展示打印，显示回放状态。

```python
from celery import shared_task
from subprocess import Popen, PIPE, STDOUT
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
import time
from .models import ReplayTask

@shared_task(bind=True)
def replay_pcap_task(self, task_id, pcap_path, speed_factor):
    channel_layer = get_channel_layer()
    task = ReplayTask.objects.get(task_id=task_id)
    
    try:
        task.status = 'running'
        task.save()
        
        # 使用tcpreplay执行回放（高性能）
        cmd = [
            'tcpreplay',
            '--intf1=eth0',         
            '--multiplier', str(speed_factor),
            ' --stats=5'          # 每5秒输出统计信息
 			'--enable-file-cache'  # 启用文件缓存提升性能
            pcap_path
        ]
        
        # 启动子进程并捕获实时输出
        proc = Popen(cmd, stdout=PIPE, stderr=STDOUT, text=True)
        
        # 实时发送日志到WebSocket
        while True:
            output = proc.stdout.readline()
            if output == '' and proc.poll() is not None:
                break
            if output:
                async_to_sync(channel_layer.group_send)(
                    f"task_logs_{task_id}",
                    {"type": "task_log", "message": output.strip()}
                )
        
        # 更新任务状态
        exit_code = proc.poll()
        if exit_code == 0:
            task.status = 'completed'
        else:
            task.status = 'failed'
        task.save()
        
    except Exception as e:
        task.status = 'failed'
        task.save()
        async_to_sync(channel_layer.group_send)(
            f"task_logs_{task_id}",
            {"type": "task_log", "message": f"任务失败: {str(e)}"}
        )
 
from channels.generic.websocket import AsyncWebsocketConsumer
import json

class TaskLogConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.task_id = self.scope['url_route']['kwargs']['task_id']
        self.group_name = f"task_logs_{self.task_id}"
        
        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )
        await self.accept()
    
    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name
        )
    
    async def task_log(self, event):
        await self.send(text_data=json.dumps({
            'type': 'log',
            'message': event['message']
        }))
```

回放是长时间的任务，需要占用大量时间。长时间任务则需要Celery来异步处理，避免阻塞Django的请求响应周期。

```python
import os
from celery import Celery
from django.conf import settings

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'pcap_replay.settings')
app = Celery('pcap_replay')
app.config_from_object('django.conf:settings', namespace='CELERY')
app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)
.........
```



### 漏洞检测

> 该功能主要是对目标URI进行web安全漏洞扫描，漏洞扫描功能是基于调用 AWVS 13 或者RSAS和Xrap三种扫描工具，三者均采用对提供的API接口进行二次开发，用户下发扫描任务可以选择扫描工具。此外，还有一些web漏洞是基于基于脚本模拟网络请求实现。根据漏洞形成的原因，生成一些测试 payload 发送到目标系统，再由返回的状态码和数据来判断payload是否有效。

### 实现效果



### 详细实现

基于AWVS的漏洞扫描检测 ： 

漏洞扫描检测任务首先工作是添加待扫描目标到 AWVS 扫描队列中。AWVS 13提供了API 接口: POST`https:{host}/api/v1/targets`，POST 请求参数为：`{"address":"XXXX.XXXX.XXXX","description":"xxxx","criticality":"10"}`。

当请求成功并返回状态码200后表示添加AWVS队列成功，返回值中包含一个 target_id ，这个值在所有扫描中是唯一的。添加完目标队列后接下来下发扫描任务，通过API 接口实现：`/api/v1/scans`，使用 POST 请求，POST 请求参数为：`{"target_id":"xxxxxxx","profile_id":"xxxxxxx"}`。

使用 Python 的第三方库 requests 来实现 API 接口的封装:

```python
try:
   	response = requests.post(targets_api, auth_headers, data, False)
	result = response.json()
	target_id = result.get('target_id')
   	return target_id
except Exception:
	return None

try:
    response = requests.post(scan_api, data, auth_headers, False)
    print(response.json())
    if response.status_code == 200:
        return True
except Exception:
	return None
```

API 接口封装已经实现，在 **views.py** 中定义 `vuln_scan()` 函数接收前端的用户输入，并调用已经封装好的 API 函数。用户输入的 url 为扫描的目标，扫描类型包括SQL注入、XSS漏洞、高位漏洞、全漏洞扫描等，如果添加成功后返回的 target_id 不是 None，说明添加扫描任务成功，开始调用AWAS 13进行扫描，开始扫描后返回状态码为200则开始扫描

```python
@csrf_exempt
def vuln_scan(request):
    url = request.POST.get('ip')
    scan_type = request.POST.get('scan_type')
    t = Target(API_URL, API_KEY)
    #将目标URL添加到扫描队列中
    target_id = t.add(url)
    #如果target_id不为None,则开始扫描
    if target_id is not None:
        s = Scan(API_URL, API_KEY)
        status_code = s.add(target_id, scan_type)
        if status_code == 200:
            return success()
    return error()
```

使用 JavaScript 来实现发送前端用户输入的数据，选择通过 POST 方法发送数据，并在发送之前判断用户输入的合法性

```javascript
function get_scan_info(ip , scan_type) {
#使用POST请求发送用户输入
        $.post('/vuln_scan', {
            ip: ip ,
            scan_type: scan_type
        }, function (data) {
            if (data.code !== 200) {
                ......
            } else {
                ...... 
            }
           ......});
    }
var domain = $('input[name=scan_url]').val();
#使用循环判断用户选择的扫描类型
for(var i=0; i<document.getElementsByName("scan_type").length; i++) {
    if (document.getElementsByName("scan_type")[i].checked) {
      var scan_type=document.getElementsByName("scan_type")[i].value;
    }
}
if(domain){
	get_scan_info(domain,scan_type)
}else{
	......
}
```

将目标扫描的结果保存到数据库中，我们需要得到所有的扫描目标，API接口请求方式为 GET，`‘/api/v1/scans‘`，请求成功后会返回所有扫描目标的信息，利用这个 API 可以实现展示所有扫描目标。要实现展示每个扫描目标的所有漏洞的功能，需要按照 target_id 来在所有扫描目标中搜索。AWVS 也提供了相应的 API，我们需要用到的 API 为：`/api/v1/vulnerabilities`

`?q=severity:{int};criticality:{int};status:{string};cvss_score:{logicexpression};cvss_score:{logicexpression};target_id:{target_id};group_id:{group_id}`。请求方式为 GET。利用 target_id 搜索每个扫描目标。当使用 target_id 搜索扫描目标成功时将会返回这个目标的所搜漏洞信息，包括这个目标包含的漏洞个数、每个漏洞的危险等级、扫描时间、扫描类型、扫描状态等信息。

具体实现步骤和添加扫描目标大体相似，首先第一步使用 requests 来实现 API 请求。核心代码如下：

```python

response=requests.get(scan_api, self.auth_headers, False) 
scan_response=response.json().get('scans')
for scan in scan_response:
   scan['request_url'] = request_url
   scan_list.append(scan)
return scan_list
vuln_search_api=f'{vuln_api}?q=status:{status};target_id:{target_id}'
try:
    response = requests.get(vuln_search_api, auth_headers, False)
    return response.text
except Exception:
    return None
```

在 **urls.py** 中加入用户访问的 url ，这个需要提供一个 target_id 方便后续功能的实现，先获取所有目标的target_id，然后使用循环将所有 target_id 加入到 urlpatterns 列表中。因为在 Django 中 views 函数通常只能使用一个 request 参数，由于这里需要将 target_id 传入到 views 函数中，使用正则匹配的 `“(?P<target_id>.*)$”` 接收传入的 target_id，在 views 里对应函数的第二个形参名必须和 `<>` 里的值一致才有效。核心代码如下：

```python
path('vulnscan', views.vulnscan, name="vulnscan"),
for target_id in target_ids:
	  #使用正则匹配获取第二个参数：taget_id
urlpatterns.append(url(r'^vuln_result/(?P<target_id>.*)$', views.vuln_result, name='vuln_result/'+target_id))
```

在 **views.py** 里定义函数 `vulnscan(request)` 获取所有对应的目标漏洞信息。使用 API 得到返回的漏洞危险等级、扫描目标URL、每个漏洞唯一标识的 vuln_id、扫描类型、扫描处理时间，API 返回的扫描处理时间不是标准的时间格式，使用正则匹配的方式，将其转换为 `“%Y-%m-%d %H:%M:%S“` 的格式，再定义函数 `vuln_result(request,target_id)`，根据 target_id 获取扫描目标中所有漏洞信息，包括存在漏洞的URL、漏洞类型、状态和处理时间等信息。核心代码如下：

```python

def vuln_result(request, target_id):
    d = Vuln(API_URL, API_KEY)
    data = []
    vuln_details = json.loads(d.search(None,None, "open", target_id=str(target_id)))

    id = 1
    for target in vuln_details['vulnerabilities']:
        item={
            'id': id,
            'severity': target['severity'],
            'target': target['affects_url'],
            'vuln_id':target['vuln_id'],
            'vuln_name': target['vt_name'],
            'time': re.sub(r'T|\..*$', " ", target['last_seen'])
        }
        id += 1
        data.append(item)
    return render(request,'vuln-reslut.html',{'data': data})
```

在 **views.py** 函数中返回的到相应的 HTML 页面时，将 data 字典一起返回。这样的返回方式可以将使用字典中的 key 值获取对应的 values 值。还可以是使用 if-else、for 等语句来分类展示数据。核心代码如下：

```django
{% for item in data %}
……………
# 这个只展示了扫描目标列，其他列类似 
<a href="/vuln_detail/{{ item.vuln_id }}"> {{ item.target }}</a>
……………
{% endfor %}
```

通过上述的代码实现，实现了将用户输入通过 JavaScript 传输给后台，后台接收数据后将调用 AWVS API，然后 AWVS 开始根据用户输入开始扫描目标 URL，扫描结束后将结果保存在数据库中。再在前端界面进行展示。

基于RSAS的漏洞扫描检测 ： 

基于RSAS的漏扫整体思路和AWVS一致，都是封装好RSAS的API接口并进行二次开发，再将扫描结果通过views.py函数返回相应的HTML页面进行展示。

RSAS使用 Python 的第三方库 requests 来实现 API 接口的封装:

```python
#!/usr/bin/env python
#-*-coding:UTF-8-*-
import requests
import re
import datetime
from baseConfig import BASECONFIG
 
class RSAS:
	def __init__(self,USERNAME,PASSWD,IP):
		self.URL = "https://" + IP
		self.HOST = IP
		self.USERNAME = USERNAME
		self.PASSWD = PASSWD
		self.SESSION = ''
		self.CSRFTOKEN = ''
		self.RSAS_HEADER = self.login()
		self.RSASCONFIG = BASECONFIG()
 
 
	def getCSRFToken(self,HTML,n = 0):
		try:
			if n == 1:
				return re.findall(r"""name='csrfmiddlewaretoken' value="(.*?)">""",HTML)[0]
			if n == 0:
				return re.findall(r"""{'data':d_s,"(.*?)',"targets":targets}""",HTML)[0]
			if n == 3:
				return re.findall(r"""<input type='hidden' value='(.*?)' name='csrfmiddlewaretoken' />""",HTML)[0]
		except:
			raise SystemExit('[-] Get Token Fail, Exitting')
 
 
	def getCookie(self,HEADER,CSRF):
		setCookie = HEADER['set-cookie']
		session = re.findall(r'sessionid=(.*?);',setCookie)[0]
		return 'csrftoken={}; sessionid={}'.format(CSRF,session)
 
 
	def getsession(self,cookie):
		return re.findall(r'=(.*?);',cookie)[0]
 
 
	def init_session(self):
		headers = {
					'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0',
					'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
					'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
					'Accept-Encoding':' gzip, deflate, br',
					'DNT': '1',
					'Connection': 'close',
					'Upgrade-Insecure-Requests': '1'
		}
		res = requests.get(url = self.URL, verify = False, headers = headers, allow_redirects = False)
		return self.getsession(res.headers['set-cookie'])
 
 
	def second_session(self):
		Cookie = self.init_session()
		self.SESSION = Cookie
		headers = {
					'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0',
					'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
					'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
					'Accept-Encoding':' gzip, deflate, br',
					'DNT': '1',
					'Connection': 'close',
					'Upgrade-Insecure-Requests': '1',
					'Cookie': 'sessionid=' + Cookie
		}
		return headers
 
 
	def check_login(self,HEADER):
		if HEADER['location'] == self.URL + '/':
			print("[+] 登录成功....")
		else:
			print("[+] 登录失败....")
 
 
	def login(self):
		tmp_header = self.second_session()
		res = requests.get(url = self.URL + '/accounts/login/', verify = False, headers = tmp_header, allow_redirects = False)
		CSRFTOKEN = self.getCSRFToken(res.content,1)
		self.CSRFTOKEN = CSRFTOKEN
		data = {
		'username' : self.USERNAME,
		'password' : self.PASSWD,
		'csrfmiddlewaretoken' : CSRFTOKEN
		}
		tmp_cookie = 'csrftoken='+ CSRFTOKEN + '; sessionid=' + self.SESSION
		headers={
					'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0',
					'Host': self.HOST,
					'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
					'Connection': 'close',
					'Cookie': tmp_cookie,
					'Referer': self.URL + '/accounts/login/',
					'Upgrade-Insecure-Requests': '1',
					'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
					'Content-Length': '87'
		}
		cookie_html = requests.post(url = self.URL + '/accounts/login_view/',data = data, verify = False, headers=headers,allow_redirects = False)
		self.check_login(cookie_html.headers)
		Cookie = self.getCookie(cookie_html.headers, CSRFTOKEN)
		headers = {
					'Host': self.HOST,
					'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0',
					'Accept': '*/*',
					'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3',
					'Content-Type': 'application/x-www-form-urlencoded',
					'X-Requested-With': 'XMLHttpRequest',
					'Referer': self.URL + '/task/',
					'Cookie': Cookie +'; left_menustatue_NSFOCUSRSAS=1|0|https://'+ self.HOST +'/task/',
					'DNT': '1',
					'Connection': 'close'
		}
		return headers
 
 
	def RSASTask(self,DATA,NAME):
		sub_res = requests.post(url=self.URL+'/task/vul/tasksubmit',data=DATA,headers=self.RSAS_HEADER, verify=False, timeout = 60)
		if 'msg:suc' in sub_res.content:
			print("[+] 成功添加任务 {}".format(NAME))
		else:
			print("[-] 添加任务失败 {}".format(NAME))
 
 
	def getrealPass(self, Keyword, HTML):
		return re.findall("""<option value='(.*?)'>{}</option>""".format(Keyword),HTML)
 
```

##  端口扫描

### 设计思路

本系统端口扫描的实现方法是利用nmap 扫描器进行直接调用，python有封装好的nmap库。指定了目标IP地址后，系统正式工作，IP传入后台对目标进行扫描，扫描完成后将开放端口和对应服务显示到前端界面上。为了提高了扫描的效率，本系统引入多线程扫描机制。

### 实现效果
![image](https://github.com/zwz-code/test_platform/blob/master/picture/portscan.png)


### 详细实现

多线程优化：单线程（串行）阻塞运行，会耗费大量时间，因此，通过并发的方式，并发请求，提升扫描速度，通过对比扫描300个端口单线程需要30s左右，多线程仅需10s左右。

本端口扫描功能中采用了并发50条线程来进行扫描，因此，在定义run方法时，每个线程扫描的两个端口号间差数为50，在程序中使用 concurrent.futures 来实现。

```python
THREADNUM = 50  # 线程数
def run(self, ip):  #多线程扫描
    hosts = []
    global PORTS, THREADNUM
    for i in PORTS:
        hosts.append('{}:{}'.format(ip, i))
    try:
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=THREADNUM) as executor:
            executor.map(self.socket_scan, hosts)
    except EOFError:
        pass
```



## 目录扫描

### 设计思路

该功能集成Dirsearch进行开发，Dirsearch主要用于对 Web 服务器进行目录和文件枚举。 扫描的结果通过 JSON的格式保存在对应的路径下。获取的数据被分成 URL 和 TIMR，URL下又分为 content-length、path、redirect、starus四个部分。因为在 JSON 格式中被不同类型括号的数据会被 Django 解析为列表、字典等格式，因此我们需要对获得的 JSON 数据进行处理，将其转换为 Django 可以识别的数据，使之在前端进行读取。

### 实现效果
![image](https://github.com/zwz-code/test_platform/blob/master/picture/dirscan.png)




