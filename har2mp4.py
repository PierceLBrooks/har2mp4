
# Author: Pierce Brooks

import os
import sys
import copy
import json
import base64
import shutil
import hashlib
import inspect
import logging
import threading
import traceback
import subprocess
import multiprocessing
from urllib.parse import urlparse
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from bounded_pool_executor import BoundedProcessPoolExecutor

mutex = threading.Lock()
requests = []

class Responder(SimpleHTTPRequestHandler):
  def __init__(self, *args, **kwargs):
    super(SimpleHTTPRequestHandler, self).__init__(*args, **kwargs)
    self.directory = os.getcwd()

  def __getattr__(self, attribute):
    if (str(attribute) == "directory"):
      return os.getcwd()
    return super(SimpleHTTPRequestHandler, self).__getattribute__(attribute)

  def do_GET(self):
    global mutex
    global requests
    clone = None
    try:
      try:
        clone = copy.deepcopy(super())
      except:
        clone = None
      request = str(copy.deepcopy(self.path))
      mutex.acquire()
      requests.append(request)
      mutex.release()
      hasher = hashlib.sha1()
      hasher.update(os.path.dirname(request).encode())
      request = os.path.join(hash.hexdigest(), os.path.basename(request))
      self.path = request
      super().do_GET()
      #print(str(clone))
    except:
      #logging.error(traceback.format_exc())
      try:
        if (clone == None):
          super().do_GET()
        else:
          clone.do_GET()
      except:
        pass

def resolve(promises):
  for promise in promises:
    try:
      yield promise.result()
    except:
      pass

def execute(command):
  lines = []
  output = None
  try:
    process = subprocess.Popen(command, env=dict(os.environ.copy()), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    while True:
      line = process.stdout.readline()
      if ((len(line) == 0) and not (process.poll() == None)):
        break
      try:
        line = line.decode("UTF-8").strip()
      except:
        continue
      lines.append(line)
    status = process.communicate()[0]
    exit = process.returncode
    if (exit == 0):
      output = status
  except:
    #logging.error(traceback.format_exc())
    output = []
  if (output == None):
    return []
  return lines

def handle(httpd):
  try:
    httpd.serve_forever()
  except:
    httpd = None

def run(target, root):
  global mutex
  global requests
  #print(root)
  data = None
  content = ""
  try:
    descriptor = open(target, "r")
    content += descriptor.read()
    descriptor.close()
  except:
    pass
  if not (len(content) == 0):
    try:
      data = json.loads(content)
    except:
      pass
  if (data == None):
    return -1
  if not ("dict" in str(type(data)).lower()):
    return -2
  #print(str(list(data.keys())))
  if not ("log" in data):
    return -3
  data = data["log"]
  if not ("dict" in str(type(data)).lower()):
    return -4
  #print(str(list(data.keys())))
  if not ("entries" in data):
    return -5
  entries = data["entries"]
  mapping = {}
  manifests = []
  outputs = []
  errors = []
  urls = []
  for entry in entries:
    urls.append(None)
    if not ("request" in entry):
      errors.append(1)
      continue
    request = entry["request"]
    if not ("url" in request):
      errors.append(2)
      continue
    url = str(request["url"])
    urls[len(urls)-1] = url
    #print(url)
    if (url in mapping):
      errors.append(3)
      continue
    if not ("response" in entry):
      errors.append(4)
      continue
    response = entry["response"]
    if ("status" in response):
      if not (str(response["status"]) == "200"):
        errors.append(5)
        continue
    if not ("content" in response):
      errors.append(6)
      continue
    content = response["content"]
    if not ("text" in content):
      errors.append(7)
      continue
    text = str(content["text"])
    size = None
    if ("size" in content):
      size = int(content["size"])
    encoding = None
    if ("encoding" in content):
      encoding = content["encoding"]
    manifest = False
    descriptor = None
    path = ""+root
    try:
      parse = urlparse(url)
      if (parse.path.endswith(".m3u8")):
        manifest = True
      if (sys.flags.debug):
        requests.append(parse.path)
        path += requests[len(requests)-1]
      else:
        hasher = hashlib.sha1()
        hasher.update(os.path.dirname(parse.path).encode())
        path = os.path.join(path, os.path.join(hasher.hexdigest(), os.path.basename(parse.path)))
      #print(path)
      if not (os.path.exists(path)):
        try:
          os.makedirs(os.path.dirname(path))
        except:
          pass
      if (encoding == None):
        descriptor = open(path, "w")
      else:
        descriptor = open(path, "wb")
    except:
      if (sys.flags.debug):
        logging.error(traceback.format_exc())
      descriptor = None
    if (descriptor == None):
      try:
        os.unlink(path)
      except:
        pass
      errors.append(8)
      continue
    if not (manifest):
      if ("mimeType" in content):
        mime = str(content["mimeType"])
        if ((mime == "application/x-mpegURL") or (mime == "application/vnd.apple.mpegurl")):
          manifest = True
    if (manifest):
      name = os.path.basename(path)
      if (name in outputs):
        try:
          os.unlink(path)
        except:
          pass
        errors.append(9)
        continue
      outputs.append(name)
      manifests.append(url)
    try:
      if (str(encoding) == "base64"):
        text = base64.b64decode(text)
      if not (size == None):
        text = text[:size]
      descriptor.write(text)
    except:
      descriptor = None
    if (descriptor == None):
      try:
        os.unlink(path)
      except:
        pass
      errors.append(10)
      continue
    descriptor.close()
    mapping[url] = path
    errors.append(0)
  if (sys.flags.debug):
    for i in range(len(errors)):
      error = errors[i]
      print(str(i)+" = "+str(error)+" @ "+str(urls[i]))
    for key in mapping:
      print(key+" -> "+mapping[key])
  if (len(manifests) == 0):
    return -6
  port = 8081
  httpd = None
  while (port < 9001):
    try:
      if (sys.flags.debug):
        httpd = ThreadingHTTPServer(("127.0.0.1", port), SimpleHTTPRequestHandler)
      else:
        httpd = ThreadingHTTPServer(("127.0.0.1", port), Responder)
    except:
      httpd = None
    if not (httpd == None):
      break
    port += 1
  if (httpd == None):
    return -7
  thread = threading.Thread(target=handle, args=[httpd])
  try:
    thread.start()
  except:
    thread = None
  if (thread == None):
    return -8
  tasks = []
  with BoundedProcessPoolExecutor(max_workers=multiprocessing.cpu_count()) as worker:
    for i in range(len(manifests)):
      if not (manifests[i] in mapping):
        continue
      uri = os.path.relpath(mapping[manifests[i]], os.getcwd())
      if (len(uri) < 2):
        continue
      if (uri[0:1] == "/"):
        uri = uri[1:]
      command = []
      command.append("ffmpeg")
      command.append("-allowed_extensions")
      command.append("ALL")
      if (sys.flags.debug):
        command.append("-y")
      else:
        command.append("-nostdin")
      command.append("-i")
      command.append("http://127.0.0.1:"+str(port)+"/"+uri)
      command.append(os.path.join(os.getcwd(), outputs[i]+".mp4"))
      task = None
      try:
        task = worker.submit(execute, command)
      except:
        task = None
      tasks.append(task)
    for task in tasks:
      if (task == None):
        continue
      try:
        futures = resolve([task])
        for future in futures:
          for line in future:
            print(str(line))
      except:
        pass
  if (sys.flags.debug):
    mutex.acquire()
    for request in requests:
      print(request)
    mutex.release()
  try:
    httpd.shutdown()
    thread.join()
  except:
    pass
  return 0

def launch(arguments):
  if (len(arguments) < 2):
    return False
  ffmpeg = None
  try:
    ffmpeg = shutil.which("ffmpeg")
  except:
    ffmpeg = None
  if (ffmpeg == None):
    return False
  script = ""
  try:
    script = os.path.basename(inspect.getframeinfo(inspect.currentframe()).filename)
  except:
    script = ""
  index = 0
  while (index < len(script)):
    if (index == 0):
      index += 1
      continue
    if (script[index:(index+1)] == "."):
      script = script[:index]
      break
    index += 1
  target = arguments[1]
  result = 0
  root = os.path.join(os.getcwd(), script)
  if (len(script) == 0):
    return False
  if (os.path.exists(root)):
    if (sys.flags.debug):
      try:
        shutil.rmtree(root)
      except:
        pass
    else:
      return False
  try:
    os.makedirs(root)
  except:
    pass
  if not (os.path.exists(root)):
    return False
  try:
    result += run(target, root)
    #result *= 2
  except:
    logging.error(traceback.format_exc())
    result = None
  print(str(result))
  if not (sys.flags.debug):
    try:
      shutil.rmtree(root)
    except:
      pass
  if not (result == 0):
    return False
  return True

if (__name__ == "__main__"):
  try:
    print(str(launch(sys.argv)))
  except:
    pass

