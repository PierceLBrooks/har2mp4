
# Author: Pierce Brooks

import os
import sys
import json
import base64
import shutil
import inspect
import logging
import threading
import traceback
import subprocess
from urllib.parse import urlparse
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler

def handle(httpd):
  try:
    httpd.serve_forever()
  except:
    httpd = None

def run(target, root):
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
  for entry in entries:
    if not ("request" in entry):
      errors.append(1)
      continue
    request = entry["request"]
    if not ("url" in request):
      errors.append(2)
      continue
    url = str(request["url"])
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
      path += parse.path
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
      #logging.error(traceback.format_exc())
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
  """
  for error in errors:
    print(str(error))
  for key in mapping:
    print(key+" -> "+mapping[key])
  """
  if (len(manifests) == 0):
    return -6
  port = 8081
  httpd = None
  while (port < 9001):
    try:
      httpd = ThreadingHTTPServer(("127.0.0.1", port), SimpleHTTPRequestHandler)
    except:
      httpd = None
    if not (httpd == None):
      break
    port += 1
  if (httpd == None):
    return -7
  thread = threading.Thread(target=handle, args=[httpd])
  try:
    thread.run()
  except:
    thread = None
  if (thread == None):
    return -8
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
    command.append("-i")
    command.append("http://127.0.0.1:"+str(port)+"/"+uri)
    command.append(os.path.join(os.getcwd(), outputs[i]+".mp4"))
    try:
      output = subprocess.check_output(command)
      if not (output == None):
        output = output.decode()
        print(output)
    except:
      pass
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
  """
  try:
    shutil.rmtree(root)
  except:
    pass
  """
  if not (result == 0):
    return False
  return True

if (__name__ == "__main__"):
  try:
    print(str(launch(sys.argv)))
  except:
    pass

