
# Author: Pierce Brooks

import os
import sys
import copy
import json
import time
import base64
import shutil
import hashlib
import inspect
import logging
import datetime
import platform
import requests as requester
import tempfile
import functools
import threading
import traceback
import mimetypes
import subprocess
import multiprocessing
from urllib.parse import urlparse
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from bounded_pool_executor import BoundedProcessPoolExecutor
from mpegdash.parser import MPEGDASHParser

directory = os.getcwd()
mutex = threading.Lock()
requests = []
temporary = ""
try:
  if (platform.system().lower().strip() == "darwin"):
    temporary += "/tmp"
  else:
    temporary += tempfile.gettempdir()
except:
  temporary = ""

class Responder(SimpleHTTPRequestHandler):
  def __init__(self, *args, **kwargs):
    global directory
    super(SimpleHTTPRequestHandler, self).__init__(*args, **kwargs)
    self.directory = directory

  def __getattr__(self, attribute):
    global directory
    if (str(attribute) == "directory"):
      return directory
    return super(SimpleHTTPRequestHandler, self).__getattribute__(attribute)

  def do_GET(self):
    global directory
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
      requests.append([request])
      mutex.release()
      if (os.path.exists(os.path.join(directory, request))):
        request = None
      """
      if not (sys.flags.debug):
        hasher = hashlib.sha1()
        if (request == None):
          hasher = None
        if not (hasher == None):
          seed = os.path.dirname(request).replace("\\", "/")
          if (seed[0:1] == "/"):
            seed = seed[1:]
          if (seed.count("/") > 0):
            seed = "/".join(seed.split("/")[1:])
          #print(seed)
          hasher.update(seed.encode())
          request = os.path.join(directory, os.path.join(hasher.hexdigest(), os.path.basename(request)))
          if (len(request) == 0):
            request = None
          else:
            if not (request[0:1] == "/"):
              request ="/"+request
      """
      if not (request == None):
        request = request.replace("\\", "/").replace("//", "/")
        mutex.acquire()
        requests[len(requests)-1].append(request)
        mutex.release()
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

#"""
  def log_message(self, format, *args):
    pass
#"""

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
  if ((output == None) and not (sys.flags.debug)):
    return []
  return lines

def serve(httpd):
  try:
    httpd.serve_forever()
  except:
    httpd = None

def test(source):
  success = True
  try:
    request = requester.get(source.replace("\\", "/").replace("://", ":///").replace("//", "/"))
    if not (str(request.status_code).strip() == "200"):
      success = False
  except:
    success = False
    if (sys.flags.debug):
      logging.error(traceback.format_exc())
  if ((sys.flags.debug) and not (success)):
    print(source)
  return success

def remove(victim, location):
  if (location >= len(victim)):
    return victim
  change = []
  if (location == 0):
    if (len(victim) > 1):
      change += victim[1:]
    return change
  if (location == len(victim)-1):
    change += victim[:location]
    return change
  change += victim[:location]+victim[(location+1):]
  return change

def handle(http, mpd, node, level):
  if (node == None):
    return node
  this = ""
  kind = str(type(node))
  total = 0
  changes = 0
  if ("BaseURL" in kind):
    if not (node.base_url_value == None):
      this += node.base_url_value
      total += 1
      if not (test(http+os.path.join(mpd, node.base_url_value))):
        changes += 1
  elif ("URL" in kind):
    if not (node.sourceURL == None):
      this += node.sourceURL
      total += 1
      if not (test(http+os.path.join(mpd, node.sourceURL))):
        changes += 1
  elif ("Period" in kind):
    if not (node.base_urls == None):
      removals = []
      for i in range(len(node.base_urls)):
        total += 1
        if (handle(http, mpd, node.base_urls[i], level+1) == None):
          changes += 1
          removals.append(i)
      for removal in removals:
        node.base_urls = remove(node.base_urls, removal)
    if not (node.adaptation_sets == None):
      removals = []
      for i in range(len(node.adaptation_sets)):
        total += 1
        if (handle(http, mpd, node.adaptation_sets[i], level+1) == None):
          changes += 1
          removals.append(i)
      for removal in removals:
        node.adaptation_sets = remove(node.adaptation_sets, removal)
  elif ("AdaptationSet" in kind):
    if not (node.base_urls == None):
      removals = []
      for i in range(len(node.base_urls)):
        total += 1
        if (handle(http, mpd, node.base_urls[i], level+1) == None):
          changes += 1
          removals.append(i)
      for removal in removals:
        node.base_urls = remove(node.base_urls, removal)
    if not (node.representations == None):
      removals = []
      for i in range(len(node.representations)):
        total += 1
        if (handle(http, mpd, node.representations[i], level+1) == None):
          changes += 1
          removals.append(i)
      for removal in removals:
        node.representations = remove(node.representations, removal)
  elif ("Representation" in kind):
    if not (node.base_urls == None):
      removals = []
      for i in range(len(node.base_urls)):
        total += 1
        if (handle(http, mpd, node.base_urls[i], level+1) == None):
          changes += 1
          removals.append(i)
      for removal in removals:
        node.base_urls = remove(node.base_urls, removal)
  elif ("MPEGDASH" in kind):
    if not (node.base_urls == None):
      removals = []
      for i in range(len(node.base_urls)):
        total += 1
        if (handle(http, mpd, node.base_urls[i], level+1) == None):
          changes += 1
          removals.append(i)
      for removal in removals:
        node.base_urls = remove(node.base_urls, removal)
    if not (node.periods == None):
      removals = []
      for i in range(len(node.periods)):
        total += 1
        if (handle(http, mpd, node.periods[i], level+1) == None):
          changes += 1
          removals.append(i)
      for removal in removals:
        node.periods = remove(node.periods, removal)
  else:
    return node
  if (total == 0):
    return node
  if (len(this) == 0):
    this += kind
  if (sys.flags.debug):
    print(this+" @ "+str(level)+" = "+str(changes)+" / "+str(total))
  if (changes >= total):
    return None
  return node

def compare(left, right):
  left = left[0]
  right = right[0]
  if (("request" in left) and ("request" in right)):
    if (("url" in left["request"]) and ("url" in right["request"])):
      if (str(left["request"]["url"]) < str(right["request"]["url"])):
        return -1
      if (str(left["request"]["url"]) > str(right["request"]["url"])):
        return 1
      if (("response" in left) and ("response" in right)):
        if (("headers" in left["response"]) and ("headers" in right["response"])):
          for i in range(len(left["response"]["headers"])):
            if ("name" in left["response"]["headers"][i]):
              key = str(left["response"]["headers"][i]["name"]).strip().lower()
              if (key == "content-range"):
                for j in range(len(right["response"]["headers"])):
                  if ("name" in right["response"]["headers"][j]):
                    if (key == str(right["response"]["headers"][j]["name"]).strip().lower()):
                      if (("value" in left["response"]["headers"][i]) and ("value" in right["response"]["headers"][j])):
                        if (str(left["response"]["headers"][i]["value"]) < str(right["response"]["headers"][j]["value"])):
                          return -1
                        if (str(left["response"]["headers"][i]["value"]) > str(right["response"]["headers"][j]["value"])):
                          return 1
                        break
                break
  if (("startedDateTime" in left) and ("startedDateTime" in right)):
    if (str(left["startedDateTime"]) < str(right["startedDateTime"])):
      return -1
    if (str(left["startedDateTime"]) > str(right["startedDateTime"])):
      return 1
  return 0

def run(script, target, root):
  global directory
  global mutex
  global requests
  global temporary
  origin = os.getcwd()
  #print(root)
  data = None
  content = ""
  if ((target.startswith("http://")) or (target.startswith("https://"))):
    final = ""
    try:
      parse = urlparse(target)
      if (parse.path.endswith(".har")):
        final += os.path.join(os.getcwd(), os.path.basename(parse.path))
      else:
        final += script
    except:
      final += script
    if not (os.path.exists(final)):
      try:
        request = requester.get(target, stream=True)
        if (str(request.status_code).strip() == "200"):
          descriptor = open(final, "wb")
          for chunk in request:
            descriptor.write(chunk)
          descriptor.close()
      except:
        if (sys.flags.debug):
          logging.error(traceback.format_exc())
        try:
          os.unlink(final)
        except:
          pass
    target = final
  if (target == script):
    return -1
  if (len(target) == 0):
    return -1
  if not (os.path.exists(target)):
    return -1
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
    return -2
  if not ("dict" in str(type(data)).lower()):
    return -3
  #print(str(list(data.keys())))
  if not ("log" in data):
    return -4
  data = data["log"]
  if not ("dict" in str(type(data)).lower()):
    return -5
  #print(str(list(data.keys())))
  if not ("entries" in data):
    return -6
  entries = []
  try:
    entries += list(data["entries"])
    for i in range(len(entries)):
      entries[i] = [entries[i], i]
    entries = list(sorted(entries, key=functools.cmp_to_key(compare)))
  except:
    entries = []
    logging.error(traceback.format_exc())
  if (len(entries) == 0):
    return -7
  mapping = {}
  manifests = []
  outputs = []
  errors = []
  urls = []
  for i in range(len(entries)):
    entry = entries[i]
    index = entry[1]
    entry = entry[0]
    urls.append(None)
    if (sys.flags.debug):
      print(str(i)+" = "+str(index))
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
    if not ("response" in entry):
      errors.append(4)
      continue
    response = entry["response"]
    append = False
    if ("status" in response):
      if (str(response["status"]).strip() == "206"):
        append = True
      if not ((append) or (str(response["status"]).strip() == "200")):
        errors.append(5)
        continue
    if not (append):
      if (url in mapping):
        errors.append(3)
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
      if ((parse.path.endswith(".m3u8")) or (parse.path.endswith(".mpd"))):
        manifest = True
      if (sys.flags.debug):
        requests.append(parse.path)
        path += requests[len(requests)-1]
      else:
        hasher = hashlib.sha1()
        seed = os.path.dirname(parse.path).replace("\\", "/")
        if (seed[0:1] == "/"):
          seed = seed[1:]
        hasher.update(seed.encode())
        path = os.path.join(path, os.path.join(hasher.hexdigest(), os.path.basename(parse.path)))
      if (sys.flags.debug):
        print(path)
      if not (os.path.exists(path)):
        try:
          os.makedirs(os.path.dirname(path))
        except:
          pass
      mode = ""
      if (append):
        mode += "a"
      else:
        mode += "w"
      if not (encoding == None):
        mode += "b"
      descriptor = open(path, mode)
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
        mime = str(content["mimeType"]).lower().strip()
        if ((mime == "application/x-mpegurl") or (mime == "application/vnd.apple.mpegurl") or (mime == "application/dash+xml")):
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
      if (error == 0):
        continue
      print(str(i)+" = "+str(error)+" @ "+str(urls[i]))
    for key in mapping:
      print(key+" -> "+mapping[key])
  if (len(manifests) == 0):
    return -8
  port = 8081
  httpd = None
  if not (sys.flags.debug):
    #directory = os.path.relpath(root, temporary)
    directory = temporary
    os.chdir(temporary)
  print(directory)
  if not (os.path.exists(directory)):
    return -9
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
    return -10
  thread = threading.Thread(target=serve, args=[httpd])
  try:
    thread.start()
  except:
    thread = None
  if (thread == None):
    return -11
  tasks = []
  with BoundedProcessPoolExecutor(max_workers=multiprocessing.cpu_count()) as worker:
    http = "http://127.0.0.1:"+str(port)+"/"
    for i in range(len(manifests)):
      if not (manifests[i] in mapping):
        continue
      #print(mapping[manifests[i]])
      uri = ""
      if (sys.flags.debug):
        uri += os.path.relpath(mapping[manifests[i]], os.getcwd())
      else:
        uri += os.path.relpath(mapping[manifests[i]], temporary)
      if (len(uri) < 2):
        continue
      mime = mimetypes.guess_type(os.path.basename(mapping[manifests[i]]).lower())[0]
      if (str(mime).lower().strip() == "application/dash+xml"):
        try:
          mpd = MPEGDASHParser.parse(mapping[manifests[i]])
          #print(str(mpd))
          handle(http, os.path.relpath(os.path.dirname(mapping[manifests[i]]), directory), mpd, 0)
          MPEGDASHParser.write(mpd, mapping[manifests[i]])
        except:
          logging.error(traceback.format_exc())
      else:
        lines = []
        try:
          descriptor = open(mapping[manifests[i]], "r")
          lines += descriptor.readlines()
          descriptor.close()
        except:
          pass
        if not (len(lines) == 0):
          try:
            descriptor = open(mapping[manifests[i]], "w")
            for line in lines:
              line = line.strip()
              if (line.startswith("#")):
                descriptor.write(line+"\n")
                continue
              parse = None
              base = ""
              if ("/" in line):
                try:
                  parse = urlparse(line)
                  base += parse.path
                except:
                  parse = None
              if ((parse == None) and (len(base) == 0)):
                base += line
              if (base[0:1] == "/"):
                base = base[1:]
              base = os.path.join(origin, os.path.join(os.path.dirname(uri), base))
              if not (os.path.exists(base)):
                continue
              descriptor.write(line+"\n")
            descriptor.close()
          except:
            pass
      if not (os.path.exists(mapping[manifests[i]])):
        continue
      if (uri[0:1] == "/"):
        uri = uri[1:]
      if (len(uri) == 0):
        continue
      uri = http+uri
      request = None
      try:
        request = requester.get(uri)
        if not (str(request.status_code).strip() == "200"):
          request = None
      except:
        request = None
        if (sys.flags.debug):
          logging.error(traceback.format_exc())
      if (request == None):
        mutex.acquire()
        requests.append([uri])
        mutex.release()
        continue
      command = []
      command.append("ffmpeg")
      command.append("-allowed_extensions")
      command.append("ALL")
      if (sys.flags.debug):
        command.append("-y")
      else:
        command.append("-nostdin")
      command.append("-re")
      command.append("-i")
      command.append(uri)
      command.append(os.path.join(origin, outputs[i]+".mp4"))
      #print(str(command))
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
  mutex.acquire()
  for request in requests:
    if (sys.flags.debug):
      print(str(request))
  mutex.release()
  try:
    httpd.shutdown()
    thread.join()
  except:
    pass
  os.chdir(origin)
  return 0

def launch(arguments):
  global temporary
  if (len(arguments) < 2):
    return False
  if (len(temporary) == 0):
    return False
  if not (os.path.exists(temporary)):
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
  root = ""
  if (sys.flags.debug):
    root += os.path.join(os.getcwd(), script)
  else:
    root += os.path.join(temporary, script)
    try:
      date = datetime.date.fromtimestamp(time.time()).strftime("%d/%m/%y@%H:%M:%S")
      hasher = hashlib.sha1()
      hasher.update(str(date).encode())
      root += "-"
      root += hasher.hexdigest()
    except:
      pass
  if (len(script) == 0):
    return False
  mimetypes.init()
  mimetypes.add_type("application/dash+xml", ".mpd", strict=True)
  if (os.path.exists(root)):
    try:
      shutil.rmtree(root)
    except:
      pass
  try:
    os.makedirs(root)
  except:
    pass
  if not (os.path.exists(root)):
    return False
  origin = os.getcwd()
  try:
    result += run(inspect.getframeinfo(inspect.currentframe()).filename, target, root)
    #result *= 2
  except:
    logging.error(traceback.format_exc())
    result = None
  os.chdir(origin)
  print(str(result))
  #"""
  if not (sys.flags.debug):
    try:
      shutil.rmtree(root)
    except:
      pass
  #"""
  if not (result == 0):
    return False
  return True

def har2mp4(target):
  return launch([sys.argv[0], str(target)])

if (__name__ == "__main__"):
  try:
    print(str(launch(sys.argv)))
  except:
    pass

