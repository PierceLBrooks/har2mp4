
# Author: Pierce Brooks

import os
import ast
import sys
import copy
import glob
import json
import math
import time
import base64
import shutil
import fnmatch
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
from ctypes.wintypes import MAX_PATH
from urllib.parse import urlparse
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from bounded_pool_executor import BoundedProcessPoolExecutor
from mpegdash.parser import MPEGDASHParser
from requests_testadapter import Resp

directory = os.getcwd()
hashes = {}
mutex = threading.Lock()
reports = []
requests = []
temporary = ""
try:
  if (platform.system().lower().strip() == "darwin"):
    temporary += "/tmp"
  else:
    temporary += tempfile.gettempdir()
except:
  temporary = ""

# https://stackoverflow.com/a/22989322
class LocalFileAdapter(requester.adapters.HTTPAdapter):
  def build_response_from_file(self, request):
    file_path = request.url[7:]
    with open(file_path, "rb") as file:
        buff = bytearray(os.path.getsize(file_path))
        file.readinto(buff)
        resp = Resp(buff)
        r = self.build_response(request, resp)
        return r

  def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
      return self.build_response_from_file(request)


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

"""
  def log_message(self, format, *args):
    pass
"""

def resolve(promises):
  for promise in promises:
    try:
      yield promise.result()
    except:
      pass

def execute(command):
  global mutex
  global reports
  lines = []
  output = None
  if (len(command) == 0):
    mutex.acquire()
    reports.append("Command parameter population threshold failure!")
    mutex.release()
    return lines
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
    else:
      mutex.acquire()
      reports.append("\"%s\" execution with invokation \"%s\" failure (%s)!"%tuple([str(command[i]), str(command), str(exit)]))
      mutex.release()
  except:
    #logging.error(traceback.format_exc())
    output = []
  if ((output == None) and not (sys.flags.debug)):
    return []
  return lines

def serve(server):
  try:
    server.serve_forever()
  except:
    server = None

def test(front, source):
  global directory
  global hashes
  success = True
  try:
    source = source.replace("\\", "/").replace("://", ":///").replace("//", "/")
    request = requester.get(source)
    if not (str(request.status_code).strip() == "200"):
      success = False
  except:
    success = False
    if (sys.flags.debug):
      logging.error(traceback.format_exc())
  if not (success):
    try:
      parse = urlparse(source)
      for floor, folders, files in os.walk(os.path.join(directory, front)):
        for i in range(len(files)):
          full = os.path.join(floor, files[i])
          if full in hashes:
            full = hashes[full]
          if (os.path.basename(full) == os.path.basename(parse.path)):
            success = True
            break
        if (success):
          break
    except:
      success = False
  if ((sys.flags.debug) and not (success)):
    print(source)
  return success

def unique(duplicates):
  uniques = []
  for duplicate in duplicates:
    if not (duplicate in uniques):
      uniques.append(duplicate)
  return uniques

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

def handle(parent, host, home, node, level):
  global directory
  global hashes
  if (node == None):
    return node
  this = ""
  kind = str(type(node))
  total = 0
  changes = 0
  front = home.replace("\\", "/").replace("//", "/")
  if (len(front) > 1):
    if (front[0:1] == "/"):
      front = front[1:]
    if (front.count("/") > 0):
      front = front.split("/")[:1][0]
  if ((len(front) == 0) or not (os.path.exists(os.path.join(directory, front)))):
    front = None
  try:
    if ("BaseURL" in kind):
      if not (node.base_url_value == None):
        this += str(node.base_url_value)
        total += 1
        if not (test(front, host+os.path.join(home, node.base_url_value))):
          changes += 1
    elif ("SegmentURL" in kind):
      if not (node.media == None):
        this += str(node.media)
        total += 1
        if not (test(front, host+os.path.join(home, node.media))):
          changes += 1
    elif ("URL" in kind):
      if not (node.sourceURL == None):
        this += str(node.sourceURL)
        total += 1
        if not (test(front, host+os.path.join(home, node.sourceURL))):
          changes += 1
    elif ("Period" in kind):
      if not (node.base_urls == None):
        removals = []
        for i in range(len(node.base_urls)):
          total += 1
          if (handle(node, host, home, node.base_urls[i], level+1) == None):
            changes += 1
            removals.append(i)
        for i in range(len(removals)):
          node.base_urls = remove(node.base_urls, removals[i]-i)
      if not (node.adaptation_sets == None):
        removals = []
        for i in range(len(node.adaptation_sets)):
          total += 1
          if (handle(node, host, home, node.adaptation_sets[i], level+1) == None):
            changes += 1
            removals.append(i)
        for i in range(len(removals)):
          node.adaptation_sets = remove(node.adaptation_sets, removals[i]-i)
      if not (node.segment_lists == None):
        removals = []
        for i in range(len(node.segment_lists)):
          total += 1
          if (handle(node, host, home, node.segment_lists[i], level+1) == None):
            changes += 1
            removals.append(i)
        for i in range(len(removals)):
          node.segment_lists = remove(node.segment_lists, removals[i]-i)
    elif ("SegmentTemplate" in kind):
      if not (node.media == None):
        this += str(node.media)
    elif ("SegmentList" in kind):
      if not (node.segment_urls == None):
        removals = []
        for i in range(len(node.segment_urls)):
          total += 1
          if (handle(node, host, home, node.segment_urls[i], level+1) == None):
            changes += 1
            removals.append(i)
        for i in range(len(removals)):
          node.segment_urls = remove(node.segment_urls, removals[i]-i)
    elif ("AdaptationSet" in kind):
      if not (node.base_urls == None):
        removals = []
        for i in range(len(node.base_urls)):
          total += 1
          if (handle(node, host, home, node.base_urls[i], level+1) == None):
            changes += 1
            removals.append(i)
        for i in range(len(removals)):
          node.base_urls = remove(node.base_urls, removals[i]-i)
      if not (node.representations == None):
        removals = []
        for i in range(len(node.representations)):
          total += 1
          if (handle(node, host, home, node.representations[i], level+1) == None):
            changes += 1
            removals.append(i)
        for i in range(len(removals)):
          node.representations = remove(node.representations, removals[i]-i)
      if not (node.segment_lists == None):
        removals = []
        for i in range(len(node.segment_lists)):
          total += 1
          if (handle(node, host, home, node.segment_lists[i], level+1) == None):
            changes += 1
            removals.append(i)
        for i in range(len(removals)):
          node.segment_lists = remove(node.segment_lists, removals[i]-i)
      if not (node.segment_templates == None):
        removals = []
        for i in range(len(node.segment_templates)):
          total += 1
          if (handle(node, host, home, node.segment_templates[i], level+1) == None):
            changes += 1
            removals.append(i)
        for i in range(len(removals)):
          node.segment_templates = remove(node.segment_templates, removals[i]-i)
    elif ("Representation" in kind):
      this += str(node.id)
      if not (node.base_urls == None):
        removals = []
        for i in range(len(node.base_urls)):
          total += 1
          if (handle(node, host, home, node.base_urls[i], level+1) == None):
            changes += 1
            removals.append(i)
        for i in range(len(removals)):
          node.base_urls = remove(node.base_urls, removals[i]-i)
      if not (node.segment_lists == None):
        removals = []
        for i in range(len(node.segment_lists)):
          total += 1
          if (handle(node, host, home, node.segment_lists[i], level+1) == None):
            changes += 1
            removals.append(i)
        for i in range(len(removals)):
          node.segment_lists = remove(node.segment_lists, removals[i]-i)
      if (changes <= total):
        if not (front == None):
          safe = True
          extensions = []
          if not (parent == None):
            if ("AdaptationSet" in str(type(parent))):
              if not (parent.segment_templates == None):
                for i in range(len(parent.segment_templates)):
                  media = parent.segment_templates[i].media
                  if (media == None):
                    continue
                  if not ("." in media):
                    continue
                  media = media[media.rindex("."):]
                  if not (media in extensions):
                    extensions.append(media)
              if not (parent.representations == None):
                for i in range(len(parent.representations)):
                  if (parent.representations[i] == node):
                    continue
                  for floor, folders, files in os.walk(os.path.join(directory, front)):
                    for j in range(len(files)):
                      full = os.path.join(floor, files[j])
                      if full in hashes:
                        full = hashes[full]
                      full = full.replace("\\", "/")
                      fulls = []
                      if ("/" in full):
                        fulls += full.split("/")
                      else:
                        fulls += [full]
                      if ((parent.representations[i].id in fulls) or (parent.representations[i].id in files[j])):
                        safe = False
                        break
                    if not (safe):
                      break
                  if not (safe):
                    break
          for floor, folders, files in os.walk(os.path.join(directory, front)):
            for i in range(len(files)):
              full = os.path.join(floor, files[i])
              if full in hashes:
                full = hashes[full]
              full = full.replace("\\", "/")
              fulls = []
              if ("/" in full):
                fulls += full.split("/")
              else:
                fulls += [full]
              if ((node.id in fulls) or (node.id in files[i])):
                safe = True
                if (len(extensions) > 0):
                  safe = False
                  for extension in extensions:
                    if (full.endswith(extension)):
                      safe = True
                      break
                break
          if not (safe):
            if (total == 0):
              total += 1
            changes = total
    elif ("MPEGDASH" in kind):
      if not (node.base_urls == None):
        removals = []
        for i in range(len(node.base_urls)):
          total += 1
          if (handle(node, host, home, node.base_urls[i], level+1) == None):
            changes += 1
            removals.append(i)
        for i in range(len(removals)):
          node.base_urls = remove(node.base_urls, removals[i]-i)
      if not (node.periods == None):
        removals = []
        for i in range(len(node.periods)):
          total += 1
          if (handle(node, host, home, node.periods[i], level+1) == None):
            changes += 1
            removals.append(i)
        for i in range(len(removals)):
          node.periods = remove(node.periods, removals[i]-i)
    else:
      total = 0
  except:
    if (sys.flags.debug):
      logging.error(traceback.format_exc())
    total = 0
  if (len(this) == 0):
    this += kind
  if (sys.flags.debug):
    print(this+" @ "+str(level)+" = "+str(changes)+" / "+str(total))
  if (total == 0):
    return node
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

def run(ffmpeg, script, target, root):
  global directory
  global hashes
  global mutex
  global reports
  global requests
  global temporary
  strict = False
  extent = sys.maxsize
  limit = sys.maxsize
  try:
    if (platform.system().lower().strip() == "windows"):
      extent = MAX_PATH
    else:
      extent = os.pathconf("/", "PC_PATH_MAX")
  except:
    extent = sys.maxsize
  try:
    if (platform.system().lower().strip() == "windows"):
      limit = MAX_PATH
    else:
      limit = os.pathconf("/", "PC_LIMIT_MAX")
  except:
    limit = sys.maxsize
  origin = os.getcwd()
  #print(root)
  data = None
  content = ""
  if ((target.startswith("http://")) or (target.startswith("https://")) or (target.startswith("file://"))):
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
        session = requester.session()
        session.mount("file://", LocalFileAdapter())
        request = session.get(target, stream=True)
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
    print("HAR file target uniqueness failure!")
    return -1
  if (len(target) == 0):
    print("HAR file target emptiness failure!")
    return -1
  try:
    if not (os.path.exists(target)):
      literal = ast.literal_eval(target)
      if (os.path.exists(literal)):
        target = literal
  except:
    pass
  if not (os.path.exists(target)):
    print("HAR file target accessibility failure (\"%s\")!"%tuple([target]))
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
    print("Data failure!")
    return -2
  if not ("dict" in str(type(data)).lower()):
    print("Data parse failure!")
    return -3
  #print(str(list(data.keys())))
  if not ("log" in data):
    print("Log recording presence failure!")
    return -4
  data = data["log"]
  if not ("dict" in str(type(data)).lower()):
    print("Log recording validation failure!")
    return -5
  #print(str(list(data.keys())))
  if not ("entries" in data):
    print("Entry presence failure!")
    return -6
  entries = []
  try:
    entries += list(data["entries"])
    for i in range(len(entries)):
      entries[i] = [entries[i], i]
    entries = list(sorted(entries, key=functools.cmp_to_key(compare)))
  except:
    print("Entry sorting failure!")
    entries = []
    logging.error(traceback.format_exc())
  if (len(entries) == 0):
    print("Entry population threshold failure!")
    return -7
  mapping = {}
  failures = {}
  manifests = []
  outputs = []
  indices = []
  errors = []
  codes = []
  paths = []
  names = []
  urls = []
  depth = 0
  for i in range(len(entries)):
    errors.append([0])
    entry = entries[i]
    index = entry[1]
    entry = entry[0]
    indices.append(index)
    names.append(None)
    paths.append(None)
    urls.append(None)
    codes.append(0)
    if (sys.flags.debug):
      print(str(i)+" = "+str(index))
    redirect = False
    depth = 0
    while not (entry == None):
      if not ("request" in entry):
        errors[len(errors)-1] = [1]
        break
      request = entry["request"]
      if not ("url" in request):
        errors[len(errors)-1] = [2]
        break
      url = str(request["url"])
      urls[len(urls)-1] = url
      #print(url)
      if not ("response" in entry):
        errors[len(errors)-1] = [4]
        break
      response = entry["response"]
      append = False
      if ("status" in response):
        code = str(response["status"]).strip()
        codes[len(codes)-1] = code
        if ((code == "301") or (code == "302") or (code == "303") or (code == "307") or (code == "308")):
          redirect = True
          error = 0
          if (i+1 < len(entries)):
            next = None
            if ("headers" in entry["response"]):
              for k in range(len(entry["response"]["headers"])):
                if ("name" in entry["response"]["headers"][k]):
                  key = str(entry["response"]["headers"][k]["name"]).strip().lower()
                  if (key == "location"):
                    if ("value" in entry["response"]["headers"][k]):
                      next = entry["response"]["headers"][k]["value"]
                      break
            if not (next == None):
              for j in range(len(entries)):
                if (i == j):
                  continue
                entry = entries[j][0]
                if ("request" in entry):
                  if ("url" in entry["request"]):
                    if (entry["request"]["url"] == next):
                      entry["request"]["url"] = url
                      next = None
                      break
              if not (next == None):
                entry = None
                redirect = False
                error = 1
            else:
              redirect = False
              error = 2
          else:
            redirect = False
            error = 3
          if (redirect):
            depth += 1
            continue
          entry = None
          redirect = True
          break
        if (code == "206"):
          append = True
        if not ((append) or (code == "200")):
          errors[len(errors)-1] = [5]
          break
      if not (append):
        if ((url in mapping) and not (redirect)):
          errors[len(errors)-1] = [3]
          break
      if not ("content" in response):
        errors[len(errors)-1] = [6]
        break
      content = response["content"]
      if not ("text" in content):
        errors[len(errors)-1] = [7]
        break
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
          hashes[path] = parse.path
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
        if ((len(path) < extent) and (len(os.path.basename(path)) < limit)):
          descriptor = open(path, mode)
        else:
          paths[len(paths)-1] = path
          if (len(os.path.basename(path)) >= limit):
            errors[len(errors)-1] = [8]
          else:
            errors[len(errors)-1] = [9]
      except:
        if (sys.flags.debug):
          logging.error(traceback.format_exc())
        descriptor = None
      if (descriptor == None):
        try:
          os.unlink(path)
        except:
          pass
        if (errors[len(errors)-1] == 0):
          errors[len(errors)-1] = [10]
        break
      if not (manifest):
        if ("mimeType" in content):
          mime = str(content["mimeType"]).lower().strip()
          if ((mime == "application/x-mpegurl") or (mime == "application/vnd.apple.mpegurl") or (mime == "application/dash+xml")):
            manifest = True
      if (manifest):
        name = os.path.basename(path)
        if (name in outputs):
          if not (append):
            try:
              os.unlink(path)
            except:
              pass
            errors[len(errors)-1] = [11]
            break
        else:
          outputs.append(name)
          manifests.append(url)
      try:
        try:
          if (str(encoding) == "base64"):
            text = base64.b64decode(text)
        except:
          if (sys.flags.debug):
            logging.error(traceback.format_exc())
          text = None
        if not (size == None):
          text = text[:size]
        descriptor.write(text)
      except:
        if (sys.flags.debug):
          logging.error(traceback.format_exc())
        descriptor = None
      if (text == None):
        try:
          os.unlink(path)
        except:
          pass
        errors[len(errors)-1] = [12]
        break
      if (descriptor == None):
        try:
          os.unlink(path)
        except:
          pass
        errors[len(errors)-1] = [13]
        break
      descriptor.close()
      mapping[url] = path
      paths[len(paths)-1] = path
      names[len(names)-1] = os.path.basename(path)
      break
    if (entry == None):
      if (redirect):
        if (errors[len(errors)-1][0] == 0):
          errors[len(errors)-1][0] = 14
        errors[len(errors)-1].append(depth)
    if not (errors[len(errors)-1] == 0):
      if (strict):
        break
  if (len(errors) > 0):
    if (strict):
      if not (errors[len(errors)-1] == 0):
        errors = [errors[len(errors)-1]]
    for i in range(len(errors)):
      error = errors[i][0]
      if (error == 0):
        continue
      try:
        failures[urls[i]] = error
        if (error == 1):
          print("Entry %i's request body inclusion failure!"%tuple([i]))
        elif (error == 2):
          print("Entry %i's URL inclusion failure!"%tuple([i]))
        elif (error == 3):
          print("Entry %i redundancy failure (\"%s\")!"%tuple([i, str(urls[i])]))
        elif (error == 4):
          print("Entry %i's response body inclusion failure!"%tuple([i]))
        elif (error == 5):
          print("Entry %i's status code correctness failure (\"%s\")!"%tuple([i, str(codes[i])]))
        elif (error == 6):
          print("Entry %i's content inclusion failure!"%tuple([i]))
        elif (error == 7):
          print("Entry %i's text inclusion failure!"%tuple([i]))
        elif (error == 8):
          print("Entry %i's extraction output name (\"%s\") length failure (%i >= %s)!"%tuple([i, str(paths[i]), len(os.path.basename(str(paths[i]))), limit]))
        elif (error == 9):
          print("Entry %i's extraction output path (\"%s\") length failure (%i >= %s)!"%tuple([i, str(paths[i]), len(str(paths[i])), extent]))
        elif (error == 10):
          print("Entry %i's extraction output failure (\"%s\")!"%tuple([i, str(paths[i])]))
        elif (error == 11):
          print("Entry %i's output name (\"%s\") uniqueness failure (\"%s\")!"%tuple([i, str(names[i]), str(urls[i])]))
        elif (error == 12):
          print("Entry %i's decoding failure!"%tuple([i]))
        elif (error == 13):
          print("Entry %i's output failure!"%tuple([i]))
        elif (error == 14):
          print("Entry %i's redirection failure (%i)!"%tuple([i, errors[i][1]]))
        else:
          print("Unknown entry %i's extraction failure (%i)!"%tuple([i, error]))
      except:
        pass
      if ((sys.flags.debug) or (strict)):
        print(str(i)+" = "+str(error)+" @ "+str(urls[i]))
      if (strict):
        print("Strictness failure!")
        return -8
  if (sys.flags.debug):
    for key in mapping:
      print(key+" -> "+mapping[key])
  if (len(manifests) == 0):
    print("Extraction manifest population threshold failure!")
    return -9
  port = 8081
  server = None
  if not (sys.flags.debug):
    #directory = os.path.relpath(root, temporary)
    directory = temporary
    os.chdir(temporary)
  #print(directory)
  if not (os.path.exists(directory)):
    print("Root extraction directory usage failure!")
    return -10
  while (port < 9001):
    try:
      if (sys.flags.debug):
        server = ThreadingHTTPServer(("127.0.0.1", port), SimpleHTTPRequestHandler)
      else:
        server = ThreadingHTTPServer(("127.0.0.1", port), Responder)
    except:
      server = None
    if not (server == None):
      break
    port += 1
  if (server == None):
    print("HTTP server construction failure (%i)!"%tuple([port]))
    return -11
  thread = threading.Thread(target=serve, args=[server])
  try:
    thread.start()
  except:
    thread = None
  if (thread == None):
    print("HTTP server initialization failure!")
    return -12
  tasks = []
  with BoundedProcessPoolExecutor(max_workers=multiprocessing.cpu_count()) as worker:
    host = "http://127.0.0.1:"+str(port)+"/"
    for i in range(len(manifests)):
      if not (manifests[i] in mapping):
        continue
      """
      if (manifests[i] in failures):
        failure = failures[manifests[i]]
        if not (failure == 0):
          continue
      """
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
          node = MPEGDASHParser.parse(mapping[manifests[i]])
          #print(str(node))
          node = handle(None, host, os.path.relpath(os.path.dirname(mapping[manifests[i]]), directory), node, 0)
          if not (node == None):
            MPEGDASHParser.write(node, mapping[manifests[i]])
          else:
            print("MPEG DASH manifest rewrite failure!")
            mapping[manifests[i]] = None
        except:
          print("MPEG DASH manifest parse failure!")
          if (sys.flags.debug):
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
              base = os.path.join(directory, os.path.join(os.path.dirname(uri), base))
              if not (os.path.exists(base)):
                #print(line)
                #print(base)
                continue
              descriptor.write(line+"\n")
            descriptor.close()
          except:
            pass
      if (mapping[manifests[i]] == None):
        continue
      if not (os.path.exists(mapping[manifests[i]])):
        continue
      if (uri[0:1] == "/"):
        uri = uri[1:]
      if (len(uri) == 0):
        continue
      uri = host+uri
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
      command.append(ffmpeg)
      command.append("-allowed_extensions")
      command.append("ALL")
      if (sys.flags.debug):
        command.append("-loglevel")
        command.append("debug")
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
  for report in reports:
    print(str(request))
  mutex.release()
  try:
    server.shutdown()
    thread.join()
  except:
    pass
  os.chdir(origin)
  for floor, folders, files in os.walk(root):
    for i in range(len(files)):
      full = os.path.join(floor, files[i])
      if (os.path.exists(os.path.join(os.getcwd(), files[i]))):
        continue
      if (full.endswith(".mp4")):
        try:
          shutil.copyfile(full, os.path.join(os.getcwd(), files[i]))
        except:
          pass
  return 0

def launch(arguments):
  global temporary
  if (len(arguments) < 2):
    print("CLI argument population threshold failure!")
    return False
  if (len(temporary) == 0):
    print("Temporary directory existence failure!")
    return False
  if not (os.path.exists(temporary)):
    print("Determination failure for existence of temporary directory!")
    return False
  ffmpeg = None
  try:
    ffmpeg = shutil.which("ffmpeg")
  except:
    ffmpeg = None
  if (ffmpeg == None):
    print("\"ffmpeg\" binary location discovery failure!")
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
    root += os.path.join(os.getcwd(), "_"+script)
  else:
    root += os.path.join(temporary, "_"+script)
    try:
      date = datetime.date.fromtimestamp(time.time()).strftime("%d/%m/%y@%H:%M:%S")
      hasher = hashlib.sha1()
      hasher.update(str(date).encode())
      root += "-"
      root += hasher.hexdigest()
    except:
      pass
  if (len(script) == 0):
    print("\"har2mp4.py\" script location discovery failure!")
    return False
  mimetypes.init()
  try:
    mimetypes.add_type("application/dash+xml", ".mpd", strict=True)
  except:
    pass
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
    print("Root extraction directory creation failure!")
    return False
  origin = os.getcwd()
  try:
    targets = []
    if (("*" in target) and not ((target.startswith("http://")) or (target.startswith("https://")) or (target.startswith("file://")))):
      target = target.replace("\\", "/")
      if (("/" in target) or (os.path.isabs(target))):
        recursion = False
        if ("**" in target):
          recursion = True
        targets += glob.glob(target, recursive=recursion)
      else:
        for floor, folders, files in os.walk(os.getcwd()):
          for i in range(len(files)):
            if (fnmatch.fnmatch(files[i], os.path.basename(target))):
              targets.append(os.path.join(floor, files[i]))
          break
      if (len(targets) > 1):
        targets = unique(targets)
    else:
      targets.append(target)
    for i in range(len(targets)):
      result += run(ffmpeg, inspect.getframeinfo(inspect.currentframe()).filename, targets[i], root)
    #result *= 2
  except:
    logging.error(traceback.format_exc())
    result = None
  os.chdir(origin)
  print(str(result))
  """
  if not (sys.flags.debug):
    try:
      shutil.rmtree(root)
    except:
      pass
  """
  if not (result == 0):
    print("General operational failure!")
    return False
  return True

def har2mp4(target):
  return launch([sys.argv[0], str(target)])

def main(environment = None):
  result = 0
  try:
    arguments = sys.argv
    length = len(arguments)
    if (length > 1):
      data = []
      if (length > 2):
        data = arguments[2:]
      if (environment == None):
        environment = os.environ.copy()
      code = har2mp4(arguments[1].strip())
      if not (code):
        print("Failure (\"%s\")! "%tuple([str(code)]))
        result = -1
    else:
      result = -2
  except:
    logging.error(traceback.format_exc())
    result = -3
  return result

if (__name__ == "__main__"):
  try:
    print(str(launch(sys.argv)))
  except:
    pass

