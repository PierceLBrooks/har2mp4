import os
import sys
import shlex
import logging
import traceback
import subprocess
from har2mp4 import har2mp4 as invoke

def dispatch(command, environment = None):
  if (len(command) == 0):
    return True
  print(str(command))
  result = None
  try:
    process = subprocess.Popen(command, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    while True:
      line = process.stdout.readline()
      if ((len(line) == 0) and not (process.poll() == None)):
        break
      print(line.decode("UTF-8").strip())
    output = process.communicate()[0]
    exit = process.returncode
    if (exit == 0):
      result = output
  except:
    pass
  if (result == None):
    return ""
  return result

def main():
  environment = os.environ.copy()
  arguments = sys.argv
  command = []
  if (len(arguments) > 1):
    arguments = arguments[1:]
    for i in range(len(arguments)):
      argument = arguments[i]
      arguments[i] = "arguments.append(\""+shlex.quote(argument)+"\")"
    if (len(arguments) > 1):
      arguments = "; ".join(arguments)
    else:
      arguments = arguments[0]
    command.append(sys.executable)
    command.append("-c")
    command.append("import sys; from har2mp4 import har2mp4 as invoke; arguments = []; "+arguments+"; sys.argv += arguments; print(str(sys.argv)); invoke.main()")
    print(str(command))
    result = ""
    try:
      result = dispatch(command, environment)
    except Exception as exception:
      result = ""
      logging.error(traceback.format_exc())
    #print(result.strip())
  else:
    print(str(invoke.main(environment)))
  return 0
