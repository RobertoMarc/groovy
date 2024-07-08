// syhunt.groovy 
// contains all the generic, reusable functions used in the pipelines. 

import org.apache.commons.lang.StringUtils

def getSyhuntDir() {
  def dir = ""
  def diruser = ""
  if (isUnix()) {
    diruser = "$USER"
    echo "usuario $diruser"
    dir = "/home/${USER}/syhunt-hybrid/carbon"
  } else {    
    dir = System.getenv("ProgramFiles")
    dir = "${dir}\\Syhunt Hybrid\\"
  }
  return dir
}

def getSyhuntCmd(String modulename) {
  def sydir = getSyhuntDir()
  def cmd = ""
  if (isUnix()) {
    cmd = "\"$sydir/${modulename}\""
  } else {    
    cmd = "\"$sydir\\${modulename}.exe\""
  }
  return cmd
}

def getOutFilename() {
  def unixTime = System.currentTimeMillis() / 1000L;
  def fn = "${unixTime}-${BUILD_NUMBER}.html"
  def workspaceDir = env.WORKSPACE
  echo "workspace"
  echo workspaceDir
  def outfn = ""
  if (isUnix()) {  
    outfn = "$workspaceDir"+"\${fn}"  
  } else {        
    def userDir = System.getenv("USERPROFILE")
    outfn = "$worksapceDir"+"\\${fn}"
  }  
  return [outFilename: outfn, outReportFilename: fn]
}

def doFail(String reason) {
  echo reason
  currentBuild.result='FAILURE'
}

def checkResults(Map o, String pfcond) {
  echo 'Checking scan results...'
  String msg_failhigh = 'Build problem: found High risk vulnerabilities.'
  String msg_failmedium = 'Build problem: found Medium risk vulnerabilities.'
  String msg_faillow = 'Build problem: found Low risk vulnerabilities.'
  def fail = false
  echo o.outFilename
  def repexists = fileExists "$o.outFilename"
  echo "$repexists"  
  if (repexists) {
    def fileContents = readFile "$o.outFilename"
    int hcount = StringUtils.countMatches(fileContents, '<br>High: 0');
    echo "hcount $hcount"
    int mcount = StringUtils.countMatches(fileContents, '<br>Medium: 0');
    echo "mcount $mcount"
    int lcount = StringUtils.countMatches(fileContents, '<br>Low: 0');
    echo "lcount $lcount"
    int ucount = StringUtils.countMatches(fileContents, '<font color="red"><b>Canceled');
    echo "ucount $ucount"
    int icount = StringUtils.countMatches(fileContents, '<b>Invalid license</b>');
    echo "icount $icount"
    echo "pfcond $pfcond"
    if (ucount == 1) { 
      doFail('Build problem: Scan aborted.') 
    }
    if (icount == 1) { 
      doFail('Build problem: Invalid license - You need to obtain a new key.') 
    }
    
    if (pfcond == 'fail-if:risk=high') {
      if (hcount != 1) { doFail(msg_failhigh) }
    }
    if (pfcond == 'fail-if:risk=mediumup') {
      if (mcount != 1) { doFail(msg_failmedium) }    
      if (hcount != 1) { doFail(msg_failhigh) }
    }
    if (pfcond == 'fail-if:risk=lowup') {
      if (lcount != 1) { doFail(msg_faillow) }    
      if (mcount != 1) { doFail(msg_failmedium) }    
      if (hcount != 1) { doFail(msg_failhigh) }      
    }  
  
  } else {
    doFail('Build problem: No results generated.')
  }
  return [outFilename: o.outFileName, outReportFilename: o.outReportFilename]
}

def scanURL(Map m) {
  def cmd = getSyhuntCmd('scanurl')
  def target = ''
  def pfcond = ''
  def huntMethod = 'appscan'  
  def genRep = true
  def output = getOutFilename()
  if (m.huntMethod?.trim()) { huntMethod = m.huntMethod } 
  if (m.target?.trim()) { target = m.target } 
  if (m.pfcond?.trim()) { pfcond = m.pfcond } 
  if (m.genRep == false) { genRep = m.genRep }
      echo "Preparing to scan URL: $target"
  if (isUnix()) {
      sh "$cmd $target -hm:$huntMethod -nv -gr -rout:$output"
  } else {      
      def cmdline = "$cmd $target -hm:$huntMethod -nv -gr -rout:$output"
      print cmdline.execute().text
   }
  return checkResults(output, pfcond)
}

def scanCode(Map m) {
  def cmd = getSyhuntCmd('scancode')
  def target = ''
  def branch = 'master'  
  def pfcond = ''
  def huntMethod = 'normal'  
  def genRep = true
  def output = getOutFilename()
  if (m.huntMethod?.trim()) { huntMethod = m.huntMethod } 
  if (m.target?.trim()) { target = m.target } 
  if (m.branch?.trim()) { branch = m.branch }  
  if (m.pfcond?.trim()) { pfcond = m.pfcond } 
  if (m.genRep == false) { genRep = m.genRep }
  echo "Preparing to scan source code directory: $target"
  if (isUnix()) {
       sh "$cmd $target -hm:$huntMethod -nv -gr -rout:$output"
  } else {      
       def cmdline = "$cmd \"$target\" -hm:$huntMethod -rb:$branch -nv -gr -rout:$output"
      print cmdline.execute().text
   }
  
    return checkResults(output, pfcond)
}

return this;
