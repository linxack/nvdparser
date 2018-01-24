#Author: Rafael Murillo
#Twitter: @cehrmurillo
#Blog: https://almost4hacker.blogspot.mx/
#Version: 0.1

import xml.sax
import time
import urllib
import zipfile
import os
import sys
import commands
#Download the recent NVD vulnerabilities feed
urllib.urlretrieve ("https://nvd.nist.gov/download/nvdcve-Recent.xml.zip", "reciente.zip")
print "Downloaded"
time.sleep(1)

fh = open('reciente.zip', 'rb')
z = zipfile.ZipFile(fh)
for name in z.namelist():
    outfile = open(name, 'wb')
    outfile.write(z.read(name))
    outfile.close()
fh.close()
print "Unzipped"
time.sleep(1)

class CveHandler( xml.sax.ContentHandler ):

   # Call when an element starts
   def startElement(self, tag, attributes):
      #print "1"
      self.CurrentData = tag
      if tag == "entry":
         print "\n***** Monitoreo *****"
         try:
            nombre = attributes["name"]
            f.write ( "\n" + str(nombre) + "\t")
            print "Nombre: ", nombre
         except:
            f.write("Null\t")
            print "Nombre: Null"
            pass
         try:
            nombre = attributes["name"]
            f.write ("https://web.nvd.nist.gov/view/vuln/detail?vulnId=" + str(nombre) + "\t")
            print "Nombre: ", nombre

         except:
            f.write("Null\t")
            print "Nombre: Null"
            pass
         try:
            published = attributes["published"]
            f.write (str(published) + "\t")
            print "Publicado: ", published
         except:
            f.write ("Null\t")
            print "Publicado: Null"
            pass
         try:
            modificado = attributes["modified"]
            f.write (str(modificado) + "\t")
            print "Modificado: ", modificado
         except:
            f.write (str("Sin ponderacion\t"))
            print "Modificado: Null"
            pass
         try:
            severidad = attributes["severity"]
            f.write (str(severidad) + "\t")
            print "Severidad: ", severidad
         except:
            f.write (str("Sin ponderacion\t"))
            print "Severidad: null"
            pass
         try:
            cvss_score = attributes["CVSS_score"]
            f.write (str(cvss_score) + "\t")
            print "CVSS Score: ", cvss_score
         except:
            f.write (str("Sin ponderacion\t"))
            print "CVSS Score: Null"
            pass

      if tag == "vuln_soft":
         #print "\n***** Monitoreo222 *****"
         try:
            version = attributes["vers"]
            f.write ( "\n" + str(version) + "\t")
            #print "Version: ", version
         except:
            f.write("Null\t")
            #print "Version: Null"
            pass
     
   # Call when an elements ends
   def endElement(self, tag):
      #print "3"
      if self.CurrentData == "descript":
         
         print "Descripcion: ", self.descript
         f.write (str(self.descript)+ "\t")
      #if self.CurrentData == "ref":
         #f.write (str(self.ref) + " ")
         #print "referencia:", self.ref + "\t"
      self.CurrentData = ""

   # Call when a character is read
   def characters(self, content):
      #print "2"
      if self.CurrentData == "descript":
         j = 0
         if j != 1:
            self.descript = content
            #self.CurrentData = ""
            #self.descript.replace ("&lt;a", " ")
            j =+ 1
         else:
            return
         j =+ 1
      if self.CurrentData == "ref":
         i = 0
         if i == 0:
            self.ref = content
            i =+ 1
         i =+ 1

if ( __name__ == "__main__"):		
   # create an XMLReader
   parser = xml.sax.make_parser()
   # turn off namepsaces
   parser.setFeature(xml.sax.handler.feature_namespaces, 0)

   # override the default ContextHandler
   Handler = CveHandler()
   parser.setContentHandler( Handler )
   
   f = open("all_vulnerabilities.txt", "w")
   parser.parse("nvdcve-recent.xml")
   f.close()
   os.remove("reciente.zip")
   

#os.system('start excel.exe "%s\\Monitoreo.xlsm"' % (sys.path[0], ))
def _del_(name):
   time.sleep(1)

del parser
os.remove("nvdcve-recent.xml")
#Modify this line and add the operating systems and applications that you want
commands.getoutput('egrep -i "in Microsoft Windows"\|"in Adobe Flash Player 11"\|"in Adobe Shockwave Player"\|"LANDesk"\|"Cisco Clean Access Agent"\|"Cisco NAC Agent"\|"Apple Application Support"\|"Configuration Manager Client"\|"CyberLink PowerDVD"\|"KB982726"\|"DirectX 9"\|"Enterprise Architect 11"\|"FreeMind"\|"Intel network"\|"Intel driver"\|"Intel connections"\|"Java 7"\|"in Microsoft .NET Framework 4.5.1"\|"in Microsoft Lync Server 2013"\|"Microsoft Office"\|"Microsoft Silverlight"\|"in Microsoft Visual"\|"Mozilla Firefox"\|"Mozilla Maintenance Service"\|"Maintenance Service in Mozilla"\|"KB954430"\|"KB973688"\|"MSXML"\|"Notepad++"\|"Parity Agent"\|"PhotoShow"\|"Quicktime"\|"RBVirtualFolder64Inst"\|"RealPlayer"\|"Realtek"\|"Roxio Creator"\|"Sonic CinePlayer"\|"Sophos anti-virus"\|"Sophos autoupdate"\|"Sophos remote"\|"Winrar"\|"Microsoft Windows Server 2008"\|"Windows Server 2008"\|"Solaris"\|"Oracle Sun Solaris"\|"Oracle Solaris"\|"Microsoft Windows Server"\|"Microsoft IIS"\|"IIS"\|"in microsoft exchange"\|"in Cisco ios" all_vulnerabilities.txt > filtered.txt')
