#!/usr/bin/env python3.5

'''
@author    Antonio Faccioli <antonio.faccioli@soluzioniopen.com>
@license   http://directory.fsf.org/wiki/License:MPLv2.0
@version   1.0
'''

import tkinter as tk
import tkinter.ttk as ttk
from tkinter import messagebox
import sys, os.path, subprocess
import urllib.request
import time
import zipfile


class Main:

    def __init__ (self):
        self.main = tk.Tk()
        self.main.title("Sodilinux Extra Package 1.0")
        self.current_dir = os.path.dirname(os.path.realpath(sys.argv[0]))
        self.header = tk.PhotoImage(file=self.current_dir + '/images/header.gif')

        #environment variables
        self.font = "Liberation Sans"
        self.label_text1 = "Installa"
        self.label_text2 = "Disinstalla"
        self.url_check = "http://www.google.it"
        self.title_infobox = "Attenzione"
        self.content_infobox = "Per eseguire questo programma devi avere i privilegi di Root!"

        self.home = subprocess.getstatusoutput("echo $HOME")
        self.download_directory = self.home[1] + "/Scaricati/SodilinuxExtra"

        if os.path.exists(self.download_directory) == False:
            subprocess.getstatusoutput("mkdir " + self.download_directory)

            
        #self.package = ""

        self.intro = '''"So.Di.Linux Extra" è un tool che aiuta e semplifica l'installazione di alcuni software non presenti nell'installazione base.

Selezionate una delle voci poste sul lato sinistro della finestra, quindi utilizzate i pulsanti posti alla fine della finestra per installare o disinstallare il programma.

I pulsanti si abilitano in base alla presenza o meno sul vostro PC del software sul quale avete cliccato.
'''
        self.info = '''Sviluppato da Antonio Faccioli
<antonio.faccioli@soluzioniopen.com>
Licenza http://directory.fsf.org/wiki/License:MPLv2.0
Versione 1.0

Il tool è stato finanziato da Italian Linux Society attraverso il crowdfunding.'''

        self.chrome = '''Google Chrome (detto anche semplicemente Chrome) è un navigatore web sviluppato da Google, basato, a partire dalla versione 28, sul motore di esecuzione Blink (precedentemente sfruttava WebKit). Basato sul navigatore web Chromium, Chrome nel corso degli anni è cresciuto a tal punto da diventare il browser più usato al mondo nell'aprile 2016 con una percentuale del 41,81% secondo il sito Netmarketshare. (Fonte Wikipedia)'''

        self.earth = '''Google Earth è un'applicazione grafica tridimensionale che permette di visualizzare fotografie aeree e satellitari della Terra con un dettaglio molto elevato. Nelle principali città del pianeta il programma è in grado di mostrare immagini con una risoluzione spaziale inferiore al metro quadrato.
Il programma non consente solamente di visualizzare le informazioni, ma consente anche al singolo utente di immettere delle informazioni aggiuntive che vengono visualizzate dal programma e che possono essere condivise con gli altri utilizzatori del programma sparsi per il pianeta.
Google Earth mostra una rappresentazione tridimensionale del terreno all'utilizzo dei dati DEM (Digital Elevation Model) collezionati durante la missione NASA Shuttle Radar Topography Mission. Da novembre 2006 sono stati integrati ulteriori dati DEM per migliorare la rappresentazione tridimensionale.
Il linguaggio KML è utilizzato all'interno del programma per gestire dati geospaziali in tre dimensioni.
Google Earth può essere utilizzato fornendogli coordinate geografiche, indirizzi o semplicemente navigando sul pianeta con il mouse.
La maggior parte delle grandi città sono disponibili in alta risoluzione in modo da potere vedere gli edifici, le strade e le macchine presenti. (Fonte Wikipedia)'''

        self.team = '''TeamViewer è un programma che vi permette di condividere il vostro schermo in maniera spontanea con qualsiasi pc via internet, anche attraverso i firewall.'''

        self.skype = '''Skype è un software proprietario freeware di messaggistica istantanea e VoIP. Esso unisce caratteristiche presenti nei client più comuni (chat, salvataggio delle conversazioni, trasferimento di file) ad un sistema di telefonate basato su un network Peer-to-peer. Gli sviluppatori dell'idea Niklas Zennström e Janus Friis sono gli stessi che hanno realizzato il popolare client di file sharing Kazaa, ossia la Sharman Networks. Il prodotto è stato introdotto nel 2003. La soluzione tecnica è stata messa a punto in Estonia da Jaan Tallinn, Ahti Heinla e Priit Kasesalu.
La possibilità di far uso di un servizio a pagamento, SkypeOut, che permette di effettuare chiamate a telefoni fissi, rendono il programma competitivo rispetto ai costi della telefonia tradizionale, soprattutto per le chiamate internazionali e intercontinentali. Con Skype è possibile anche inviare sms a basso costo verso tutti gli operatori di rete mobile.
Skype fa uso di un protocollo VoIP proprietario (cioè non formalizzato in alcuno standard internazionale) per trasmettere le chiamate. I dati, trasmessi in forma digitale, vengono cifrati tramite algoritmi non divulgati pubblicamente. L'azienda produttrice del programma assicura un grado di protezione della comunicazione comparabile con quello dei più diffusi standard crittografici. (Fonte Wikipedia)'''

        self.pdf = '''PDF-XChange Viewer è un lettore PDF per Windows. Il lettore in versione base, distribuito sotto licenza freeware, include caratteristiche avanzate oltre a quelle di visualizzazione base, quali scrivere sopra ad un PDF, evidenziare le righe di un testo, mettere note e timbri, disegnare (sia forme preimpostate, sia a mano libera), salvare una o più pagine in formato JPEG. È inoltre possibile cercare stringhe di testo all'interno del file aperto o sui principali motori di ricerca online, compresa Wikipedia, direttamente dalla barra degli strumenti del programma.

I file PDF che sono assegnati in modo predefinito a questo programma, hanno come propria icona l'anteprima della loro pagina iniziale, senza dover sbloccare funzioni avanzate di Windows.

PDF-XChange Viewer lavora bene anche sull'emulatore Wine per Linux, divenendo così un software valido per le annotazioni sui file PDF anche fuori dall'ambiente Windows. (Fonte Wikipedia)'''

        self.cmaps = '''È un programma multipiattaforma per sviluppare e visualizzare mappe concettuali realizzato dall’Institute for
Human and Machine Cognition dell’Università della West Florida. È prodotto da un gruppo di lavoro che fa
direttamente riferimento a Joseph D. Novak. (Fonte guida Cmaps)'''

        self.font = '''Intalla i più comuni font presenti nei sistemi Microsoft. Vengono installati anche i font liberi Caladea e Carlito, sostituti di Cambria e Calibri.'''

        self.adobe = '''Adobe Integrated Runtime (AIR) è un ambiente di sviluppo multipiattaforma per applicazioni internet che usano Adobe Flash, Adobe Flex, HTML, o AJAX, che possono essere utilizzate come applicazioni desktop.
AIR, senza alcun uso di un browser, consente di scrivere applicazioni per garantire molte delle caratteristiche dei più tradizionali programmi installabili su desktop, grazie all'uso di codice Flash, HTML e JavaScript.
Un programma scritto in Flash è quindi eseguibile su qualunque computer abbia installato Adobe Air: sia esso un Pc con Windows, un Macintosh, un tablet con Android o un dispositivo mobile iOs. (Fonte Wikipedia)

Adobe Air è indispensabile per eseguire il software Scratch 2.0
'''

        self.ubuntu = '''Nei sistemi Linux l’installazione di default consente di riprodurre un numero limitato di formati audio video: i formati “free”. Per riprodurre ad esempio i files mp3, wma o dvx è necessario installare i codec specifici. Per installare i codec principali in Ubuntu è possibile installare il pacchetto ubuntu-restricted-extras . (Fonte Web)'''

        #message in status bar
        self.label_statebar = ["Seleziona una voce della lista",
                               "Sto controllando la connessione",
                               "ERRORE: Connessione non presente",
                               "Sto scaricando il pacchetto selezionato",
                               "Sto installado il pacchetto selezionato",
                               "Procedura completata",
                               "Sto disinstallando il pacchetto",
                               "Introduzione",
                               "Pacchetto Google Chrome",
                               "Pacchetto Google Earth",
                               "Pacchetto Teamviewer",
                               "Pacchetto Skype",
                               "Pacchetto Pdf-xchange",
                               "Pacchetto Cmaps",
                               "Pacchetto Fonts",
                               "Pacchetto Adobe Air",
                               "Pacchetto Ubuntu Extra",
                               "Informazioni",
                               "Connessione presente"]

        #header
        self.frame1 = tk.Frame(self.main, bd=1, relief="raised", bg="white")
        self.frame1.grid(row=0, column=0, sticky="we")
        self.label1 = tk.Label(self.frame1, image=self.header, bd=0)
        self.label1.grid(row=0, column=0)

        #button frame    
        self.frame2 = tk.Frame(self.main, bd=1, relief="raised")
        self.frame2.grid(row=1, column=0, sticky="we")

        #listbox area
        self.lb = tk.Listbox(self.frame2)
        self.lb.grid(row=0, column=0, sticky="we")
        self.lb.insert("end", "Introduzione")
        self.lb.insert("end", "Google Chrome")
        self.lb.insert("end", "Google Earth")
        self.lb.insert("end", "Teamviewer")
        self.lb.insert("end", "Skype")
        self.lb.insert("end", "Pdf-xchange")
        self.lb.insert("end", "Cmaps")
        self.lb.insert("end", "Fonts Microsoft")
        self.lb.insert("end", "Adobe Air")
        self.lb.insert("end", "Ubuntu Extra")
        self.lb.insert("end", "Informazioni")
        self.lb.config(selectbackground="green")
        self.lb.config(height=22)
        self.lb.bind("<<ListboxSelect>>", self.Click)

        #description area
        self.text = tk.Text(self.frame2, wrap="word")
        self.text.grid(row=0, column=1, sticky="we")
        self.text.insert("end", self.intro)
        self.text.config(state='disabled')
        self.text.config(height=23)

        #button frame    
        self.frame3 = tk.Frame(self.main, bd=1, relief="raised")
        self.frame3.grid(row=2, column=0, sticky="we")
        self.button_install = tk.Button(self.frame3, text=self.label_text1)
        self.button_install.grid(row=0, column=0, padx=4, pady=4, sticky="we")
        self.button_install.configure(state="disabled")
        self.button_uninstall = tk.Button(self.frame3, text=self.label_text2)
        self.button_uninstall.grid(row=0, column=1, padx=4, pady=4, sticky="we")
        self.button_uninstall.configure(state="disabled")
        self.progressFrame = ttk.Frame(self.frame3)
        self.progressFrame.grid(row=0, column=2)
        self.progressbar = ttk.Progressbar(self.progressFrame, orient='horizontal', mode='indeterminate', length=550)
        
        
        #state bar
        self.frame4 = tk.Frame(self.main, bd=1, relief="raised")
        self.frame4.grid(row=3, column=0, sticky="we")
        self.label_statusbar = tk.Label(self.frame4, text=self.label_statebar[0])
        self.label_statusbar.grid(row=0, column=0, padx=4, pady=4)

    def Click(self, event):
        widget = event.widget
        selection=widget.curselection()
        value = widget.get(selection[0])
        if value == "Introduzione":
            self.text.config(state='normal')
            self.text.delete(1.0, "end")
            self.text.insert("end", self.intro)
            self.text.config(state='disabled')
            self.change_label(7, 'normal', 'black')
        elif value == "Informazioni":
            self.text.config(state='normal')
            self.text.delete(1.0, "end")
            self.text.insert("end", self.info)
            self.text.config(state='disabled')
            self.change_label(17, 'normal', 'black')
        elif value == "Google Chrome":
            package = "google-chrome-stable"
            if self.query_arch() == "x86_64":
                version = "chrome64"
            else:
                version = "chrome32" 
            self.button_install.configure(state=self.query_package(package, "i", "dpkg"), command= lambda: self.install_google(package, version))
            self.button_uninstall.configure(state=self.query_package(package, "r", "dpkg"), command= lambda: self.uninstall_deb(package))
            self.change_label(8, 'normal', 'black') 
            self.text.config(state='normal')
            self.text.delete(1.0, "end")
            self.text.insert("end", self.chrome)
            self.text.config(state='disabled')
        elif value == "Google Earth":
            package = "google-earth-stable"
            if self.query_arch() == "x86_64":
                version = "earth64"
            else:
                version = "earth32"
            self.button_install.configure(state=self.query_package(package, "i", "dpkg"), command= lambda: self.install_google(package, version))
            self.button_uninstall.configure(state=self.query_package(package, "r", "dpkg"), command= lambda: self.uninstall_deb(package))
            self.change_label(9, 'normal', 'black')
            self.text.config(state='normal')
            self.text.delete(1.0, "end")
            self.text.insert("end", self.earth)
            self.text.config(state='disabled')
        elif value == "Teamviewer":
            package = "teamviewer"
            self.button_install.configure(state=self.query_package(package, "i", "dpkg"), command= lambda: self.install_dpkg(package))
            self.button_uninstall.configure(state=self.query_package(package, "r", "dpkg"), command= lambda: self.uninstall_deb(package))
            self.change_label(10, 'normal', 'black')
            self.text.config(state='normal')
            self.text.delete(1.0, "end")
            self.text.insert("end", self.team)
            self.text.config(state='disabled')
        elif value == "Skype":
            if self.query_arch() == "x86_64":
                version = "skype64"
                package = "skypeforlinux"
            else:
                version = "skype32"
                package = "skype"
            self.button_install.configure(state=self.query_package(package, "i", "dpkg"), command= lambda: self.install_dpkg(version))
            self.button_uninstall.configure(state=self.query_package(package, "r", "dpkg"), command= lambda: self.uninstall_deb(package))
            self.change_label(11, 'normal', 'black')
            self.text.config(state='normal')
            self.text.delete(1.0, "end")
            self.text.insert("end", self.skype)
            self.text.config(state='disabled')
        elif value == "Pdf-xchange":
            package = self.home[1]+"/.wine/drive_c/Program Files/Tracker Software/PDF Viewer/PDFXCview.exe"
            self.button_install.configure(state=self.query_package(package, "i", "path"), command=self.install_pdfxchange)
            self.button_uninstall.configure(state=self.query_package(package, "r", "path"), command=self.uninstall_pdfxchange)
            self.change_label(12, 'normal', 'black')
            self.text.config(state='normal')
            self.text.delete(1.0, "end")
            self.text.insert("end", self.pdf)
            self.text.config(state='disabled')
        elif value == "Cmaps":
            package = "/opt/IHMC CmapTools/CmapTools"
            if self.query_arch() == "x86_64":
                version = "cmap64"
            else:
                version = "cmap32"
            self.button_install.configure(state=self.query_package(package, "i", "path"), command= lambda: self.install_cmap(version))
            self.button_uninstall.configure(state=self.query_package(package, "r", "path"), command=self.uninstall_cmap)
            self.change_label(13, 'normal', 'black')
            self.text.config(state='normal')
            self.text.delete(1.0, "end")
            self.text.insert("end", self.cmaps)
            self.text.config(state='disabled')
        elif value == "Fonts Microsoft":
            package = "ttf-mscorefonts-installer"
            self.button_install.configure(state=self.query_package(package, "i", "dpkg"), command=self.install_fonts)
            self.button_uninstall.configure(state=self.query_package(package, "r", "dpkg"), command=self.uninstall_fonts)
            self.change_label(14, 'normal', 'black')
            self.text.config(state='normal')
            self.text.delete(1.0, "end")
            self.text.insert("end", self.font)
            self.text.config(state='disabled')
        elif value == "Adobe Air":
            package = "/opt/Adobe AIR/Versions/1.0/Adobe AIR Application Installer"
            if self.query_arch() == "x86_64":
                version = "air64"
            else:
                version = "air32"
            self.button_install.configure(state=self.query_package(package, "i", "path"), command= lambda: self.install_air(version))
            self.button_uninstall.configure(state=self.query_package(package, "r", "path"), command=self.uniinstall_air)
            self.change_label(15, 'normal', 'black')
            self.text.config(state='normal')
            self.text.delete(1.0, "end")
            self.text.insert("end", self.adobe)
            self.text.config(state='disabled')
        elif value == "Ubuntu Extra":
            package = "ubuntu-restricted-extras"
            self.button_install.configure(state=self.query_package(package, "i", "dpkg"), command=self.install_extra)
            self.button_uninstall.configure(state=self.query_package(package, "r", "dpkg"), command=self.uninstall_extra)
            self.change_label(16, 'normal', 'black')
            self.text.config(state='normal')
            self.text.delete(1.0, "end")
            self.text.insert("end", self.ubuntu)
            self.text.config(state='disabled')

    def query_package(self, package, action, type_query):
        if type_query == "dpkg":
            status = subprocess.getstatusoutput("dpkg-query -Wf='${db:Status-abbrev}' " + package)
            if status[1] == "ii ":
                if action == "i":
                    state = 'disabled'
                elif action == "r":
                    state = 'normal'
            else:
                if action == "i":
                    state = 'normal'
                elif action == "r":
                    state = 'disabled'  
        elif type_query == "path":
            if os.path.exists(package):
                if action == "i":
                    state = 'disabled'
                elif action == "r":
                    state = 'normal'
            else:
                if action == "i":
                    state = 'normal'
                elif action == "r":
                    state = 'disabled'
        return state


    def install_google(self, package, version):
        self.check_connection()
        self.change_state_button('disabled')
        self.change_label(3, 'normal', 'black')
        link_key = "https://dl-ssl.google.com/linux/linux_signing_key.pub"
        package_name = {"chrome64":"sudo sh -c 'echo \"deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main\" >> /etc/apt/sources.list.d/google.list'",
                    "chrome32":"sudo sh -c 'echo \"deb http://dl.google.com/linux/chrome/deb/ stable main\" >> /etc/apt/sources.list.d/google.list'",
                    "earth64":"sudo sh -c 'echo \"deb [arch=amd64] http://dl.google.com/linux/earth/deb/ stable main\" >> /etc/apt/sources.list.d/google.list'",
                    "earth32":"sudo sh -c 'echo \"deb http://dl.google.com/linux/earth/deb/ stable main\" >> /etc/apt/sources.list.d/google.list'"
                    }

        proc = subprocess.Popen('wget -q -O - ' + link_key + ' | sudo apt-key add -', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen(package_name[version], shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('sudo apt-get --assume-yes update', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('sudo apt-get --assume-yes install ' + package, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        

    def uninstall_deb(self, package):
        self.start_progressbar()
        proc = subprocess.Popen('sudo apt-get --assume-yes remove ' + package, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        self.stop_progressbar()


    def install_dpkg(self, package):
        self.start_progressbar()
        self.check_connection()
        self.change_state_button('disabled')
        self.change_label(3, 'normal', 'black')
        link_get = {'teamviewer':'http://download.teamviewer.com/download/teamviewer_i386.deb',
                    'skype64':'https://go.skype.com/skypeforlinux-64-alpha.deb',
                    'skype32':'http://www.skype.com/go/getskype-linux-deb'
                    }
        package_name = {'teamviewer':'teamviewer_i386.deb',
                    'skype64':'skypeforlinux-64-alpha.deb',
                    'skype32':'skype-debian_4.3.0.37-1_i386.deb'
                    }
        proc = subprocess.Popen('wget ' + link_get[package] + ' -P ' + self.download_directory, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('dpkg -i ' + self.download_directory + '/' + package_name[package], shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('apt -f install', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        self.stop_progressbar()
        

    def install_pdfxchange(self):
        self.check_connection()
        self.change_state_button('disabled')
        link_get = {'pdfxchange':'https://www.tracker-software.com/downloads/PDFXVwer.zip'}
        proc = subprocess.Popen('wget ' + link_get['pdfxchange'] + ' -P ' + self.download_directory, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        zip_ref = zipfile.ZipFile(self.download_directory + '/PDFXVwer.zip', 'r')
        zip_ref.extractall(self.download_directory)
        zip_ref.close()
        proc = subprocess.Popen('wine ' + self.download_directory + '/PDFXVwer.exe /VERYSILENT /NORESTART', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()

    def uninstall_pdfxchange(self):
        pdfxchange = "~/.wine/drive_c/Program\ Files/Tracker\ Software/PDF\ Viewer/unins000.exe"
        proc = subprocess.Popen('wine ' + pdfxchange, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()

    def install_cmap(self, package):
        self.check_connection()
        link_get = {'cmap32':'http://cmapdownload.ihmc.us/installs/CmapTools/Linux/Linux32CmapTools_v6.02_08-11-16.bin',
                    'cmap64':'http://cmapdownload.ihmc.us/installs/CmapTools/Linux/Linux64CmapTools_v6.02_08-11-16.bin'
                    }
        
        confcmap = open(self.download_directory + "/installer.properties", "w")

        confcmap.write("INSTALLER_UI=SILENT\n")
        confcmap.write("CONFIGURATION=Advanced\n")
        confcmap.write("USER_INSTALL_DIR=/opt/IHMC CmapTools\n")
        confcmap.write("USER_SHORTCUTS=" + self.home[1] + "/Scrivania\n")
        confcmap.write("USER_PROFILE=" + self.home[1] + "/CmapTools/profile\n")
        confcmap.write("LOGS=1\n")
        confcmap.write("LOGS_PATH=" + self.home[1] + "/CmapTools/profile/CmapToolsLogs\n")

        confcmap.close()

        proc = subprocess.Popen('wget ' + link_get[package] + ' -P ' + self.download_directory, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()

        proc = subprocess.Popen('sudo chmod +x ' + self.download_directory + '/Linux64CmapTools_v6.02_08-11-16.bin', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()         

        proc = subprocess.Popen('sudo ' + self.download_directory + '/Linux64CmapTools_v6.02_08-11-16.bin -i silent -f ' + self.download_directory + '/installer.properties', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()

        proc = subprocess.Popen('wget http://cmap.ihmc.us/wp-content/themes/cmap/img/cmap-logo.png -P /opt/\'IHMC CmapTools\'/', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()

        iconFile = open('/usr/share/applications/cmaptools.desktop','w')

        iconFile.write('[Desktop Entry]\n')
        iconFile.write('Type=Application\n')
        iconFile.write('Icon=/opt/IHMC CmapTools/cmap-logo.png\n')
        iconFile.write('Name=CmapTools\n')
        iconFile.write('Name[it]=CmapTools\n')
        iconFile.write('Categories=Graphics;\n')
        iconFile.write('Exec=/opt/\'IHMC CmapTools\'/CmapTools\n')
        iconFile.write('StartupNotify=true\n')
        iconFile.write('Terminal=false\n')
        iconFile.write('MimeType=x-directory/normal;inode/directory;\n')
        iconFile.write('Encoding=UTF-8\n')
        iconFile.write('X-Desktop-File-Install-Version=0.11\n')

        iconFile.close()
        

    def uninstall_cmap(self):
        proc = subprocess.Popen('sudo rm /opt/\'IHMC CmapTools\'/cmap-logo.png', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('sudo rm /usr/share/applications/cmaptools.desktop', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('sudo /opt/\'IHMC CmapTools\'/\'Uninstall CmapTools\'', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()

    def install_fonts(self):
        self.start_progressbar()
        self.check_connection()
        self.change_state_button('disabled')
        proc = subprocess.Popen('apt install cabextract', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait() 
        link_get = {'fonts':'http://ftp.de.debian.org/debian/pool/contrib/m/msttcorefonts/ttf-mscorefonts-installer_3.6_all.deb'}
        proc = subprocess.Popen('wget ' + link_get['fonts'] + ' -P ' + self.download_directory, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('apt --assume-yes install cabextract', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('dpkg -i ' + self.download_directory + '/ttf-mscorefonts-installer_3.6_all.deb', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('apt --assume-yes install fonts-crosextra-caladea', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('apt --assume-yes install fonts-crosextra-carlito', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('apt --assume-yes -f install', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        self.stop_progressbar()

    def uninstall_fonts(self):
        proc = subprocess.Popen('apt --assume-yes remove ttf-mscorefonts-installer', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('apt --assume-yes remove fonts-crosextra-caladea', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('apt --assume-yes remove fonts-crosextra-carlito', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()

    def install_air(self, version):
        self.check_connection()
        self.change_state_button('disabled')
        link_get = {'air32':'adobeair_2.6.0.2_i386.deb',
                    'air64':'adobeair_2.6.0.2_amd64.deb'
                    }
        proc = subprocess.Popen('wget http://drive.noobslab.com/data/apps/AdobeAir/' + link_get[version] +  ' -P ' + self.download_directory, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('dpkg -i ' + self.download_directory + '/' + link_get[version], shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('apt-get install -f', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('wget https://scratch.mit.edu/scratchr2/static/sa/Scratch-456.0.1.air -P ' + self.download_directory, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('/opt/Adobe AIR/Versions/1.0/Adobe AIR Application Installer -silent -location /opt ' + self.download_directory + '/' + 'Scratch-456.0.1.air', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()

    def unistall_air():
        proc = subprocess.Popen('apt autoremove adobeair', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()

    def install_extra(self):
        proc = subprocess.Popen('apt --assume-yes install ubuntu-restricted-extras', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('apt --assume-yes install libdvdnav4 libdvdread4 gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly libdvd-pkg', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('dpkg-reconfigure libdvd-pkg', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('apt --assume-yes -f install', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()

    def uninstall_extra(self):
        proc = subprocess.Popen('apt --assume-yes remove ubuntu-restricted-extras', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('apt --assume-yes remove libdvdnav4 libdvdread4 gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly libdvd-pkg', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()

    #control architecture 32 or 64
    def query_arch(self):
        self.arch = subprocess.getstatusoutput("uname -m")
        return self.arch[1]

    #control root session
    def check_root(self):
        if os.getuid() != 0:
                messagebox.showinfo(self.title_infobox, self.content_infobox)
                sys.exit()

    #change button
    def change_state_button(self, new_state):
        self.button_install.config(state=new_state)
        self.button_uninstall.config(state=new_state)

    #change label
    def change_label(self, label_id, style, color):
        self.label_statusbar.config(fg=color, text=self.label_statebar[label_id])

    def start_progressbar(self):
        self.progressbar.grid(row=0, column=0)
        self.progressbar.start(50)

    def stop_progressbar(self):
        self.progressbar.stop()
        self.progressbar.grid_remove()

    #close window
    def halt(self):
        self.destroy

    #control connection
    def check_connection(self):
        self.check_root()
        self.change_state_button('disabled')
        self.change_label(1, 'normal', 'black')
        try:
                urllib.request.urlopen(self.url_check)
                self.change_label(18, 'normal', 'black')
                self.change_state_button('normal')
        except:
                self.change_label(2, 'normal', 'red')
                self.change_state_button('normal')

    def start(self):
        self.main.mainloop()
	
app = Main()
app.start()
