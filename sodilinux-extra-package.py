#!/usr/bin/env python3.5

'''
@author    Antonio Faccioli <antonio.faccioli@soluzioniopen.com>
@license   http://directory.fsf.org/wiki/License:MPLv2.0
@version   1.2
'''

import tkinter as tk
import tkinter.ttk as ttk
from tkinter import messagebox
import sys, os.path, subprocess
import urllib.request
from time import sleep
import zipfile
from tkinter.simpledialog import askstring
from urllib.error import URLError, HTTPError


class Main:

    def __init__ (self):
        self.main = tk.Tk()
        self.main.title("Sodilinux Extra Package 1.1")
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


        self.intro = '''"So.Di.Linux Extra" è un tool che aiuta e semplifica l'installazione di alcuni software non presenti nell'installazione base.

Selezionate una delle voci poste sul lato sinistro della finestra, quindi utilizzate i pulsanti posti alla fine della finestra per installare o disinstallare il programma.

I pulsanti si abilitano in base alla presenza o meno sul vostro PC del software sul quale avete cliccato.
'''
        self.info = '''Sviluppato da Antonio Faccioli
<antonio.faccioli@soluzioniopen.com>
Licenza http://directory.fsf.org/wiki/License:MPLv2.0
Versione 1.1

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

        self.air = '''Scratch è un ambiente di programmazione gratuito, con un linguaggio di programmazione di tipo grafico. Il linguaggio, ispirato alla teoria costruzionista dell'apprendimento e progettato per l'insegnamento della programmazione tramite primitive visive, è adatto a studenti, insegnanti e genitori, ed utilizzabile per progetti pedagogici e di intrattenimento che spaziano dalla matematica alla scienza, consentendo la realizzazione di simulazioni, visualizzazione di esperimenti, animazioni, musica, arte interattiva, e semplici giochi.
Scratch prevede un approccio orientato agli oggetti (denominati Sprites).
Scratch è un linguaggio di programmazione che consente di elaborare storie interattive, giochi, animazioni, arte e musica. Inoltre permette di condividere i progetti con altri utenti del web.
L'idea di questo linguaggio è che anche i bambini o le persone inesperte di linguaggi di programmazione possono imparare importanti concetti di calcolo matematico, a ragionare in modo sistematico, a pensare in modo creativo e anche a lavorare partecipativamente.
Scratch è caratterizzato da una programmazione con blocchi di costruzione (blocchi grafici) creati per adattarsi l'un l'altro, ma solo se inseriti in una corretta successione, in questo modo si evitano inesattezze nella sintassi.
'''
        self.vKaraoke = '''vanBasco's Karaoke Player 2.53 è un riproduttore MIDI Karaoke che mostra i testi a schermo intero. Supporta skin, cambiamenti e richiami di tempo, volume e chiave, disabilitare / assolo degli strumenti, e altro ancora.'''

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
                               "Pacchetto Adobe Air e Scratch",
                               "Pacchetto Ubuntu Extra",
                               "Informazioni",
                               "Connessione presente",
                               "Pacchetto vanBasco Karaoke"]

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
        self.lb.insert("end", "Adobe Air e Scratch")
        self.lb.insert("end", "Ubuntu Extra")
        self.lb.insert("end", "vKaraoke")
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
            package = "google-earth-pro-stable"
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
            package = self.home[1] + "/.wine/drive_c/Program\ Files/Tracker\ Software/PDF\ Viewer/PDFXCview.exe"
            self.button_install.configure(state=self.query_package(package, "i", "path"), command=self.install_pdfxchange)
            self.button_uninstall.configure(state=self.query_package(package, "r", "path"), command=self.uninstall_pdfxchange)
            self.change_label(12, 'normal', 'black')
            self.text.config(state='normal')
            self.text.delete(1.0, "end")
            self.text.insert("end", self.pdf)
            self.text.config(state='disabled')
        elif value == "Cmaps":
            package = "/opt/IHMC Cmapt-getools/Cmapt-getools"
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
        elif value == "Adobe Air e Scratch":
            package = "/opt/Adobe AIR/Versions/1.0/Adobe AIR Application Installer"
            if self.query_arch() == "x86_64":
                version = "air64"
            else:
                version = "air32"
            self.button_install.configure(state=self.query_package(package, "i", "path"), command=self.install_scratch)
            self.button_uninstall.configure(state=self.query_package(package, "r", "path"), command=self.uninstall_air)
            self.change_label(15, 'normal', 'black')
            self.text.config(state='normal')
            self.text.delete(1.0, "end")
            self.text.insert("end", self.air)
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
        elif value == "vKaraoke":
            package = self.home[1]+"/.wine/drive_c/Program\ Files\ \(x86\)/vanBasco's\ Karaoke\ Player/vmidi.exe"
            self.button_install.configure(state=self.query_package(package, "i", "path"), command=self.install_vkaraoke)
            self.button_uninstall.configure(state=self.query_package(package, "r", "path"), command=self.uninstall_vkaraoke)
            self.change_label(19, 'normal', 'black')
            self.text.config(state='normal')
            self.text.delete(1.0, "end")
            self.text.insert("end", self.vKaraoke)
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


    def getPsw(self, message):
        psw = askstring('Password', message, show='*')                                                                                                                            
        return psw                                                                                 
       
    def install_google(self, package, version):
        self.psw = self.getPsw("Inserisci la password per l'installazione")
        self.check_connection()
        self.change_state_button('disabled')
        self.change_label(3, 'normal', 'black')
        link_key = "https://dl.google.com/linux/linux_signing_key.pub"
        package_name = {"chrome64":" sh -c 'echo \"deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main\" >> /etc/apt/sources.list.d/google-chrome.list'",
                    "chrome32":" sh -c 'echo \"deb http://dl.google.com/linux/chrome/deb/ stable main\" >> /etc/apt/sources.list.d/google-chrome.list'",
                    "earth64":" sh -c 'echo \"deb [arch=amd64] http://dl.google.com/linux/earth/deb/ stable main\" >> /etc/apt/sources.list.d/google-earth.list'",
                    "earth32":" sh -c 'echo \"deb http://dl.google.com/linux/earth/deb/ stable main\" >> /etc/apt/sources.list.d/google-earth.list'"
                    }

        pathList = {"chrome64":"/etc/apt/sources.list.d/google-chrome.list",
                    "chrome32":"/etc/apt/sources.list.d/google-chrome.list",
                    "earth64":"/etc/apt/sources.list.d/google-earth.list",
                    "earth32":"/etc/apt/sources.list.d/google-earth.list"
                    }

        proc = subprocess.Popen('wget ' + link_key + ' -P ' + self.download_directory, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('echo ' + self.psw + ' | sudo -S apt-key add ' + self.download_directory + '/linux_signing_key.pub', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        if os.path.exists(pathList[version]) == False:
            proc = subprocess.Popen('echo ' + self.psw + ' | sudo -S '+ package_name[version], shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
            proc.wait()
        self.change_label(4, 'normal', 'black')
        proc = subprocess.Popen('echo ' + self.psw + ' | sudo -S apt-get --assume-yes update', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('echo ' + self.psw + ' | sudo -S apt-get --assume-yes install ' + package, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('echo ' + self.psw + ' | sudo -S apt-get --assume-yes install -f', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        self.change_label(5, 'normal', 'black')
        self.main.update()


    def uninstall_deb(self, package):
        self.psw = self.getPsw("Inserisci la password per l'installazione")
        self.change_label(6, 'normal', 'black')
        proc = subprocess.Popen('echo '+ self.psw + ' | sudo -S sudo apt-get --assume-yes remove ' + package, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        self.change_label(5, 'normal', 'black')


    def install_dpkg(self, package):
        self.psw = self.getPsw("Inserisci la password per l'installazione")
        self.check_connection()
        self.change_state_button('disabled')
        self.change_label(3, 'normal', 'black')
        link_get = {'teamviewer':'http://download.teamviewer.com/download/teamviewer_i386.deb',
                    'skype64':'https://go.skype.com/skypeforlinux-64.deb',
                    'skype32':'http://www.skype.com/go/getskype-linux-deb'
                    }
        package_name = {'teamviewer':'teamviewer_i386.deb',
                    'skype64':'skypeforlinux-64.deb',
                    'skype32':'skype-debian_4.3.0.37-1_i386.deb'
                    }
        proc = subprocess.Popen('wget ' + link_get[package] + ' -P ' + self.download_directory, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        self.change_label(4, 'normal', 'black')
        proc = subprocess.Popen('echo '+ self.psw + ' | sudo -S dpkg -i ' + self.download_directory + '/' + package_name[package], shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('echo '+ self.psw + ' | sudo -S apt-get --assume-yes -f install', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        self.change_label(5, 'normal', 'black')


    def install_pdfxchange(self):
        self.check_connection()
        self.change_state_button('disabled')
        self.change_label(3, 'normal', 'black')
        link_get = {'pdfxchange':'https://www.tracker-software.com/downloads/PDFXVwer.zip'}
        proc = subprocess.Popen('wget ' + link_get['pdfxchange'] + ' -P ' + self.download_directory, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        zip_ref = zipfile.ZipFile(self.download_directory + '/PDFXVwer.zip', 'r')
        zip_ref.extractall(self.download_directory)
        zip_ref.close()
        self.change_label(4, 'normal', 'black')
        proc = subprocess.Popen('wine ' + self.download_directory + '/PDFXVwer.exe /VERYSILENT /NORESTART', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        self.change_label(5, 'normal', 'black')

    def uninstall_pdfxchange(self):
        self.change_label(6, 'normal', 'black')
        pdfxchange = "~/.wine/drive_c/Program\ Files/Tracker\ Software/PDF\ Viewer/unins000.exe"
        proc = subprocess.Popen('wine ' + pdfxchange, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        self.change_label(5, 'normal', 'black')

    def install_vkaraoke(self):
        self.check_connection()
        self.change_state_button('disabled')
        self.change_label(3, 'normal', 'black')
        link_get = {'vkaraoke':'http://www.vanbasco.com/downloads/vkaraoke.exe'}
        proc = subprocess.Popen('wget ' + link_get['vkaraoke'] + ' -P ' + self.download_directory, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        self.change_label(4, 'normal', 'black')
        proc = subprocess.Popen('wine ' + self.download_directory + '/vkaraoke.exe /VERYSILENT /NORESTART', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        self.change_label(5, 'normal', 'black')

    def uninstall_vkaraoke(self):
        self.change_label(6, 'normal', 'black')
        vkaraoke = "~/.wine/drive_c/Program\ Files\ \(x86\)/vanBasco's\ Karaoke\ Player/uninst.exe"
        proc = subprocess.Popen('wine ' + vkaraoke, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        self.change_label(5, 'normal', 'black')

    def install_cmap(self, package):
        self.psw = self.getPsw("Inserisci la password per l'installazione")
        self.check_connection()
        self.change_label(3, 'normal', 'black')
        link_get = {'cmap32':'http://cmapdownload.ihmc.us/installs/Cmapt-getools/Linux/Linux32Cmapt-getools_v6.03_10-04-17.bin',
                    'cmap64':'http://cmapdownload.ihmc.us/installs/Cmapt-getools/Linux/Linux64Cmapt-getools_v6.03_10-04-17.bin'
                    }
        
        link_inst = {'cmap32':'Linux32Cmapt-getools_v6.03_10-04-17.bin',
                    'cmap64':'Linux64Cmapt-getools_v6.03_10-04-17.bin'
                    }

        confcmap = open(self.download_directory + "/installer.properties", "w")

        confcmap.write("INSTALLER_UI=SILENT\n")
        confcmap.write("CONFIGURATION=Advanced\n")
        confcmap.write("USER_INSTALL_DIR=/opt/IHMC Cmapt-getools\n")
        confcmap.write("USER_SHORTCUTS=" + self.home[1] + "/Scrivania\n")
        confcmap.write("USER_PROFILE=" + self.home[1] + "/Cmapt-getools/profile\n")
        confcmap.write("LOGS=1\n")
        confcmap.write("LOGS_PATH=" + self.home[1] + "/Cmapt-getools/profile/Cmapt-getoolsLogs\n")

        confcmap.close()

        proc = subprocess.Popen('wget ' + link_get[package] + ' -P ' + self.download_directory, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        self.change_label(4, 'normal', 'black')
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S chmod +x ' + self.download_directory + '/' + link_get[package], shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()

        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S  ' + self.download_directory + '/' + link_get[package] + '-i silent -f ' + self.download_directory + '/installer.properties', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()

        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S wget http://cmap.ihmc.us/wp-content/themes/cmap/img/cmap-logo.png -P /opt/\'IHMC Cmapt-getools\'/', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()

        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S ', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()

        iconFile = open(self.download_directory + '/cmapt-getools.desktop','w')

        iconFile.write('[Desktop Entry]\n')
        iconFile.write('Type=Application\n')
        iconFile.write('Icon=/opt/IHMC Cmapt-getools/cmap-logo.png\n')
        iconFile.write('Name=CmapTools\n')
        iconFile.write('Name[it]=CmapTools\n')
        iconFile.write('Categories=SDL-IMP;SDL-COMP;PRI;SPG;SSG;UNI;AC;\n')
        iconFile.write('Exec=/opt/\'IHMC Cmapt-getools\'/Cmapt-getools\n')
        iconFile.write('StartupNotify=true\n')
        iconFile.write('Terminal=false\n')
        iconFile.write('MimeType=application/cmaptools;\n')
        iconFile.write('Encoding=UTF-8\n')
        iconFile.write('X-Desktop-File-Install-Version=0.11\n')

        iconFile.close()

        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S cp ' + self.download_directory + '/cmapt-getools.desktop /usr/share/applications/cmapt-getools.desktop', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        
        self.change_label(5, 'normal', 'black')


    def uninstall_cmap(self):
        self.psw = self.getPsw("Inserisci la password per l'installazione")
        self.change_label(6, 'normal', 'black')
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S rm /opt/\'IHMC Cmapt-getools\'/cmap-logo.png', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S rm /usr/share/applications/cmapt-getools.desktop', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S /opt/\'IHMC Cmapt-getools\'/\'Uninstall Cmapt-getools\'', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        self.change_label(5, 'normal', 'black')

    def install_fonts(self):
        self.psw = self.getPsw("Inserisci la password per l'installazione")
        self.check_connection()
        self.change_label(3, 'normal', 'black')
        self.change_state_button('disabled')
        proc = subprocess.Popen('apt-get install cabextract', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        link_get = {'fonts':'http://ftp.de.debian.org/debian/pool/contrib/m/msttcorefonts/ttf-mscorefonts-installer_3.6_all.deb'}
        proc = subprocess.Popen('wget ' + link_get['fonts'] + ' -P ' + self.download_directory, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        self.change_label(4, 'normal', 'black')
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S apt-get --assume-yes install cabextract', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S dpkg -i ' + self.download_directory + '/ttf-mscorefonts-installer_3.6_all.deb', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S apt-get --assume-yes install fonts-crosextra-caladea', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S apt-get --assume-yes install fonts-crosextra-carlito', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S apt-get --assume-yes install -f', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        self.change_label(5, 'normal', 'black')

    def uninstall_fonts(self):
        self.psw = self.getPsw("Inserisci la password per l'installazione")
        self.change_label(6, 'normal', 'black')
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S apt-get --assume-yes remove ttf-mscorefonts-installer', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S apt-get --assume-yes remove fonts-crosextra-caladea', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S apt-get --assume-yes remove fonts-crosextra-carlito', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        self.change_label(5, 'normal', 'black')

    def uninstall_air(self):
        self.psw = self.getPsw("Inserisci la password per l'installazione")
        self.change_label(6, 'normal', 'black')
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S rm -R /opt/adobe-air-sdk/', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        self.change_label(5, 'normal', 'black')

    def install_scratch(self):
        self.psw = self.getPsw("Inserisci la password per l'installazione")
        self.check_connection()
        self.change_state_button('disabled')
        self.change_label(3, 'normal', 'black')
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S apt-get --assume-yes install libgtk2.0-0:i386 libstdc++6:i386 libxml2:i386 libxslt1.1:i386 libcanberra-gtk-module:i386 gtk2-engines-murrine:i386 libqt4-qt3support:i386 libgnome-keyring0:i386 libnss-mdns:i386 libnss3:i386', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S ln -s /usr/lib/i386-linux-gnu/libgnome-keyring.so.0 /usr/lib/libgnome-keyring.so.0', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S ln -s /usr/lib/i386-linux-gnu/libgnome-keyring.so.0.2.0 /usr/lib/libgnome-keyring.so.0.2.0', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('wget http://airdownload.adobe.com/air/lin/download/2.6/AdobeAIRSDK.tbz2 -P ' + self.download_directory, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S mkdir /opt/adobe-air-sdk', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S tar jxf ' + self.download_directory + '/AdobeAIRSDK.tbz2 -C /opt/adobe-air-sdk', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('wget https://aur.archlinux.org/cgit/aur.git/snapshot/adobe-air.tar.gz -P ' + self.download_directory, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S tar xvf ' + self.download_directory + '/adobe-air.tar.gz -C /opt/adobe-air-sdk', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S chmod +x /opt/adobe-air-sdk/adobe-air/adobe-air', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S mkdir /opt/adobe-air-sdk/scratch', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('wget https://scratch.mit.edu/scratchr2/static/sa/Scratch-456.0.4.air -P ' + self.download_directory, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S cp ' + self.download_directory + '/Scratch-456.0.4.air /opt/adobe-air-sdk/scratch/Scratch.air', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('wget https://dl2.macupdate.com/images/icons128/25203.png -P ' + self.download_directory, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S cp ' + self.download_directory + '/25203.png /opt/adobe-air-sdk/scratch/scratch.png', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        self.change_label(4, 'normal', 'black')

        iconFile = open(self.download_directory + '/Scratch2.desktop','w')

        iconFile.write('[Desktop Entry]\n')
        iconFile.write('Type=Application\n')
        iconFile.write('Icon=/opt/adobe-air-sdk/scratch/scratch.png\n')
        iconFile.write('Name=Scratch 2\n')
        iconFile.write('Name[it]=Scratch 2\n')
        iconFile.write('Categories=PS;SPG;SSG;SDL-IMP;\n')
        iconFile.write('Exec=/opt/adobe-air-sdk/adobe-air/adobe-air /opt/adobe-air-sdk/scratch/Scratch.air\n')
        iconFile.write('StartupNotify=true\n')
        iconFile.write('Terminal=false\n')
        iconFile.write('MimeType=application/x-scratch-project\n')
        iconFile.write('Encoding=UTF-8\n')
        iconFile.write('X-Desktop-File-Install-Version=0.11\n')

        iconFile.close()

        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S cp ' + self.download_directory + '/Scratch2.desktop /usr/share/applications/Scratch2.desktop', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()

        self.change_label(5, 'normal', 'black')
        

    def install_extra(self):
        self.psw = self.getPsw("Inserisci la password per l'installazione")
        self.change_label(4, 'normal', 'black')
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S apt-get --assume-yes install ubuntu-restricted-extras', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S apt-get --assume-yes install libdvdnav4 libdvdread4 gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly libdvd-pkg', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S dpkg-reconfigure libdvd-pkg', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S apt-get --assume-yes install -f', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        self.change_label(5, 'normal', 'black')

    def uninstall_extra(self):
        self.psw = self.getPsw("Inserisci la password per l'installazione")
        self.change_label(6, 'normal', 'black')
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S apt-get --assume-yes remove ubuntu-restricted-extras', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        proc = subprocess.Popen('echo '+ self.psw +' | sudo -S apt-get --assume-yes remove libdvdnav4 libdvdread4 gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly libdvd-pkg', shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None, executable="/bin/bash")
        proc.wait()
        self.change_label(5, 'normal', 'black')

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
        self.label_statusbar.pack()
        self.main.update_idletasks()

    #close window
    def halt(self):
        self.destroy

    #control connection
    def check_connection(self):
        try:
                urllib.request.urlopen(self.url_check)
                self.change_state_button('disabled')
                self.change_label(1, 'normal', 'black')
                self.change_label(18, 'normal', 'black')
                self.change_state_button('normal')
        except:
                self.change_label(2, 'normal', 'red')
                self.change_state_button('normal')

    def create_window(self):
        t = tk.Toplevel(self.main)
        t.wm_title("Window #%s" % self.counter)
        l = tk.Label(t, text="This is window #%s" % self.counter)
        l.pack(side="top", fill="both", expand=True, padx=100, pady=100)

    def start(self):
        self.main.mainloop()

app = Main()
app.start()

