# ATTACK WIFI

U ovom poglavlju naučit ćemo kako koristiti alate za razbijanje Wi-Fi mreže koje je ugradio Kali Linux. Međutim, važno je da bežična kartica koju imate podržava način praćenja.

Fern Wifi Cracker
Fern Wifi kreker je jedan od alata koje Kali ima za razbijanje bežične mreže.

Prije otvaranja Fern-a, trebamo prebaciti bežičnu karticu u nadzorni mod. Da biste to učinili, upišite “airmon-ng start wlan-0” u terminal.

Airmon Ng
Sada otvorite Fern Wireless Cracker.

Korak 1 − Aplikacije → Kliknite na “Wireless Attacks” → “Fern Wireless Cracker”.

Fern Wireless Cracker
Korak 2 − Odaberite bežičnu karticu kao što je prikazano na sljedećem snimku ekrana.

Wireless Card
Korak 3 − Kliknite na „Skeniraj pristupne tačke“.

Pristupna tačka
Korak 4 − Nakon završetka skeniranja, prikazat će se sve pronađene bežične mreže. U ovom slučaju pronađene su samo “WPA mreže”.

WPA mreža
Korak 5 − Kliknite na WPA mreže kao što je prikazano na gornjoj slici ekrana. Prikazuje sve pronađene bežične veze. Općenito, u WPA mrežama, kao takav izvodi napade rječnika.

Korak 6 − Kliknite na "Pretraži" i pronađite listu riječi koju ćete koristiti za napad.

Lista riječi
Korak 7 − Kliknite na „Wifi napad“.

Wifi Attack
Korak 8 – Nakon završetka napada na rječnik, pronašao je lozinku i prikazat će se kao što je prikazano na sljedećoj slici ekrana.

Dictionary Attack
Kismet
Kismet je alat za analizu WIFI mreže. To je 802.11 layer-2 bežični mrežni detektor, njuškalo i sistem za detekciju upada. Radit će sa bilo kojom bežičnom karticom koja podržava neobrađeni način praćenja (rfmon) i može njuškati 802.11a/b/g/n saobraćaj. Identificira mreže prikupljanjem paketa i skrivenih mreža.

Da biste je koristili, okrenite bežičnu karticu u način nadzora i da biste to učinili, upišite “airmon-ng start wlan-0” u terminal.

Pokrenite Wlan
Naučimo kako koristiti ovaj alat.

Korak 1 – Da biste ga pokrenuli, otvorite terminal i upišite “kismet”.

Pokreni
Korak 2 − Kliknite na “OK”.

Kismet
Korak 3 − Kliknite na “Da” kada se zatraži pokretanje Kismet servera. U suprotnom će prestati funkcionirati.

Pokrenite server
Korak 4 – Opcije pokretanja, ostavite kao zadano. Kliknite na “Start”.

Ostavi zadano
Korak 5 − Sada će se prikazati tabela u kojoj se traži da definirate bežičnu karticu. U tom slučaju kliknite na Da.

Definiraj tablicu
Korak 6 – U ovom slučaju, bežični izvor je “wlan0”. Morat ćete ga napisati u odjeljku “Intf” → kliknite na “Dodaj”.

Wirless Source
Korak 7 – Počet će njuškati wifi mreže kao što je prikazano na sljedećem snimku ekrana.

Mreže
Korak 8 – Kliknite na bilo koju mrežu, ona proizvodi bežične detalje kao što je prikazano na sljedećem snimku ekrana.

Bežična mreža
GISKismet
GISKismet je bežični alat za vizualizaciju za predstavljanje podataka prikupljenih korištenjem Kismeta na praktičan način. GISKismet pohranjuje informacije u bazu podataka tako da možemo tražiti podatke i generirati grafikone koristeći SQL. GISKismet trenutno koristi SQLite za bazu podataka i GoogleEarth / KML datoteke za crtanje.

Naučimo kako koristiti ovaj alat.

Korak 1 − Da biste otvorili GISKismet, idite na: Aplikacije → Kliknite na “Wireless Attacks” → giskismet.

Giskismet
Kao što se sjećate u prethodnom dijelu, koristili smo Kismet alat za istraživanje podataka o bežičnim mrežama i sve te podatke Kismet pakira u netXML datoteke.

Korak 2 – Da biste uvezli ovu datoteku u Giskismet, upišite “root@kali:~# giskismet -x Kismetfilename.netxml” i on će početi uvoziti datoteke.

Uvoz datoteka
Kada ih uvezemo, možemo ih uvesti u Google Earth Hotspots koje smo ranije pronašli.

Korak 3 − Pod pretpostavkom da smo već instalirali Google Earth, kliknemo Fajl → Otvori datoteku koju je Giskismet kreirao → Kliknite na „Otvori“.

google zemlja
Bit će prikazana sljedeća mapa.

Mapa
Ghost Phisher
Ghost Phisher je popularan alat koji pomaže u stvaranju lažnih bežičnih pristupnih tačaka, a zatim iu stvaranju Man-in-The-Middle-Attack-a.

Korak 1 − Da biste ga otvorili, kliknite na Aplikacije → Bežični napadi → „fišing duhova“.

Ghost Phisher
Korak 2 – Nakon otvaranja, podesit ćemo lažni AP koristeći sljedeće detalje.

Ulaz bežičnog interfejsa: wlan0
SSID: naziv bežične pristupne tačke
IP adresa: IP koji će imati AP
WAP: Lozinka koja će imati ovaj SSID za povezivanje
Otvaranje Ghost Phishera
Korak 3 − Kliknite na dugme Start.

Wifite
To je još jedan alat za bežično klakanje, koji napada više WEP, WPA i WPS šifriranih mreža zaredom.

Prvo, bežična kartica mora biti u modu za nadzor.

Korak 1 − Da biste ga otvorili, idite na Aplikacije → Wireless Attack → Wifite.

Wifite
Korak 2 − Upišite "wifite –showb" da biste skenirali mreže.

Wifite Showb
Scan Network
Korak 3 − Za početak napada na bežične mreže kliknite Ctrl + C.

Napada
Korak 4 − Upišite “1” da razbijete prvu bežičnu vezu.

Crack First
Korak 5 − Nakon što je napad završen, ključ će biti pronađen.

In this chapter, we will learn how to use Wi-Fi cracking tools that Kali Linux has incorporated. However, it is important that the wireless card that you has a support monitoring mode.

Fern Wifi Cracker
Fern Wifi cracker is one of the tools that Kali has to crack wireless.

Before opening Fern, we should turn the wireless card into monitoring mode. To do this, Type “airmon-ng start wlan-0” in the terminal.

Airmon Ng
Now, open Fern Wireless Cracker.

Step 1 − Applications → Click “Wireless Attacks” → “Fern Wireless Cracker”.

Fern Wireless Cracker
Step 2 − Select the Wireless card as shown in the following screenshot.

Wireless Card
Step 3 − Click “Scan for Access Points”.

Access Point
Step 4 − After finishing the scan, it will show all the wireless networks found. In this case, only “WPA networks” was found.

WPA Network
Step 5 − Click WPA networks as shown in the above screenshot. It shows all the wireless found. Generally, in WPA networks, it performs Dictionary attacks as such.

Step 6 − Click “Browse” and find the wordlist to use for attack.

Wordlist
Step 7 − Click “Wifi Attack”.

Wifi Attack
Step 8 − After finishing the dictionary attack, it found the password and it will show as depicted in the following screenshot picture.

Dictionary Attack
Kismet
Kismet is a WIFI network analyzing tool. It is a 802.11 layer-2 wireless network detector, sniffer, and intrusion detection system. It will work with any wireless card that supports raw monitoring (rfmon) mode, and can sniff 802.11a/b/g/n traffic. It identifies the networks by collecting packets and also hidden networks.

To use it, turn the wireless card into monitoring mode and to do this, type “airmon-ng start wlan-0” in the terminal.

Start Wlan
Let’s learn how to use this tool.

Step 1 − To launch it, open terminal and type “kismet”.

Launch
Step 2 − Click “OK”.

Kismet
Step 3 − Click “Yes” when it asks to start Kismet Server. Otherwise it will stop functioning.

Start Server
Step 4 − Startup Options, leave as default. Click “Start”.

Leave Default
Step 5 − Now it will show a table asking you to define the wireless card. In such case, click Yes.

Define Table
Step 6 − In this case, the wireless source is “wlan0”. It will have to be written in the section “Intf” → click “Add”.

Wirless Source
Step 7 − It will start sniffing the wifi networks as shown in the following screenshot.

Networks
Step 8 − Click on any network, it produces the wireless details as shown in the following screenshot.

Wireless Network
GISKismet
GISKismet is a wireless visualization tool to represent data gathered using Kismet in a practical way. GISKismet stores the information in a database so we can query data and generate graphs using SQL. GISKismet currently uses SQLite for the database and GoogleEarth / KML files for graphing.

Let’s learn how to use this tool.

Step 1 − To open GISKismet, go to: Applications → Click “Wireless Attacks” → giskismet.

Giskismet
As you remember in the previous section, we used Kismet tool to explore data about wireless networks and all this data Kismet packs in netXML files.

Step 2 − To import this file into Giskismet, type “root@kali:~# giskismet -x Kismetfilename.netxml” and it will start importing the files.

Importing Files
Once imported, we can import them to Google Earth the Hotspots that we found before.

Step 3 − Assuming that we have already installed Google Earth, we click File → Open File that Giskismet created → Click “Open”.

Google Earth
The following map will be displayed.

Map
Ghost Phisher
Ghost Phisher is a popular tool that helps to create fake wireless access points and then later to create Man-in-The-Middle-Attack.

Step 1 − To open it, click Applications → Wireless Attacks → “ghost phishing”.

Ghost Phisher
Step 2 − After opening it, we will set up the fake AP using the following details.

Wireless Interface Input: wlan0
SSID: wireless AP name
IP address: IP that the AP will have
WAP: Password that will have this SSID to connect
Opening Ghost Phisher
Step 3 − Click the Start button.

Wifite
It is another wireless clacking tool, which attacks multiple WEP, WPA, and WPS encrypted networks in a row.

Firstly, the wireless card has to be in the monitoring mode.

Step 1 − To open it, go to Applications → Wireless Attack → Wifite.

Wifite
Step 2 − Type "wifite –showb"to scan for the networks.

Wifite Showb
Scan Network
Step 3 − To start attacking the wireless networks, click Ctrl + C.

Attacking
Step 4 − Type “1” to crack the first wireless.

Crack First
Step 5 − After attacking is complete, the key will be found.

WIFI AIRMON
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

Šalje deauth (deauthentication) pakete na wifi mrežu što rezultira prekidom mreže za povezane uređaje. Koristi scapy modul za slanje deauth paketa. Saznajte više o napadu deautentifikacije

Zavisnosti
aircrack-ng. (Preporučujem da instalirate najnoviju verziju, iz izvora kako biste podržali više mrežnih drajvera/kartica.)
sudo apt-get install aircrack-ng -y
scapy
sudo apt-get install python-scapy -y
Kako trčati?
Možemo trčati na 2 načina:

sudo python deauth.py

Automatski će kreirati mon0 sa airmon-ng start wlan0 (neće kreirati, ako već postoji) i njuškati wifi signal na tom interfejsu. Nakon nekoliko sekundi, prikazat će se SSID i njegov MAC za odabir.

sudo python deauth.py -m XX:YY:AA:XX:YY:AA

MAC adresa kao argument komandne linije. U ovom slučaju, nema potrebe da njuškate wifi.

Šta je novo u verziji 3.1
Demonizira napad, tj. izvodi napad u pozadini
Kompatibilan sa novom airmon-ng verzijom
Može otkriti različita imena bežičnog interfejsa (kao wlp13s0)
Opcija ubiti demona
Sada možete dobiti wifi mreže pomoću iwlist alata (Relativno brže)
Upotreba
root@ghost:/opt/scripts#./deauth.py -h
upotreba: deauth.py [-h] [-d] [-c BROJ] [-m MAC] [-w] [-k] [-v]

Šalje pakete za poništavanje autentikacije na wifi mrežu što rezultira prekidom mreže
za povezane uređaje. [Kodirao VEERENDRA KAKUMANU]

neobavezni argumenti:
  -h, --help prikaži ovu poruku pomoći i izađi
  -d Pokreni kao demon
  -c COUNT Zaustavlja praćenje nakon što ovaj broj dostigne. Podrazumevano jeste
              2000
  -m MAC Šalje deauth pakete ovoj mreži
  -w Koristi "iwlist" da dobije listu wifi hotspotova
  -k Ubija "Deauth Daemon" ako je pokrenut
  -v pokazati broj verzije programa i izaći
U akciji

FAQ
Koja je opcija -c "COUNT"?
To je granična vrijednost za zaustavljanje "nadgledanja". Pristupna tačka ili wifi hotspot periodično prenosi okvire beacona kako bi najavila svoje prisustvo. Okvir beacona sadrži sve informacije o mreži. Sada, skripta traži ove beacone i računa. Ako broj dostigne granicu, to će zaustaviti praćenje.

Ako mislite, monoring oduzima mnogo vremena? zatim odredite broj sa manjim brojem (podrazumevano je 2000), ali možda neće dobiti sve wifi pristupne tačke blizu vas. Zato što slušate samo nekoliko signalnih signala
Koja je opcija -w "Koristi "iwlist" za dobijanje liste wifi hotspota"?
Skripta pokreće iwlist wlan0 s i približava wifi mreže vama

Koja je opcija -d "Pokreni kao demon"?
Skripta radi u pozadini dok napada. (Koristite opciju -k da ubijete)

Poznati problemi
Iz nekih razloga, ponekad skripta ne može pronaći sve bliske WiFi pristupne tačke. (Koristite opciju -w)
Ako pokušate da napadnete wifi hotspot koji je kreirao "Android" uređaj, to neće raditi!.(Možda koristi 802.11w)
Nemojte izvoditi skriptu sa -w neprekidno dva puta ili više, možete dobiti donju grešku. Ako je to slučaj, ponovo pokrenite network-manager; sudo service network-manager restart
wlp13s0 Interfejs ne podržava skeniranje: uređaj ili resurs zauzet
Uzmi ga!
wget -qO deauth.py https://goo.gl/bnsV9C

Kako izbjeći napad deautentifikacije?
Koristite rutere podržane 802.11w. Saznajte više o 802.11w i pročitajte cisco dokument

BILJEŠKA:
Da bi napad deautentifikacije bio uspješan, trebali biste se približiti ciljnoj mreži. Deauth paketi bi trebali doći do povezanih uređaja ciljne mreže(a)
