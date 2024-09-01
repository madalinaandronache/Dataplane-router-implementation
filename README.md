# Protocoale de comunicatii - Tema 1

Student: Andronache Madalina-Georgiana
Grupa: 322CC

Urmatorul fisier contine informatii despre rezolvarea cerintelor propuse in 
tema 1 de la PCom: Dataplane Router.

Cea mai mare provocare intalnita a fost rezolvarea corecta si cat mai eficienta
a problemei propuse intr-un timp cat mai scurt. Aceasta tema a fost rezolvata
pe parcursul a 7 zile: in total am lucrat la aceasta tema aproximativ 30 h, 
dintre care 2 h fiind necesare pentru scrierea fisierului README, iar restul 
pentru codarea si depanarea cerintelor. In viitor, imi doresc rezolvarea mai 
rapida a cerintelor. Punctajul obtinut la testarea locala este de 100/100 pct. 

Cuprins:
1. Procesul de dirijare
2. Longest Prefix Match eficient
3. Protocolul ARP
4. Protocolul ICMP

# 1. Procesul de dirijare - protocolul IPv4

1. Verificam daca ip-ul router-ului este destinatia pachetului, daca este va 
raspunde cu un `ICMP message`.
2. Calculam suma de control si verificam daca coincide cu vechea suma, daca 
sunt diferite, atunci, pachetul a fost corupt, deci il aruncam (trecem mai 
departe).
3. Daca campul time-to-live al pachetului este 1 sau 0, router-ul va raspunde 
cu un `ICMP message`, altfel, campul este decrementat.
4. Cautam adresa ip a destinatiei folosind `Longest Prefix Match eficient`, 
implementata folosind Trie. Daca nu se gaseste adresa urmatorului hop, 
router-ul va trimite inapoi un `ICMP message` si se arunca pachetul.
5. Actualizam checksum-ul pentru a pregati pachetul din nou pentru a fi trimis:
se reseteaza checksum la 0 si se recalculeaza cu `checksum()`.
6. Rescriem adresele din ethernet header: adresa sursa va fi adresa interfetei
router-ului pe care este trimis pachetul mai departe, iar pentru adresa 
urmatorului hop, se cauta mai intai in `cache-ul ARP`. Daca se gaseste si adresa
respectiva nu este de broadcast, atunci putem trimite pachetul mai departe, 
altfel, asteptam un ARP response, deci adaugam pachetul in `coada ARP`.
7. Daca este posibil, trimitem pachetul folosind functia `send_to_link` cu datele
aflate & setate anterior.

# 2. Longest Prefix Match eficient - Trie

TrieNode are urmatoarea structura: pointeri catre nodurile fii: `left`(0) si 
`right`(1), campul `isLeaf` marcheaza daca in nod se termina prefixul valid si
campul `entry` care este un pointer cate o intrare in routing table.

Functiile corespunzatoare pentru acest tip de date sunt:
* create_new_node() - creaza un nou nod.
* insert(root, entry) - folosit pentru a insera o intrare din routing table 
in trie: parcurge fiecare bit al prefixului de la cel mai semnificativ la cel 
mai putin semnificativ, urmand calea spre stanga sau dreapta in functie de 
valoarea bitului corespunzator si creand noi noduri, atunci cand este necesar.
* get_best_route(root, ip) - se porneste din radacina si se parcurge trie-ul 
inregistrand cea mai lunga potrivire, deci cea mai buna ruta corespunzatoare.

Eficienta este mai buna decat cea a variantei de cautare liniara O(N), fiind 
in timp constant O(1).

# 3. Protocolul ARP

1. Atunci cand cautam o intrare in cache-ul ARP:
* daca o gasim si adresa nu este de broadcast, trimitem pachetul folosind 
noua adresa.
* daca o gasim, dar adresa este este de broadcast, asta inseamna ca deja am 
trimis un `ARP request`, dar inca nu am primit un `ARP reply`, deci nu 
avem acces la destinatia corespunzatoare, trebuie sa asteptam.
* daca nu o gasim, trebuie sa trimitem un `ARP request`, sa adaugam o noua 
intrare in cache, avand grija ca adresa mac sa fie completata ca si 
broadcast. 
2. Pachetul este adaugat in coada ARP `packet_queue`.
3. Daca router-ul primeste un packet ARP, ne putem afla in 2 cazuri:
* este un `ARP REQUEST`, deci router-ul trebuie sa trimita un reply, 
modifica continutul pachetului primit si adresele ip si mac pentru
sursa si destinatie.
* este un `ARP REPLAY`, deci verificam daca putem actualiza o intare 
din cache-ul ARP si dupa trimitem pachetele din coada pentru care adresa
mac este cunoscuta, si nu una de broadcast.

# 4. Protocolul ICMP

Pentru acest protocol am implementat functia 
void send_icmp(int interface, char *buf, uint8_t type), care trimite un pachet
de tip ICMP in functie de type-ul dat ca si parametru. In cazul temei se 
disting urmatoarele cazuri:
* ICMP "Time exceeded" message - atunci cand campul TTL a expirat
* ICMP "Destination unreachable" message - atunci cand nu exista ruta pana la
destinatie
* ICMP "Echo reply" - cand router-ul este destinatia pachetului.

In interiorul functiei se actualizeaza campurile sursa si destinatie atat pentru
header-ul IPv4, cat si pentru cel Ethernet, se adauga header-ul pentru ICMP si
se configureaza checksum, cat si celalalte field-uri din ICMP header, in functie 
de tipul mesajului trimis.
