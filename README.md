# TER

Ce travail étudie la sécurité des combinaisons de fonctions de hachage itératives face aux attaques par collisions.
Contrairement à l’intuition, la concaténation de deux fonctions H1 et H2 de tailles n1 et n2 n’assure pas une
résistance de l’ordre de 2(n1+n2)/2. En effet, les attaques par multi-collisions, lorsque H1 ou H2 sont construites
itérativement, permettent d’utiliser la structure de construction des fonctions de hachage itératives pour réduire
la recherche de collisions. Dans ce projet, nous analysons certains types de constructions de fonctions de hachage
plus résistants à cette attaque et nous analysons également l’attaque Parallel Collision Search, une attaque sur
une fonction de hachage utilisant plusieurs processeurs en parallèle.

Pour vérifier ceci nous avons implémenté en Rust la construction de multicollisions de Joux sur une fonction de hachage
itérative suivant le schéma Davies-Meyer. 
Nous avons fait varier la taille de la sortie de $f$ de $20$ à $48$ bits. Pour chaque taille $n$, nous avons adapté le nombre de répétitions : $100$ pour $n \leq 32$, $50$ pour $n \leq 40$, $20$ pour $n \leq 44$, et seulement $10$ pour $n = 48$.
La construction de $2^{24}$ messages nécessite environ **3 Go de RAM** pour stocker les messages, puisque, dans cette implémentation Rust, chaque message n’est pas stocké comme une simple valeur compacte de $48$ bits, mais comme une structure dynamique `Vec<u64>` contenant plusieurs blocs de $64$ bits.

Afin d’approfondir cette étude, nous avons étendu l’application de l’attaque de Joux à cinq architectures de combinaison distinctes. Nous avons combiné la même fonction de hachage itérative, ayant pour fonction de compression **SHA-256 tronquée à $n$ bits**, avec différents IV. Nous avons fait varier la taille de $n$ de $20$ à $48$ bits. L’analyse de ces structures confirme et approfondit les observations initiales sur la fragilité des fonctions itératives.

Voici le détail des cinq types de combinateurs testés :

### 1. Concatenation

**Définition :**

$$
H(m) = H_1(m) \parallel H_2(m)
$$

Juxtaposition simple des condensats de deux fonctions indépendantes.

**Analyse :** Les résultats confirment une croissance stable de l’efficacité de l’attaque de Joux. Pour $n = 28$ bits (haché final de $56$ bits), l’attaque est $2^{28,10}$ fois plus rapide qu’une recherche par force brute. Cela démontre que doubler la taille du haché par simple concaténation n’offre qu’une sécurité illusoire face aux multicollisions.

### 2. XorSum

**Définition :**

$$
H(m) = H_1(m) \oplus H_2(m)
$$

Somme des condensats via l’opérateur XOR.

**Analyse :** Le facteur d’accélération par rapport à une recherche par force brute reste proche de l’unité ($1{,}07\times$ pour $n = 28$). L’attaque de Joux ne procure donc pas un grand avantage.

### 3. Interacting

**Définition :**

$$
H(m) = H_1(m) \parallel H_2(m, IV = H_1(m))
$$

Ici, $H_1(m)$ sert d’état initial (IV) pour la seconde fonction.

**Analyse :** Cette structure présente une vulnérabilité critique avec un gain d’efficacité de $821{,}54\times$ pour $n = 28$. La transmission de l’état interne permet aux multicollisions de se propager inévitablement à travers toute la chaîne de hachage.

### 4. RobustInteraction

**Définition :**

$$
H(m) = H_1(m) \parallel H_2\left(m \oplus H_1(m)\right)
$$

Introduction d’une dépendance directe via le message de la seconde fonction.

**Analyse :** C’est l’architecture la plus vulnérable. Pour $n = 28$, le ratio atteint $2966{,}71\times$ ($987,272,783$ itérations directes contre seulement $332,784$ pour Joux).

Ce résultat concorde avec les mesures sur des tailles supérieures, par exemple $n_1 = 32$ et $n_2 = 40$, où le gain atteignait environ $3334\times$, prouvant que la complexité du mélange est négligeable face au coût de construction des multicollisions initiales.

### 5. WidePipe

**Définition :** La sortie de la fonction de compression est deux fois plus large que celle de $H_1(m)$.

**Analyse :** WidePipe s’avère la plus robuste ($0{,}03\times$ pour $n = 28$). Elle rend le coût de formation des multicollisions dans le tuyau interne, de taille $2n$, supérieur à celui d’une attaque directe sur la sortie, neutralisant ainsi l’avantage de l’attaquant.

