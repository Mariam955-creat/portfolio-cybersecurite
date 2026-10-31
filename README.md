# Détection d'attaques par force brute avec Splunk

> Projet de laboratoire SOC : simuler une attaque par force brute sur un compte Windows, collecter les journaux de sécurité dans un SIEM (Splunk), détecter l'attaque avec des recherches SPL et créer une alerte automatique.

**Auteure :** Mariam Balde · [LinkedIn](https://linkedin.com/in/mariam-balde-611457124)
**Niveau :** débutant · **Durée :** [2] heures
**Outils :** Splunk Enterprise, journaux d'événements Windows, PowerShell, MITRE ATT&CK

---

## 1. Objectifs

- Installer et configurer un SIEM (Splunk Enterprise) pour collecter les journaux de sécurité Windows.
- Simuler une attaque par force brute sur un compte local.
- Écrire des recherches SPL pour détecter l'attaque et identifier un compte potentiellement compromis.
- Créer une alerte planifiée, comme dans un SOC.
- Relier la détection au référentiel MITRE ATT&CK et proposer des mesures de remédiation.

## 2. Compétences mises en pratique

| Domaine | Compétence |
|---|---|
| SIEM | Installation, création d'index, ingestion de journaux, alertes |
| Analyse de logs | Lecture des événements Windows 4624 / 4625, extraction de champs |
| Détection | Recherches SPL (`stats`, `bin`, `timechart`, `eval`, `mvindex`) |
| Threat Intelligence | Mapping MITRE ATT&CK, identification d'IoC |
| Réponse aux incidents | Qualification, rapport, recommandations |

## 3. Environnement du labo

| Élément | Détail |
|---|---|
| SIEM | Splunk Enterprise (licence d'essai), interface en français |
| Système surveillé | Poste Windows (langue : français), Splunk installé en local |
| Source de données | Journal Windows **Security** (entrée « Logs d'événements locaux ») |
| Index | `wineventlog` |
| Sourcetype | `WinEventLog:Security` |
| Compte cible (test) | `testlab` (compte local créé pour l'exercice) |

```
┌──────────────────────────────┐
│ Poste Windows                │
│                              │
│  PowerShell ──► échecs de    │
│  (attaque simulée) connexion │
│                    │         │
│                    ▼         │
│  Journal Security (4625/4624)│
│                    │         │
│                    ▼         │
│  Splunk Enterprise           │
│  index = wineventlog         │
│   ├─ recherches SPL          │
│   └─ alerte toutes les 5 min │
└──────────────────────────────┘
```

## 4. Mise en place

1. **Installation de Splunk Enterprise** sur Windows (compte de service : [Local System / Virtual account]).
2. **Création de l'index** `wineventlog` (Paramètres → Index → Nouvel index).
3. **Collecte des journaux** : Paramètres → Ajouter des données → Surveiller → Logs d'événements locaux → **Security** → index `wineventlog`.
4. **Activation de l'audit des ouvertures de session** (invite de commandes administrateur) :

   ```
   auditpol /set /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
   ```

   > L'identifiant (GUID) de la sous-catégorie est utilisé à la place du nom « Logon », car les noms sont traduits sur un Windows en français.

5. **Création du compte de test** :

   ```
   net user testlab <mot_de_passe> /add
   ```

![Données collectées](captures/01-donnees-collectees-4625.png)

## 5. Simulation de l'attaque

L'attaque par force brute est simulée avec PowerShell : 12 tentatives de connexion avec de mauvais mots de passe, puis une tentative réussie.

```powershell
# 12 tentatives avec de mauvais mots de passe
for ($i=1; $i -le 12; $i++) {
  $p = ConvertTo-SecureString "Mauvais$i!" -AsPlainText -Force
  $c = New-Object System.Management.Automation.PSCredential("testlab", $p)
  try { Start-Process cmd -Credential $c -ErrorAction Stop } catch { Write-Host "Echec $i" }
}

# Tentative réussie (l'« attaquant » trouve le mot de passe)
$p = ConvertTo-SecureString "<mot_de_passe>" -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential("testlab", $p)
Start-Process cmd -Credential $c
```

Chaque échec génère un événement Windows **4625** (échec d'ouverture de session) ; la réussite génère un **4624** (ouverture de session réussie).

## 6. Détection avec Splunk (SPL)

> Sur un Windows en français, les champs extraits par Splunk sont en français (`Nom_du_compte` au lieu de `Account_Name`). Dans un événement 4625, `Nom_du_compte` contient deux valeurs (le demandeur, puis le compte visé) : `mvindex(Nom_du_compte,-1)` récupère le compte visé.

### A. Échecs de connexion par compte

```spl
index=wineventlog EventCode=4625
| eval compte=mvindex(Nom_du_compte,-1)
| stats count AS echecs by compte
| sort - echecs
```

![Échecs par compte](captures/02-echecs-par-compte.png)

### B. Chronologie de l'attaque

```spl
index=wineventlog EventCode=4625
| timechart span=1m count AS echecs
```

Le pic d'échecs concentrés sur quelques secondes est typique d'une attaque automatisée.

![Chronologie de l'attaque](captures/05-chronologie-attaque.png)

### C. Détection de force brute (plus de 5 échecs en 5 minutes)

```spl
index=wineventlog EventCode=4625
| eval compte=mvindex(Nom_du_compte,-1)
| bin _time span=5m
| stats count AS echecs by _time compte
| where echecs > 5
```

![Détection de force brute](captures/03-detection-force-brute.png)

### D. Compte potentiellement compromis (échecs suivis d'un succès)

```spl
index=wineventlog (EventCode=4625 OR EventCode=4624)
| eval compte=mvindex(Nom_du_compte,-1)
| stats count(eval(EventCode=4625)) AS echecs count(eval(EventCode=4624)) AS succes by compte
| where echecs > 5 AND succes > 0
```

C'est la détection la plus critique : une série d'échecs suivie d'une réussite indique que l'attaquant a probablement trouvé le mot de passe.

![Compte compromis](captures/04-compte-compromis.png)

### E. Tableau d'investigation

```spl
index=wineventlog EventCode=4625
| eval compte=mvindex(Nom_du_compte,-1)
| table _time compte Nom_de_la_station_de_travail "Adresse du réseau source" "Type d*ouverture de session" "Raison de l*"
```

> Les jokers (`*`) évitent d'avoir à taper l'apostrophe typographique (’) présente dans certains noms de champs français.

Extrait du résultat :

| _time | compte | Station de travail | Adresse source | Type d'ouverture | Raison de l'échec |
|---|---|---|---|---|---|
| 2026-10-30 10:40:10.620 | testlab | poste du labo | ::1 | 2 | Nom d'utilisateur inconnu ou mot de passe incorrect. |
| 2026-10-30 10:40:10.618 | testlab | poste du labo | ::1 | 2 | Nom d'utilisateur inconnu ou mot de passe incorrect. |
| … | … | … | … | … | … |
| 2026-10-30 10:12:45.052 | testlab | poste du labo | ::1 | 2 | Nom d'utilisateur inconnu ou mot de passe incorrect. |

![Tableau d'investigation](captures/06-tableau-investigation.png)

## 7. Alerte automatique

La recherche C a été enregistrée comme alerte planifiée :

| Paramètre | Valeur |
|---|---|
| Titre | Brute force - echecs de connexion |
| Planification | cron `*/5 * * * *` (toutes les 5 minutes) |
| Plage temporelle | 5 dernières minutes |
| Condition | nombre de résultats > 0 |
| Action | Ajouter aux alertes déclenchées, gravité **élevée** |

![Alerte configurée](captures/07-alerte-configuree.png)
![Alerte déclenchée](captures/08-alerte-declenchee.png)

## 8. Rapport d'incident (simulé)

| Élément | Détail |
|---|---|
| **Type d'incident** | Attaque par force brute sur un compte local |
| **Détection** | Alerte Splunk « Brute force - echecs de connexion » |
| **Compte visé** | `testlab` |
| **Volume** | 11 échecs de connexion au total, dont **9 en moins d'une seconde** (30/10/2026, 10:40:10), puis une connexion réussie |
| **Gravité** | Élevée (le compte est considéré comme compromis) |
| **Technique MITRE ATT&CK** | [T1110.001 – Brute Force : Password Guessing](https://attack.mitre.org/techniques/T1110/001/) |

### Indicateurs de compromission (IoC)

- Rafale d'événements **4625** sur le compte `testlab` : 9 tentatives espacées de quelques millisecondes, un rythme impossible pour un humain, donc une attaque automatisée.
- Événement **4624** (connexion réussie) sur ce même compte après la série d'échecs.
- Raison de l'échec : *Nom d'utilisateur inconnu ou mot de passe incorrect.*
- Type d'ouverture de session : **2** (interactive).
- Adresse source : **::1** (adresse locale IPv6) : l'attaque provient de la machine elle-même, ce qui est cohérent avec la simulation. Dans un cas réel, une adresse externe ou un autre poste du réseau orienterait l'investigation vers l'origine de l'attaque.

> Dans ce labo, la connexion réussie a été simulée après coup (31/10/2026) ; dans une attaque réelle, elle suivrait directement la série d'échecs. La recherche D les relie quand même, car elle compare les échecs et les succès d'un compte sur toute la période analysée.

### Observation complémentaire

Le tableau d'investigation a aussi fait apparaître 3 échecs antérieurs à l'exercice (29/10/2026), **sans nom de compte** (`-`), dont deux depuis **127.0.0.1** avec la raison *« Une erreur s'est produite lors de l'ouverture de session »*. Ils ne correspondent pas à une attaque par force brute (peu nombreux, espacés), mais dans un vrai SOC ils feraient l'objet d'une vérification : service local mal configuré, application tentant une authentification sans identifiant…

### Recommandations

1. **Verrouillage de compte** : bloquer le compte après 5 à 10 échecs (stratégie de verrouillage Windows).
2. **Authentification multifacteur (MFA)** sur les comptes exposés.
3. **Politique de mots de passe robustes** (longueur, phrases de passe).
4. **Surveiller aussi l'événement 4740** (compte verrouillé) pour repérer les attaques en cours.
5. En cas d'incident réel : **réinitialiser le mot de passe** du compte, examiner son activité après la connexion réussie, et isoler le poste si nécessaire.

## 9. Ce que j'ai appris

- Le fonctionnement d'un SIEM, de l'ingestion des logs jusqu'à l'alerte.
- La lecture des événements de sécurité Windows (4624, 4625).
- L'importance de l'**audit** : sans activation de la stratégie d'audit, l'attaque reste invisible.
- L'adaptation aux réalités du terrain : champs traduits en français, droits du compte de service, blocages de téléchargement.
- [À compléter avec tes propres mots.]

## 10. Améliorations prévues

- Installer le **Splunk Add-on for Microsoft Windows** pour normaliser les champs.
- Créer un **tableau de bord** de suivi des connexions.
- Passer à une architecture plus réaliste : **machine virtuelle + Universal Forwarder**.
- Ajouter **Sysmon** pour enrichir la télémétrie.
- Détecter d'autres techniques (ex. password spraying : un mot de passe testé sur plusieurs comptes).

## 11. Nettoyage du labo

```
net user testlab /delete
```

Désactiver l'alerte dans Splunk : Paramètres → Recherches, rapports et alertes → Désactiver.
