# Portfolio Cybersécurité — Mariam Balde

Étudiante en dernière année de Bachelier en Informatique de Gestion (Bruxelles), je me forme à la **sécurité défensive** et je recherche un premier emploi d'**analyste SOC junior** ou de **technicienne support et sécurité**.

Ce dépôt rassemble mes travaux pratiques. Chaque projet contient un rapport détaillé : méthode, commandes utilisées, constats, recommandations et ce que j'en ai retenu.

## Projets

| # | Projet | Ce que j'ai fait | Outils | Rapport |
|---|---|---|---|---|
| 1 | **Audit de sécurité d'un poste Windows** | Contrôle des mises à jour, de l'antivirus, du pare-feu, des comptes et du chiffrement du disque ; 3 recommandations | Sécurité Windows, PowerShell, BitLocker | [PDF](audit-securite.pdf) |
| 2 | **Commandes Linux** | Installation d'Ubuntu sous WSL 2 (diagnostic et activation de la virtualisation dans le BIOS), navigation, permissions, recherche | Ubuntu, WSL 2, `chmod`, `grep` | [PDF](commandes-linux.pdf) |
| 3 | **Analyse d'un journal de connexions** | Détection d'une attaque par force brute et d'un compte compromis | `grep`, `sort`, `uniq` | [PDF](analyse-journaux.pdf) |
| 4 | **Gestion d'incident** | Traitement d'un compte compromis, de la détection au retour d'expérience | Méthode NIST SP 800-61 | [PDF](gestion-incident.pdf) |

## Exemple : repérer les échecs de connexion par adresse IP

```bash
grep "FAILED" connexions.log | grep -o "ip=.*" | sort | uniq -c
```

```
      1 ip=192.168.1.10
      2 ip=198.51.100.7
      4 ip=203.0.113.5
```

L'IP qui a le plus d'échecs n'est pas la plus dangereuse : `198.51.100.7` a réussi à se connecter après deux échecs. C'est le signe d'un compte compromis, et c'est l'événement à traiter en priorité.

## Compétences

- **Postes de travail** : Windows 11, Microsoft 365, Microsoft Defender, pare-feu, BitLocker
- **Systèmes** : Linux (Ubuntu, WSL 2), PowerShell
- **Analyse** : journaux de connexion, indicateurs de compromission
- **Gestion d'incident** : méthode NIST (détection, confinement, éradication, retour d'expérience)
- **Développement** : Java (Spring Boot), JavaScript, Angular, SQL (MySQL, PostgreSQL), Git

## Remarques

- Les scénarios des projets 3 et 4 sont **simulés**. Les adresses IP utilisées sont réservées à la documentation (RFC 5737) ou privées.
- Les informations personnelles (nom du poste, comptes, notifications) ont été **masquées** sur les rapports et les captures.

## Contact

LinkedIn : *à compléter*
