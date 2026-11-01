# Stratégie de Support des Frameworks .NET et Plan de Dépréciation

## 1. Contexte et Calendrier Officiel du Support .NET

Au 1er novembre 2026, l'alignement sur la politique officielle de support Microsoft ([Microsoft .NET Support Policy](https://dotnet.microsoft.com/en-us/platform/support/policy)) établit le statut suivant pour les cibles du projet :

| Cible | Statut Officiel Microsoft | Statut Projet Unconfuser | Fin de Support Officielle | Rôle et Stratégie |
| :--- | :--- | :--- | :--- | :--- |
| **`net10.0-windows`** | **LTS Active (Recommandée)** | **Cible moderne pérenne cible** | **14 Novembre 2028** | Cible LTS principale à adopter pour l'exécution moderne 64-bit et l'analyse statique. |
| **`net8.0-windows`** | **LTS en fin de support (Maintenance)** | **Cible de transition** | **10 Novembre 2026** | Conservée temporairement pour la compatibilité avec les environnements de build n'ayant pas encore déployé le SDK .NET 10. Ne doit plus être présentée comme pérenne. |
| **`net6.0-windows`** | **End of Life (EOL)** | **Déprécié (Phase d'extinction)** | **12 Novembre 2024** | Conservée uniquement pour rétro-compatibilité binaire des workers existants. Génère l'avertissement de build documenté `NETSDK1138`. |
| **`net48`** | **Actif (Composant OS Windows)** | **Cible x86 32-bit requise** | **Cycle de vie de Windows** | Cible indispensable pour l'exécution dynamique des protections historiques 32-bit (`AntiTamper`, `Constants`). |

---

## 2. Analyse et Justification Technique

1. **Fin de vie imminente de .NET 8 :**
   .NET 8.0 atteint sa fin de support officielle le 10 novembre 2026. Bien qu'il serve actuellement de cible par défaut dans la branche courante, il ne constitue plus une solution pérenne à moyen et long terme.

2. **Adoption de .NET 10 LTS :**
   .NET 10.0 est la version LTS active actuelle, bénéficiant d'un support complet jusqu'au 14 novembre 2028.
   L'étude de faisabilité confirme que l'ensemble du moteur (`ConfuserExKillerRunner`), ses dépendances épinglées (`dnlib`, `de4dot.blocks`) et les API Win32 (Job Objects, `kernelbase.dll`, `NtQueryObject`) compilent et fonctionnent de manière identique sous .NET 10.

3. **Préservation de `net48` (x86 32-bit) :**
   La compatibilité avec les assemblies protégés par ConfuserEx historique 32-bit requiert impérativement un runtime CLR 32-bit natif. `net48` assure cette fonction sans dépendre d'un runtime .NET Core obsolète.

4. **Gestion de l'avertissement `NETSDK1138` :**
   Lors de la compilation avec un SDK moderne (.NET 8 ou .NET 10), le ciblage de `net6.0-windows` produit l'avertissement suivant :
   ```text
   warning NETSDK1138: La version cible de .NET Framework ('net6.0-windows') n'est pas prise en charge et ne recevra pas les mises à jour de sécurité.
   ```
   Cet avertissement est attendu et traçable tant que `net6.0-windows` est maintenu dans `<TargetFrameworks>` pour des motifs de compatibilité transitoire.

---

## 3. Calendrier de Transition et Feuille de Route

### Étape 1 : Préparation de l'Infrastructure CI (Actuel)
- Mise à jour du workflow CI (`.github/workflows/ci.yml`) pour installer explicitement le SDK .NET 10 (`10.0.x`) aux côtés du SDK 8 et du SDK 6.
- Validation de la compilation de la solution sous le compilateur .NET 10 SDK 10.0.403.
- Maintien transitoire de `net48;net8.0-windows;net6.0-windows` pour garantir qu'aucun build existant ne soit brisé.

### Étape 2 : Retrait de `net6.0-windows` et Généralisation de `net10.0-windows` (Prochaine Release Majeure v2.0)
- Remplacement du multi-ciblage par :
  ```xml
  <TargetFrameworks>net48;net10.0-windows;net8.0-windows</TargetFrameworks>
  ```
- Retrait définitif de `net6.0-windows`, éliminant l'avertissement `NETSDK1138`.
- Migration progressive des tests et benchmarks vers `net10.0-windows`.

### Étape 3 : Retrait de `net8.0-windows` (Postérieurement au 10 Novembre 2026)
- Retrait de `net8.0-windows` une fois que l'ensemble des postes de développement et runners CI auront migré vers .NET 10 SDK.
- Cibles finales stabilisées : `net48` (x86) et `net10.0-windows` (AnyCPU/x64).

---

## 4. Recommandations Pratiques

- **Pour les nouveaux déploiements et intégrations CI :** Installer le SDK .NET 10 LTS (`10.0.x`) et exécuter le runtime sous .NET 10 ou .NET 8 (transition).
- **Pour l'analyse de binaires 32-bit obfusqués :** Utiliser systématiquement l'exécutable compilé pour `net48` (`bin/Release/net48/ConfuserExKillerRunner.exe`).
- **Pour le développement local :** Les développeurs disposant du SDK .NET 10 peuvent d'ores et déjà compiler et exécuter l'ensemble des composants de manière transparente.

