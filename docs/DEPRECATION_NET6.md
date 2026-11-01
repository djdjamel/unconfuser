# Stratégie de Support des Frameworks .NET et Plan de Dépréciation

## 1. Contexte et Calendrier Officiel du Support .NET

Au 1er novembre 2026, l'alignement sur la politique officielle de support Microsoft ([Microsoft .NET Support Policy](https://dotnet.microsoft.com/en-us/platform/support/policy)) établit le statut suivant pour les cibles du projet :

| Cible | Statut Officiel Microsoft | Statut Projet Unconfuser | Fin de Support Officielle | Rôle et Stratégie |
| :--- | :--- | :--- | :--- | :--- |
| **`net10.0-windows`** | **LTS Active (Recommandée)** | **Cible cible v2.0 (Non activée dans les .csproj actuels)** | **14 Novembre 2028** | Cible LTS future planifiée pour la v2.0. Le SDK .NET 10 est déployé en CI, mais la cible n'est pas encore déclarée dans `<TargetFrameworks>`. |
| **`net8.0-windows`** | **LTS en fin de support (Maintenance)** | **Cible de transition active actuelle (AnyCPU)** | **10 Novembre 2026** | Cible moderne active actuellement déclarée, compilée et exécutée par la suite de tests et les benchmarks. Ne doit plus être présentée comme pérenne. |
| **`net6.0-windows`** | **End of Life (EOL)** | **Déprécié (Phase d'extinction)** | **12 Novembre 2024** | Conservée temporairement pour la rétro-compatibilité binaire des workers existants. Génère l'avertissement de build documenté `NETSDK1138`. |
| **`net48`** | **Actif (Composant OS Windows)** | **Cible x86 32-bit active requise** | **Cycle de vie de Windows** | Cible indispensable pour l'exécution dynamique des protections historiques 32-bit (`AntiTamper`, `Constants`). |

---

## 2. Analyse Technique et Niveaux de Support

Afin d'éviter toute ambiguïté technique, trois niveaux distincts sont définis et respectés :

1. **Niveau 1 — Outillage de compilation (SDK .NET 10) :**
   - Le workflow CI (`.github/workflows/ci.yml`) installe explicitement le SDK .NET 10 (`10.0.x`) aux côtés des SDKs 8 et 6.
   - La solution actuelle est compilée avec succès sous le compilateur MSBuild du SDK .NET 10 (SDK 10.0.403).

2. **Niveau 2 — Ciblage de framework (`TargetFrameworks`) :**
   - Les fichiers de projet (`ConfuserExKillerRunner.csproj`, etc.) conservent à ce stade le multi-ciblage `net48;net8.0-windows;net6.0-windows`.
   - La cible `net10.0-windows` n'est **pas encore ajoutée** dans les balises `<TargetFrameworks>` afin d'éviter les ruptures de build (`NETSDK1045`) sur les postes de développement disposant uniquement du SDK 8.

3. **Niveau 3 — Exécution et validation runtime :**
   - Les tests unitaires, tests d'intégration et benchmarks s'exécutent sous le runtime `net8.0-windows` (AnyCPU) et `net48` (x86 natif).
   - Le projet **ne revendique pas** de validation d'exécution sous le runtime natif .NET 10 tant qu'un véritable `TargetFramework` `net10.0-windows` n'a pas été formellement intégré et testé de bout en bout.

4. **Gestion de l'avertissement `NETSDK1138` :**
   Lors de la compilation avec un SDK moderne (.NET 8 ou .NET 10), le ciblage de `net6.0-windows` produit l'avertissement documenté :
   ```text
   warning NETSDK1138: La version cible de .NET Framework ('net6.0-windows') n'est pas prise en charge et ne recevra pas les mises à jour de sécurité.
   ```
   Cet avertissement est attendu tant que `net6.0-windows` subsiste pour des motifs de compatibilité transitoire.

---

## 3. Feuille de Route et Calendrier de Retrait

### Étape 1 : Préparation de l'Infrastructure CI (Statut actuel — Post-CI #48)
- Déploiement du SDK .NET 10 (`10.0.x`) en CI pour garantir la compatibilité de l'outillage.
- Maintien transitoire strict de `net48;net8.0-windows;net6.0-windows` dans les fichiers `.csproj`.
- Les tests s'exécutent sous `net8.0-windows` et `net48`.

### Étape 2 : Retrait de `net6.0-windows` et Ajout de `net10.0-windows` (Release Majeure v2.0)
- Ajout formel de `net10.0-windows` dans `<TargetFrameworks>` :
  ```xml
  <TargetFrameworks>net48;net10.0-windows;net8.0-windows</TargetFrameworks>
  ```
- Retrait définitif de `net6.0-windows`, éliminant l'avertissement `NETSDK1138`.
- Exécution et validation complètes de la suite de tests sous le runtime .NET 10.

### Étape 3 : Retrait de `net8.0-windows` (Postérieurement au 10 Novembre 2026)
- Retrait de `net8.0-windows` une fois la transition des environnements achevée.
- Cibles finales stabilisées : `net48` (x86 32-bit) et `net10.0-windows` (AnyCPU/x64).

---

## 4. Recommandations Utilisateurs et Développeurs

- **Postes de développement :** Continuer d'utiliser le SDK .NET 8.0 ou le SDK .NET 10.0 indifféremment pour compiler la branche courante.
- **Exécution 32-bit native :** Utiliser systématiquement l'exécutable compilé pour `net48` (`bin/Release/net48/ConfuserExKillerRunner.exe`).
- **Nouveaux déploiements :** Prévoir le déploiement du SDK .NET 10 LTS en vue de la future release v2.0.


