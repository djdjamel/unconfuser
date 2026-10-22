# Plan d'Obsolescence et Dépréciation de `net6.0-windows`

## 1. Contexte et Calendrier

| Cible | Statut Microsoft | Support dans le Projet | Date de Fin de Support Prévue |
| :--- | :--- | :--- | :--- |
| **`net6.0-windows`** | **End of Life (EOL) — 12 Novembre 2024** | **Déprécié (Phase 4)** | **Prochaine version majeure/mineure (v2.0)** |
| **`net8.0-windows`** | **Actif — Support Long Terme (LTS jusqu'en Nov 2026)** | **Cible moderne recommandée** | Pérenne |
| **`net48`** | **Actif — Composant natif de Windows 10/11** | **Cible x86 32-bit requise** | Aligné sur le cycle de vie de Windows |

Microsoft a mis fin au support officiel de .NET 6.0 le 12 novembre 2024. Aucun correctif de sécurité ni mise à jour de runtime n'est désormais fourni par Microsoft pour .NET 6.0.

---

## 2. Justification Technique

1. **Sécurité et Maintenance :** Le maintien d'un runtime EOL expose les environnements d'exécution à des vulnérabilités non corrigées au niveau du CLR et des bibliothèques de classes de base (BCL).
2. **Support des SDK Modernes :** Les SDK .NET récents (version 8.0 / 9.0+) génèrent des avertissements d'obsolescence lors de la compilation pour `net6.0-windows`.
3. **Parité Fonctionnelle Complète :** Toutes les capacités requises par `ConfuserExKillerRunner` (analyse statique dnlib/de4dot, Job Objects Win32, SimpleJson, exécution dynamique de workers isolés) sont pleinement supportées et plus performantes sous `net8.0-windows`.
4. **Cible 32-bit Historique Préservée :** La rétro-compatibilité 32-bit avec les cibles protégées par ConfuserEx historique s'appuie sur `net48` (architecture x86 native), qui reste activement maintenue sans dépendre de .NET 6.

---

## 3. Étapes de Transition et Migration

### Étape 1 : Notification et Documentation (Phase 4 — Actuel)
- Formalisation du statut `Déprécié` dans la documentation (`docs/DEPRECATION_NET6.md`, `docs/LICENSES.md`, `README.md`).
- Les binaires `net6.0-windows` restent compilés pour assurer la continuité opérationnelle des environnements existants.

### Étape 2 : Retrait Programmé du Multi-Ciblage (Prochaine Release)
- Retrait de `net6.0-windows` de la balise `<TargetFrameworks>` dans `ConfuserExKillerRunner.csproj`.
- Ciblage simplifié à deux cibles claires et pérennes :
  ```xml
  <TargetFrameworks>net48;net8.0-windows</TargetFrameworks>
  ```
- Les scripts de benchmark Python et la suite de tests continueront de cibler `net8.0-windows` et `net48`.

---

## 4. Recommandation Utilisateur

Pour toute nouvelle installation ou intégration CI/CD :
- Utiliser le SDK .NET 8.0 LTS avec le runtime `net8.0-windows` (64-bit et analyse statique portable).
- Utiliser le runtime `net48` (32-bit x86) pour les cas nécessitant l'exécution dynamique de protections 32-bit natives (`AntiTamper`, `Constants`).
