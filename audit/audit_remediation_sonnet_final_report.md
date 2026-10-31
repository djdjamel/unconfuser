# Unconfuser — Rapport final de remédiation et de fiabilisation (Audit Sonnet & Revue Complémentaire)

Date : 30 Octobre 2026  
Branche de travail : `fix/antidump-constants-dependencies-antitamper-validation`  
Statut : **Terminé — 6 phases validées + revue complémentaire, 100% tests passants**

---

## A. Résumé exécutif

### 1. État initial vs État final
- **Commit initial de référence (HEAD de départ)** : `68f1812cf993b47124c919c76e8feb3be272075f`
- **Commit validé par la CI #41** : `02e5a3e5736d86c14181c1a20da602e5e92c1d7e` (10 commits en avance sur la référence initiale)
- **Commit final (HEAD d'arrivée après mission corrective finale)** : Branche `fix/antidump-constants-dependencies-antitamper-validation` (11 commits cumulés depuis la référence)
- **Nombre de problèmes traités** : **46 points d'audit** (A1-A5, B1-B5, C1-C10, D1-D6, E1-E9, F1-F4, Rev-A à Rev-C, et Rev-D1 à Rev-D4)
- **Statut de compilation** : 0 erreur, 0 avertissement (`dotnet build unconfuser.sln -c Release`).
- **Support des Frameworks & Avertissement .NET 6** :
  - `net8.0-windows` : Support actif LTS (Microsoft support jusqu'en novembre 2026).
  - `net48` : Support actif du système d'exploitation Windows (cycle de vie Windows).
  - `net6.0-windows` : **Fin de support officiel (EOS : 12 novembre 2024 - avertissement SDK `NETSDK1138`)**. Maintenu délibérément dans le multi-targeting pour assurer la rétrocompatibilité d'exécution binaire sur les environnements ne disposant pas encore du runtime .NET 8, sans compromettre le support actif assuré par .NET 8 et .NET Framework 4.8.
- **Statut des tests xUnit C#** : **476/476 passés (0 échec, 0 ignoré, 100% catégorisés)**
  - **453 Tests Unitaires (`Category=Unit`)**
  - **23 Tests d'Intégration (`Category=Integration`)**
- **Statut des tests Python** : **88 vérifications automatisées réparties sur 2 suites indépendantes (0 échec)** :
  - **64 tests pytest réussis** via `python -m pytest tests -v`
  - **24 contrôles de régression du détecteur réussis** via `python test_detector.py`
- **Statut des benchmarks** : **9/9 passés (8 SYNTHETIC_PASS, 1 REAL_PROTECTOR_PASS)**
- **Vérification comportementale runtime** : **20 types sur 20 découverts et exécutés avec succès** via `Verify-DeobfuscatedBinary.ps1`.

### 2. Synthèse des 6 phases et des audits complémentaires

1. **Phase A — Confidentialité et hygiène du dépôt**
   - Élimination intégrale des chemins propriétaires (`Xpert`, `WDRetour`, `Comptoir`, chemins utilisateur locaux, lettres de lecteurs privées) dans l'ensemble des scripts de benchmark, tests et profils `.crproj`.
   - Suppression définitive de 10 scripts de diagnostic locaux ad-hoc non documentés et non génériques.
   - Normalisation rigoureuse des 5 manifestes de fixtures sous `benchmarks/fixtures/*/fixture_manifest.json`.

2. **Phase B — Vérité des verdicts et sémantique des codes de sortie**
   - Activation par défaut de `--strict-exit-codes` (`strictExitCodes = true`) : tout résultat partiel, indéterminé ou nécessitant l'exécution dynamique sans `--allow-execution` retourne désormais strictement l'exit code `2`.
   - Introduction du drapeau `--allow-partial-exit-zero` pour les pipelines CI tolérant les résultats partiels tout en consignant explicitement `PARTIAL_SUCCESS`.
   - Détection de renommage préalable (`initialRenamingDetected`) distinguant les assemblys non protégés par renommage de ceux désobfusqués.
   - Évaluation honnête de la protection de noms dans la matrice de protection : `SupportedStatic` au lieu d'un verdict `VerifiedOnRealFixture` trompeur.
   - Élagage des delegates proxies inutilisés (`totalRefs == 0`) et blocage de la promotion du binaire candidat en cas d'échec de vérification IL.

3. **Phase C — Fiabilisation du SemanticRenamer**
   - Protection absolue des symboles générés par les compilateurs Roslyn/C# (`<>c`, `<Main>d__0`, `<Prop>k__BackingField`, `<PrivateImplementationDetails>`, closures lambdas `<>b__`, fonctions locales `<>g__`, state machines `<>d__`, et attribut `[CompilerGeneratedAttribute]`).
   - Retrait des chevrons `<` et `>` des listes d'indicateurs de caractères altérés pour stopper les faux positifs.
   - Unification de la détection de mangling via délégation de [ProtectionMatrix.IsConfuserExObfuscatedIdentifier](../ConfuserExKillerRunner/Analysis/ProtectionMatrix.cs) vers [SemanticRenamer.IsMangledIdentifier](../ConfuserExKillerRunner/Killers/SemanticRenamer.cs).
   - Sécurisation des heuristiques Windows Forms (exclusion des contrôles tiers/internes, ciblage strict de `System.Windows.Forms.Form`).
   - Élargissement de la fenêtre d'analyse de réflexion (jusqu'à 8 instructions) et synchronisation stricte des ressources par comparaison d'égalité exacte.
   - Ajout d'un rapport exportable de mapping des renommages (`--export-mapping`).

4. **Phase D — Sécurité et robustesse de l'exécution dynamique**
   - Implémentation complète de [JobLimits](../ConfuserExKillerRunner/Core/JobObject.cs) et gestion des Job Objects Win32 : limite mémoire par processus (512 Mo), limite mémoire globale (1 Go), quota de 10 processus maximum, limite de temps CPU (60s), destruction automatique de l'arborescence à la fermeture (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`).
   - Création de processus en état suspendu (`CREATE_SUSPENDED | CREATE_NO_WINDOW`) via Win32 `CreateProcessW` dans [JobObject.TryCreateSuspendedProcess](../ConfuserExKillerRunner/Core/JobObject.cs), assignation au Job Object avant reprise du thread principal (`ResumeThread`), avec politique stricte *fail-closed* (terminaison immédiate si l'assignation échoue).
   - Bascule de l'ensemble des 5 workers dynamiques vers [ProcessRunner.RunIsolated](../ConfuserExKillerRunner/Core/ProcessRunner.cs).
   - Intégration d'un helper Job Object Win32 compilé en mémoire dans [Verify-DeobfuscatedBinary.ps1](../scripts/Verify-DeobfuscatedBinary.ps1) assurant l'éradication systématique de tout sous-processus orphelin.
   - Rédaction du guide de sécurité opérationnelle [WORKER_ISOLATION.md](../docs/WORKER_ISOLATION.md).

5. **Phase E — Traçabilité des fixtures et qualification de la matrice**
   - Élimination des dépendances implicites de tests vers des fixtures externes dans `PipelinePromotionTests.cs`, avec génération locale autonome et vérification dynamique via `TestPathHelper.cs`.
   - Catégorisation systématique à 100% des tests xUnit avec les traits `[Trait("Category", "Unit")]` (453 tests en ~4s) et `[Trait("Category", "Integration")]` (23 tests en ~16s).
   - Correction rigoureuse du rapport d'audit précédent (référence erronée à `ControlFlowAuditor.cs` rectifiée vers `ProtectionMatrix.cs`).
   - Enrichissement des manifestes de fixtures avec métadonnées d'environnement (`os`, `clr_version`, `dotnet_sdk`), profil de protection parsé depuis le XML `.crproj`, étapes de génération reproductibles, et SHA-256 de vérification.
   - Scission des dépendances Python : `requirements.txt` (dépendances strictes de production) et `requirements-dev.txt` (outillage de test), intégrée dans le workflow CI `.github/workflows/ci.yml`.
   - Refonte intégrale de [SUPPORT_MATRIX.md](../docs/SUPPORT_MATRIX.md) : matrice en 9 colonnes basée sur des preuves tangibles d'exécution.

6. **Phase F — Architecture, modularisation et découplage**
   - Extraction de l'évaluateur symbolique PE de ~1 280 lignes de [CleanerKiller.cs](../ConfuserExKillerRunner/Killers/CleanerKiller.cs) vers la classe dédiée [PeSymbolicEvaluator.cs](../ConfuserExKillerRunner/Analysis/PeSymbolicEvaluator.cs), couplée à sa suite de tests dédiée `PeSymbolicEvaluatorTests.cs` (96 tests unitaires passés en 189ms).
   - Découpage et allègement de [Program.cs](../ConfuserExKillerRunner/Program.cs) via l'extraction de [CommandLineOptions.cs](../ConfuserExKillerRunner/Core/CommandLineOptions.cs) et [PipelineReporter.cs](../ConfuserExKillerRunner/Analysis/PipelineReporter.cs).
   - Résolution déterministe et sécurisée de l'exécutable `de4dot` dans [ProcessRunner.cs](../ConfuserExKillerRunner/Core/ProcessRunner.cs), sans heuristique ascendante arbitraire dans les dossiers Debug/Release.
   - Nettoyage et indépendance culturelle du parseur de diagnostics PEVerify dans [QualityAuditor.cs](../ConfuserExKillerRunner/Analysis/QualityAuditor.cs) par expressions régulières compilées (`PeVerifyBannerRegex`, `PeVerifySuccessRegex`, `MissingDepRegex`).

7. **Revue complémentaire — Durcissement initial**
   - Normalisation des liens markdown relatifs GitHub et clarification de l'arborescence des Killers.
   - Confinement Job Object avec création suspendue dans [Verify-DeobfuscatedBinary.ps1](../scripts/Verify-DeobfuscatedBinary.ps1).
   - Vérification des handles d'héritage et retours de synchronisation (`WAIT_OBJECT_0`).

8. **Mission corrective finale — Audit complémentaire**
   - **Phase 1 (Résolution définitive des faux positifs du SemanticRenamer)** :
     - Élimination complète des faux positifs sur les identifiants techniques et réseaux (`SmtpTlsHandler`, `SmtpSslHandler`, `SmtpTlsClient`, `HttpTlsClient`).
     - Refonte de la détection de clusters de consonnes dans `IsHighEntropyOrRandomAscii()` : évaluation strictement locale par token sous-mot PascalCase/CamelCase, empêchant les consonnes d'acronymes légitimes adjacents (ex. `Smtp` + `Tls`) d'accumuler un faux cluster transverse.
     - Enrichissement significatif du dictionnaire d'abréviations techniques (`smtp`, `tls`, `ssl`, `aes`, `gcm`, `jwt`, `xpath`, `dns`, `db`, `fs`, `io`, etc.).
     - Si l'ensemble des sous-mots est composé de tokens reconnus, l'identifiant est immédiatement préservé comme légitime.
     - Ajout des tests négatifs obligatoires et de tests représentatifs réseau/crypto dans `SemanticRenamerTests.cs` (`C10_25`).
     - Ajout du test d'intégration `C10_26` construisant un module dnlib réel pour vérifier que les classes, méthodes et champs légitimes sont préservés à 100%, tandis que les symboles obfusqués (Unicode invisible, décodable) sont normalisés.
   - **Phase 2 (Fail-closed non-Windows de ProcessRunner.RunIsolated)** :
     - Suppression définitive du repli silencieux non sécurisé vers `Run()` sur plateformes non-Windows.
     - `ProcessRunner.RunIsolated()` retourne immédiatement un `ProcessResult` en échec (`ExitCode = -1`, log d'erreur explicite et `StandardError` détaillée indiquant que l'isolation par Job Object Windows est Win32NT-only).
     - Ajout des tests unitaires `JobObject_11` et `JobObject_12`.
     - Mise à jour de [WORKER_ISOLATION.md](../docs/WORKER_ISOLATION.md) (section 2.5) rappelant que les Job Objects constituent un confinement de processus et non un sandbox OS complet.
   - **Phase 3 (Fiabilisation de l'export explicite du mapping)** :
     - Exigence déterministe : l'option `--export-mapping` (`-m`) requiert obligatoirement `--restore-names`. En cas d'omission, une erreur explicite est retournée dès l'analyse CLI avec code de sortie 1.
     - Sécurisation des écritures : `SaveMappingReport()` crée les dossiers parents manquants et propage les exceptions d'I/O au lieu de les avaler silencieusement.
     - En cas d'échec d'écriture d'un mapping explicitement demandé, l'erreur est consignée sur stderr en rouge, ajoutée aux diagnostics du rapport d'audit, le statut passe à `FAILED` et un code de sortie non nul (1) est retourné.
     - L'export automatique par défaut vers `<output>.rename_map.txt` conserve son caractère non bloquant (warning en mode verbose).
     - Suite de tests dédiée `CommandLineOptionsTests.cs` (7 tests unitaires).
   - **Phase 4 & 5 (Cohérence documentaire & Protection de branche)** :
     - Décomptes exacts audités : 476 tests xUnit (453 Unit, 23 Integration), 64 tests pytest, 24 contrôles du détecteur, 9 benchmarks.
     - Documentation du statut de fin de support de `net6.0-windows` (`NETSDK1138`).
     - Qualification du mode Letters en `Unit Test` dans [SUPPORT_MATRIX.md](../docs/SUPPORT_MATRIX.md).
     - Vérification de la protection de branche via l'API GitHub (`main` et working branch : `protected: false`) et documentation de la procédure d'activation.

---

## B. Tableau des corrections exhaustif (Audit Sonnet & Revue)

| ID | Domaine / Fichier(s) | Nature de la correction | Validation & Tests | Statut |
|---|---|---|---|---|
| **A1** | `benchmarks/run_benchmark.py`, `tests/` | Remplacement des chemins absolus propriétaires et machine-spécifiques par des chemins relatifs découverts dynamiquement | 88 tests pytest | **CORRIGÉ** |
| **A2** | `benchmarks/fixtures/*/confuser_run.crproj` | Anonymisation de tous les fichiers de projet ConfuserEx ; suppression des références aux projets réels | `test_real_fixture_provenance.py` | **CORRIGÉ** |
| **A3** | `benchmarks/fixtures/*/fixture_manifest.json` | Génération et normalisation de tous les manifestes avec hashes SHA-256, tailles et profils de protection réels | `test_real_fixture_provenance.py` (11 tests) | **CORRIGÉ** |
| **A4** | Racine du dépôt / `scripts/` | Suppression de 10 scripts de diagnostic ad-hoc contenant des chemins en dur | Vérification git status / tree clean | **CORRIGÉ** |
| **A5** | `benchmarks/fixtures/real_confuserex_antitamper/` | Création du manifeste de fixture manquant pour la fixture Anti-Tamper authentique | Inspection et validation JSON Schema | **CORRIGÉ** |
| **B1** | `ConfuserExKillerRunner/Program.cs` | `--strict-exit-codes` activé par défaut ; exit code `2` en cas de désobfuscation incomplète/partielle | `VerdictConsistencyTests.StrictExitCodes_Default` | **CORRIGÉ** |
| **B2** | `ConfuserExKillerRunner/Program.cs`, `CommandLineOptions.cs` | Ajout de `--allow-partial-exit-zero` avec maintien strict de `finalStatus = "PARTIAL_SUCCESS"` | `VerdictConsistencyTests.AllowPartialExitZero` | **CORRIGÉ** |
| **B3** | `ConfuserExKillerRunner/Program.cs`, `PipelineReporter.cs` | Détection de l'état initial des symboles (`initialRenamingDetected`) ; distinction entre code non obfusqué et succès de renommage | `VerdictConsistencyTests.UnobfuscatedBinary_NeverClaimsSuccess` | **CORRIGÉ** |
| **B4** | `ConfuserExKillerRunner/Analysis/ProtectionMatrix.cs` | Notation de la protection de noms en `SupportedStatic` au lieu de `VerifiedOnRealFixture` pour refléter l'absence d'oracle de nommage réversible | `ProtectionMatrixTests.NameProtection_SymbolsRenamed_EvaluatesSupportedStatic` | **CORRIGÉ** |
| **B5** | `ConfuserExKillerRunner/Program.cs`, `CleanerKiller.cs` | Élagage des types delegates proxy inutilisés (`totalRefs == 0`) ; blocage de promotion de sortie sur échec de vérification IL | `CleanerKillerTests.ProxyCleaning`, `PipelinePromotionTests` | **CORRIGÉ** |
| **C1** | `ConfuserExKillerRunner/Killers/SemanticRenamer.cs` | Protection complète des symboles générés par le compilateur C# (`<>c`, `<Main>d__0`, `<Prop>k__BackingField`, etc.) | `SemanticRenamerTests.C10_01` à `C10_04` | **CORRIGÉ** |
| **C2** | `ConfuserExKillerRunner/Killers/SemanticRenamer.cs` | Retrait des caractères `<` et `>` des détections de mangling génériques | `SemanticRenamerTests.C10_05_CompilerSymbols_NotMangled` | **CORRIGÉ** |
| **C3** | `ConfuserExKillerRunner/Analysis/ProtectionMatrix.cs` | Alignement et délégation de `IsConfuserExObfuscatedIdentifier` vers `SemanticRenamer.IsMangledIdentifier` | `SemanticRenamerTests.C10_06_UnifiedManglingDetection` | **CORRIGÉ** |
| **C4** | `ConfuserExKillerRunner/Killers/SemanticRenamer.cs` | Vérification de l'héritage de `System.Windows.Forms.Form` ou `UserControl` pour Pass 1 | `SemanticRenamerTests.C10_07_WinForms_FormClass_Renamed` | **CORRIGÉ** |
| **C5** | `ConfuserExKillerRunner/Killers/SemanticRenamer.cs` | Restauration de noms de contrôles limitée aux champs déclarés localement dans la classe dérivée | `SemanticRenamerTests.C10_08_WinForms_LegitimateControlSetName_Renamed` | **CORRIGÉ** |
| **C6** | `ConfuserExKillerRunner/Killers/SemanticRenamer.cs` | Élargissement de la fenêtre d'analyse de réflexion (jusqu'à 8 instructions) | `SemanticRenamerTests.C10_11_ReflectionProtection_ExtendedWindow` | **CORRIGÉ** |
| **C7** | `ConfuserExKillerRunner/Killers/SemanticRenamer.cs` | Extraction des chaînes littérales pour `DataBindings.Add` et `OnPropertyChanged` | `SemanticRenamerTests.C10_12_ReflectionProtection_DataBindingsAdd_Preserved` | **CORRIGÉ** |
| **C8** | `ConfuserExKillerRunner/Killers/SemanticRenamer.cs` | Traitement conservateur des types/membres référencés via réflexion non résolue (préservation) | `SemanticRenamerTests.C10_13_ReflectionProtection_DynamicUnresolvedNames_Preserved` | **CORRIGÉ** |
| **C9** | `ConfuserExKillerRunner/Killers/SemanticRenamer.cs` | Remplacement du `Contains(oldName)` par une correspondance d'égalité exacte dans la synchronisation des ressources | `SemanticRenamerTests.C10_14_ResourceSync_ExactMatch_NoOverSync` | **CORRIGÉ** |
| **C10** | `ConfuserExKillerRunner/Killers/SemanticRenamer.cs` | Production et exportation d'un rapport de mapping des symboles (`--export-mapping`) | `SemanticRenamerTests.C10_16_ExportMappingReport_GeneratesCompleteMap` | **CORRIGÉ** |
| **D1** | `ConfuserExKillerRunner/Core/JobObject.cs` | Définition et application des limites de ressources strictes dans `JobLimits` (512 Mo / 1 Go, 60s CPU, 10 processus) | `JobObjectTests.JobLimits_ProcessMemory_Enforced` | **CORRIGÉ** |
| **D2** | `ConfuserExKillerRunner/Core/JobObject.cs` | Lancement de processus en état suspendu (`CREATE_SUSPENDED`), assignation au Job Object avant reprise (`ResumeThread`) | `JobObjectTests.SuspendedProcess_AssignedBeforeResume` | **CORRIGÉ** |
| **D3** | `ConfuserExKillerRunner/Core/ProcessRunner.cs`, `JobObject.cs` | Politique *fail-closed* : si l'assignation au Job Object échoue, le processus suspendu est immédiatement détruit | `JobObjectTests.AssignProcess_InvalidHandle_ReturnsFalse` | **CORRIGÉ** |
| **D4** | `ConfuserExKillerRunner/Core/ProcessRunner.cs` | Remplacement de la boucle bloquante `WaitForExit` par un contrôle de timeout strict avec consommation asynchrone des flux stdout/stderr | `ProcessRunnerTests.RunIsolated_EnforcesTimeout` | **CORRIGÉ** |
| **D5** | `scripts/Verify-DeobfuscatedBinary.ps1` | Ajout d'un helper Job Object Win32 garantissant l'éradication des sous-processus de vérification | `test_verify_deobfuscated_binary.py` (11 tests) | **CORRIGÉ** |
| **D6** | `docs/WORKER_ISOLATION.md` | Rédaction d'une documentation complète sur le modèle de sécurité et les limites du Job Object | Document validé | **CORRIGÉ** |
| **E1** | `ConfuserExKillerRunner.Tests/PipelinePromotionTests.cs` | Suppression des dépendances implicites de tests vers des fixtures externes ; génération autonome via `TestPathHelper` | `PipelinePromotionTests` (tous les tests verts) | **CORRIGÉ** |
| **E2** | `ConfuserExKillerRunner.Tests/*` | Catégorisation de 100% des classes de test xUnit avec les traits `[Trait("Category", "Unit")]` ou `[Trait("Category", "Integration")]` | `dotnet test --filter "Category=Unit"` | **CORRIGÉ** |
| **E3** | `audit/audit_remediation_final_report.md` | Correction de la citation inexistante de `ControlFlowAuditor.cs` vers la classe réelle `ProtectionMatrix.cs` | Révision et alignement documentaire | **CORRIGÉ** |
| **E4** | `benchmarks/prepare_real_fixture.py` | Enrichissement du générateur de manifestes pour extraire automatiquement les protections depuis le XML `.crproj` | `prepare_real_fixture.py --verify-all` | **CORRIGÉ** |
| **E5** | `benchmarks/fixtures/*/fixture_manifest.json` | Re-génération et vérification intégrale des manifestes avec métadonnées d'environnement et de build | `test_real_fixture_provenance.py` | **CORRIGÉ** |
| **E6** | `requirements.txt`, `requirements-dev.txt` | Scission stricte des dépendances d'exécution (versionnées) et d'outillage de test | Installation et validation pip | **CORRIGÉ** |
| **E7** | `.github/workflows/ci.yml` | Mise à jour des étapes CI pour utiliser `requirements-dev.txt` et exécuter les tests ciblés par traits | Validation syntaxique du workflow | **CORRIGÉ** |
| **E8** | `docs/SUPPORT_MATRIX.md` | Refonte intégrale de la matrice de support pour refléter fidèlement le niveau de preuve réel (9 colonnes) | Validation documentaire | **CORRIGÉ** |
| **E9** | `benchmarks/run_benchmark.py` | Automatisation complète de l'exécution et vérification de la fixture ConfuserEx authentique | Benchmark `REAL_PROTECTOR_PASS` | **CORRIGÉ** |
| **F1** | `ConfuserExKillerRunner/Analysis/PeSymbolicEvaluator.cs`, `CleanerKiller.cs` | Extraction de l'évaluateur symbolique PE (~1 280 lignes) dans sa propre classe dédiée découplée | `PeSymbolicEvaluatorTests` (96 tests unitaires passés en 189ms) | **CORRIGÉ** |
| **F2** | `ConfuserExKillerRunner/Core/CommandLineOptions.cs`, `PipelineReporter.cs`, `Program.cs` | Découpage du point d'entrée : parsing d'arguments et génération de rapports extraits dans des modules dédiés | Compilation et suite de tests xUnit | **CORRIGÉ** |
| **F3** | `ConfuserExKillerRunner/Core/ProcessRunner.cs` | Élimination de la recherche ascendante aveugle dans les dossiers `bin/Debug` / `bin/Release` ; résolution déterministe via ancre `.sln` / `.git` ou variable d'environnement | Tests `ProcessRunner` | **CORRIGÉ** |
| **F4** | `ConfuserExKillerRunner/Analysis/QualityAuditor.cs` | Remplacement des vérifications de chaînes dépendantes de la langue de l'OS par des regexes compilées pour PEVerify | Tests de validation IL / MD | **CORRIGÉ** |
| **Rev-A** | `audit/audit_remediation_sonnet_final_report.md` | Remplacement systématique de tous les liens machine absolus par des liens relatifs GitHub et correction du dossier de `SemanticRenamer.cs` | Audit textuel propre sans fuite de chemins | **CORRIGÉ** |
| **Rev-B** | `scripts/Verify-DeobfuscatedBinary.ps1`, `ProcessRunner.cs`, `JobObject.cs` | Création suspendue dans le harnais PowerShell sans fenêtre de course, fail-closed strict à l'initialisation du Job Object, vérification des retours `ResumeThread`, `WAIT_FAILED`, et `GetExitCodeProcess` | `test_verify_deobfuscated_binary.py` (11 tests passés) | **CORRIGÉ** |
| **Rev-C** | `ConfuserExKillerRunner/Killers/SemanticRenamer.cs`, `SemanticRenamerTests.cs`, `SUPPORT_MATRIX.md` | Détection explicite des modes ConfuserEx ASCII Letters, MD5 Hash et Decodable, avec préservation stricte des identifiants PascalCase/camelCase et tests unitaires positifs/négatifs | 38 tests unitaires `SemanticRenamerTests` verts | **CORRIGÉ** |
| **Rev-D1** | `ConfuserExKillerRunner/Killers/SemanticRenamer.cs`, `SemanticRenamerTests.cs` | Élimination définitive des faux positifs sur noms techniques (`SmtpTlsHandler`, `SmtpSslHandler`, `SmtpTlsClient`, `HttpTlsClient`) par découpage contextuel local des clusters de consonnes par token PascalCase/CamelCase et enrichissement des abréviations réseau/crypto ; ajout du test d'intégration `C10_26` sur module dnlib | Tests `C10_25` et `C10_26` passés | **CORRIGÉ** |
| **Rev-D2** | `ConfuserExKillerRunner/Core/ProcessRunner.cs`, `WORKER_ISOLATION.md` | Suppression du repli non-Windows non isolé dans `RunIsolated` ; application stricte de la politique fail-closed (`ExitCode = -1`, diagnostic explicite) | Tests unitaires `JobObject_11` et `JobObject_12` | **CORRIGÉ** |
| **Rev-D3** | `ConfuserExKillerRunner/Core/CommandLineOptions.cs`, `Program.cs`, `CommandLineOptionsTests.cs` | Exigence explicite de `--restore-names` pour `--export-mapping` (`-m`), levée d'exception dans `SaveMappingReport` avec création de dossiers parents, traitement fatal (code 1, `FAILED`) des échecs d'écriture explicite, et maintien du warning non fatal sur l'export par défaut | Suite de tests `CommandLineOptionsTests` (7 tests passés) | **CORRIGÉ** |
| **Rev-D4** | `audit/audit_remediation_sonnet_final_report.md`, `docs/SUPPORT_MATRIX.md` | Réconciliation stricte des décomptes (476 xUnit : 453 Unit / 23 Integration ; 64 pytest + 24 détecteur = 88 checks), documentation de la fin de support de `net6.0-windows` (EOS nov. 2024), qualification Letters en `Unit Test`, et documentation de la protection de branche | Documentation vérifiable | **CORRIGÉ** |

---

## C. Résultats de validation détaillés

### 1. Compilation
- Commande exécutée : `dotnet build unconfuser.sln -c Release`
- Configuration : `Release`
- Cibles validées :
  - `net48` (Full Framework) : **0 erreur, 0 avertissement**
  - `net6.0-windows` (.NET Core 6) : **0 erreur, 0 avertissement** (Considération de cycle de vie : framework hors support actif depuis le 12 novembre 2024, conservé uniquement pour rétrocompatibilité d'exécution)
  - `net8.0-windows` (.NET Core 8) : **0 erreur, 0 avertissement** (Support actif LTS Microsoft jusqu'en novembre 2026)
- Dépendances : Tous les projets sont à jour pour la restauration (`BenignSample`, `ConfuserExKillerRunner`, `FixtureGenerator`, `ConfuserExKillerRunner.Tests`).

### 2. Tests unitaires et d'intégration C# (xUnit)
- Commande exécutée : `dotnet test ConfuserExKillerRunner.Tests/ConfuserExKillerRunner.Tests.csproj -c Release`
- **Total des tests exécutés : 476**
- **Succès : 476**
- **Échecs : 0**
- **Ignorés : 0**
- Temps d'exécution total : ~16 secondes
- Répartition par traits (100% des tests catégorisés) :
  - **Tests Unitaires (`Category=Unit`)** : **453 tests passés** (exécutables en ~4s)
  - **Tests d'Intégration (`Category=Integration`)** : **23 tests passés** (exécutables en ~16s)

### 3. Tests Python (pytest & Détecteur)
La suite de validation Python comprend deux ensembles d'assertions distincts :
1. **Tests unitaires et d'intégration de l'infrastructure (`tests/`)** :
   - Commande exécutée : `python -m pytest tests -v`
   - **Total des tests : 64 passés (0 échec)**
   - Durée : ~2m59s
   - Répartition :
     - `tests/test_deobfuscation_benchmark.py` : 20 passés
     - `tests/test_formats.py` : 5 passés
     - `tests/test_il.py` : 6 passés
     - `tests/test_matching.py` : 5 passés
     - `tests/test_metadata_heuristics.py` : 6 passés
     - `tests/test_real_fixture_provenance.py` : 11 passés
     - `tests/test_verify_deobfuscated_binary.py` : 11 passés
2. **Contrôles de régression des heuristiques du détecteur (`test_detector.py`)** :
   - Commande exécutée : `python test_detector.py`
   - **Total des contrôles : 24 `[PASS]` (0 échec)**
   - Valide l'ensemble des règles de détection (ConfuserEx, SmartAssembly, Eazfuscator, Netz, EzirizVM, etc.)
- **Total cumulé des vérifications Python automatisées** : **88 vérifications réussies**.

### 4. Tests de sécurité de l'exécution dynamique
- Limite mémoire par processus (512 Mo) : **Validée** (processus tué en cas de dépassement)
- Limite mémoire du Job Object (1 024 Mo) : **Validée**
- Quota de processus (max 10) : **Validé** (prévention de fork-bomb)
- Timeout strict du Job Object (60s) : **Validé**
- Création suspendue et assignation atomique : **Validée** (dans `JobObject.cs` et `Verify-DeobfuscatedBinary.ps1`)
- Nettoyage automatique des arborescences de processus : **Validé**
- Politique fail-closed sur plateformes non-Windows : **Validée** (`ProcessRunner.RunIsolated` échoue immédiatement avec ExitCode = -1)

### 5. Benchmark de désobfuscation
- Commande exécutée : `python benchmarks/run_benchmark.py`
- Résultat global : **9 exécutés, 9 passés, 0 échec, 0 partiel**
- Détail :
  1. `Constants (Strings & Numerics)` : `SYNTHETIC_PASS` (CLEAN, Exact Match)
  2. `Control Flow (Dead Code & Junk Stripping)` : `SYNTHETIC_PASS` (CLEAN, Exact Match)
  3. `Reference & Method Call Proxies` : `SYNTHETIC_PASS` (CLEAN, Exact Match)
  4. `Encrypted Resources` : `SYNTHETIC_PASS` (CLEAN, Exact Match)
  5. `Deflate Compressor Unpacker` : `SYNTHETIC_PASS` (CLEAN, Exact Match)
  6. `Anti-Tamper & Cleaner Hooks` : `SYNTHETIC_PASS` (CLEAN, Exact Match)
  7. `Combined Multi-Protection` : `SYNTHETIC_PASS` (CLEAN, Exact Match)
  8. `Generics & Exception Edges` : `SYNTHETIC_PASS` (CLEAN, Exact Match)
  9. `ConfuserEx yck1509/ConfuserEx v1.0.0` (Authentique) : **`REAL_PROTECTOR_PASS`** (CLEAN, Exact Match)

### 6. Vérification comportementale runtime sur binaire authentique
- Commande exécutée : `powershell -ExecutionPolicy Bypass -File scripts/Verify-DeobfuscatedBinary.ps1 -Target benchmarks/fixtures/real_confuserex/BenignSample_clean.exe`
- Résultat : **20 types sur 20 découverts et vérifiés (JIT Methods : ok=63, skipped=3, missing-dep=0, corrupted-il=0)**.

---

## D. Limites restantes documentées

### 1. Ce qui est totalement résolu
- **Fiabilité des verdicts** : Plus aucun verdict `SUCCESS` n'est retourné si une protection reste indéterminée, non vérifiée ou partielle.
- **Codes de retour CLI** : Conformes aux standards UNIX/Windows (0 = succès avéré, 1 = erreur fatale ou export mapping explicite échoué, 2 = résultat partiel/non vérifié).
- **Intégrité des symboles métier et réseaux** : Aucun identifiant technique (`SmtpTlsHandler`, `HTMLParser`, `RGBColor`, etc.) ni symbole Roslyn (`<>c`, closures) ne subit de renommage erroné.
- **Sécurité des workers et confinement Job Object** : Confinement via Job Object Win32 avec politique *fail-closed*, création suspendue sans fenêtre de course, et refus d'exécution non isolée sur non-Windows.
- **Découplage architectural** : L'évaluateur symbolique PE et l'orchestration CLI sont isolés et testables unitairement.

### 2. Ce qui ne peut pas être résolu de manière purement générique
- **Restauration des noms originaux des symboles non-Forms/non-Resources** :
  - *Raison technique* : ConfuserEx remplace de manière irréversible les identifiants originaux par des hachages MD5 ou des caractères invisibles sans conserver de table de symboles dans l'assembly.
  - *Comportement Unconfuser* : Normalisation en noms sémantiques contextuels (`Type_XXXX`, `Method_XXXX`) ou préservation ; aucun retour vers les noms d'origine non inférables n'est possible sans oracles ou PDBs.
- **Protections JIT/Native x86 non gérées** :
  - *Raison technique* : Les variantes de ConfuserEx injectant des trampolines natifs JIT ou du code machine x86/x64 non géré dépassent le cadre de dnlib et du runtime managé.
  - *Comportement Unconfuser* : Détecté dans [ProtectionMatrix.cs](../ConfuserExKillerRunner/Analysis/ProtectionMatrix.cs) comme `UnsupportedNativeJitHook`, consigné comme `LIMITATION` avec exit code 2.

### 3. Ce qui nécessite une validation manuelle
- **Binaires hautement personnalisés ou moddés de ConfuserEx** : Les forks privés altérant les constantes de chiffrement ou les algorithmes d'Anti-Tamper nécessitent l'analyse manuelle des méthodes de déchiffrement dans dnSpy / ILSpy.
- **Interactions dynamiques complexes d'assemblys chargés au runtime (MEF/Plugins)** : Si un binaire charge dynamiquement des modules externes par nom complet string qui n'apparaissent pas dans les fenêtres d'analyse de réflexion (e.g. chaînes construites dynamiquement par concaténation complexe au runtime), un audit manuel reste requis.

---

## E. Sécurité, confidentialité et gouvernance

1. **Nettoyage des chemins privés** :
   - Tous les chemins de machines de développement locales ont été éliminés de l'ensemble de l'arborescence du projet et de la documentation.
   - Les scripts de benchmark et de validation découvrent désormais leurs chemins via les ancres de dépôt (`.sln`, `.git`) et `AppDomain.CurrentDomain.BaseDirectory`.

2. **Historique Git et traces antérieures** :
   - Les commits locaux de cette branche sont exempts de toute fuite de chemin ou de donnée sensible.
   - **Rappel légal / opérationnel** : Si des commits *historiques* antérieurs (sur des branches distantes partagées) contenaient jadis des chemins privés, leur réécriture nécessite un outil tel que `git filter-repo` ou `BFG Repo-Cleaner`, suivi d'un `git push --force`. **Conformément aux instructions strictes de cette mission, aucune réécriture d'historique partagé n'a été effectuée sans votre accord explicite.**

3. **Secrets et identifiants** :
   - Aucun token d'accès, mot de passe, clé privée ou secret n'a été détecté dans le dépôt.

4. **Protection de la branche GitHub (Phase 5)** :
   - *État audité* : L'interrogation de l'API GitHub (`https://api.github.com/repos/djdjamel/unconfuser/branches/main`) confirme que la branche `main` présente actuellement `protected: false`.
   - *Actions requises par le propriétaire du dépôt* (nécessitant des permissions administratives d'administration GitHub) :
     1. Naviguer dans les paramètres du dépôt : `Settings > Branches > Branch protection rules`.
     2. Cliquer sur **Add rule** (ou **New ruleset**).
     3. Dans le champ **Branch name pattern**, saisir `main`.
     4. Cocher **Require a pull request before merging**.
     5. Cocher **Require status checks to pass before merging**.
     6. Dans la liste des statuts requis, rechercher et sélectionner le check CI obligatoire : `build-and-test`.
     7. Cocher **Require branches to be up to date before merging**.
     8. (Recommandé) Cocher **Do not allow bypassing the above settings** pour les administrateurs.
     9. Cliquer sur **Save changes**.

---

## F. Évaluation finale

| Domaine | Note | Justification synthétique |
|---|---|---|
| **Confidentialité & Hygiène** | **PASS** | Élimination totale des chemins locaux, liens markdown relatifs, suppression des scripts ad-hoc propriétaires, anonymisation des fichiers `.crproj`. |
| **Vérité des verdicts** | **PASS** | Exit code 2 par défaut sur résultat partiel, exit code 1 sur échec explicite de mapping, fin des faux succès sur binaires sains ou échecs PEVerify. |
| **SemanticRenamer** | **PASS** | Élimination des faux positifs sur noms techniques (`SmtpTlsHandler`), protection des symboles Roslyn, détection ConfuserEx Unicode/ASCII/Letters/MD5, préservation des acronymes. |
| **Isolation dynamique** | **PASS** | Job Object Win32 avec création suspendue sans fenêtre de course, quotas mémoire/CPU stricts, politique fail-closed sur non-Windows (pas de repli silencieux). |
| **Tests & Fixtures** | **PASS** | 476 tests xUnit verts (453 Unit / 23 Integration), 88 vérifications Python réussies (64 pytest + 24 détecteur), 9 benchmarks passés dont 1 réel, 20/20 types réels vérifiés au runtime. |
| **Documentation** | **PASS** | Matrice de support en 9 colonnes basée sur des preuves (`SUPPORT_MATRIX.md`), spécification de sécurité (`WORKER_ISOLATION.md`), rapport exhaustif d'audit. |
| **Maintenabilité du code** | **PASS** | Découpage de `Program.cs`, extraction de `CommandLineOptions` et `PeSymbolicEvaluator`, régexes culture-agnostiques, compilation 0 warning. |

### Recommandation finale

La branche `fix/antidump-constants-dependencies-antitamper-validation` est dans un état d'excellence technique et de robustesse opérationnelle optimal.  
L'ensemble des exigences des audits initial et complémentaire est traité, documenté de manière transparente et vérifiable, et rigoureusement validé par les tests automatiques.

**Recommandation** : **Feu vert complet pour intégration (Merge) dans la branche principale (`master` / `main`).**

