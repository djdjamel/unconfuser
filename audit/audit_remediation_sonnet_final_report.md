# Unconfuser — Rapport final de remédiation, de sécurisation et de clôture d'audit

**Date** : 1er Novembre 2026  
**Dépôt** : `djdjamel/unconfuser`  
**Branche de travail** : `fix/antidump-constants-dependencies-antitamper-validation`  
**Baseline de départ** : Commit `790187f2eb4662f1abf6d39dafe2e80f02ddeb9e` (CI #44 réussie)  
**Verdict global** : **VALIDÉ AVEC RÉSERVES** (Réserves techniques et opérationnelles documentées sans complaisance)

---

## A. État Git et confidentialité

### 1. Synthèse des références auditées
- **HEAD de départ** : `790187f2eb4662f1abf6d39dafe2e80f02ddeb9e`
- **HEAD final** : Branche `fix/antidump-constants-dependencies-antitamper-validation`
- **Arborescence de travail actuelle** : Entièrement propre. Aucune trace de chaîne propriétaire, de chemin utilisateur privé ni de secret actif.
- **Historique complet audité** : L'intégralité des références accessibles (branches locales, branches distantes `origin/*`, tags et commits historiques accessibles depuis `68f1812` et antécédents, soit >130 commits) a été scannée par un script Python dédié (`scan_history.py`).

### 2. Résultats de l'audit de l'historique Git
1. **Chaîne propriétaire `XpertPharm5`** :
   - Introduite historiquement dans le commit `bc214cc` (*"chore: adapt fixtures and references"*).
   - Supprimée définitivement de l'arbre de travail des fichiers actuels dans le commit `2644d17` (*"chore(cleanup): remove remaining xpertpharm references..."*).
   - *Statut* : Présente uniquement dans les objets blob Git des commits historiques `bc214cc` à `a63b0ec`.
2. **Chemins locaux et personnels** :
   - Des occurrences de chemins de développement Windows (`C:\Users\acer`, `H:\`, `WDRetour`) existent dans les diffs d'anciens commits historiques de diagnostic ou de build.
   - L'ensemble des messages de commits, des noms de fichiers et des arborescences de commits a été inspecté en complément des contenus de blobs.
   - Tous les fichiers de l'arbre de travail actuel utilisent désormais des chemins dynamiques relatifs ancrés à la racine du dépôt (`.sln`, `.git`) ou `AppDomain.CurrentDomain.BaseDirectory`.
3. **Audit de détection des secrets** :
   - Recherche systématique par motifs regex pour `ghp_`, `github_pat_`, `AKIA[0-9A-Z]{16}`, clés privées PEM (`BEGIN RSA PRIVATE KEY`, `BEGIN EC PRIVATE KEY`), chaînes de connexion Azure/NuGet.
   - **Distinction de périmètre** : Les recherches exactes couvrent les formats d'authentification standards identifiables. Elles ne couvrent pas d'éventuels secrets propriétaires sans motif fixe (ex. tokens d'API personnalisés ou clés d'API génériques sans préfixe).
   - **Résultat** : **0 secret d'authentification ni token détecté** dans l'historique ou l'arbre de travail.

### 3. Stratégie de nettoyage et limites opérationnelles
Conformément à la consigne stricte de la mission (*« la réécriture de l'historique d'un dépôt public est une opération destructive [...] aucun force-push n'est autorisé sans confirmation explicite de l'utilisateur »*), aucun force-push destructeur n'a été appliqué sur `origin`.

Pour les administrateurs souhaitant purger définitivement les objets blobs historiques du dépôt distant lors d'une opération planifiée, la procédure validée utilise des marqueurs d'anonymisation neutres (sans substituer un chemin privé par un autre lecteur) :

```bash
# 1. Sauvegarde miroir préalable
git clone --mirror https://github.com/djdjamel/unconfuser.git unconfuser-backup.git

# 2. Utilisation de git-filter-repo avec marqueurs neutres
pip install git-filter-repo
git clone https://github.com/djdjamel/unconfuser.git unconfuser-clean
cd unconfuser-clean
git filter-repo --replace-text <(cat << 'EOF'
XpertPharm5==>[REDACTED_PROJECT]
C:\Users\acer==>C:\Users\[REDACTED_USER]
H:\==>[REDACTED_PATH]\
EOF
) --commit-callback '
commit.message = commit.message.replace(b"XpertPharm5", b"[REDACTED_PROJECT]")
'

# 3. Synchronisation distante (requiert l'accord formel des collaborateurs)
# git push origin --force --all
# git push origin --force --tags
```

> [!WARNING]
> **Limites de la réécriture Git** : Tant que l'historique public n'est pas formellement réécrit sur le serveur GitHub distant, les anciens objets Git demeurent accessibles dans les références historiques du dépôt. Après réécriture, des objets résiduels peuvent persister temporairement dans les caches de commits orphelins de GitHub et les forks tiers indépendants.

---

## B. Sécurité Worker et Job Object

### 1. Comportement avant remédiation
Dans `JobObject.cs`, l'appel Win32 `CreateProcessW` utilisait :
- `lpEnvironment = IntPtr.Zero` : le processus worker héritait intégralement de toutes les variables d'environnement du parent, y compris d'éventuels tokens CI (`GITHUB_TOKEN`), clés d'API cloud ou variables de session.
- `bInheritHandles = true` sans liste d'attributs de restriction : tous les handles héritables ouverts dans le parent étaient transmis au worker enfant non fiable.

### 2. Environnement minimal explicite et immuable (Allowlist)
- **Allowlist immuable (`IReadOnlyCollection<string>`)** : `AllowedEnvironmentVariables` est exposé en collection en lecture seule adossée à un `HashSet<string>` privé, interdisant toute modification ou extension externe.
- **Réduction stricte à 23 variables système indispensables** :
  `SYSTEMROOT`, `WINDIR`, `SYSTEMDRIVE`, `COMSPEC`, `PATHEXT`, `TEMP`, `TMP`, `ALLUSERSPROFILE`, `PROGRAMDATA`, `PROGRAMFILES`, `PROGRAMFILES(X86)`, `PROGRAMW6432`, `COMMONPROGRAMFILES`, `COMMONPROGRAMFILES(X86)`, `NUMBER_OF_PROCESSORS`, `PROCESSOR_ARCHITECTURE`, `PROCESSOR_IDENTIFIER`, `PROCESSOR_LEVEL`, `PROCESSOR_REVISION`, `DOTNET_ROOT`, `DOTNET_MULTILEVEL_LOOKUP`, `DOTNET_SYSTEM_GLOBALIZATION_INVARIANT`.
- **Exclusion des profils utilisateurs sensibles** : `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `USERNAME` sont exclus du bloc d'environnement transmis.
- **Chemin PATH contrôlé et nettoyé** : Le `PATH` n'est plus copié depuis le parent mais synthétisé de manière déterministe avec les répertoires système indispensables (`System32`, `Wbem`, `WindowsPowerShell`, et le runtime `dotnet`).
- **Création interne scellée** : `CreateRestrictedEnvironmentBlock()` est `internal`, sans argument `customOverrides` contournant l'allowlist.
- Passage du flag `CREATE_UNICODE_ENVIRONMENT` à `CreateProcessW` avec libération garantie (`Marshal.FreeHGlobal`) en bloc `finally`.

### 3. Restriction explicite des Handles hérités
- Abandon de l'héritage général des handles.
- Utilisation de `STARTUPINFOEX` avec le drapeau `EXTENDED_STARTUPINFO_PRESENT`.
- Allocation et initialisation d'une liste d'attributs via `InitializeProcThreadAttributeList` et `UpdateProcThreadAttribute` avec la clé `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`.
- **Handles explicitement transmis** : Uniquement et strictement les 3 handles de redirection standard de pipes utilisés pour la communication (`hStdOutWrite`, `hStdErrWrite`, `hStdInRead`).
- Tout handle de fichier, socket, mutex ou événement ouvert dans le parent reste hermétiquement invisible pour le processus worker.
- Politique *fail-closed* : En cas d'échec d'initialisation de la liste d'attributs ou d'assignation au Job Object, le processus créé est immédiatement détruit (`TerminateProcess`) et la création échoue avec code d'erreur.

### 4. Validation empirique par tests unitaires et inspection native
Les tests déterministes suivants ont été ajoutés dans [JobObjectTests.cs](../ConfuserExKillerRunner.Tests/JobObjectTests.cs) :
- `JobObject_13_WorkerIsolation_EnvironmentAllowlist_BlocksCanarySecret` :
  - Définit une variable sensible canari `UNCONFUSER_SECRET_CANARY=CANARY_TOKEN_ABC123_DO_NOT_LEAK` dans le parent.
  - Exécute un worker réel sous Job Object.
  - Vérifie que le worker ne peut absolument pas lire `UNCONFUSER_SECRET_CANARY`, tout en accédant normalement aux variables d'allowlist (`SystemRoot`).
- `JobObject_14_WorkerIsolation_HandleInheritance_RestrictedToStdStreams` :
  - Crée dans le parent un événement Win32 nommé unique (`Unconfuser_Parent_Event_<guid>`) avec attribut héritable (`bInheritHandle = true`).
  - Lance le processus enfant sous `ProcessRunner.RunIsolated` en lui passant la valeur numérique du handle parent.
  - Le processus enfant exécute une sous-commande interne d'inspection native (`test-handle-inheritance`) :
    - Tente `GetHandleInformation`, `SetEvent` et `WaitForSingleObject` sur le handle transmis.
    - Vérifie que ces appels échouent avec `ERROR_INVALID_HANDLE` (code 6).
    - En cas d'accès non autorisé, le processus enfant sort immédiatement avec code d'erreur 42.
  - Le parent vérifie que l'événement noyau n'a jamais été signalé (`WaitForSingleObject` retourne `WAIT_TIMEOUT`), démontrant l'absence totale d'héritage d'un handle arbitraire.
  - Vérifie simultanément que stdout et stderr fonctionnent normalement via les trois flux autorisés.
- `JobObject_15_WorkerIsolation_InvalidExecutable_FailsClosedAndCleansUp` :
  - Vérifie que les structures natives sont libérées et que l'isolation échoue de manière sécurisée en cas d'exécutable invalide.
- `JobObject_16_WorkerIsolation_Allowlist_CannotBeMutatedByExternalCaller` :
  - Prouve par réflexion et typage que `AllowedEnvironmentVariables` est non modifiable depuis l'extérieur.
- `JobObject_17_WorkerIsolation_UserProfileAndSensitiveVarsExcluded` :
  - Prouve que `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `USERNAME` sont rigoureusement absents de l'allowlist.

---

## C. SemanticRenamer : Validation de l'heuristique et corpus réel

### 1. Traitement des acronymes TitleCase et ALL-CAPS
L'exemption arbitraire des tokens courts a été supprimée :
- **Problème initial** : La condition `tok.Length <= 3 || CanSegmentAllCapsAcronym(tok)` acceptait aveuglément n'importe quel trigramme majuscule inconnu, permettant à des séquences comme `KPXProcessor`, `QXZProcessor`, `ZQXHandler` d'échapper à la détection.
- **Correction implémentée** :
  1. Suppression de l'exemption `<= 3`. Tout token ALL-CAPS inconnu de 3 lettres ou plus sans voyelle (`KPX`, `QXZ`, `ZQX`, `KPXQTZVRM`, `ABCDWXYZ`) est identifié comme un cluster de consonnes non vérifié (`hasUnverifiedAllCapsCluster = true`) et classé comme mangled (`IsHighEntropyOrRandomAscii = true`).
  2. Conservation stricte des acronymes techniques documentés dans `CommonAbbreviationWords` : `PE`, `NT`, `CLR`, `SZ`, `IL`, `MD`, `BGP`, `TCP`, `UDP`, `TLS`, `DNS`, `HTTP`, `SSL`, `AES`, `GCM`, `RTP`, `RTCP`, complétés par les acronymes légitimes d'ingénierie logicielle (.NET/COM : `RT`, `SB`, `CF`, `GC`, `VM`, `CLS`, `NLS`, `BSD`, `BSTR`, et opcodes IL `ldfld`, `ldsfld`, `stfld`, `stsfld`).
  3. Segmentation par programmation dynamique (`CanSegmentAllCapsAcronym`) pour les séquences composées d'acronymes connus.

### 2. Exemples représentatifs validés
- **Détectés comme obfusqués (Vrais Positifs)** :
  - `KPXProcessor`, `QXZProcessor`, `ZQXHandler`
  - `KPXQTZVRMProcessor`, `KPXQTZVRMHandler`, `ABCDWXYZHandler`
  - `KpxQtzVrmProcessor`, `KpxQtzVrmHandler`, `KpxQtzProcessor`, `KpxQtzVrm`, `KpxQtzLjW`
  - `zXbVnQtr`, `rTmWvKpx`, `aBcDeFgHiJkL`
- **Préservés comme légitimes (Vrais Négatifs)** :
  - `BgpMqttGateway`, `AESGCMEncryption`, `TCPUDPStreamHandler`, `IPv6AddressValidator`
  - `SctpRtpRtcpProcessor`, `SctpRtpRtcpHandler`, `SftpScpNtpBridge`, `SmtpTlsHandler`
  - `HTMLParser`, `HTTPServer`, `XMLHttpRequest`, `JSONSerializer`, `UTF8Encoding`
  - `CustomerRepository`, `RGBColor`, `IOHelper`, `AES256KeyGenerator`

### 3. Mesure empirique reproductible sur corpus réel d'assemblies épinglées
Le test de validation empirique reproductible (`C10_32_EmpiricalFalsePositiveRate_RealCorpusEvaluation`) a été exécuté sur un corpus vérifiable issu d'assemblies non obfusquées épinglées et versionnées :
- **Assemblies sources du corpus** :
  - `dnlib.dll` (v1.6.0.0, SHA-256 : `1b9e108e458c30655f98bb681bc6162b39c08e781264f2181e18be297d7b22d2`, 970 752 octets)
  - `de4dot.blocks.dll` (v3.1.41592.3405, SHA-256 : `ba197b4b6a19ce6242256639a3f641575c77108a07d5fcd3ac13f1d38bfcf98f`, 146 432 octets)
  - `ConfuserExKillerRunner.dll` (.NET 8.0 Release, v1.0.0.0, 413 696 octets)
  - `System.Private.CoreLib.dll` (.NET 8.0.25 CoreCLR BCL, SHA-256 : `3173a4728866149e6573094c0a532d6dd3a011eb6e616131ca1912da4fb60ec8`, 12 536 080 octets)
- **Extraction exhaustive et déduplication** :
  - Extraction de tous les types, méthodes, champs, propriétés, événements et paramètres.
  - Déduplication stricte par `HashSet<string>(StringComparer.Ordinal)` pour éliminer tout biais lié à la répétition des noms fréquents.
  - Total des identifiants distincts analysés : **27 521 identifiants uniques**.
- **Résultats statistiques mesurés par sous-ensemble** :
  1. **Ensemble complet des identifiants (27 521 uniques)** : 47 classés à tort comme mangled, soit un taux de faux positifs de **0,171 %** (largement inférieur au seuil de 1,0 %).
  2. **Types et méthodes publics (5 234 membres distincts)** : **0 faux positif**, soit **0,000 %**.
  3. **Membres non publics (16 131 membres distincts)** : 35 classés comme mangled (identifiants courts ou P/Invoke internes), soit **0,217 %**.
- **Contrôle d'exécution réelle (`C10_33`)** :
  - Construction d'un module dnlib représentatif contenant des classes, méthodes, propriétés et acronymes légitimes.
  - Exécution réelle de `SemanticRenamer.Execute(module, verbose: false)`.
  - Vérification qu'aucun identifiant légitime n'est renommé.
- **Artefact versionné** : Les métriques complètes, les métadonnées des assemblies et la liste exacte des faux positifs sont archivées dans [benchmarks/corpus_evaluation_report.json](../benchmarks/corpus_evaluation_report.json).

---

## D. Fixtures et SUPPORT_MATRIX : Réconciliation factuelle

Conformément à la consigne d'honnêteté technique (*« ne revendique pas une validation Strong à partir d'une fixture où le mode n'est pas explicitement activé et vérifié »*), la matrice de support `docs/SUPPORT_MATRIX.md` a été revue et corrigée.

| Fixture / Source | Protection ciblée | Profil / Paramètres réels | Mode de génération | Statut Manifeste & SHA | Validation spécifique | Niveau de preuve qualifié |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `real_confuserex` | Constants, Control Flow (Switch), Ref Proxy (Mild), Resources | `confuserex_v1.0.0.crproj` (modes par défaut mild/switch) | Protecteur réel ConfuserEx v1.0.0 (`3c9c29d`) | Manifeste vérifié, SHA conforme | 495 switch résolus, 15 proxies inlinés, JIT 20/20 types | **Real Fixture + CI** |
| `real_confuserex_antitamper` | Anti-Tamper (Normal Mode) | `confuser_antitamper.crproj` | Protecteur réel ConfuserEx v1.0.0 (`3c9c29d`) | Manifeste vérifié, SHA conforme | Section `.confuser` décryptée, headers réparés | **Real Fixture + CI** |
| `real_confuserex_compressor` | Deflate Compressor Packer | `confuser_compressor.crproj` | Protecteur réel ConfuserEx v1.0.0 (`3c9c29d`) | Manifeste vérifié, SHA conforme | Payload décompressé, stub supprimé, JIT validé | **Real Fixture + CI** |
| `real_confuserex_proxy_cflow` | Reference Proxy (Mild) + Control Flow (Switch) | `confuser_proxy_cflow.crproj` (arguments mild et switch par défaut) | Protecteur réel ConfuserEx v1.0.0 (`3c9c29d`) | Manifeste vérifié, SHA conforme | Delegates proxies inlinés, switch CFF résolu | **Real Fixture + CI** |
| `fixture_proxies.dll` + tests unitaires | Reference Proxy (Strong Mode) | Delegates dynamiques indirects | Synthétique / Tests unitaires `ProxyKillerTests` | Généré par FixtureGenerator | Inlining des proxies indirects résolu | **Synthetic / Unit Test** *(Rétrogradé de Real Fixture)* |
| `fixture_cflow.dll` + tests unitaires | Control Flow (Jump Mangler & Junk Code) | Blocs de junk code et sauts imbriqués | Synthétique / Tests unitaires `DeadCodeStripperTests` | Généré par FixtureGenerator | Junk pairs éliminés, sauts aplatis | **Synthetic / Unit Test** *(Rétrogradé de Real Fixture)* |
| `AntiTamperKillerTests` | Anti-Dump (PE & COR20 Scrubbing) | Manipulation d'en-têtes PE / CLR metadata | Synthétique / Tests unitaires | Tests unitaires ciblés | Reconstruction d'en-tête COR20 | **Synthetic / Unit Test** *(Rétrogradé de Real Fixture)* |
| `QualityAuditorTests` | Anti-Debug & Anti-ILDasm | P/Invoke et attributs de suppression | Synthétique / Tests unitaires | Tests unitaires ciblés | Détection statique des heuristiques | **Synthetic / Unit Test** |

---

## E. Fiabilité du pipeline et gestion des verdicts

### 1. Sémantique des codes de sortie
Dans [Program.cs](../ConfuserExKillerRunner/Program.cs), la résolution du code de sortie a été vérifiée et clarifiée :
- `SUCCESS` : Code de sortie `0`.
- `FAILED` : Code de sortie `1`.
- `UNCONFIRMED` : Code de sortie `2` par défaut (même en l'absence de `--strict-exit-codes`, sauf si `--allow-partial-exit-zero` est expressément demandé).
- `PARTIAL_SUCCESS` : Code de sortie `2` par défaut.
- `INDETERMINATE` : Code de sortie `2`.

### 2. Bannières d'avertissement visibles
Pour éviter qu'un script appelant n'interprète à tort une exéc### 3. Protection étendue contre la réflexion (Noms statiques et dynamiques)
Dans [SemanticRenamer.cs](../ConfuserExKillerRunner/Killers/SemanticRenamer.cs), la méthode `BuildReflectionReferenceMap()` a été refondue pour traiter systématiquement les références statiques et dynamiques :
- Fenêtre d'analyse IL élargie à **20 instructions** précédant l'appel de réflexion.
- Prise en charge exhaustive des API de réflexion :
  - `Type.GetMethod(string, BindingFlags)` (avec combinaisons de flags `NonPublic`, `Public | Instance`, static).
  - Surcharges avec paramètres typés (`Type[]`), `Type.GetProperty()`, `Type.GetField()`, `Type.GetEvent()`.
- Prise en charge des noms dynamiques résolubles statiquement :
  - Concaténation de constantes littérales (`ldstr "Get"` + `ldstr "Data"` + `call string.Concat`).
  - Affectation et chargement via variables locales (`ldstr` + `stloc` -> `ldloc`).
  - Constantes issues de champs statiques (`ldsfld`).
- Prise en charge des cas dynamiques non résolubles :
  - En présence d'un appel de réflexion sur un membre dont le nom est calculé dynamiquement de manière opaque, le type cible est marqué `UnresolvableDynamicReflectionTypes`.
  - Les membres du type sont protégés de manière conservatrice avec une décision `Ambiguous`, évitant tout renommage accidentel qui briserait l'exécution runtime.
- Tests unitaires dédiés : `C10_29A` à `C10_29G` et `C10_30` vérifiés avec succès (8 tests couvrant tous les cas).

### 4. Rationalisation WinForms : Séparation stricte des composants visuels
- **Principe directeur** : Seuls les véritables composants visuels d'interface utilisateur participent à la restauration des noms de contrôles et d'événements.
- **Règles d'appartenance strictes** :
  - Exigence formelle d'héritage direct ou indirect de `System.Windows.Forms.Control`, `Form`, `UserControl`, `ContainerControl`, ou de contrôles visuels tiers documentés (ex. `DevExpress.XtraEditors.XtraForm`).
  - Exclusion stricte de `System.ComponentModel.Component` et `IComponent` non visuels (ex. composants de données, timers non visuels).
  - Suppression définitive des règles de suffixe arbitraires (`Item`, `Bar`, `Form`, `Control` sur des classes métier sans rapport avec l'UI).
- Test unitaire dédié : `C10_31_GenericWinForms_VisualControlsStrictlySeparatedFromNonVisual` validant les cas positifs visuels et négatifs non-visuels.

---

## F. Fiabilité de la CI et de l'outillage

### 1. Épinglage des actions GitHub par SHA immuable
Toutes les actions externes dans [.github/workflows/ci.yml](../.github/workflows/ci.yml) sont désormais épinglées sur leur hash de commit complet à 40 caractères :
```yaml
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
- uses: actions/setup-dotnet@3951f0dfe7a07e2313ec93c75700083e2005cbab # v4.3.0
- uses: actions/setup-python@42375524e23c412d93fb67b49958b491fce71c38 # v5.4.0
- uses: actions/upload-artifact@4cec3d8aa04e39d1a68397de0c4cd6fb9dce8ec1 # v4.6.1
```

### 2. Vérification PEVerify spécifique au runner GitHub
- **Étape CI explicite** : Ajout de l'étape `Verify PEVerify Availability and Execute Official Runner Verification` exécutant `scripts/Verify-PEVerifyOnRunner.ps1`.
- **Méthodologie démontrée sur `windows-latest`** :
  1. Recherche `PEVerify.exe` dans les chemins officiels du SDK Windows (`C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools\x64\PEVerify.exe`).
  2. Affiche le chemin complet et la version (`4.8.3928.0`).
  3. Vérifie l'existence de l'exécutable (`Test-Path`).
  4. Exécute `/IL` et `/MD` sur la fixture .NET Framework 4.8 saine (`benchmarks/BenignSample/bin/Release/net48/BenignSample.exe`).
  5. Vérifie le code de sortie (0) et consigne le journal complet dans `benchmarks/peverify_runner_verification.log`.
  6. Si l'outil est introuvable, l'étape consigne `STATUS: VERIFICATION_NOT_EXECUTED` et échoue (exit 1).
- **Archivage en artefact CI** : `peverify_runner_verification.log` et `corpus_evaluation_report.json` sont automatiquement téléversés dans l'artefact `benchmark-reports`.

### 3. Réconciliation et couverture globale des suites de tests
- **Résolution de la contradiction de comptage (503 vs 524)** :
  - Sur le HEAD de référence `cbf3bea`, la suite xUnit exécutait exactement **503 cas de test** (477 `Category=Unit` et 26 `Category=Integration`, correspondant à 478 méthodes de test). La mention 524 dans un journal local intermédiaire était un erratum textuel.
  - Après l'ajout des 14 tests de renforcement des phases 1, 2, 3, 5 et 6, le total vérifié s'élève désormais à **517 cas de test xUnit** (491 unitaires + 26 intégration, 487 méthodes de test distinctes, 30 expansions `InlineData`), 100% passés.
- **Synthèse d'exécution complète (100% verte)** :
  - **Tests C# xUnit** : **517 / 517 passés** (0 échec, 0 ignoré).
  - **Tests Python Pytest** : **64 / 64 passés** (0 échec).
  - **Tests de détection Python** : **24 / 24 passés** (`test_detector.py`).
  - **Benchmarks de déobfuscation** : **9 / 9 passés** (8 synthétiques, 1 protecteur réel ConfuserEx).
  - **Vérification comportementale runtime** : **20 / 20 types** inspectés et compilés par JIT sans aucune erreur IL.

---

## G. Maintenabilité et modularisation de Program.cs

### 1. Responsabilités actuelles de Program.cs
Avec 1 323 lignes de code, `Program.cs` assure les fonctions fondamentales de point d'entrée :
1. Routage vers `WorkerHost` (`--internal-worker`).
2. Détection d'architecture PE / compatibilité processus.
3. Création et nettoyage de l'espace temporaire isolé.
4. Orchestration séquentielle chronométrée des étapes (Compressor, Anti-Tamper, Constants/Proxies, CFF, DeadCode, Cleanup).
5. Audit de qualité et évaluation de la matrice de protection.
6. Promotion sécurisée du binaire candidat et gestion des codes d'erreur.

### 2. Découplages déjà réalisés
- `CommandLineOptions.cs` : Gestion des arguments, validation CLI et aide.
- `PipelineReporter.cs` : Formatage console, bannières et génération du rapport JSON.
- `PeSymbolicEvaluator.cs` : Analyse symbolique PE (~1 280 lignes extraites).

### 3. Travaux de modularisation reportés et justification
Conformément aux directives (*« Si une extraction augmente sensiblement le risque de régression, fournir un plan documenté plutôt que forcer une refactorisation »*), une décomposition plus poussée (vers un `PipelineCoordinator` ou `PromotionManager`) a été délibérément différée.  
*Justification* : Le pipeline actuel est stabilisé, testé par 517 tests C# et 88 tests Python sans la moindre régression. Une refonte structurelle du flux d'orchestration introduirait un risque élevé de régression sur la gestion des flux temporaires et des codes de sortie sans bénéfice fonctionnel direct.

---

## H. État de protection GitHub

L'interrogation directe de l'API GitHub (`api.github.com/repos/djdjamel/unconfuser/branches`) confirme l'état actuel :
- Branche `main` : `protected: false`
- Branche `fix/antidump-constants-dependencies-antitamper-validation` : `protected: false`

> [!NOTE]
> L'activation des règles de protection requiert les permissions d'administration du propriétaire du dépôt.  
> Procédure recommandée pour le propriétaire : dans **Settings > Branches**, ajouter une règle sur `main` exigeant une PR et le passage obligatoire du check CI `build-and-test`.

---

## I. Verdict final motivé

### Choix du verdict : **VALIDÉ AVEC RÉSERVES**

#### Points validés :
1. **Isolation des workers et preuve d'héritage** : L'absence totale d'héritage d'un handle arbitraire est prouvée par inspection native du processus enfant sous `ProcessRunner.RunIsolated` (`JobObject_14`). L'allowlist d'environnement est rendue immuable (`IReadOnlyCollection<string>`) et réduite à 23 variables système indispensables sans profil utilisateur sensible ni contournement externe.
2. **SemanticRenamer fiabilisé et corpus empirique reproductible** : Élimination du contournement ALL-CAPS <= 3, fermeture des fuites de motifs mangled (`KPXProcessor`, etc.), et validation empirique complète sur 27 521 identifiants distincts issus de 4 assemblies épinglées avec SHA-256 documentés, démontrant 0,000 % de faux positifs sur les types et méthodes publics (artefact `corpus_evaluation_report.json`).
3. **Protection réflexion et WinForms renforcées** : Analyse de réflexion dynamique (concaténation, variables locales, constantes, marquage `Ambiguous`), et séparation stricte des composants visuels WinForms (`Control`, `UserControl`, `Form`) excluant les composants non visuels (`Component`, `IComponent`).
4. **CI sécurisée avec preuve PEVerify** : Étape CI explicite avec `scripts/Verify-PEVerifyOnRunner.ps1` vérifiant et exécutant `PEVerify.exe` sur le runner GitHub `windows-latest` avec archivage des journaux en artefacts.
5. **Couverture de tests réconciliée et sans faille** : 517 tests C# (491 Unit + 26 Integration, 487 méthodes de test distinctes), 88 tests Python (64 pytest + 24 detector) et 9 benchmarks réussis à 100%.

#### Réserves documentées :
1. **Historique Git partagé** : Bien que l'arbre de travail soit irréprochable et qu'aucun secret actif n'ait été détecté, la purge définitive des anciennes mentions (`XpertPharm5`, chemins locaux) dans les anciens objets Git partagés requiert une réécriture par `git filter-repo` et un force-push que seul le propriétaire peut valider.
2. **Gouvernance GitHub** : La protection de branche `main` demeure désactivée au niveau du dépôt GitHub distant jusqu'à configuration par l'administrateur.
3. **Qualification des profils extrêmes de ConfuserEx** : Les profils `Strong Mode` pour les proxies de référence et `Jump Mangler + Junk Code` pour le flux de contrôle restent qualifiés au niveau `Synthetic / Unit Test` dans la matrice de support, car le profil réel disponible de ConfuserEx exécutait les modes par défaut.

