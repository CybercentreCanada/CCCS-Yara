# Canadian Centre for Cyber Security

## CCCS YARA Specification

The [CCCS YARA Specification](https://github.com/CybercentreCanada/CCCS-Yara/blob/master/CCCS_YARA.yml) has been created to define and validate the style and format of YARA rule metadata. It comes with a cli which allow you to validate and generate metadata automatically (such as unique id, rule fingerprint, actor enrichment from ATT&CK).

Over the years we have seen many YARA rules; in order to leverage them to their full potential we always had to modify some of their associated metadata, even for rules we developed ourselves. Adjusting simple elements such as datetime format and adding important information to help analysts.

You can leverage it in your CI/CD pipeplines to automatically verify and enrich your Yara rules before new rules are merged in!

This specification also include fields specific to the [MITRE ATT&CK framework](https://attack.mitre.org/matrices/enterprise/) to identify techniques and universal [MITRE ATT&CK threat groups](https://attack.mitre.org/groups/).

[AssemblyLine](https://www.cyber.gc.ca/en/assemblyline) supports this specification natively and will leverage it to provide more context around YARA signature hits.

[vscode-yara](https://github.com/infosec-intern/vscode-yara) creates a custom meta section that aligns with this specification, using the User or Workspace settings file, `settings.json`. See [settings.json](settings.json) for an example.

## Sample rule

```
rule MemoryModule {
    meta:
	id = "6O9mUMvPhziJ72IXHf6muZ"
	fingerprint = "4aa0a23f28698898404d700cb363ddf06dd275f5798815e797113656a2a40ae8"
	version = "1.0"
	date = "2020-05-06"
	modified = "2020-05-06"
	status = "RELEASED"
	sharing = "TLP:WHITE"
	source = "CCCS"
	author = "analyst@CCCS"
	description = "Yara rule to detect usage of MemoryModule Library"
	category = "TECHNIQUE"
	technique = "LOADER:MEMORYMODULE"
	mitre_att = "T1129"
	report = "TA20-0192"
	hash = "812bbe8b9acabad05b08add50ee55c883e1f7998f3a7cae273d3f0d572a79adc"

    strings:
        $func_ptr =    {55 8B EC 6A 00 68 [3] 00 68 [3] 00 68 [3] 00 68 [3] 00 68 [3] 00}
        $func_ptr_64 = {48 [3] 48 [4] 00 00 00 00 48 8? [5] 48 8? [3] 4? 8? [5] 48 8? [3-5] 48 8?}
        $api_1 = "LoadLibraryA"
        $api_2 = "GetProcAddress"
        $api_3 = "FreeLibrary"
        $api_4 = "VirtualFree"
        $api_5 = "VirtualProtect"
        $api_6 = "VirtualAlloc"

    condition:
        uint16(0) == 0x5a4d and all of ($api*) and ($func_ptr or $func_ptr_64)
}
```

## YARA repositories using this standard - thanks!

- https://github.com/reversinglabs/reversinglabs-yara-rules
- https://github.com/bartblaze/Yara-rules
- https://github.com/0xThiebaut/Signatures

## Components

### Validation
This is composed of using a Pydantic model to define the expected metadata fields, their types, acceptable values and any auto-generation of fields as needed. The validator library is used to validate YARA rules' metadata against this model.

### Knowledge Bases & Enrichment
This is a collection of modules to assist in enriching YARA rules with additional context with information from MITRE ATT&CK framework, Malpedia, MISP clusters, and any other piece of open threat intelligence that can be mapped to YARA rules.

*NOTE: The enrichment modules are still under development and will be expanded over time to include more sources and better mapping techniques. It is recommended to review metadata that gets added to the rule to ensure accuracy and relevance.*

### CLI (cccs-yara)
This is the command line interface to perform validation and enrichment of YARA rules. The CLI uses the validator library to validate and auto-generate metadata information as needed. It also uses the enricher library to add additional context to the YARA rules. The CLI supports passing in an alternate validation model written in Pydantic and default metadata information.


## CLI Usage
The CLI contains two subcommands: `info` and `validate`. `info` displays information about the YARA validator, while `validate` validates YARA rules against the CCCS YARA standard (as you're probably more familiar with in previous versions).

### General
```bash
$ cccs-yara --help
      ____ ____ ____ ____   __   __ _    ____      _
     / ___/ ___/ ___/ ___|  \ \ / // \  |  _ \    / \
    | |  | |  | |   \___ \   \ V // _ \ | |_) |  / _ \
    | |__| |__| |___ ___) |   | |/ ___ \|  _ <  / ___ \
     \____\____\____|____/    |_/_/   \_\_| \_\/_/   \_\

usage: cccs-yara [-h] [--validator VALIDATOR] {info,validate} ...

CCCS YARA CLI to validate and enrich YARA rules.

options:
  -h, --help            show this help message and exit
  --validator VALIDATOR
                        Path to Pydantic model configuration, i.e. yara_validator.validator:RuleValidatorModel

subcommands:
  {info,validate}
    info                Display information about the YARA validator.
    validate            Validate YARA rules against the CCCS YARA standard.
```

### Validate
```bash
$cccs-yara validate --help
      ____ ____ ____ ____   __   __ _    ____      _
     / ___/ ___/ ___/ ___|  \ \ / // \  |  _ \    / \
    | |  | |  | |   \___ \   \ V // _ \ | |_) |  / _ \
    | |__| |__| |___ ___) |   | |/ ___ \|  _ <  / ___ \
     \____\____\____|____/    |_/_/   \_\_| \_\/_/   \_\

usage: cccs-yara validate [-h] [-r] [-v {INFO,DEBUG,WARN,ERROR}] [-e] [-dm DEFAULT_METADATA] [-o {inplace,createfile}] [paths ...]

positional arguments:
  paths                 A list of files or folders to be enriched.

options:
  -h, --help            show this help message and exit
  -r, --recursive       Recursively search folders provided.
  -v {INFO,DEBUG,WARN,ERROR}, --verbose {INFO,DEBUG,WARN,ERROR}
                        Control the verbosity of logging output. Options are INFO, DEBUG, WARN, ERROR. Default is ERROR to track only errors. WARN to track
                        warnings and errors such as proposed changes. INFO to track high-level processing information. DEBUG to track detailed debugging
                        information.
  -e, --enrich          Enrich the YARA rules with additional metadata from knowledge sources.
  -dm DEFAULT_METADATA, --default-metadata DEFAULT_METADATA
                        A JSON string representing default metadata to apply to rules during validation.
  -o {inplace,createfile}, --output {inplace,createfile}
                        Decide how to handle output of validated rules. Options are 'inplace' to modify files in place and 'createfile' to write validated rules to new files named after the rule.
```

Quick example:

```bash
# Rule will be converted inline
cccs-yara validate -v -i <path>
```

# Centre canadien pour la cybersécurité

## Spécification YARA du CCCS

La [Spécification YARA du CCCS](https://github.com/CybercentreCanada/CCCS-Yara/blob/master/CCCS_YARA.yml) a été créé pour définir et validé le style et le format des attributs pour les règles YARA. Un outil ligne de commandes permet de valider et généré les tags automatiquement!

Au fil des années nous avons vu beaucoup de régles YARA; mais pour pouvoir les utilisées à leur plein potentiel nous devions modifiée les méta données associtiées, parfois même pour nos propres règles. En ajustant des éléments aussi simples que le format de date et en ajoutant des attributs important pour les analystes.

Ce standard pour les méta données inclus aussi des champs spécifique au [MITRE ATT&CK framework](https://attack.mitre.org/matrices/enterprise/) pour identifier les techniques et les groups d'acteurs [MITRE ATT&CK threat groups](https://attack.mitre.org/groups/).

[AssemblyLine](https://www.cyber.gc.ca/fr/chaine-de-montage-assemblyline) supporte cette spécification nativement et l'utilisera pour fournir d'avantage d'information à l'utilisateur lors du déclanchement d'une signature.

## Exemple

```
rule MemoryModule {
    meta:
	id = "6O9mUMvPhziJ72IXHf6muZ"
	fingerprint = "4aa0a23f28698898404d700cb363ddf06dd275f5798815e797113656a2a40ae8"
	version = "1.0"
	date = "2020-05-06"
	modified = "2020-05-06"
	status = "RELEASED"
	sharing = "TLP:WHITE"
	source = "CCCS"
	author = "analyst@CCCS"
	description = "Yara rule to detect usage of MemoryModule Library"
	category = "TECHNIQUE"
	technique = "LOADER:MEMORYMODULE"
	mitre_att = "T1129"
	report = "TA20-0192"
	hash = "812bbe8b9acabad05b08add50ee55c883e1f7998f3a7cae273d3f0d572a79adc"

    strings:
        $func_ptr =    {55 8B EC 6A 00 68 [3] 00 68 [3] 00 68 [3] 00 68 [3] 00 68 [3] 00}
        $func_ptr_64 = {48 [3] 48 [4] 00 00 00 00 48 8? [5] 48 8? [3] 4? 8? [5] 48 8? [3-5] 48 8?}
        $api_1 = "LoadLibraryA"
        $api_2 = "GetProcAddress"
        $api_3 = "FreeLibrary"
        $api_4 = "VirtualFree"
        $api_5 = "VirtualProtect"
        $api_6 = "VirtualAlloc"

    condition:
        uint16(0) == 0x5a4d and all of ($api*) and ($func_ptr or $func_ptr_64)
}
```

## Répertoires de règles YARA qui utilise ce standard - merci!

- https://github.com/reversinglabs/reversinglabs-yara-rules
- https://github.com/bartblaze/Yara-rules

### Validation
Elle consiste à utiliser un modèle Pydantic pour définir les champs de métadonnées attendus, leurs types, les valeurs acceptables et toute génération automatique de champs si nécessaire. La bibliothèque de validation est utilisée pour valider les métadonnées des règles YARA par rapport à ce modèle.

### Bases de connaissances et enrichissement
Il s'agit d'un ensemble de modules destinés à enrichir les règles YARA avec des informations contextuelles supplémentaires provenant du cadre MITRE ATT&CK, de Malpedia, des clusters MISP et de toute autre source d'informations ouvertes sur les menaces pouvant être mappées aux règles YARA.

### CLI (cccs-yara)
Il s'agit de l'interface de ligne de commande permettant d'effectuer la validation et l'enrichissement des règles YARA. La CLI utilise la bibliothèque de validation pour valider et générer automatiquement les informations de métadonnées selon les besoins. Elle utilise également la bibliothèque d'enrichissement pour ajouter du contexte supplémentaire aux règles YARA. La CLI prend en charge le passage d'un modèle de validation alternatif écrit en Pydantic et d'informations de métadonnées par défaut.


## Utilisation de la CLI
La CLI contient deux sous-commandes : info` et `validate`. `info` affiche des informations sur le validateur YARA, tandis que `validate` valide les règles YARA par rapport à la norme CCCS YARA (que vous connaissez probablement mieux dans les versions précédentes).

### General
```bash
$ cccs-yara --help
      ____ ____ ____ ____   __   __ _    ____      _
     / ___/ ___/ ___/ ___|  \ \ / // \  |  _ \    / \
    | |  | |  | |   \___ \   \ V // _ \ | |_) |  / _ \
    | |__| |__| |___ ___) |   | |/ ___ \|  _ <  / ___ \
     \____\____\____|____/    |_/_/   \_\_| \_\/_/   \_\

usage: cccs-yara [-h] [--validator VALIDATOR] {info,validate} ...

CCCS YARA CLI to validate and enrich YARA rules.

options:
  -h, --help            show this help message and exit
  --validator VALIDATOR
                        Path to Pydantic model configuration, i.e. yara_validator.validator:RuleValidatorModel

subcommands:
  {info,validate}
    info                Display information about the YARA validator.
    validate            Validate YARA rules against the CCCS YARA standard.
```
### Validate
```bash
$cccs-yara validate --help
      ____ ____ ____ ____   __   __ _    ____      _
     / ___/ ___/ ___/ ___|  \ \ / // \  |  _ \    / \
    | |  | |  | |   \___ \   \ V // _ \ | |_) |  / _ \
    | |__| |__| |___ ___) |   | |/ ___ \|  _ <  / ___ \
     \____\____\____|____/    |_/_/   \_\_| \_\/_/   \_\

usage: cccs-yara validate [-h] [-r] [-v {INFO,DEBUG,WARN,ERROR}] [-e] [-dm DEFAULT_METADATA] [-o {inplace,createfile}] [paths ...]

positional arguments:
  paths                 A list of files or folders to be enriched.

options:
  -h, --help            show this help message and exit
  -r, --recursive       Recursively search folders provided.
  -v {INFO,DEBUG,WARN,ERROR}, --verbose {INFO,DEBUG,WARN,ERROR}
                        Control the verbosity of logging output. Options are INFO, DEBUG, WARN, ERROR. Default is ERROR to track only errors. WARN to track
                        warnings and errors such as proposed changes. INFO to track high-level processing information. DEBUG to track detailed debugging
                        information.
  -e, --enrich          Enrich the YARA rules with additional metadata from knowledge sources.
  -dm DEFAULT_METADATA, --default-metadata DEFAULT_METADATA
                        A JSON string representing default metadata to apply to rules during validation.
  -o {inplace,createfile}, --output {inplace,createfile}
                        Decide how to handle output of validated rules. Options are 'inplace' to modify files in place and 'createfile' to write validated rules to new files named after the rule.
```

Exemple rapide:

```bash
# La règle sera convertie en ligne
cccs-yara validate -v -i <path>
```
