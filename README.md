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

validator.py: This is the validator library. It is used to validate the metadata section of YARA rules. It verifies specified metadata information, auto-generates some of metadata information and re-sorts the metadata information into the canonical order with all 'unknown' metadata information appended to the bottom.

- [CCCS_YARA.yml](https://github.com/CybercentreCanada/CCCS-Yara/blob/master/CCCS_YARA.yml): This is the definition of the CCCS YARA Standard in the YAML format. (Limitation: This file is provided to show what fields are expected, currently the yara_validator doeSn't use this file directly, this will be addressed in a future release.)

- [CCCS_YARA_values.yml](https://github.com/CybercentreCanada/CCCS-Yara/blob/master/CCCS_YARA_values.yml): File which describe the list of acceptable values for fields defined in the CCCS_YARA.yml

yara_validator: This is a command line interface utility. It takes a file, list of files, a folder looking for files with the .yar or .yara extension.

## Requirements

Python 3.6+

All required python packages are in the requirements.txt

The [Cyber Threat Intelligence Repository](https://github.com/mitre/cti) is a submodule of this repository:

```
git clone https://github.com/CybercentreCanada/CCCS-Yara.git
cd CCCS-Yara
pip install  .
```

## yara_validator usage

```
yara_validator -h
     ____ ____ ____ ____   __   __ _    ____      _
    / ___/ ___/ ___/ ___|  \ \ / // \  |  _ \    / \
   | |  | |  | |   \___ \   \ V // _ \ | |_) |  / _ \
   | |__| |__| |___ ___) |   | |/ ___ \|  _ <  / ___ \
    \____\____\____|____/    |_/_/   \_\_| \_\/_/   \_\

usage: yara_validator [-h] [-r] [-n] [-v] [-vv] [-f] [-w] [-s] [-st]
                             [-m] [-i | -c]
                             paths [paths ...]

CCCS YARA script to run the CCCS YARA validator, use the -i or -c flags to
generate the id, fingerprint, version, or modified (if
not already present) and add them to the file.

positional arguments:
  paths                A list of files or folders to be analyzed.

optional arguments:
  -h, --help           show this help message and exit
  -r, --recursive      Recursively search folders provided.
  -n, --no-changes     Makes no changes and outputs potential results to the
                       output.
  -v, --verbose        Verbose mode, will print why a rule was invalid.
  -vv, --very-verbose  Very-verbose mode, will printout what rule is about to
                       be processed, the invalid rules, the reasons they are
                       invalid and all contents of the rule.
  -f, --fail           Fail mode, only prints messages about invalid rules.
  -w, --warnings       This mode will ignore warnings and proceed with other
                       behaviors if the rule is valid.
  -s, --standard       This prints the YARA standard to the screen.
  -st, --strict        This causes the cli to return a non-zero exit code for
                       warnings.
  -m, --module         This flag overrides the check for modules that have not
                       been imported.
  -i, --in-place       Modifies valid files in place, mutually exclusive with
                       -c.
  -c, --create-files   Writes a new file for each valid file, mutually
                       exclusive with -i.
```

Quick example:

```
# Rule will be converted inline
python yara_validator -v -i <path>
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

## Composantes

validator.py: La librairie de validation. Elle permet de vérifier si une règle YARA a tous les attributs nécessaires, elle auto-génère aussi certain attribut et les ordonnent selon l'ontologie. Tous les attributs supplémentaires ne faisant pas partie de la spécification sont placé à la fin.

- [CCCS_YARA.yml](https://github.com/CybercentreCanada/CCCS-Yara/blob/master/CCCS_YARA.yml): Fichier de de définition de la spécification. (Limitation: Ce fichier démontre les attributs nécessaires, présentement le validateur n'utilise pas se fichier directement, ceci sera améliorer dans le futur.)

- [CCCS_YARA_values.yml](https://github.com/CybercentreCanada/CCCS-Yara/blob/master/CCCS_YARA_values.yml): Fichier qui décrit les valeurs acceptables pour chacun des attributs définit dans CCCS_YARA.yml.

yara_validator: Utilitaire de validation pour la ligne de commande. Il accepte une règle, une liste de règles ou un dossier pour validé les fichiers se terminant par .yar ou .YARA.

## Exigences

Python 3.6+

Tous les libraries python sont dans le fichier requirements.txt

[Cyber Threat Intelligence Repository](https://github.com/mitre/cti) est un sous module de ce répertoire:

```
git clone https://github.com/CybercentreCanada/CCCS-Yara.git
cd CCCS-Yara
pip install  .
```

## yara_validator en ligne de commandes

```
yara_validator -h
     ____ ____ ____ ____   __   __ _    ____      _
    / ___/ ___/ ___/ ___|  \ \ / // \  |  _ \    / \
   | |  | |  | |   \___ \   \ V // _ \ | |_) |  / _ \
   | |__| |__| |___ ___) |   | |/ ___ \|  _ <  / ___ \
    \____\____\____|____/    |_/_/   \_\_| \_\/_/   \_\

usage: yara_validator [-h] [-r] [-n] [-v] [-vv] [-f] [-w] [-s] [-st]
                             [-m] [-i | -c]
                             paths [paths ...]

CCCS YARA script to run the CCCS YARA validator, use the -i or -c flags to
generate the id, fingerprint, version, or modified (if
not already present) and add them to the file.

positional arguments:
  paths                A list of files or folders to be analyzed.

optional arguments:
  -h, --help           show this help message and exit
  -r, --recursive      Recursively search folders provided.
  -n, --no-changes     Makes no changes and outputs potential results to the
                       output.
  -v, --verbose        Verbose mode, will print why a rule was invalid.
  -vv, --very-verbose  Very-verbose mode, will printout what rule is about to
                       be processed, the invalid rules, the reasons they are
                       invalid and all contents of the rule.
  -f, --fail           Fail mode, only prints messages about invalid rules.
  -w, --warnings       This mode will ignore warnings and proceed with other
                       behaviors if the rule is valid.
  -s, --standard       This prints the YARA standard to the screen.
  -st, --strict        This causes the cli to return a non-zero exit code for
                       warnings.
  -m, --module         This flag overrides the check for modules that have not
                       been imported.
  -i, --in-place       Modifies valid files in place, mutually exclusive with
                       -c.
  -c, --create-files   Writes a new file for each valid file, mutually
                       exclusive with -i.
```
